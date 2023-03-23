#![deny(clippy::all, clippy::pedantic, clippy::format_push_string)]
//
// TODO: re-check the casting lints - they might indicate an issue
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::if_not_else, // FIXME: remove this
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
)]

mod arch;
mod args;
mod syscall_info;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Row, Table};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use syscalls::{Sysno, SysnoMap, SysnoSet};
use users::get_user_by_name;

use crate::arch::enable_follow_forks;
use crate::args::{ArgCommand, Args, Filter};
use crate::syscall_info::{RetCode, SyscallInfo};

const STRING_LIMIT: usize = 32;

fn main() -> Result<()> {
    let config = Args::parse();

    let pid = match &config.command {
        ArgCommand::Attach(pid) => {
            let pid = Pid::from_raw(pid.attach);
            ptrace::attach(pid).with_context(|| format!("Unable to attach to process {pid}"))?;
            pid
        }

        // FIXME: I suspect this breaks Rust's safety: fork() spawn a thread and that thread
        //        is accessing the same memory as the parent thread (command/env/username/config)
        ArgCommand::Command(command) => match unsafe { fork() } {
            Ok(ForkResult::Child) => return run_tracee(command, &config.env, &config.username),
            Ok(ForkResult::Parent { child }) => child,
            Err(err) => bail!("fork() failed: {err}"),
        },
    };

    Tracer::new(pid, config)?.run_tracer()
}

struct Tracer {
    pid: Pid,
    args: Args,
    string_limit: Option<usize>,
    filter: Filter,
    syscalls_time: SysnoMap<Duration>,
    syscalls_pass: SysnoMap<u64>,
    syscalls_fail: SysnoMap<u64>,
    use_colors: bool,
    output: Box<dyn Write>,
}

impl Tracer {
    fn new(pid: Pid, args: Args) -> Result<Self> {
        // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
        let use_colors;
        let output: Box<dyn Write> = if let Some(filepath) = &args.file {
            use_colors = false;
            Box::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(filepath)?,
            ))
        } else {
            use_colors = atty::is(atty::Stream::Stdout);
            Box::new(std::io::stdout())
        };

        Ok(Self {
            pid,
            filter: args.create_filter()?,
            string_limit: if args.no_abbrev {
                None
            } else {
                Some(args.string_limit.unwrap_or(STRING_LIMIT))
            },
            args,
            syscalls_time: SysnoMap::from_iter(
                SysnoSet::all().iter().map(|v| (v, Duration::default())),
            ),
            syscalls_pass: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),
            syscalls_fail: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),
            use_colors,
            output,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn run_tracer(&mut self) -> Result<()> {
        // Use a flag to indicate if we have already set the needed options once in a loop (if required)
        let mut follow_forks = self.args.follow_forks;
        // If Some(t), we expect the next syscall to be the first call of a pair of syscalls
        let mut syscall_start_time: Option<SystemTime> = None;

        loop {
            // Wait for the next system call
            wait()?;

            // TODO: move this out of the loop if possible, or explain why can't
            if follow_forks {
                follow_forks = false;
                enable_follow_forks(self.pid)?;
            }

            let Ok(registers) = ptrace::getregs(self.pid) else {
                break
            };

            // FIXME: what is 336??? The highest syscall we have is rseq = 334
            //        per syscalls crate, there is a big gap after rseq until pidfd_send_signal = 424
            if registers.orig_rax >= 336 {
                continue;
            }
            let Ok(sys_no) = (registers.orig_rax as u32).try_into() else {
                continue
            };

            // ptrace gets invoked twice per system call: once before and once after execution
            // only print output at second ptrace invocation
            // TODO: explain why these two syscalls should be handled differently?
            // TODO: should we handle if two subsequent syscalls are NOT the same?
            if syscall_start_time.is_some()
                || sys_no == Sysno::execve
                || sys_no == Sysno::exit_group
            {
                let ret_code = RetCode::from_raw(registers.rax);
                let collection = if let RetCode::Err(_) = ret_code {
                    &mut self.syscalls_fail
                } else {
                    &mut self.syscalls_pass
                };

                if let Some(v) = collection.get_mut(sys_no) {
                    *v += 1;
                }

                if self.filter.matches(sys_no, ret_code) {
                    // Measure system call execution time
                    let elapsed = if let Some(start_time) = syscall_start_time {
                        let elapsed = SystemTime::now()
                            .duration_since(start_time)
                            .unwrap_or_default();
                        if let Some(v) = self.syscalls_time.get_mut(sys_no) {
                            *v += elapsed;
                        }
                        elapsed
                    } else {
                        Duration::default()
                    };

                    if !self.args.summary_only {
                        // TODO: if we follow forks, we should also capture/print the pid of the child process
                        let info = SyscallInfo::new(self.pid, sys_no, ret_code, registers, elapsed);
                        if self.args.json {
                            let json = serde_json::to_string(&info)?;
                            writeln!(&mut self.output, "{json}")?;
                        } else {
                            info.write_syscall(
                                self.use_colors,
                                self.string_limit,
                                self.args.syscall_number,
                                self.args.syscall_times,
                                &mut self.output,
                            )?;
                        }
                    }
                }
                syscall_start_time = None;
            } else {
                syscall_start_time = Some(SystemTime::now());
            }

            if ptrace::syscall(self.pid, None).is_err() {
                break;
            }
        }

        if !self.args.json && (self.args.summary_only || self.args.summary) {
            if !self.args.summary_only {
                // Make a gap between the last syscall and the summary
                writeln!(&mut self.output)?;
            }
            self.report_summary()?;
        }

        Ok(())
    }

    fn report_summary(&mut self) -> Result<()> {
        let headers = vec!["% time", "time", "time/call", "calls", "errors", "syscall"];
        let mut table = Table::new();
        table
            .load_preset(UTF8_BORDERS_ONLY)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(&headers);
        for i in 0..headers.len() {
            table.column_mut(i).unwrap().set_cell_alignment(Right);
        }

        let mut sorted_sysno: Vec<_> = self.filter.all_enabled().iter().collect();
        sorted_sysno.sort_by_key(|k| k.name());
        let t_time: Duration = self.syscalls_time.values().sum();

        for sysno in sorted_sysno {
            let (Some(pass), Some(fail), Some(time)) = (
                self.syscalls_pass.get(sysno),
                self.syscalls_fail.get(sysno),
                self.syscalls_time.get(sysno),
            ) else { continue };

            let calls = pass + fail;
            if calls == 0 {
                continue;
            }

            let time_percent = if !t_time.is_zero() {
                time.as_secs_f32() / t_time.as_secs_f32() * 100f32
            } else {
                0f32
            };

            table.add_row(vec![
                Cell::new(&format!("{time_percent:.1}%")),
                Cell::new(&format!("{}µs", time.as_micros())),
                Cell::new(&format!("{:.1}ns", time.as_nanos() as f64 / calls as f64)),
                Cell::new(&format!("{calls}")),
                Cell::new(&format!("{fail}")),
                Cell::new(sysno.name()),
            ]);
        }

        // Create the totals row, but don't add it to the table yet
        let failed = self.syscalls_fail.values().sum::<u64>();
        let calls: u64 = self.syscalls_pass.values().sum::<u64>() + failed;
        let totals: Row = vec![
            Cell::new("100%"),
            Cell::new(format!("{}µs", t_time.as_micros())),
            Cell::new(format!("{:.1}ns", t_time.as_nanos() as f64 / calls as f64)),
            Cell::new(calls),
            Cell::new(failed.to_string()),
            Cell::new("total"),
        ]
        .into();

        // TODO: consider using another table-creating crate
        //       https://github.com/Nukesor/comfy-table/issues/104
        // This is a hack to add a line between the table and the summary,
        // computing max column width of each existing row plus the totals row
        let divider_row: Vec<String> = table
            .column_max_content_widths()
            .iter()
            .copied()
            .enumerate()
            .map(|(idx, val)| {
                let cell_at_idx = totals.cell_iter().take(idx + 1).last().unwrap();
                (val as usize).max(cell_at_idx.content().len())
            })
            .map(|v| str::repeat("-", v))
            .collect();
        table.add_row(divider_row);
        table.add_row(totals);

        if !self.args.summary_only {
            // separate a list of syscalls from the summary table with an blank line
            writeln!(&mut self.output)?;
        }
        writeln!(&mut self.output, "{table}")?;

        Ok(())
    }
}

fn run_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<()> {
    ptrace::traceme()?;
    personality(ADDR_NO_RANDOMIZE).map_err(|_| anyhow!("Unable to set ADDR_NO_RANDOMIZE"))?;

    let mut cmd = Command::new(command.get(0).ok_or_else(|| anyhow!("No command"))?);
    cmd.args(command[1..].iter()).stdout(Stdio::null());

    for token in envs {
        let mut parts = token.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => cmd.env(key, value),
            (Some(key), None) => cmd.env_remove(key),
            _ => unreachable!(),
        };
    }

    if let Some(username) = username {
        if let Some(user) = get_user_by_name(username) {
            cmd.uid(user.uid());
        }
    }

    cmd.exec();

    Ok(())
}
