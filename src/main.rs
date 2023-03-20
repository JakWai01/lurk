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

use crate::arch::enable_follow_forks;
use crate::args::{Args, Filter};
use crate::syscall_info::{RetCode, SyscallInfo};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Table};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use syscalls::Sysno;
use users::get_user_by_name;

const STRING_LIMIT: usize = 32;

fn main() -> Result<()> {
    let config = Args::parse();
    // Check whether to attach to an existing process or create a new one
    if let Some(pid) = config.attach {
        ptrace::attach(Pid::from_raw(pid))
            .with_context(|| format!("Failed to ptrace attach to process {pid}"))?;
        Tracer::new(Pid::from_raw(pid), config)?.run_tracer()?;
    } else {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => run_tracee(config)?,
            Ok(ForkResult::Parent { child }) => Tracer::new(child, config)?.run_tracer()?,
            Err(err) => panic!("[main] fork() failed: {err}"),
        }
    }
    Ok(())
}

struct Tracer {
    child: Pid,
    args: Args,
    string_limit: Option<usize>,
    filter: Filter,
    system_call_timer_stop: HashMap<Sysno, Duration>,
    successful_syscall: Vec<Sysno>,
    failed_syscall: Vec<Sysno>,
    use_colors: bool,
    output: Box<dyn Write>,
}

impl Tracer {
    fn new(child: Pid, args: Args) -> Result<Self> {
        // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
        let use_colors;
        let output_file: Box<dyn Write> = if let Some(filepath) = &args.file {
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
            child,
            filter: args.create_filter()?,
            string_limit: if args.no_abbrev {
                None
            } else {
                Some(args.string_limit.unwrap_or(STRING_LIMIT))
            },
            args,
            system_call_timer_stop: HashMap::new(),
            successful_syscall: vec![],
            failed_syscall: vec![],
            use_colors,
            output: output_file,
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
                enable_follow_forks(self.child)?;
            }

            let Ok(registers) = ptrace::getregs(self.child) else {
                break ;
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
            // TODO: explain why these two syscalls should be handled differently
            // TODO: should we handle if two subsequent syscalls are NOT the same?
            if syscall_start_time.is_some()
                || sys_no == Sysno::execve
                || sys_no == Sysno::exit_group
            {
                let ret_code = RetCode::from_raw(registers.rax);
                if self.filter.matches(sys_no, ret_code) {
                    // Measure system call execution time
                    let elapsed = if let Some(start_time) = syscall_start_time {
                        let elapsed = SystemTime::now()
                            .duration_since(start_time)
                            .unwrap_or_default();
                        self.system_call_timer_stop
                            .entry(sys_no)
                            .and_modify(|v| *v += elapsed)
                            .or_insert(elapsed);
                        elapsed
                    } else {
                        Duration::default()
                    };

                    // TODO: if we follow forks, we should also capture/print the pid of the child process
                    let info = SyscallInfo::new(self.child, sys_no, ret_code, registers, elapsed);
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
                syscall_start_time = None;
                if self.args.summary_only || self.args.summary {
                    self.successful_syscall.push(sys_no);
                }
            } else {
                syscall_start_time = Some(SystemTime::now());
            }

            if ptrace::syscall(self.child, None).is_err() {
                break;
            }
        }

        if !self.args.json && (self.args.summary_only || self.args.summary) {
            self.report_summary()?;
        }

        Ok(())
    }

    fn report_summary(&mut self) -> Result<()> {
        let mut table = Table::new();
        table
            .load_preset(UTF8_BORDERS_ONLY)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "% time",
                "seconds",
                "usecs/call",
                "calls",
                "errors",
                "syscall",
            ]);
        for i in 0..5 {
            table.column_mut(i).unwrap().set_cell_alignment(Right);
        }

        // TODO: this needs to be reworked
        //       possibly use an array-based indexing instead of ever-growing vectors
        let total_elapsed_time: Duration = self.system_call_timer_stop.values().sum();
        let syscall_map = count_element_function(&self.successful_syscall);
        let mut syscall_sorted: Vec<_> = syscall_map.iter().collect();
        syscall_sorted.sort_by_key(|v| v.0);

        let error_map = count_element_function(&self.failed_syscall);
        let mut failed_syscall_count = 0;

        // Construct summary columns
        for (key, value) in syscall_sorted {
            let mut percent_time = 0f32;
            let stop_time = self.system_call_timer_stop.get(key);
            let (seconds, calls) = if let Some(v) = stop_time {
                let call_time_ms = v.as_millis() as f32;
                if !total_elapsed_time.is_zero() {
                    percent_time = call_time_ms / (total_elapsed_time.as_millis() as f32 / 100f32);
                }
                (
                    call_time_ms / 1000f32,
                    (call_time_ms / 1000f32) / (*value as f32) * 1_000_000_f32,
                )
            } else {
                (0.0, 0.0)
            };

            let errors = if let Some(i) = error_map.get(key) {
                failed_syscall_count += i;
                i.to_string()
            } else {
                String::new()
            };

            table.add_row(vec![
                Cell::new(format!("{percent_time:.2}")),
                Cell::new(format!("{seconds:.6}",)),
                Cell::new(format!("{calls:.0}",)),
                Cell::new(value),
                Cell::new(errors),
                Cell::new(key.name()),
            ]);
        }

        // FIXME: this is a hack to add a line between the table and the summary
        //        https://github.com/Nukesor/comfy-table/issues/104
        table.add_row(vec![
            "------",
            "-----------",
            "-----------",
            "---------",
            "---------",
            "----------------",
        ]);

        let seconds = total_elapsed_time.as_millis() as f32 / 1000_f32;
        let usecs_call = (total_elapsed_time.as_millis() as f32
            / self.successful_syscall.len() as f32)
            * 1000_f32;
        table.add_row(vec![
            Cell::new("100.00"),
            Cell::new(format!("{seconds:.6}")),
            Cell::new(format!("{usecs_call:.0}",)),
            Cell::new(total_elapsed_time.as_millis().to_string()),
            Cell::new(failed_syscall_count.to_string()),
            Cell::new("total"),
        ]);

        if !self.args.summary_only {
            // separate a list of syscalls from the summary table
            writeln!(&mut self.output)?;
        }
        writeln!(&mut self.output, "{table}")?;

        Ok(())
    }
}

fn run_tracee(config: Args) -> Result<()> {
    let mut args: Vec<String> = Vec::new();
    let mut program = String::new();

    ptrace::traceme()?;
    personality(ADDR_NO_RANDOMIZE).map_err(|_| anyhow!("Unable to set ADDR_NO_RANDOMIZE"))?;

    // Handle arguments passed to the program to be traced
    for (index, arg) in config.command.iter().enumerate() {
        if index == 0 {
            program = arg.to_string();
        } else {
            args.push(String::from(arg));
        }
    }

    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::null());
    // Add and remove environment variables to/from the environment
    for token in config.env {
        let mut parts = token.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => cmd.env(key, value),
            (Some(key), None) => cmd.env_remove(key),
            _ => unreachable!(),
        };
    }

    if let Some(user) = get_user_by_name(&config.username.unwrap_or_default()) {
        cmd.uid(user.uid());
    }

    cmd.exec();

    Ok(())
}

fn count_element_function<I>(it: I) -> HashMap<I::Item, usize>
where
    I: IntoIterator,
    I::Item: Eq + core::hash::Hash,
{
    it.into_iter().fold(HashMap::new(), |mut acc, x| {
        *acc.entry(x).or_insert(0) += 1;
        acc
    })
}
