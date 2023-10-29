//! lurk is a pretty (simple) alternative to strace.
//!
//! ## Installation
//!
//! Add the following dependencies to your `Cargo.toml`
//!
//! ```toml
//! [dependencies]
//! lurk-cli = "0.3.4"
//! nix = { version = "0.27.1", features = ["ptrace", "signal"] }
//! console = "0.15.8"
//! ```
//!
//! ## Usage
//!
//! First crate a tracee using [`run_tracee`] method. Then you can construct a [`Tracer`]
//! struct to trace the system calls via calling [`run_tracer`].
//!
//! ## Examples
//!
//! ```rust
//! use anyhow::{bail, Result};
//! use console::Style;
//! use lurk_cli::{args::Args, style::StyleConfig, Tracer};
//! use nix::unistd::{fork, ForkResult};
//! use std::io;
//!
//! fn main() -> Result<()> {
//!     let command = String::from("/usr/bin/ls");
//!
//!     let pid = match unsafe { fork() } {
//!         Ok(ForkResult::Child) => {
//!             return lurk_cli::run_tracee(&[command], &[], &None);
//!         }
//!         Ok(ForkResult::Parent { child }) => child,
//!         Err(err) => bail!("fork() failed: {err}"),
//!     };
//!
//!     let args = Args::default();
//!     let output = io::stdout();
//!     let style = StyleConfig {
//!         pid: Style::new().cyan(),
//!         syscall: Style::new().white().bold(),
//!         success: Style::new().green(),
//!         error: Style::new().red(),
//!         result: Style::new().yellow(),
//!         use_colors: true,
//!     };
//!
//!     Tracer::new(pid, args, output, style)?.run_tracer()
//! }
//! ```
//!
//! [`run_tracee`]: crate::run_tracee
//! [`Tracer`]: crate::Tracer
//! [`run_tracer`]: crate::Tracer::run_tracer

#[deny(clippy::all, clippy::pedantic, clippy::format_push_string)]
// TODO: re-check the casting lints - they might indicate an issue
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools
)]
pub mod arch;
pub mod args;
pub mod style;
pub mod syscall_info;

use anyhow::{anyhow, Result};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Row, Table};
use libc::{user_regs_struct, PTRACE_SYSCALL_INFO_EXIT};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace::{self, Event};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use style::StyleConfig;
use syscalls::{Sysno, SysnoMap, SysnoSet};
use users::get_user_by_name;

use crate::args::{Args, Filter};
use crate::syscall_info::{RetCode, SyscallInfo};

const STRING_LIMIT: usize = 32;

pub struct Tracer<W: Write> {
    pid: Pid,
    args: Args,
    string_limit: Option<usize>,
    filter: Filter,
    syscalls_time: SysnoMap<Duration>,
    syscalls_pass: SysnoMap<u64>,
    syscalls_fail: SysnoMap<u64>,
    style_config: StyleConfig,
    output: W,
}

impl<W: Write> Tracer<W> {
    pub fn new(pid: Pid, args: Args, output: W, style_config: StyleConfig) -> Result<Self> {
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
            style_config,
            output,
        })
    }

    pub fn set_output(&mut self, output: W) {
        self.output = output;
    }

    #[allow(clippy::too_many_lines)]
    pub fn run_tracer(&mut self) -> Result<()> {
        // Create a hashmap to track entry and exit times across all forked processes individually.
        let mut start_times = HashMap::<Pid, Option<SystemTime>>::new();
        start_times.insert(self.pid, None);

        let mut options_initialized = false;

        loop {
            let status = wait()?;

            if !options_initialized {
                if self.args.follow_forks {
                    arch::ptrace_init_options_fork(self.pid)?;
                } else {
                    arch::ptrace_init_options(self.pid)?;
                }
                options_initialized = true;
            }

            match status {
                // `WIFSTOPPED(status), signal is WSTOPSIG(status)
                WaitStatus::Stopped(pid, signal) => {
                    // There are three reasons why a child might stop with SIGTRAP:
                    // 1) syscall entry
                    // 2) syscall exit
                    // 3) child calls exec
                    //
                    // Because we are tracing with PTRACE_O_TRACESYSGOOD, syscall entry and syscall exit
                    // are stopped in PtraceSyscall and not here, which means if we get a SIGTRAP here,
                    // it's because the child called exec.
                    if signal == Signal::SIGTRAP {
                        self.log_standard_syscall(pid, None, None)?;
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // If we trace with PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, and PTRACE_O_TRACECLONE,
                    // a created child of our tracee will stop with SIGSTOP.
                    // If our tracee creates children of their own, we want to trace their syscall times with a new value.
                    if signal == Signal::SIGSTOP {
                        if self.args.follow_forks {
                            start_times.insert(pid, None);

                            if !self.args.summary_only {
                                writeln!(&mut self.output, "Attaching to child {}", pid,)?;
                            }
                        }

                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // The SIGCHLD signal is sent to a process when a child process terminates, interrupted, or resumes after being interrupted
                    // This means, that if our tracee forked and said fork exits before the parent, the parent will get stopped.
                    // Therefor issue a PTRACE_SYSCALL request to the parent to continue execution.
                    // This is also important if we trace without the following forks option.
                    if signal == Signal::SIGCHLD {
                        self.issue_ptrace_syscall_request(pid, Some(signal))?;
                        continue;
                    }

                    // If we fall through to here, we have another signal that's been sent to the tracee,
                    // in this case, just forward the singal to the tracee to let it handle it.
                    // TODO: Finer signal handling, edge-cases etc.
                    ptrace::cont(pid, signal)?;
                }
                // WIFEXITED(status)
                WaitStatus::Exited(pid, _) => {
                    // If the process that exits is the original tracee, we can safely break here,
                    // but we need to continue if the process that exits is a child of the original tracee.
                    if self.pid == pid {
                        break;
                    } else {
                        continue;
                    };
                }
                // The traced process was stopped by a `PTRACE_EVENT_*` event.
                WaitStatus::PtraceEvent(pid, _, code) => {
                    // We stop at the PTRACE_EVENT_EXIT event because of the PTRACE_O_TRACEEXIT option.
                    // We do this to properly catch and log exit-family syscalls, which do not have an PTRACE_SYSCALL_INFO_EXIT event.
                    if code == Event::PTRACE_EVENT_EXIT as i32 && self.is_exit_syscall(pid)? {
                        self.log_standard_syscall(pid, None, None)?;
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // Tracee is traced with the PTRACE_O_TRACESYSGOOD option.
                WaitStatus::PtraceSyscall(pid) => {
                    // ptrace(PTRACE_GETEVENTMSG,...) can be one of three values here:
                    // 1) PTRACE_SYSCALL_INFO_NONE
                    // 2) PTRACE_SYSCALL_INFO_ENTRY
                    // 3) PTRACE_SYSCALL_INFO_EXIT
                    let event = ptrace::getevent(pid)? as u8;

                    // Snapshot current time, to avoid polluting the syscall time with
                    // non-syscall related latency.
                    let timestamp = Some(SystemTime::now());

                    // We only want to log regular syscalls on exit
                    if let Some(syscall_start_time) = start_times.get_mut(&pid) {
                        if event == PTRACE_SYSCALL_INFO_EXIT {
                            self.log_standard_syscall(pid, *syscall_start_time, timestamp)?;
                            *syscall_start_time = None;
                        } else {
                            *syscall_start_time = timestamp;
                        }
                    } else {
                        return Err(anyhow!("Unable to get start time for tracee {}", pid));
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // WIFSIGNALED(status), signal is WTERMSIG(status) and coredump is WCOREDUMP(status)
                WaitStatus::Signaled(pid, signal, coredump) => {
                    writeln!(
                        &mut self.output,
                        "Child {} terminated by signal {} {}",
                        pid,
                        signal,
                        if coredump { "(core dumped)" } else { "" }
                    )?;
                    break;
                }
                // WIFCONTINUED(status), this usually happens when a process receives a SIGCONT.
                // Just continue with the next iteration of the loop.
                WaitStatus::Continued(_) | WaitStatus::StillAlive => {
                    continue;
                }
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

    pub fn report_summary(&mut self) -> Result<()> {
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
            ) else {
                continue;
            };

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
                let cell_at_idx = totals.cell_iter().nth(idx).unwrap();
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

    fn log_standard_syscall(
        &mut self,
        pid: Pid,
        syscall_start_time: Option<SystemTime>,
        syscall_end_time: Option<SystemTime>,
    ) -> Result<()> {
        let (syscall_number, registers) = self.parse_register_data(pid)?;

        // Theres no PTRACE_SYSCALL_INFO_EXIT for an exit-family syscall, hence ret_code will always be 0xffffffffffffffda (which is -38)
        // -38 is ENOSYS which is put into RAX as a default return value by the kernel's syscall entry code.
        // In order to not pollute the summary with this false positive, avoid exit-family syscalls from being counted (same behaviour as strace).
        let ret_code = match syscall_number {
            Sysno::exit | Sysno::exit_group => RetCode::from_raw(0),
            _ => {
                #[cfg(target_arch = "x86_64")]
                let code = RetCode::from_raw(registers.rax);
                #[cfg(target_arch = "riscv64")]
                let code = RetCode::from_raw(registers.a7);
                match code {
                    RetCode::Err(_) => self.syscalls_fail[syscall_number] += 1,
                    _ => self.syscalls_pass[syscall_number] += 1,
                }
                code
            }
        };

        if self.filter.matches(syscall_number, ret_code) {
            let elapsed = syscall_start_time.map_or(Duration::default(), |start_time| {
                let end_time = syscall_end_time.unwrap_or(SystemTime::now());
                end_time.duration_since(start_time).unwrap_or_default()
            });

            if syscall_start_time.is_some() {
                self.syscalls_time[syscall_number] += elapsed;
            }

            if !self.args.summary_only {
                let info = SyscallInfo::new(pid, syscall_number, ret_code, registers, elapsed);
                self.write_syscall_info(&info)?;
            }
        }

        Ok(())
    }

    fn write_syscall_info(&mut self, info: &SyscallInfo) -> Result<()> {
        if self.args.json {
            let json = serde_json::to_string(&info)?;
            Ok(writeln!(&mut self.output, "{json}")?)
        } else {
            info.write_syscall(
                self.style_config.clone(),
                self.string_limit,
                self.args.syscall_number,
                self.args.syscall_times,
                &mut self.output,
            )
        }
    }

    // Issue a PTRACE_SYSCALL request to the tracee, forwarding a signal if one is provided.
    fn issue_ptrace_syscall_request(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        ptrace::syscall(pid, signal)
            .map_err(|_| anyhow!("Unable to issue a PTRACE_SYSCALL request in tracee {}", pid))
    }

    // TODO: This is arch-specific code and should be modularized
    fn get_registers(&self, pid: Pid) -> Result<user_regs_struct> {
        ptrace::getregs(pid).map_err(|_| anyhow!("Unable to get registers from tracee {}", pid))
    }

    fn get_syscall(&self, registers: user_regs_struct) -> Result<Sysno> {
        #[cfg(target_arch = "x86_64")]
        let reg = registers.orig_rax;
        #[cfg(target_arch = "riscv64")]
        let reg = registers.a7;
        (reg as u32).try_into()
            .map_err(|_| anyhow!("Invalid syscall number {}", reg))
    }

    // Issues a ptrace(PTRACE_GETREGS, ...) request and gets the corresponding syscall number (Sysno).
    fn parse_register_data(&self, pid: Pid) -> Result<(Sysno, user_regs_struct)> {
        let registers = self.get_registers(pid)?;
        let syscall_number = self.get_syscall(registers)?;

        Ok((syscall_number, registers))
    }

    fn is_exit_syscall(&self, pid: Pid) -> Result<bool> {
        self.get_registers(pid).map(|registers| {
            #[cfg(target_arch = "x86_64")]
            let reg = registers.orig_rax;
            #[cfg(target_arch = "riscv64")]
            let reg = registers.a7;
            reg == Sysno::exit as u64 || reg == Sysno::exit_group as u64
        })
    }
}

pub fn run_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<()> {
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
