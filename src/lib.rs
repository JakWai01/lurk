//! A small Linux system-call tracer.
//!
//! [`spawn_tracee`] is the preferred launcher.  [`run_tracee`] remains for
//! compatibility with callers that perform the fork themselves.

#[deny(clippy::pedantic, clippy::format_push_string)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools
)]
pub mod arch;
pub mod args;
pub mod style;
pub mod syscall_info;

use anyhow::{anyhow, bail, Context, Result};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Row, Table};
use libc::user_regs_struct;
use nix::sys::ptrace::{self, Event};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use syscalls::Sysno;
use uzers::get_user_by_name;

use crate::args::{Args, Filter};
use crate::style::StyleConfig;
use crate::syscall_info::{RetCode, SyscallArgs, SyscallId, SyscallInfo};

const STRING_LIMIT: usize = 32;

pub struct Tracer<W: Write> {
    pid: Pid,
    args: Args,
    string_limit: Option<usize>,
    filter: Filter,
    syscall_stats: HashMap<SyscallId, SyscallStats>,
    style_config: StyleConfig,
    output: W,
    exec_retry_counts: HashMap<Pid, usize>,
    initial_tracees: Vec<(Pid, StartupStop)>,
}

#[derive(Debug, Default)]
struct SyscallStats {
    time: Duration,
    pass: u64,
    fail: u64,
}

#[derive(Debug)]
struct SyscallEntry {
    syscall: SyscallId,
    registers: user_regs_struct,
    args: SyscallArgs,
    started_wall: Instant,
    started_system: Duration,
}

#[derive(Debug, Default)]
struct TraceeState {
    entry: Option<SyscallEntry>,
    startup_stop: Option<StartupStop>,
    seized: bool,
    fallback_needs_sync: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupStop {
    LegacySigstop,
    SeizedLaunch,
    SeizedInterrupt,
    AutoAttachedChild,
}

enum SyscallStop {
    Entry {
        raw: u64,
        arch: Option<u32>,
        args: Option<[u64; 6]>,
    },
    Exit(i64, bool),
    Unknown,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallEntry {
    nr: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallExit {
    sval: i64,
    is_error: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallSeccomp {
    nr: u64,
    args: [u64; 6],
    ret_data: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
union PtraceSyscallData {
    entry: PtraceSyscallEntry,
    exit: PtraceSyscallExit,
    seccomp: PtraceSyscallSeccomp,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PtraceSyscallInfo {
    op: u8,
    reserved: u8,
    flags: u16,
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: PtraceSyscallData,
}

/// How the original tracee terminated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceOutcome {
    Exited(i32),
    Signaled(Signal),
}

impl TraceOutcome {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Exited(code) => code,
            Self::Signaled(signal) => 128 + signal as i32,
        }
    }
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
            syscall_stats: HashMap::new(),
            style_config,
            output,
            exec_retry_counts: HashMap::new(),
            initial_tracees: vec![(pid, StartupStop::LegacySigstop)],
        })
    }

    pub fn set_output(&mut self, output: W) {
        self.output = output;
    }

    /// Mark the original tracee as a child launched with `PTRACE_SEIZE`.
    pub fn set_seized_spawn(&mut self) {
        self.initial_tracees = vec![(self.pid, StartupStop::SeizedLaunch)];
    }

    /// Register all threads seized while attaching to an existing process.
    pub fn set_attached_tracees(&mut self, tracees: Vec<Pid>) {
        self.initial_tracees = tracees
            .into_iter()
            .map(|pid| (pid, StartupStop::SeizedInterrupt))
            .collect();
    }

    pub fn run_tracer(&mut self) -> Result<()> {
        self.run_tracer_with_outcome().map(drop)
    }

    #[allow(clippy::too_many_lines)]
    pub fn run_tracer_with_outcome(&mut self) -> Result<TraceOutcome> {
        let mut states: HashMap<_, _> = self
            .initial_tracees
            .iter()
            .map(|(pid, startup_stop)| {
                (
                    *pid,
                    TraceeState {
                        startup_stop: Some(*startup_stop),
                        seized: !matches!(startup_stop, StartupStop::LegacySigstop),
                        fallback_needs_sync: matches!(startup_stop, StartupStop::SeizedInterrupt),
                        ..TraceeState::default()
                    },
                )
            })
            .collect();
        let mut options_initialized = false;
        let mut root_outcome = None;

        while !states.is_empty() {
            let (status, task_system_time, observed_at) = match wait_for_tracee() {
                Ok(observation) => observation,
                Err(nix::errno::Errno::ECHILD) if states.is_empty() => break,
                Err(error) => return Err(error.into()),
            };

            let stopped = matches!(
                &status,
                WaitStatus::Stopped(_, _)
                    | WaitStatus::PtraceEvent(_, _, _)
                    | WaitStatus::PtraceSyscall(_)
            );
            if !options_initialized && status.pid() == Some(self.pid) && stopped {
                if self.args.follow_forks {
                    arch::ptrace_init_options_fork(self.pid)?;
                } else {
                    arch::ptrace_init_options(self.pid)?;
                }
                options_initialized = true;
            }

            match status {
                WaitStatus::Stopped(pid, signal) => {
                    let state = states.entry(pid).or_default();
                    if is_expected_plain_startup_stop(state.startup_stop, signal) {
                        state.startup_stop = None;
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    match ptrace::getsiginfo(pid) {
                        Ok(_) => self.issue_ptrace_syscall_request(pid, Some(signal))?,
                        Err(nix::errno::Errno::EINVAL) if is_stopping_signal(signal) => {
                            if !state.seized || !listen_tracee(pid)? {
                                self.issue_ptrace_syscall_request(pid, None)?;
                            }
                        }
                        Err(nix::errno::Errno::ESRCH) => {}
                        Err(_) => self.issue_ptrace_syscall_request(pid, Some(signal))?,
                    }
                }
                WaitStatus::PtraceSyscall(pid) => {
                    self.handle_syscall_stop(pid, &mut states, task_system_time, observed_at)?;
                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                WaitStatus::PtraceEvent(pid, signal, code) => {
                    if code == Event::PTRACE_EVENT_STOP as i32 {
                        let state = states.entry(pid).or_default();
                        state.seized = true;
                        if is_expected_event_startup_stop(state.startup_stop, signal) {
                            state.startup_stop = None;
                            self.issue_ptrace_syscall_request(pid, None)?;
                            continue;
                        }
                        if state.seized && is_stopping_signal(signal) && listen_tracee(pid)? {
                            continue;
                        }
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }
                    if code == Event::PTRACE_EVENT_EXEC as i32 {
                        self.migrate_exec_state(pid, &mut states)?;
                    } else if code == Event::PTRACE_EVENT_FORK as i32
                        || code == Event::PTRACE_EVENT_VFORK as i32
                        || code == Event::PTRACE_EVENT_CLONE as i32
                    {
                        let child = Pid::from_raw(ptrace::getevent(pid)? as libc::pid_t);
                        let child_was_known = states.contains_key(&child);
                        let parent_seized = states.get(&pid).is_some_and(|state| state.seized);
                        states
                            .entry(child)
                            .and_modify(|state| state.seized = parent_seized)
                            .or_insert_with(|| TraceeState {
                                startup_stop: Some(StartupStop::AutoAttachedChild),
                                seized: parent_seized,
                                ..TraceeState::default()
                            });
                        if !child_was_known && !self.args.summary_only {
                            writeln!(&mut self.output, "Attaching to child {child}")?;
                        }
                    } else if code == Event::PTRACE_EVENT_EXIT as i32 {
                        let entry = states
                            .get_mut(&pid)
                            .and_then(|state| state.entry.take())
                            .filter(|entry| {
                                entry.syscall.is(Sysno::exit) || entry.syscall.is(Sysno::exit_group)
                            });
                        if let Some(entry) = entry {
                            let (wall_time, system_time) = completed_times(
                                entry.started_wall,
                                entry.started_system,
                                observed_at,
                                task_system_time,
                            );
                            self.log_completed_syscall(
                                pid,
                                entry,
                                RetCode::Ok(0),
                                wall_time,
                                system_time,
                            )?;
                        }
                    }

                    if let Some(state) = states.get_mut(&pid) {
                        state.startup_stop = None;
                    }
                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                WaitStatus::Exited(pid, code) => {
                    states.remove(&pid);
                    if pid == self.pid {
                        root_outcome = Some(TraceOutcome::Exited(code));
                    }
                }
                WaitStatus::Signaled(pid, signal, coredump) => {
                    states.remove(&pid);
                    if !self.args.summary_only {
                        writeln!(
                            &mut self.output,
                            "Child {pid} terminated by signal {signal}{}",
                            if coredump { " (core dumped)" } else { "" }
                        )?;
                    }
                    if pid == self.pid {
                        root_outcome = Some(TraceOutcome::Signaled(signal));
                    }
                }
                WaitStatus::Continued(_) | WaitStatus::StillAlive => {}
            }
        }

        if !self.args.json && (self.args.summary_only || self.args.summary) {
            if !self.args.summary_only {
                writeln!(&mut self.output)?;
            }
            self.report_summary()?;
        }

        root_outcome.ok_or_else(|| anyhow!("tracee disappeared without an exit status"))
    }

    pub fn report_summary(&mut self) -> Result<()> {
        let headers = vec!["% time", "time", "time/call", "calls", "errors", "syscall"];
        let mut table = Table::new();
        table
            .load_preset(UTF8_BORDERS_ONLY)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(&headers);
        for index in 0..headers.len() {
            table.column_mut(index).unwrap().set_cell_alignment(Right);
        }

        let mut stats: Vec<_> = self.syscall_stats.iter().collect();
        stats.sort_by_key(|(syscall, _)| syscall.name());
        let total_time: Duration = stats.iter().map(|(_, stat)| stat.time).sum();
        for (syscall, stat) in stats {
            let calls = stat.pass + stat.fail;
            let percent = if total_time.is_zero() {
                0.0
            } else {
                stat.time.as_secs_f64() / total_time.as_secs_f64() * 100.0
            };
            table.add_row(vec![
                Cell::new(format!("{percent:.1}%")),
                Cell::new(format!("{}µs", stat.time.as_micros())),
                Cell::new(format!(
                    "{:.1}ns",
                    stat.time.as_nanos() as f64 / calls as f64
                )),
                Cell::new(calls),
                Cell::new(stat.fail),
                Cell::new(syscall.name()),
            ]);
        }

        let failed = self
            .syscall_stats
            .values()
            .map(|stat| stat.fail)
            .sum::<u64>();
        let calls = self
            .syscall_stats
            .values()
            .map(|stat| stat.pass + stat.fail)
            .sum::<u64>();
        let average = if calls == 0 {
            0.0
        } else {
            total_time.as_nanos() as f64 / calls as f64
        };
        let totals: Row = vec![
            Cell::new(if calls == 0 { "0%" } else { "100%" }),
            Cell::new(format!("{}µs", total_time.as_micros())),
            Cell::new(format!("{average:.1}ns")),
            Cell::new(calls),
            Cell::new(failed),
            Cell::new("total"),
        ]
        .into();
        let divider_row: Vec<String> = table
            .column_max_content_widths()
            .iter()
            .copied()
            .enumerate()
            .map(|(index, width)| {
                let cell = totals.cell_iter().nth(index).unwrap();
                (width as usize).max(cell.content().len())
            })
            .map(|width| str::repeat("-", width))
            .collect();
        table.add_row(divider_row);
        table.add_row(totals);
        if !self.args.summary_only {
            writeln!(&mut self.output)?;
        }
        writeln!(&mut self.output, "{table}")?;
        Ok(())
    }

    fn handle_syscall_stop(
        &mut self,
        pid: Pid,
        states: &mut HashMap<Pid, TraceeState>,
        task_system_time: Duration,
        observed_at: Instant,
    ) -> Result<()> {
        let state = states.entry(pid).or_default();
        let stop = read_syscall_stop(pid);
        let stop = match stop {
            SyscallStop::Unknown => {
                let registers = self.get_registers(pid)?;
                if state.fallback_needs_sync {
                    state.fallback_needs_sync = false;
                    if fallback_stop_is_entry(registers) == Some(false) {
                        return Ok(());
                    }
                }
                if state.entry.is_some() {
                    let raw = raw_return_value(registers);
                    SyscallStop::Exit(raw, (-4095..=-1).contains(&raw))
                } else {
                    SyscallStop::Entry {
                        raw: raw_syscall_number(registers),
                        arch: registers_use_native_abi(registers).then(native_audit_arch),
                        args: Some(register_args_for_abi(registers)),
                    }
                }
            }
            known => {
                state.fallback_needs_sync = false;
                known
            }
        };

        match stop {
            SyscallStop::Entry {
                raw,
                arch,
                args: raw_args,
            } => {
                let registers = self.get_registers(pid)?;
                let syscall = SyscallId::from_raw_for_native_abi(
                    raw,
                    arch.is_some_and(|arch| arch == native_audit_arch()),
                );
                let args = syscall.known().map_or_else(
                    || {
                        raw_args.map_or_else(
                            || arch::unknown_args(registers),
                            arch::unknown_args_from_values,
                        )
                    },
                    |known| arch::parse_entry_args(pid, known, registers, self.string_limit),
                );
                state.entry = Some(SyscallEntry {
                    syscall,
                    registers,
                    args,
                    started_wall: Instant::now(),
                    started_system: task_system_time,
                });
            }
            SyscallStop::Exit(value, is_error) => {
                let Some(mut entry) = state.entry.take() else {
                    return Ok(());
                };
                if let Some(known) = entry.syscall.known() {
                    entry.args = arch::parse_exit_args(
                        pid,
                        known,
                        entry.registers,
                        self.string_limit,
                        value,
                        &entry.args,
                    );
                }
                let result =
                    RetCode::from_exit(value, is_error, syscall_returns_address(entry.syscall));
                let (wall_time, system_time) = completed_times(
                    entry.started_wall,
                    entry.started_system,
                    observed_at,
                    task_system_time,
                );
                self.log_completed_syscall(pid, entry, result, wall_time, system_time)?;
            }
            SyscallStop::Unknown => unreachable!(),
        }
        Ok(())
    }

    fn log_completed_syscall(
        &mut self,
        pid: Pid,
        entry: SyscallEntry,
        result: RetCode,
        wall_time: Duration,
        system_time: Duration,
    ) -> Result<()> {
        if !self.filter.matches(entry.syscall, result) {
            return Ok(());
        }

        let stats = self.syscall_stats.entry(entry.syscall).or_default();
        stats.time += system_time;
        match result {
            RetCode::Err(_) => stats.fail += 1,
            RetCode::Ok(_) | RetCode::Address(_) => stats.pass += 1,
        }

        if self.args.collapse_exec_retries
            && (entry.syscall.is(Sysno::execve) || entry.syscall.is(Sysno::execveat))
        {
            if result == RetCode::Err(-libc::ENOENT) {
                *self.exec_retry_counts.entry(pid).or_default() += 1;
                return Ok(());
            }
            if let Some(count) = self.exec_retry_counts.remove(&pid) {
                if count > 0 && !self.args.summary_only {
                    writeln!(
                        &mut self.output,
                        "[{pid}] execve: collapsed {count} failed attempts"
                    )?;
                }
            }
        }

        if !self.args.summary_only {
            self.write_syscall_info(&SyscallInfo {
                typ: "SYSCALL",
                pid,
                syscall: entry.syscall,
                args: entry.args,
                result,
                duration: wall_time,
            })?;
        }
        Ok(())
    }

    fn write_syscall_info(&mut self, info: &SyscallInfo) -> Result<()> {
        if self.args.json {
            let json = serde_json::to_string(info)?;
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

    fn issue_ptrace_syscall_request(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        normalize_ptrace_restart(pid, ptrace::syscall(pid, signal))
    }

    fn get_registers(&self, pid: Pid) -> Result<user_regs_struct> {
        ptrace::getregs(pid)
            .map_err(|error| anyhow!("unable to read registers from tracee {pid}: {error}"))
    }

    fn migrate_exec_state(
        &mut self,
        pid: Pid,
        states: &mut HashMap<Pid, TraceeState>,
    ) -> Result<()> {
        let former_tid = Pid::from_raw(ptrace::getevent(pid)? as libc::pid_t);
        if former_tid != pid && former_tid.as_raw() > 0 {
            if let Some(state) = states.remove(&former_tid) {
                states.insert(pid, state);
            }
            if let Some(count) = self.exec_retry_counts.remove(&former_tid) {
                self.exec_retry_counts.insert(pid, count);
            }
        }
        Ok(())
    }
}

fn read_syscall_stop(pid: Pid) -> SyscallStop {
    let mut info = std::mem::MaybeUninit::<PtraceSyscallInfo>::zeroed();
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GET_SYSCALL_INFO,
            pid.as_raw(),
            std::mem::size_of::<PtraceSyscallInfo>() as *mut libc::c_void,
            info.as_mut_ptr(),
        )
    };
    if result < 0 {
        return SyscallStop::Unknown;
    }
    let info = unsafe { info.assume_init() };
    match info.op {
        libc::PTRACE_SYSCALL_INFO_ENTRY => SyscallStop::Entry {
            raw: unsafe { info.data.entry.nr },
            arch: Some(info.arch),
            args: Some(unsafe { info.data.entry.args }),
        },
        libc::PTRACE_SYSCALL_INFO_EXIT => {
            let exit = unsafe { info.data.exit };
            SyscallStop::Exit(exit.sval, exit.is_error != 0)
        }
        _ => SyscallStop::Unknown,
    }
}

const fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    return 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    return 0xc000_00b7;
    #[cfg(target_arch = "riscv64")]
    return 0xc000_00f3;
}

fn registers_use_native_abi(registers: user_regs_struct) -> bool {
    #[cfg(target_arch = "x86_64")]
    return registers.cs == 0x33;
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    return true;
}

fn register_args_for_abi(registers: user_regs_struct) -> [u64; 6] {
    #[cfg(target_arch = "x86_64")]
    if !registers_use_native_abi(registers) {
        return [
            registers.rbx,
            registers.rcx,
            registers.rdx,
            registers.rsi,
            registers.rdi,
            registers.rbp,
        ]
        .map(|value| value & u64::from(u32::MAX));
    }
    arch::register_args(registers)
}

fn fallback_stop_is_entry(registers: user_regs_struct) -> Option<bool> {
    #[cfg(target_arch = "x86_64")]
    return Some(registers.rax as i64 == -i64::from(libc::ENOSYS));
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    return None;
}

fn raw_syscall_number(registers: user_regs_struct) -> u64 {
    #[cfg(target_arch = "x86_64")]
    return registers.orig_rax;
    #[cfg(target_arch = "riscv64")]
    return registers.a7;
    #[cfg(target_arch = "aarch64")]
    return registers.regs[8];
}

fn raw_return_value(registers: user_regs_struct) -> i64 {
    #[cfg(target_arch = "x86_64")]
    return registers.rax as i64;
    #[cfg(target_arch = "riscv64")]
    return registers.a0 as i64;
    #[cfg(target_arch = "aarch64")]
    return registers.regs[0] as i64;
}

fn syscall_returns_address(syscall: SyscallId) -> bool {
    matches!(
        syscall.known().map(|known| known.name()),
        Some("mmap" | "mmap2" | "mremap" | "brk" | "shmat")
    )
}

fn is_stopping_signal(signal: Signal) -> bool {
    matches!(
        signal,
        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
    )
}

fn completed_times(
    started_wall: Instant,
    started_system: Duration,
    observed_at: Instant,
    task_system_time: Duration,
) -> (Duration, Duration) {
    (
        observed_at.saturating_duration_since(started_wall),
        task_system_time.saturating_sub(started_system),
    )
}

fn is_expected_plain_startup_stop(startup: Option<StartupStop>, signal: Signal) -> bool {
    signal == Signal::SIGSTOP
        && matches!(
            startup,
            Some(
                StartupStop::LegacySigstop
                    | StartupStop::SeizedLaunch
                    | StartupStop::AutoAttachedChild
            )
        )
}

fn is_expected_event_startup_stop(startup: Option<StartupStop>, signal: Signal) -> bool {
    match startup {
        Some(StartupStop::SeizedInterrupt) => signal == Signal::SIGTRAP,
        Some(
            StartupStop::LegacySigstop | StartupStop::SeizedLaunch | StartupStop::AutoAttachedChild,
        ) => signal == Signal::SIGTRAP || signal == Signal::SIGSTOP,
        None => false,
    }
}

fn normalize_ptrace_restart(pid: Pid, result: nix::Result<()>) -> Result<()> {
    match result {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(anyhow!("unable to resume tracee {pid}: {error}")),
    }
}

fn ptrace_listen(pid: Pid) -> nix::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_LISTEN,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    nix::errno::Errno::result(result).map(drop)
}

fn listen_tracee(pid: Pid) -> Result<bool> {
    match ptrace_listen(pid) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(true),
        Err(nix::errno::Errno::EIO) | Err(nix::errno::Errno::EINVAL) => Ok(false),
        Err(error) => Err(anyhow!("unable to listen to stopped tracee {pid}: {error}")),
    }
}

fn duration_from_timeval(time: libc::timeval) -> Duration {
    let seconds = u64::try_from(time.tv_sec).unwrap_or_default();
    let micros = u32::try_from(time.tv_usec).unwrap_or_default().min(999_999);
    Duration::new(seconds, micros * 1_000)
}

fn wait_for_tracee() -> nix::Result<(WaitStatus, Duration, Instant)> {
    loop {
        let mut raw_status = 0;
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let pid = unsafe {
            libc::wait4(
                -1,
                &mut raw_status,
                WaitPidFlag::__WALL.bits(),
                usage.as_mut_ptr(),
            )
        };
        if pid < 0 {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(error);
        }
        let observed_at = Instant::now();
        let usage = unsafe { usage.assume_init() };
        let status = WaitStatus::from_raw(Pid::from_raw(pid), raw_status)?;
        return Ok((status, duration_from_timeval(usage.ru_stime), observed_at));
    }
}

#[derive(Debug)]
struct Credentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

fn credentials(username: &Option<String>) -> Result<Option<Credentials>> {
    let Some(username) = username else {
        return Ok(None);
    };
    let user =
        get_user_by_name(username).ok_or_else(|| anyhow!("user '{username}' does not exist"))?;
    let groups = user
        .groups()
        .unwrap_or_default()
        .into_iter()
        .map(|group| group.gid())
        .collect();
    Ok(Some(Credentials {
        uid: user.uid(),
        gid: user.primary_group_id(),
        groups,
    }))
}

fn environment(envs: &[String]) -> BTreeMap<OsString, OsString> {
    let mut environment: BTreeMap<_, _> = std::env::vars_os().collect();
    for token in envs {
        let mut parts = token.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        if let Some(value) = parts.next() {
            environment.insert(key.into(), value.into());
        } else {
            environment.remove(OsStr::new(key));
        }
    }
    environment
}

fn resolve_executable(
    command: &str,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<PathBuf> {
    let command_path = Path::new(command);
    if command_path.components().count() > 1 {
        return Ok(command_path.to_owned());
    }
    let path = environment
        .get(OsStr::new("PATH"))
        .ok_or_else(|| anyhow!("PATH is not set"))?;
    std::env::split_paths(path)
        .map(|directory| directory.join(command))
        .find(|candidate| {
            candidate.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .ok_or_else(|| anyhow!("command '{command}' was not found in PATH"))
}

/// Fork and seize a tracee using only async-signal-safe operations in the child.
///
/// Credential setup is completed before tracing begins, and the child inherits
/// the caller's standard streams and address-space randomization settings.
pub fn spawn_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<Pid> {
    spawn_tracee_with_options(command, envs, username, false)
}

/// Fork and seize a tracee, installing fork-following options atomically when requested.
pub fn spawn_tracee_with_options(
    command: &[String],
    envs: &[String],
    username: &Option<String>,
    follow_forks: bool,
) -> Result<Pid> {
    let program = command.first().ok_or_else(|| anyhow!("no command"))?;
    let environment = environment(envs);
    let executable = resolve_executable(program, &environment)?;
    let executable = CString::new(executable.as_os_str().as_bytes())?;
    let argv: Vec<CString> = command
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<std::result::Result<_, _>>()?;
    let mut argv_ptrs: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let environment: Vec<CString> = environment
        .into_iter()
        .map(|(key, value)| {
            let mut pair = key;
            pair.push("=");
            pair.push(value);
            CString::new(pair.as_os_str().as_bytes())
        })
        .collect::<std::result::Result<_, _>>()?;
    let mut env_ptrs: Vec<_> = environment.iter().map(|value| value.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let credentials = credentials(username)?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            if let Err(error) = wait_for_spawn_stop(child) {
                terminate_unstarted_tracee(child);
                return Err(error);
            }
            if let Err(error) = ptrace::seize(child, arch::ptrace_options(follow_forks)) {
                terminate_unstarted_tracee(child);
                return Err(anyhow!("unable to seize tracee {child}: {error}"));
            }
            if let Err(error) = kill(child, Signal::SIGCONT) {
                terminate_unstarted_tracee(child);
                return Err(anyhow!("unable to continue tracee {child}: {error}"));
            }
            Ok(child)
        }
        ForkResult::Child => unsafe {
            if let Some(credentials) = credentials {
                if libc::setgroups(credentials.groups.len(), credentials.groups.as_ptr()) == -1
                    || libc::setgid(credentials.gid) == -1
                    || libc::setuid(credentials.uid) == -1
                {
                    libc::_exit(126);
                }
            }
            libc::raise(libc::SIGSTOP);
            libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            let error = nix::errno::Errno::last();
            let message = b"lurk: unable to execute command\n";
            libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
            libc::_exit(if error == nix::errno::Errno::ENOENT {
                127
            } else {
                126
            });
        },
    }
}

fn wait_for_spawn_stop(child: Pid) -> Result<()> {
    loop {
        match waitpid(child, Some(WaitPidFlag::WUNTRACED)) {
            Ok(WaitStatus::Stopped(pid, Signal::SIGSTOP)) if pid == child => return Ok(()),
            Ok(WaitStatus::Exited(_, code)) => {
                bail!("tracee exited with status {code} before it could be seized")
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                bail!("tracee was killed by {signal} before it could be seized")
            }
            Ok(status) => bail!("unexpected tracee status before seize: {status:?}"),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn terminate_unstarted_tracee(child: Pid) {
    let _ = kill(child, Signal::SIGKILL);
    while let Err(nix::errno::Errno::EINTR) = waitpid(child, None) {}
}

/// Seize an existing process and, with `follow_forks`, all current threads.
pub fn attach_tracees(pid: Pid, follow_forks: bool) -> Result<Vec<Pid>> {
    let options = arch::ptrace_options(follow_forks);
    ptrace::seize(pid, options).with_context(|| format!("Unable to attach to process {pid}"))?;
    match ptrace::interrupt(pid) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(error) => return Err(anyhow!("Unable to stop attached process {pid}: {error}")),
    }

    let mut tracees = vec![pid];
    if !follow_forks {
        return Ok(tracees);
    }

    let mut attempted = HashSet::from([pid]);
    loop {
        let mut found_new_thread = false;
        let task_directory = format!("/proc/{pid}/task");
        let entries = match fs::read_dir(&task_directory) {
            Ok(entries) => entries,
            Err(_) => break,
        };
        for entry in entries.flatten() {
            let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<libc::pid_t>().ok())
                .map(Pid::from_raw)
            else {
                continue;
            };
            if !attempted.insert(tid) {
                continue;
            }
            found_new_thread = true;
            if ptrace::seize(tid, options).is_err() {
                continue;
            }
            tracees.push(tid);
            let _ = ptrace::interrupt(tid);
        }
        if !found_new_thread {
            break;
        }
    }
    Ok(tracees)
}

fn apply_credentials(credentials: &Credentials) -> Result<()> {
    let failed = unsafe {
        libc::setgroups(credentials.groups.len(), credentials.groups.as_ptr()) == -1
            || libc::setgid(credentials.gid) == -1
            || libc::setuid(credentials.uid) == -1
    };
    if failed {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Legacy child-side launcher retained for library compatibility.
pub fn run_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<()> {
    if let Some(credentials) = credentials(username)? {
        apply_credentials(&credentials)?;
    }
    ptrace::traceme()?;
    nix::sys::signal::raise(Signal::SIGSTOP)?;
    let program = command.first().ok_or_else(|| anyhow!("no command"))?;
    let mut cmd = Command::new(program);
    cmd.args(&command[1..]);
    for token in envs {
        let mut parts = token.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        if let Some(value) = parts.next() {
            cmd.env(key, value);
        } else {
            cmd.env_remove(key);
        }
    }
    let error = cmd.exec();
    bail!("unable to execute '{program}': {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_stop_matching_never_consumes_an_unrelated_signal() {
        assert!(is_expected_plain_startup_stop(
            Some(StartupStop::LegacySigstop),
            Signal::SIGSTOP
        ));
        assert!(!is_expected_plain_startup_stop(
            Some(StartupStop::LegacySigstop),
            Signal::SIGUSR1
        ));
        assert!(!is_expected_plain_startup_stop(
            Some(StartupStop::SeizedInterrupt),
            Signal::SIGSTOP
        ));
        assert!(is_expected_event_startup_stop(
            Some(StartupStop::SeizedInterrupt),
            Signal::SIGTRAP
        ));
        assert!(is_expected_event_startup_stop(
            Some(StartupStop::LegacySigstop),
            Signal::SIGTRAP
        ));
    }

    #[test]
    fn esrch_is_a_benign_ptrace_restart_race() {
        let pid = Pid::from_raw(123);
        assert!(normalize_ptrace_restart(pid, Err(nix::errno::Errno::ESRCH)).is_ok());
        assert!(normalize_ptrace_restart(pid, Err(nix::errno::Errno::EIO)).is_err());
    }

    #[test]
    fn completed_time_uses_the_wait_observation_snapshot() {
        let started = Instant::now();
        let observed = started + Duration::from_micros(25);
        let (wall, system) = completed_times(
            started,
            Duration::from_micros(10),
            observed,
            Duration::from_micros(17),
        );
        assert_eq!(wall, Duration::from_micros(25));
        assert_eq!(system, Duration::from_micros(7));
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn local_syscall_info_layout_matches_libc() {
        assert_eq!(
            std::mem::size_of::<PtraceSyscallInfo>(),
            std::mem::size_of::<libc::ptrace_syscall_info>()
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn compat_register_fallback_uses_the_i386_calling_convention() {
        let mut registers = unsafe { std::mem::zeroed::<user_regs_struct>() };
        registers.cs = 0x23;
        registers.rbx = 1;
        registers.rcx = 2;
        registers.rdx = 3;
        registers.rsi = 4;
        registers.rdi = 5;
        registers.rbp = 6;
        registers.rax = (-i64::from(libc::ENOSYS)) as u64;
        assert!(!registers_use_native_abi(registers));
        assert_eq!(register_args_for_abi(registers), [1, 2, 3, 4, 5, 6]);
        assert_eq!(fallback_stop_is_entry(registers), Some(true));
    }
}
