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

mod args;
mod syscalls_i64;
use anyhow::{anyhow, Context, Result};

use crate::args::{Args, Filter};
use crate::syscalls_i64::{SystemCallArgumentType, SYSTEM_CALLS};
use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use byteorder::{LittleEndian, WriteBytesExt};
use clap::Parser;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Table};
use libc::{c_long, c_ulonglong, c_void, user_regs_struct};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::SystemTime;
use users::get_user_by_name;
use SystemCallArgumentType::{Addr, Int, Str};

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
    filter: Filter,
    system_call_timer_start: Option<SystemTime>,
    system_call_timer_stop: HashMap<usize, u128>,
    successful_syscall: Vec<usize>,
    failed_syscall: Vec<usize>,
    use_colors: bool,
    output_file: Box<dyn Write>,
}

enum RetCode {
    Success(i32),
    Error(i32),
    Address(usize),
}

impl RetCode {
    fn new(ret_code: c_ulonglong) -> Self {
        let ret_i32 = ret_code as isize;
        if ret_i32.abs() > 32768 {
            Self::Address(ret_code as usize)
        } else if ret_i32 < 0 {
            Self::Error(ret_i32 as i32)
        } else {
            Self::Success(ret_i32 as i32)
        }
    }
}

impl Display for RetCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success(v) | Self::Error(v) => write!(f, "{v}"),
            Self::Address(v) => write!(f, "{v:#X}"),
        }
    }
}

impl Tracer {
    fn new(child: Pid, args: Args) -> Result<Self> {
        // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
        let use_colors;
        let output_file: Box<dyn Write> = if let Some(filepath) = &args.file {
            use_colors = false;
            Box::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(filepath)?,
            )
        } else {
            use_colors = atty::is(atty::Stream::Stdout);
            Box::new(std::io::stdout())
        };

        Ok(Self {
            child,
            filter: args.create_filter(),
            args,
            system_call_timer_start: None,
            system_call_timer_stop: HashMap::new(),
            successful_syscall: vec![],
            failed_syscall: vec![],
            use_colors,
            output_file,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn run_tracer(&mut self) -> Result<()> {
        let mut on_syscall_end = false;
        // If --follow-forks is set, set options to follow forks
        let mut follow_forks = self.args.follow_forks;

        loop {
            // Wait for the next system call
            wait()?;

            if follow_forks {
                follow_forks = false;
                ptrace::setoptions(
                    self.child,
                    Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK
                        | Options::PTRACE_O_TRACECLONE,
                )?;
            }

            let Ok(registers) = ptrace::getregs(self.child) else {
                break;
            };

            // FIXME: what is 336???
            if registers.orig_rax < 336 {
                self.on_syscall(&mut on_syscall_end, registers)?;
            } else {
                // TODO: report ignored system call ID that is not in the list
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

    fn on_syscall(&mut self, on_syscall_end: &mut bool, registers: user_regs_struct) -> Result<()> {
        let syscall_id = registers.orig_rax as usize;

        // only print output at second invocation of ptrace
        // ptrace gets invoked twice per system call - once before and once after execution
        if !*on_syscall_end && syscall_id != 59 && syscall_id != 231 {
            self.system_call_timer_start = Some(SystemTime::now());
            *on_syscall_end = true;
        } else {
            // Print output for the current system call if the filter expression did
            // not sort it out beforehand. Furthermore, check if the filter expression
            // was negated.
            if self.filter.show_syscall(syscall_id) {
                // Measure system call execution time
                let elapsed = if let Some(start_time) = self.system_call_timer_start {
                    let elapsed = SystemTime::now()
                        .duration_since(start_time)
                        .unwrap_or_default()
                        .as_millis();
                    self.system_call_timer_stop
                        .entry(syscall_id)
                        .and_modify(|v| *v += elapsed)
                        .or_insert(elapsed);
                    elapsed
                } else {
                    0
                };
                self.report_syscall(&RetCode::new(registers.rax), elapsed, syscall_id, registers)?;
            }

            self.system_call_timer_start = None;

            if self.args.summary_only || self.args.summary {
                self.successful_syscall.push(syscall_id);
            }
            *on_syscall_end = false;
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
        let total_elapsed_time: u128 = self.system_call_timer_stop.values().sum();
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
                if total_elapsed_time != 0 {
                    percent_time = *v as f32 / (total_elapsed_time as f32 / 100f32);
                }
                (
                    *v as f32 / 1000f32,
                    (*v as f32 / 1000f32) / (*value as f32) * 1_000_000_f32,
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
                Cell::new(SYSTEM_CALLS[**key].0),
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

        let seconds = total_elapsed_time as f32 / 1000_f32;
        let usecs_call =
            (total_elapsed_time as f32 / self.successful_syscall.len() as f32) * 1000_f32;
        table.add_row(vec![
            Cell::new("100.00"),
            Cell::new(format!("{seconds:.6}")),
            Cell::new(format!("{usecs_call:.0}",)),
            Cell::new(total_elapsed_time.to_string()),
            Cell::new(failed_syscall_count.to_string()),
            Cell::new("total"),
        ]);

        if !self.args.summary_only {
            // separate a list of syscalls from the summary table
            writeln!(&mut self.output_file)?;
        }
        writeln!(&mut self.output_file, "{table}")?;

        Ok(())
    }

    fn read_string(&self, address: c_ulonglong) -> String {
        let mut string = String::new();
        // Move 8 bytes up each time for next read.
        let mut count = 0;
        let word_size = 8;

        'done: loop {
            let address = unsafe { (address as *mut c_void).offset(count) };

            let res: c_long = match ptrace::read(self.child, address) {
                Ok(c_long) => c_long,
                Err(_) => break 'done,
            };

            let mut bytes: Vec<u8> = vec![];
            bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
                panic!("Failed to write {res} as i64 LittleEndian: {err}");
            });
            for b in bytes {
                if b == 0 {
                    break 'done;
                }
                string.push(b as char);
            }

            count += word_size;
        }

        string
    }

    fn args_to_json_vec(
        &mut self,
        registers: user_regs_struct,
        syscall_args: &[Option<SystemCallArgumentType>],
    ) -> Vec<Value> {
        syscall_args
            .iter()
            .filter_map(Option::as_ref)
            .enumerate()
            .map(|(idx, arg)| (arg, syscalls_i64::get_arg_value(registers, idx)))
            .map(|(arg, value)| match arg {
                Int => value.into(),
                Str => self.read_string(value).into(),
                Addr => {
                    if value == 0 {
                        Value::Null
                    } else {
                        format!("{value:#x}").into()
                    }
                }
            })
            .collect()
    }

    pub fn if_print_syscall(&self, ret_code: &RetCode) -> bool {
        let cfg = &self.args;
        if self.args.summary_only {
            false
        } else {
            let allow_all = !cfg.failed_only && !cfg.successful_only;
            match ret_code {
                RetCode::Success(_) | RetCode::Address(_) => allow_all || cfg.successful_only,
                RetCode::Error(_) => allow_all || cfg.failed_only,
            }
        }
    }

    fn trim_str(&self, string: String) -> String {
        if self.args.no_abbrev {
            string
        } else {
            let limit = self.args.string_limit.unwrap_or(STRING_LIMIT);
            match string.chars().as_str().get(..limit) {
                None => string,
                Some(s) => format!("{s}..."),
            }
        }
    }

    fn report_syscall(
        &mut self,
        ret_code: &RetCode,
        elapsed: u128,
        syscall_id: usize,
        registers: user_regs_struct,
    ) -> Result<()> {
        if !self.if_print_syscall(ret_code) {
            return Ok(());
        }

        let (syscall, syscall_args) = &SYSTEM_CALLS[syscall_id];

        if self.args.json {
            let json = json!({
                "syscall": syscall,
                "args": self.args_to_json_vec(registers, syscall_args),
                "result": ret_code.to_string(),
                "pid": self.child.as_raw().to_string(),
                "type": "SYSCALL"
            });
            writeln!(&mut self.output_file, "{json}")?;
            return Ok(());
        }

        let mut buff = String::new();
        buff.push('[');
        let child = self.child.as_raw();
        if self.use_colors {
            let child = Blue.bold().paint(child.to_string()).to_string();
            buff.push_str(&child);
        } else {
            buff.push_str(&child.to_string());
        }
        buff.push_str("] ");
        if self.args.syscall_number {
            let _ = write!(buff, "{syscall_id:>3} ");
        }
        let syscall = SYSTEM_CALLS[syscall_id].0;
        if self.use_colors {
            #[allow(clippy::unnecessary_to_owned)]
            buff.push_str(&Style::new().bold().paint(syscall).to_string());
        } else {
            buff.push_str(syscall);
        }
        buff.push('(');
        for (idx, arg) in syscall_args.iter().enumerate() {
            if let Some(arg) = arg {
                let value = syscalls_i64::get_arg_value(registers, idx);
                if idx > 0 {
                    buff.push_str(", ");
                }
                match arg {
                    Int => buff.push_str(&value.to_string()),
                    Str => {
                        // Use JSON string escaping
                        let s: Value = self.trim_str(self.read_string(value)).into();
                        buff.push_str(&s.to_string());
                    }
                    Addr => {
                        if value == 0 {
                            buff.push_str("NULL");
                        } else {
                            let _ = write!(buff, "{value:#x}");
                        }
                    }
                }
            }
        }
        buff.push_str(") = ");
        if self.use_colors {
            let style = match ret_code {
                RetCode::Success(_) => Green.bold(),
                RetCode::Error(_) => Red.bold(),
                RetCode::Address(_) => Yellow.bold(),
            };
            #[allow(clippy::unnecessary_to_owned)]
            buff.push_str(&style.paint(ret_code.to_string()).to_string());
        } else {
            buff.push_str(&ret_code.to_string());
        }
        if self.args.syscall_times {
            let _ = write!(buff, " <{elapsed:.6}>");
        }
        writeln!(self.output_file, "{buff}")?;

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
