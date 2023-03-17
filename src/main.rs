#![deny(clippy::all, clippy::pedantic)]
//
// TODO: re-check the casting lints - they might indicate an issue
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::redundant_closure_for_method_calls
)]

mod args;
mod system_call_names;

use crate::args::Args;
use crate::system_call_names::{
    SystemCallArgumentType, SYSTEM_CALLS, TRACE_CLOCK, TRACE_CREDS, TRACE_DESC, TRACE_FILE,
    TRACE_FSTAT, TRACE_FSTATFS, TRACE_IPC, TRACE_LSTAT, TRACE_MEMORY, TRACE_NETWORK, TRACE_PROCESS,
    TRACE_PURE, TRACE_SIGNAL, TRACE_STAT, TRACE_STATFS, TRACE_STATFS_LIKE, TRACE_STAT_LIKE,
};
use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use byteorder::{LittleEndian, WriteBytesExt};
use clap::Parser;
use libc::{c_long, c_ulonglong, c_void};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::ptrace::Options;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};
use std::time::SystemTime;
use users::get_user_by_name;

const STRING_LIMIT: usize = 32;

fn main() {
    let config = Args::parse();
    // Check whether to attach to an existing process or create a new one
    if let Some(pid) = config.attach {
        ptrace::attach(Pid::from_raw(pid))
            .map_err(|e| format!("Failed to ptrace attach {pid} ({e})"))
            .unwrap();

        Tracer::new(Pid::from_raw(pid), config).run_tracer();
    } else {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => run_tracee(config),
            Ok(ForkResult::Parent { child }) => Tracer::new(child, config).run_tracer(),
            Err(err) => panic!("[main] fork() failed: {err}"),
        }
    }
}

#[derive(Debug)]
struct Tracer {
    child: Pid,
    config: Args,
    system_call_timer_start: Option<SystemTime>,
    system_call_timer_stop: HashMap<u64, u64>,
    second_ptrace_invocation: bool,
    successful_system_calls: Vec<u64>,
    failed_system_calls: Vec<u64>,
    set_follow_fork_option: bool,
    expr_negation: bool,
    suppress_system_calls: HashSet<&'static str>,
    system_calls: HashSet<&'static str>,
}

impl Tracer {
    fn new(child: Pid, config: Args) -> Self {
        let mut slf = Self {
            child,
            config,
            system_call_timer_start: None,
            system_call_timer_stop: HashMap::new(),
            second_ptrace_invocation: false,
            successful_system_calls: vec![],
            failed_system_calls: vec![],
            set_follow_fork_option: false,
            expr_negation: false,
            suppress_system_calls: HashSet::new(),
            system_calls: HashSet::new(),
        };

        let all_system_calls: HashSet<&'static str> = SYSTEM_CALLS.iter().map(|v| v.0).collect();

        // Sort system calls listed with --expr into their category to handle them accordingly
        for token in &slf.config.expr {
            let mut tokens = token.splitn(2, '=');
            match (tokens.next(), tokens.next()) {
                (Some(token_key), Some(mut token_value))
                    if token_key == "t" || token_key == "trace" =>
                {
                    if token_value.starts_with('!') {
                        slf.expr_negation = true;
                        token_value = &token_value[1..];
                    }

                    for part in token_value.split(',') {
                        if let Some(part) = part.strip_prefix('?') {
                            let val = all_system_calls.get(part);
                            if let Some(val) = val {
                                slf.suppress_system_calls.insert(val);
                            } else {
                                panic!("System call '{part}' is not valid!");
                            }
                        } else if let Some(part) = part.strip_prefix('/') {
                            if let Ok(pattern) = Regex::new(part) {
                                for system_call in SYSTEM_CALLS.iter() {
                                    let system_call = system_call.0;
                                    if pattern.is_match(system_call) {
                                        slf.system_calls.insert(system_call);
                                    }
                                }
                            } else {
                                panic!("Invalid regex pattern: {part}");
                            }
                        } else if let Some(part) = part.strip_prefix('%') {
                            let category: &[usize] = match part {
                                "file" => &TRACE_FILE,
                                "process" => &TRACE_PROCESS,
                                "network" | "net" => &TRACE_NETWORK,
                                "signal" => &TRACE_SIGNAL,
                                "ipc" => &TRACE_IPC,
                                "desc" => &TRACE_DESC,
                                "memory" => &TRACE_MEMORY,
                                "creds" => &TRACE_CREDS,
                                "stat" => &TRACE_STAT,
                                "lstat" => &TRACE_LSTAT,
                                "fstat" => &TRACE_FSTAT,
                                "%stat" => &TRACE_STAT_LIKE,
                                "statfs" => &TRACE_STATFS,
                                "fstatfs" => &TRACE_FSTATFS,
                                "%statfs" => &TRACE_STATFS_LIKE,
                                "clock" => &TRACE_CLOCK,
                                "pure" => &TRACE_PURE,
                                v => panic!("Category '{v}' is not valid!"),
                            };
                            let calls = category.iter().map(|e| SYSTEM_CALLS[*e].0);
                            slf.system_calls.extend(calls);
                        } else {
                            let val = all_system_calls.get(part);
                            if let Some(val) = val {
                                slf.system_calls.insert(val);
                            } else {
                                panic!("System call '{part}' is not valid!");
                            }
                        }
                    }
                }
                _ => panic!("expr {token} is not supported. Please have a look at the syntax."),
            }
        }

        slf
    }

    #[allow(clippy::too_many_lines)]
    fn run_tracer(&mut self) {
        let config = &self.config;

        loop {
            let mut file: Option<File> = None;
            // If the given path is not empty, check if the file exists. If --file is set, write the
            // output to the file.
            if let Some(filepath) = &config.file {
                file = Some(if filepath.exists() {
                    OpenOptions::new()
                        .append(true)
                        .open(filepath)
                        .expect("open failed!")
                } else {
                    File::create(filepath).expect("create failed!")
                });
            }
            // Wait for the next system call
            wait().unwrap();
            // If --follow-forks is set, set options to follow forks
            if !self.set_follow_fork_option {
                if config.follow_forks {
                    ptrace::setoptions(
                        self.child,
                        Options::PTRACE_O_TRACEFORK
                            | Options::PTRACE_O_TRACEVFORK
                            | Options::PTRACE_O_TRACECLONE,
                    )
                    .unwrap();
                }
                self.set_follow_fork_option = true;
            }

            // Read registers
            match ptrace::getregs(self.child) {
                Ok(x) if x.orig_rax < 336 => {
                    let syscall_id = x.orig_rax;
                    let (syscall, syscall_args) = SYSTEM_CALLS[syscall_id as usize];

                    // If --syscall-number is set, display the number of the system call at the
                    // start of the output
                    let mut output = if file.is_some() {
                        let child = self.child.as_raw();
                        if config.syscall_number {
                            format!("[{child}] {syscall_id:>3} {syscall}(")
                        } else {
                            format!("[{child}] {syscall}(")
                        }
                    } else {
                        let child = Blue.bold().paint(self.child.as_raw().to_string());
                        let syscall = Style::new().bold().paint(syscall);
                        if config.syscall_number {
                            format!("[{child}] {syscall_id:>3} {syscall}(")
                        } else {
                            format!("[{child}] {syscall}(")
                        }
                    };

                    // Handle system call arguments
                    let mut arguments: Vec<Value> = Vec::new();
                    for (i, arg) in syscall_args.iter().enumerate() {
                        let value = match i {
                            0 => x.rdi,
                            1 => x.rsi,
                            2 => x.rdx,
                            3 => x.r10,
                            4 => x.r8,
                            5 => x.r9,
                            v => panic!("Invalid system call definition '{v}'!"),
                        };
                        let Some(arg) = arg else { continue };
                        if i > 0 {
                            output.push_str(", ");
                        }
                        // Handle type of system call argument accordingly
                        match arg {
                            SystemCallArgumentType::Integer => {
                                output.push_str(&value.to_string());
                                arguments.push(value.into());
                            }
                            SystemCallArgumentType::String => {
                                output.push('"');
                                let string = self.read_string(x.rsi as *mut c_void);
                                if config.no_abbrev {
                                    output.push_str(&string);
                                } else {
                                    let limit = config.string_limit.unwrap_or(STRING_LIMIT);
                                    match string.chars().as_str().get(..limit) {
                                        None => output.push_str(&string),
                                        Some(s) => output.push_str(&format!("{s}...")),
                                    }
                                };
                                output.push('"');
                                arguments.push(string.into());
                            }
                            SystemCallArgumentType::Address => {
                                if value == 0 {
                                    output.push_str("NULL");
                                    arguments.push(Value::Null);
                                } else {
                                    output.push_str(&format!("{value:#x}"));
                                    arguments.push(format!("{value:#x}").into());
                                }
                            }
                        }
                    }
                    output.push(')');

                    // Only print output at second invocation of ptrace (ptrace gets invoked twice
                    // per system call. Once before and once after execution).
                    if self.second_ptrace_invocation || syscall_id == 59 || syscall_id == 231 {
                        let end = SystemTime::now();
                        let mut elapsed: u128 = 0;
                        // Measure system call execution time
                        if let Some(i) = self.system_call_timer_start {
                            elapsed = end.duration_since(i).unwrap_or_default().as_millis();
                            if let Some(old_value) = self.system_call_timer_stop.get(&syscall_id) {
                                let new_value = old_value + elapsed as u64;
                                self.system_call_timer_stop.insert(syscall_id, new_value);
                            } else {
                                self.system_call_timer_stop
                                    .insert(syscall_id, elapsed as u64);
                            }
                        };
                        // Print output for the current system call if the filter expression did
                        // not sort it out beforehand. Furthermore, check if the filter expression
                        // was negated.
                        if self.system_calls.contains(syscall) && !self.expr_negation
                            || !self.system_calls.contains(syscall) && self.expr_negation
                            || self.system_calls.is_empty()
                        {
                            let ret_code = x.rax;
                            let ret_i32 = ret_code as i32;

                            // Handle return value. The return value is distinguished into
                            // different categories (successful, failed, address) and handled
                            // accordingly
                            if ret_i32.abs() > 32768 {
                                if let Some(mut fd) = file {
                                    if !config.json {
                                        if config.syscall_times {
                                            writeln!(
                                                &mut fd,
                                                "{output} = {ret_i32:#x} <{elapsed:.6}>"
                                            )
                                            .unwrap();
                                        } else {
                                            writeln!(&mut fd, "{output} = {ret_i32:#x}").unwrap();
                                        }
                                    }

                                    if config.json
                                        && !config.summary_only
                                        && !config.summary
                                        && config.should_print(ret_i32 >= 0)
                                    {
                                        let json = self.to_json(syscall, &arguments, ret_code);
                                        write!(&mut fd, "{json}").unwrap();
                                    }
                                } else if !config.summary_only {
                                    if !config.failed_only && !config.json {
                                        let ret = Yellow.bold().paint(format!("{ret_code:#x}"));
                                        if config.syscall_times {
                                            println!("{output} = {ret} <{elapsed:.6}>");
                                        } else {
                                            println!("{output} = {ret}");
                                        }
                                    }

                                    if config.json
                                        && !config.summary
                                        && config.should_print(ret_i32 >= 0)
                                    {
                                        let json = self.to_json(syscall, &arguments, ret_code);
                                        println!("{json}");
                                    }
                                }
                            } else if let Some(mut fd) = file {
                                if !config.json {
                                    if config.syscall_times {
                                        writeln!(&mut fd, "{output} = {ret_i32} <{elapsed:.6}>")
                                            .unwrap();
                                    } else {
                                        writeln!(&mut fd, "{output} = {ret_i32}").unwrap();
                                    }
                                }

                                if config.json
                                    && !config.summary_only
                                    && !config.summary
                                    && config.should_print(ret_i32 >= 0)
                                {
                                    let json = self.to_json(syscall, &arguments, ret_code);
                                    write!(&mut fd, "{json}").unwrap();
                                }
                            } else {
                                if ret_i32 < 0
                                    && ((!self.expr_negation
                                        && !self.suppress_system_calls.contains(syscall))
                                        || (self.expr_negation
                                            && self.suppress_system_calls.contains(syscall))
                                        || self.suppress_system_calls.is_empty())
                                {
                                    self.failed_system_calls.push(syscall_id);

                                    if !config.successful_only
                                        && !config.summary_only
                                        && !config.json
                                    {
                                        let ret = Red.bold().paint((ret_code as i64).to_string());
                                        if config.syscall_times {
                                            println!("{output} = {ret} <{elapsed:.6}>");
                                        } else {
                                            println!("{output} = {ret}");
                                        }
                                    }
                                }
                                if ret_i32 >= 0
                                    && !config.failed_only
                                    && !config.summary_only
                                    && !config.json
                                {
                                    let ret = Green.bold().paint(ret_i32.to_string());
                                    if config.syscall_times {
                                        println!("{output} = {ret} <{elapsed:.6}>");
                                    } else {
                                        println!("{output} = {ret}");
                                    }
                                }
                                if config.json
                                    && !config.summary_only
                                    && !config.summary
                                    && config.should_print(ret_i32 >= 0)
                                {
                                    let json = self.to_json(syscall, &arguments, ret_code);
                                    println!("{json}");
                                }
                            }
                        }

                        self.second_ptrace_invocation = false;
                        self.system_call_timer_start = None;

                        if config.summary_only || config.summary {
                            self.successful_system_calls.push(syscall_id);
                        }
                    } else {
                        self.system_call_timer_start = Some(SystemTime::now());
                        self.second_ptrace_invocation = true;
                    }
                }
                Ok(_) => {
                    // TODO: report ignored system call ID that is not in the list
                }
                Err(_) => {
                    break;
                }
            };

            if ptrace::syscall(self.child, None).is_err() {
                break;
            }
        }

        if !config.json && (config.summary_only || config.summary) {
            let mut total_elapsed_time = 0;
            for value in self.system_call_timer_stop.values() {
                total_elapsed_time += value;
            }

            println!("% time     seconds  usecs/call     calls    errors syscall");
            println!("------ ----------- ----------- --------- --------- ----------------");

            let syscall_map = count_element_function(&self.successful_system_calls);
            let mut syscall_sorted: Vec<_> = syscall_map.iter().collect();
            syscall_sorted.sort_by_key(|v| v.0);

            let error_map = count_element_function(&self.failed_system_calls);
            let mut number_of_failed_system_calls = 0;

            // Construct summary columns
            for (key, value) in syscall_sorted {
                let mut percent_time = 0_f32;
                let stop_time = self.system_call_timer_stop.get(key);
                let (seconds, calls) = if let Some(v) = stop_time {
                    if total_elapsed_time != 0 {
                        percent_time = *v as f32 / (total_elapsed_time as f32 / 100_f32);
                    }
                    (
                        *v as f32 / 1000_f32,
                        (*v as f32 / 1000_f32) / (*value as f32) * 1_000_000_f32,
                    )
                } else {
                    (0.0, 0.0)
                };

                println!(
                    "{percent_time:>6.2} {seconds:>11.6} {calls:>11.0} {value:>9} {:>9} {}",
                    {
                        if let Some(i) = error_map.get(key) {
                            number_of_failed_system_calls += i;
                            i.to_string()
                        } else {
                            String::new()
                        }
                    },
                    SYSTEM_CALLS[**key as usize].0
                );
            }

            println!("------ ----------- ----------- --------- --------- ----------------");
            println!(
            "100.00 {:>11.6} {:>11.0} {total_elapsed_time:>9} {number_of_failed_system_calls:>9} total",
            total_elapsed_time as f32 / 1000_f32,
            (total_elapsed_time as f32 / self.successful_system_calls.len() as f32) * 1000_f32
        );
        }
    }

    fn read_string(&self, address: AddressType) -> String {
        let mut string = String::new();
        // Move 8 bytes up each time for next read.
        let mut count = 0;
        let word_size = 8;

        'done: loop {
            let address = unsafe { address.offset(count) };

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

    fn to_json(&self, syscall: &str, arguments: &Vec<Value>, ret_code: c_ulonglong) -> Value {
        let ret_i32 = ret_code as i32;
        json!({
            "syscall": syscall,
            "args": arguments,
            "result": if ret_i32.abs() > 32768 {
                format!("{ret_code:#x}")
            } else {
                ret_i32.to_string()
            },
            "pid": self.child.as_raw().to_string(),
            "type": "SYSCALL"
        })
    }
}

fn run_tracee(config: Args) {
    let mut args: Vec<String> = Vec::new();
    let mut program = String::new();

    ptrace::traceme().unwrap();
    personality(ADDR_NO_RANDOMIZE).unwrap();
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
        let arg: Vec<String> = token.split('=').map(|s| s.to_string()).collect();
        if arg.len() == 2 {
            cmd.env(arg[0].as_str(), arg[1].as_str());
        } else {
            cmd.env_remove(arg[0].as_str());
        }
    }

    if let Some(user) = get_user_by_name(&config.username.unwrap_or_default()) {
        cmd.uid(user.uid());
    }

    cmd.exec();

    // TODO: why is this needed?
    exit(0)
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
