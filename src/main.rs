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
use libc::{c_long, c_void};
use linux_personality::{personality, ADDR_NO_RANDOMIZE};
use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::ptrace::Options;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
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

        run_tracer(Pid::from_raw(pid), config);
    } else {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => run_tracee(config),
            Ok(ForkResult::Parent { child }) => run_tracer(child, config),
            Err(err) => panic!("[main] fork() failed: {err}"),
        }
    }
}

fn run_tracer(child: Pid, config: Args) {
    let mut system_call_timer_start: Option<SystemTime> = None;
    let mut system_call_timer_stop: HashMap<u64, u64> = HashMap::new();
    let mut second_ptrace_invocation = true;

    let mut successful_system_calls: Vec<u64> = Vec::new();
    let mut failed_system_calls: Vec<u64> = Vec::new();

    let mut set_follow_fork_option: bool = false;

    let mut expr_negation: bool = false;
    let mut expr_filter_categories: Vec<String> = Vec::new();

    let mut suppress_system_calls: Vec<String> = Vec::new();
    let mut filter_system_calls: Vec<String> = Vec::new();
    let mut regex_system_call_patterns: Vec<String> = Vec::new();

    // Sort system calls listed with --expr into their category to handle them accordingly
    for token in &config.expr {
        let arg: Vec<String> = token.split('=').map(|s| s.to_string()).collect();

        match arg[0].as_str() {
            "t" | "trace" => {
                let mut argument_token: Vec<String> =
                    arg[1].as_str().split(',').map(|s| s.to_string()).collect();
                let first_char_in_argument_token: Vec<char> = argument_token[0].chars().collect();

                expr_negation = first_char_in_argument_token[0] == '!';

                if expr_negation {
                    let first_token: Vec<char> = argument_token[0].chars().collect();
                    argument_token[0] = first_token[1..].iter().cloned().collect::<String>();
                }

                for token_chars in argument_token {
                    let chars: Vec<char> = token_chars.chars().collect();
                    match chars[0] {
                        '?' => suppress_system_calls
                            .push(chars[1..].iter().cloned().collect::<String>()),
                        '/' => regex_system_call_patterns
                            .push(chars[1..].iter().cloned().collect::<String>()),
                        '%' => expr_filter_categories
                            .push(chars[1..].iter().cloned().collect::<String>()),
                        _ => filter_system_calls.push(chars.iter().cloned().collect::<String>()),
                    }
                }
            }
            _ => panic!("This command is not supported. Please have a look at the syntax."),
        }
    }

    let mut regex_system_calls: Vec<String> = Vec::new();
    // Check if system calls match to any regex_system_call_patterns pattern. If there is a match,
    // add the system call to regex_system_calls
    for i in 0..334 {
        let mut is_match: bool = false;
        let current_syscall = SYSTEM_CALLS[i as usize].0;

        for pattern in &regex_system_call_patterns {
            let re = Regex::new(pattern.as_str()).unwrap();
            if re.is_match(current_syscall) {
                is_match = true;
            }
        }

        if is_match {
            regex_system_calls.push(String::from(current_syscall));
        }
    }

    let mut system_calls: Vec<String> =
        [&regex_system_calls[..], &filter_system_calls[..]].concat();
    system_calls = apply_filter_categories(system_calls, expr_filter_categories);

    loop {
        let mut file: Option<File> = None;
        // If the given path is not empty, check if the file exists. If --file is set, write the
        // output to the file.
        if let Some(filepath) = &config.file {
            file = Some(if !filepath.exists() {
                File::create(filepath).expect("create failed!")
            } else {
                OpenOptions::new()
                    .append(true)
                    .open(filepath)
                    .expect("open failed!")
            });
        }
        // Wait for the next system call
        wait().unwrap();
        // If --follow-forks is set, set options to follow forks
        if !set_follow_fork_option {
            if config.follow_forks {
                ptrace::setoptions(
                    child,
                    Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK
                        | Options::PTRACE_O_TRACECLONE,
                )
                .unwrap();
            }
            set_follow_fork_option = true;
        }

        let reg;
        // Read registers
        match ptrace::getregs(child) {
            Ok(x) => {
                if x.orig_rax < 336 {
                    reg = x.rsi;

                    let system_call_tuple = SYSTEM_CALLS[(x.orig_rax) as usize];

                    let argument_type_array = [
                        system_call_tuple.1,
                        system_call_tuple.2,
                        system_call_tuple.3,
                        system_call_tuple.4,
                        system_call_tuple.5,
                        system_call_tuple.6,
                    ];

                    let mut arguments: Vec<serde_json::Value> = Vec::new();

                    // If --syscall-number is set, display the number of the system call at the
                    // start of the output
                    let mut output = if file.is_some() {
                        let child = child.as_raw();
                        let rax = SYSTEM_CALLS[(x.orig_rax) as usize].0;
                        if config.syscall_number {
                            format!("[{child}] {:>3} {rax}(", x.orig_rax)
                        } else {
                            format!("[{child}] {rax}(")
                        }
                    } else {
                        let child = Blue.bold().paint(child.as_raw().to_string());
                        let rax = SYSTEM_CALLS[(x.orig_rax) as usize].0;
                        let rax = Style::new().bold().paint(rax);
                        if config.syscall_number {
                            format!("[{child}] {:>3} {rax}(", x.orig_rax)
                        } else {
                            format!("[{child}] {rax}(")
                        }
                    };
                    let mut first_comma = true;
                    // Handle system call arguments
                    for (i, arg) in argument_type_array.iter().enumerate() {
                        let value = match i {
                            0 => x.rdi,
                            1 => x.rsi,
                            2 => x.rdx,
                            3 => x.r10,
                            4 => x.r8,
                            5 => x.r9,
                            val => panic!("Invalid system call definition '{val}'!"),
                        };
                        match arg {
                            SystemCallArgumentType::None => continue,
                            SystemCallArgumentType::Integer
                            | SystemCallArgumentType::String
                            | SystemCallArgumentType::Address => {
                                if first_comma {
                                    first_comma = false;
                                } else {
                                    output.push_str(", ")
                                }
                            }
                        }
                        // Handle type of system call argument accordingly
                        match arg {
                            SystemCallArgumentType::Integer => {
                                output.push_str(format!("{value}").as_str());
                                arguments.push(value.into());
                            }
                            SystemCallArgumentType::String => {
                                let mut string = read_string(child, reg as *mut c_void);
                                arguments.push(string.clone().into());
                                let truncated_string = if config.no_abbrev {
                                    string.as_str()
                                } else {
                                    truncate(
                                        string.as_str(),
                                        config.string_limit.unwrap_or(STRING_LIMIT),
                                    )
                                };
                                if string != truncated_string {
                                    string = format!("{truncated_string}...");
                                }
                                output.push_str(string.as_str());
                            }
                            SystemCallArgumentType::Address => {
                                if value == 0 {
                                    output.push_str("NULL");
                                    arguments.push(serde_json::Value::Null);
                                } else {
                                    output.push_str(format!("{value:#x}").as_str());
                                    arguments.push(format!("{value:#x}").into());
                                }
                            }
                            SystemCallArgumentType::None => {
                                continue;
                            }
                        }
                    }

                    output.push(')');
                    // Only print output at second invocation of ptrace (ptrace gets invoked twice
                    // per system call. Once before and once after execution).
                    if second_ptrace_invocation || x.orig_rax == 59 || x.orig_rax == 231 {
                        let end = SystemTime::now();
                        let mut elapsed: u128 = 0;
                        // Measure system call execution time
                        if let Some(i) = system_call_timer_start {
                            elapsed = end.duration_since(i).unwrap_or_default().as_millis();
                            let syscall = x.orig_rax;

                            if let Some(old_value) = system_call_timer_stop.get(&syscall) {
                                let new_value = old_value + elapsed as u64;
                                system_call_timer_stop.insert(syscall, new_value);
                            } else {
                                system_call_timer_stop.insert(syscall, elapsed as u64);
                            }
                        };
                        // Print output for the current system call if the filter expression did
                        // not sort it out beforehand. Furthermore, check if the filter expression
                        // was negated.
                        if system_calls
                            .contains(&String::from(SYSTEM_CALLS[(x.orig_rax) as usize].0))
                            && !expr_negation
                            || !system_calls
                                .contains(&String::from(SYSTEM_CALLS[(x.orig_rax) as usize].0))
                                && expr_negation
                            || system_calls.is_empty()
                        {
                            let return_value: String = if (x.rax as i32).abs() > 32768 {
                                format!("{:#x}", x.rax)
                            } else {
                                format!("{}", x.rax as i32)
                            };

                            // Handle return value. The return value is distinguished into
                            // different categories (successful, failed, address) and handled
                            // accordingly
                            if (x.rax as i32).abs() > 32768 {
                                if let Some(mut fd) = file {
                                    if !config.json {
                                        let rax = x.rax as i32;
                                        if config.syscall_times {
                                            writeln!(&mut fd, "{output} = {rax:#x} <{elapsed:.6}>")
                                                .unwrap();
                                        } else {
                                            writeln!(&mut fd, "{output} = {rax:#x}").unwrap();
                                        }
                                    }

                                    if config.json
                                        && !config.summary_only
                                        && !config.summary
                                        && ((config.successful_only && (x.rax as i32) >= 0)
                                            || (config.failed_only && (x.rax as i32) < 0)
                                            || (!config.failed_only && !config.successful_only))
                                    {
                                        let json = json!({
                                            "syscall": SYSTEM_CALLS[x.orig_rax as usize].0,
                                            "args": arguments,
                                            "result": return_value,
                                            "pid": child.as_raw().to_string(),
                                            "type": "SYSCALL"
                                        });

                                        write!(&mut fd, "{json}").unwrap();
                                    }
                                } else if !config.summary_only {
                                    if !config.failed_only && !config.json {
                                        let rax = Yellow.bold().paint(format!("{:#x}", x.rax));
                                        if config.syscall_times {
                                            println!("{output} = {rax} <{elapsed:.6}>");
                                        } else {
                                            println!("{output} = {rax}");
                                        }
                                    }

                                    if config.json
                                        && !config.summary
                                        && ((config.successful_only && (x.rax as i32) >= 0)
                                            || (config.failed_only && (x.rax as i32) < 0)
                                            || (!config.failed_only && !config.successful_only))
                                    {
                                        let json = json!({
                                            "syscall": SYSTEM_CALLS[x.orig_rax as usize].0,
                                            "args": arguments,
                                            "result": return_value,
                                            "pid": child.as_raw().to_string(),
                                            "type": "SYSCALL"
                                        });

                                        println!("{json}");
                                    }
                                }
                            } else if let Some(mut fd) = file {
                                if !config.json {
                                    let rax = x.rax as i32;
                                    if config.syscall_times {
                                        writeln!(&mut fd, "{output} = {rax} <{elapsed:.6}>")
                                            .unwrap();
                                    } else {
                                        writeln!(&mut fd, "{output} = {rax}").unwrap();
                                    }
                                }

                                if config.json
                                    && !config.summary_only
                                    && !config.summary
                                    && ((config.successful_only && (x.rax as i32) >= 0)
                                        || (config.failed_only && (x.rax as i32) < 0)
                                        || (!config.failed_only && !config.successful_only))
                                {
                                    let json = json!({
                                        "syscall": SYSTEM_CALLS[x.orig_rax as usize].0,
                                        "args": arguments,
                                        "result": return_value,
                                        "pid": child.as_raw().to_string(),
                                        "type": "SYSCALL"
                                    });

                                    write!(&mut fd, "{json}").unwrap();
                                }
                            } else {
                                if (x.rax as i32) < 0
                                    && ((!expr_negation
                                        && !suppress_system_calls.contains(&String::from(
                                            SYSTEM_CALLS[(x.orig_rax) as usize].0,
                                        )))
                                        || (expr_negation
                                            && suppress_system_calls.contains(&String::from(
                                                SYSTEM_CALLS[(x.orig_rax) as usize].0,
                                            )))
                                        || suppress_system_calls.is_empty())
                                {
                                    failed_system_calls.push(x.orig_rax);

                                    if !config.successful_only
                                        && !config.summary_only
                                        && !config.json
                                    {
                                        if config.syscall_times {
                                            println!(
                                                "{output} = {} <{elapsed:.6}>",
                                                Red.bold().paint((x.rax as i64).to_string())
                                            );
                                        } else {
                                            println!(
                                                "{output} = {}",
                                                Red.bold().paint((x.rax as i64).to_string())
                                            );
                                        }
                                    }
                                }
                                if (x.rax as i32) >= 0
                                    && !config.failed_only
                                    && !config.summary_only
                                    && !config.json
                                {
                                    if config.syscall_times {
                                        println!(
                                            "{output} = {} <{elapsed:.6}>",
                                            Green.bold().paint((x.rax as i32).to_string())
                                        );
                                    } else {
                                        println!(
                                            "{output} = {}",
                                            Green.bold().paint((x.rax as i32).to_string())
                                        );
                                    }
                                }
                                if config.json
                                    && !config.summary_only
                                    && !config.summary
                                    && ((config.successful_only && (x.rax as i32) >= 0)
                                        || (config.failed_only && (x.rax as i32) < 0)
                                        || (!config.failed_only && !config.successful_only))
                                {
                                    let json = json!({
                                        "syscall": SYSTEM_CALLS[x.orig_rax as usize].0,
                                        "args": arguments,
                                        "result": return_value,
                                        "pid": child.as_raw().to_string(),
                                        "type": "SYSCALL"
                                    });

                                    println!("{json}");
                                }
                            }
                        }

                        second_ptrace_invocation = false;
                        system_call_timer_start = None;

                        if config.summary_only || config.summary {
                            successful_system_calls.push(x.orig_rax);
                        }
                    } else {
                        system_call_timer_start = Some(SystemTime::now());
                        second_ptrace_invocation = true;
                    }
                }
            }
            Err(_) => {
                break;
            }
        };

        match ptrace::syscall(child, None) {
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    if !config.json && (config.summary_only || config.summary) {
        let mut total_elapsed_time = 0;
        for value in system_call_timer_stop.values() {
            total_elapsed_time += value;
        }

        println!("% time     seconds  usecs/call     calls    errors syscall");
        println!("------ ----------- ----------- --------- --------- ----------------");

        let syscall_map = count_element_function(&successful_system_calls);
        let mut syscall_sorted: Vec<_> = syscall_map.iter().collect();
        syscall_sorted.sort_by(|x, y| x.0.cmp(y.0));

        let error_map = count_element_function(failed_system_calls);
        let mut number_of_failed_system_calls = 0;
        // Construct summary columns
        for (key, value) in &syscall_sorted {
            println!(
                "{:>6} {:>11} {:>11} {value:>9} {:>9} {}",
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        if total_elapsed_time != 0 {
                            format!("{:.2}", *i as f32 / (total_elapsed_time as f32 / 100_f32))
                        } else {
                            "0.00".to_string()
                        }
                    } else {
                        "0.00".to_string()
                    }
                },
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        format!("{:.6}", *i as f32 / 1000_f32)
                    } else {
                        "0.000000".to_string()
                    }
                },
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        format!(
                            "{:.0}",
                            (*i as f32 / 1000_f32) / (**value as f32) * 1_000_000_f32
                        )
                    } else {
                        "0".to_string()
                    }
                },
                {
                    if let Some(i) = error_map.get(key) {
                        number_of_failed_system_calls += i;
                        format!("{i}")
                    } else {
                        String::new()
                    }
                },
                SYSTEM_CALLS[***key as usize].0
            );
        }

        let number_of_successful_system_calls = successful_system_calls.len();

        println!("------ ----------- ----------- --------- --------- ----------------");
        println!(
            "100.00 {:>11.6} {:>11.0} {total_elapsed_time:>9} {number_of_failed_system_calls:>9} total",
            total_elapsed_time as f32 / 1000_f32,
            (total_elapsed_time as f32 / number_of_successful_system_calls as f32) * 1000_f32
        );
    }
}

fn run_tracee(config: Args) {
    let mut args: Vec<String> = Vec::new();
    let mut program = String::new();

    ptrace::traceme().unwrap();
    personality(ADDR_NO_RANDOMIZE).unwrap();
    // Handle arguments passed to the program to be traced
    for (index, arg) in config.command.iter().enumerate() {
        if index != 0 {
            args.push(String::from(arg));
        } else {
            program = arg.to_string();
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

fn read_string(pid: Pid, address: AddressType) -> String {
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let mut bytes: Vec<u8> = vec![];
        let address = unsafe { address.offset(count) };

        let res: c_long = match ptrace::read(pid, address) {
            Ok(c_long) => c_long,
            Err(_) => break 'done,
        };

        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {res} as i64 LittleEndian: {err}");
        });

        for b in bytes {
            if b != 0 {
                string.push(b as char);
            } else {
                break 'done;
            }
        }
        count += word_size;
    }

    string
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

fn count_element_function<I>(it: I) -> HashMap<I::Item, usize>
where
    I: IntoIterator,
    I::Item: Eq + core::hash::Hash,
{
    let mut result = HashMap::new();

    for item in it {
        *result.entry(item).or_insert(0) += 1;
    }

    result
}

/// Add all `system_calls` from the given categories to the `system_calls` Vector
fn apply_filter_categories(
    mut system_calls: Vec<String>,
    expr_filter_categories: Vec<String>,
) -> Vec<String> {
    for keyword in expr_filter_categories {
        match keyword.as_str() {
            "file" => add_traces(&mut system_calls, &TRACE_FILE),
            "process" => add_traces(&mut system_calls, &TRACE_PROCESS),
            "network" | "net" => add_traces(&mut system_calls, &TRACE_NETWORK),
            "signal" => add_traces(&mut system_calls, &TRACE_SIGNAL),
            "ipc" => add_traces(&mut system_calls, &TRACE_IPC),
            "desc" => add_traces(&mut system_calls, &TRACE_DESC),
            "memory" => add_traces(&mut system_calls, &TRACE_MEMORY),
            "creds" => add_traces(&mut system_calls, &TRACE_CREDS),
            "stat" => add_traces(&mut system_calls, &TRACE_STAT),
            "lstat" => add_traces(&mut system_calls, &TRACE_LSTAT),
            "fstat" => add_traces(&mut system_calls, &TRACE_FSTAT),
            "%stat" => add_traces(&mut system_calls, &TRACE_STAT_LIKE),
            "statfs" => add_traces(&mut system_calls, &TRACE_STATFS),
            "fstatfs" => add_traces(&mut system_calls, &TRACE_FSTATFS),
            "%statfs" => add_traces(&mut system_calls, &TRACE_STATFS_LIKE),
            "clock" => add_traces(&mut system_calls, &TRACE_CLOCK),
            "pure" => add_traces(&mut system_calls, &TRACE_PURE),
            _ => panic!("This is not a valid option!"),
        }
    }
    system_calls.sort();
    system_calls.dedup();
    system_calls
}

fn add_traces(system_calls: &mut Vec<String>, traces: &[usize]) {
    *system_calls = [
        system_calls,
        &traces
            .iter()
            .map(|e| String::from(SYSTEM_CALLS[*e].0))
            .collect::<Vec<String>>()[..],
    ]
    .concat();
}
