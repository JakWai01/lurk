mod app;
mod config;
mod system_call_names;

use crate::config::Config;
use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use libc::pid_t;
use libc::{c_long, c_void};
use linux_personality::personality;
use nix::sys::ptrace;
use nix::sys::ptrace::AddressType;
use nix::sys::ptrace::*;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};
use std::time::SystemTime;
use users;

fn main() {
    let matches = app::build_app().get_matches_from(env::args_os());
    let config = construct_config(matches).unwrap();
    // Check whether to attach to an existing process or create a new one
    if config.attach != 0 {
        let pid: pid_t = config.attach;

        ptrace::attach(Pid::from_raw(pid))
            .map_err(|e| format!("Failed to ptrace attach {} ({})", pid, e))
            .unwrap();

        run_tracer(Pid::from_raw(pid), config);
    } else {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                run_tracee(config);
            }

            Ok(ForkResult::Parent { child }) => {
                run_tracer(child, config);
            }

            Err(err) => {
                panic!("[main] fork() failed: {}", err);
            }
        }
    }
}

fn run_tracer(child: Pid, config: Config) {
    let mut system_call_timer_start: Option<std::time::SystemTime> = None;
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
        let arg: Vec<String> = token.split("=").map(|s| s.to_string()).collect();

        match arg[0].as_str() {
            "t" | "trace" => {
                let mut argument_token: Vec<String> =
                    arg[1].as_str().split(",").map(|s| s.to_string()).collect();
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
        let current_syscall = system_call_names::SYSTEM_CALLS[i as usize].0;

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
        let mut file: Option<std::fs::File> = None;
        // If the given path is not empty, check if the file exists. If --file is set, write the
        // output to the file.
        if !config.file.is_empty() {
            if !std::path::Path::new(&config.file).exists() {
                file = Some(std::fs::File::create(&config.file).expect("create failed!"));
            } else {
                file = Some(
                    OpenOptions::new()
                        .append(true)
                        .open(&config.file)
                        .expect("open failed!"),
                );
            }
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

                    let system_call_tuple = system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize];

                    let argument_type_array: [system_call_names::SystemCallArgumentType; 6] = [
                        system_call_tuple.1,
                        system_call_tuple.2,
                        system_call_tuple.3,
                        system_call_tuple.4,
                        system_call_tuple.5,
                        system_call_tuple.6,
                    ];
                    let mut arguments: Vec<String> = Vec::new();

                    // If --syscall-number is set, display the number of the system call at the
                    // start of the output
                    let mut output = if config.syscall_number {
                        if !config.file.is_empty() {
                            format!(
                                "[{}] {:>3} {}(",
                                child.as_raw().to_string(),
                                x.orig_rax,
                                system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0
                            )
                        } else {
                            format!(
                                "[{}] {:>3} {}(",
                                Blue.bold().paint(child.as_raw().to_string()),
                                x.orig_rax,
                                Style::new().bold().paint(
                                    system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0
                                )
                            )
                        }
                    } else {
                        if !config.file.is_empty() {
                            format!(
                                "[{}] {}(",
                                child.as_raw().to_string(),
                                system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0
                            )
                        } else {
                            format!(
                                "[{}] {}(",
                                Blue.bold().paint(child.as_raw().to_string()),
                                Style::new().bold().paint(
                                    system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0
                                )
                            )
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
                            _ => panic!("Invalid system call definition!"),
                        };
                        match arg {
                            system_call_names::SystemCallArgumentType::None => continue,
                            system_call_names::SystemCallArgumentType::Integer
                            | system_call_names::SystemCallArgumentType::String
                            | system_call_names::SystemCallArgumentType::Address => {
                                if first_comma {
                                    first_comma = false;
                                } else {
                                    output.push_str(", ")
                                }
                            }
                        }
                        // Handle type of system call argument accordingly
                        match arg {
                            system_call_names::SystemCallArgumentType::Integer => {
                                output.push_str(format!("{:?}", value).as_str());
                                arguments.push(format!("{:?}", value));
                            }
                            system_call_names::SystemCallArgumentType::String => {
                                let mut string = read_string(child, reg as *mut c_void);
                                let truncated_string = if config.no_abbrev {
                                    string.as_str()
                                } else {
                                    truncate(string.as_str(), config.string_limit as usize)
                                };
                                if string.eq(truncated_string) {
                                    string = format!("{:?}", string);
                                } else {
                                    string = format!("{:?}...", truncated_string);
                                }
                                output.push_str(string.as_str());
                                arguments.push(string);
                            }
                            system_call_names::SystemCallArgumentType::Address => {
                                if value == 0 {
                                    output.push_str("NULL");
                                    arguments.push(String::from("NULL"));
                                } else {
                                    output.push_str(format!("0x{:x}", value as i32).as_str());
                                    arguments.push(format!("0x{:x}", value as i32));
                                }
                            }
                            system_call_names::SystemCallArgumentType::None => {
                                continue;
                            }
                        }
                    }

                    output.push_str(")");
                    // Only print output at second invocation of ptrace (ptrace gets invoked twice
                    // per system call. Once before and once after execution).
                    if second_ptrace_invocation || x.orig_rax == 59 || x.orig_rax == 231 {
                        let end = SystemTime::now();
                        let mut elapsed: u128 = 0;
                        // Measure system call execution time
                        if let Some(i) = system_call_timer_start {
                            elapsed = end.duration_since(i).unwrap_or_default().as_millis();
                            let syscall = x.orig_rax as u64;

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
                        if system_calls.contains(&String::from(
                            system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0,
                        )) && !expr_negation
                            || !system_calls.contains(&String::from(
                                system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0,
                            )) && expr_negation
                            || system_calls.len() == 0
                        {
                            let return_value: String = if (x.rax as i32).abs() > 32768 {
                                format!("0x{:x}", x.rax as i32)
                            } else {
                                format!("{}", x.rax as i32)
                            };

                            // Handle return value. The return value is distinguished into
                            // different categories (successful, failed, address) and handled
                            // accordingly
                            if (x.rax as i32).abs() > 32768 {
                                if !config.file.is_empty() {
                                    if let Some(mut fd) = file {
                                        if !config.json {
                                            if config.syscall_times {
                                                write!(
                                                    &mut fd,
                                                    "{} = 0x{:x} <{:.6}> \n",
                                                    output, x.rax as i32, elapsed
                                                )
                                                .unwrap();
                                            } else {
                                                write!(&mut fd, "{} = 0x{:x}\n", output, x.rax as i32)
                                                    .unwrap();
                                            }
                                        }

                                        if config.json && !config.summary_only && !config.summary {
                                            if (config.successful_only && (x.rax as i32) >= 0)
                                                || (config.failed_only && (x.rax as i32) < 0)
                                                || (!config.failed_only && !config.successful_only)
                                            {
                                                let json = json!({
                                                    "syscall": system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0,
                                                    "args": arguments,
                                                    "result": return_value,
                                                    "pid": child.as_raw().to_string(),
                                                    "type": "SYSCALL"
                                                });

                                                write!(&mut fd, "{}", json).unwrap();
                                            }
                                        }
                                    }
                                } else {
                                    if !config.failed_only && !config.summary_only && !config.json {
                                        if config.syscall_times {
                                            println!(
                                                "{} = {} <{:.6}>",
                                                output,
                                                Yellow
                                                    .bold()
                                                    .paint(format!("0x{:x}", x.rax as i32)),
                                                elapsed
                                            );
                                        } else {
                                            println!(
                                                "{} = {}",
                                                output,
                                                Yellow
                                                    .bold()
                                                    .paint(format!("0x{:x}", x.rax as i32))
                                            );
                                        }
                                    }

                                    if config.json && !config.summary_only && !config.summary {
                                        if (config.successful_only && (x.rax as i32) >= 0)
                                            || (config.failed_only && (x.rax as i32) < 0)
                                            || (!config.failed_only && !config.successful_only)
                                        {
                                            let json = json!({
                                                "syscall": system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0,
                                                "args": arguments,
                                                "result": return_value,
                                                "pid": child.as_raw().to_string(),
                                                "type": "SYSCALL"
                                            });

                                            println!("{}", json);
                                        }
                                    }
                                }
                            } else {
                                if !config.file.is_empty() {
                                    if let Some(mut fd) = file {
                                        if !config.json {
                                            if config.syscall_times {
                                                write!(
                                                    &mut fd,
                                                    "{} = {} <{:.6}>\n",
                                                    output, x.rax as i32, elapsed
                                                )
                                                .unwrap();
                                            } else {
                                                write!(&mut fd, "{} = {}\n", output, x.rax as i32)
                                                    .unwrap();
                                            }
                                        }

                                        if config.json && !config.summary_only && !config.summary {
                                            if (config.successful_only && (x.rax as i32) >= 0)
                                                || (config.failed_only && (x.rax as i32) < 0)
                                                || (!config.failed_only && !config.successful_only)
                                            {
                                                let json = json!({
                                                    "syscall": system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0,
                                                    "args": arguments,
                                                    "result": return_value,
                                                    "pid": child.as_raw().to_string(),
                                                    "type": "SYSCALL"
                                                });

                                                write!(&mut fd, "{}", json).unwrap();
                                            }
                                        }
                                    }
                                } else {
                                    if (x.rax as i32) < 0
                                        && ((!expr_negation
                                            && !suppress_system_calls.contains(&String::from(
                                                system_call_names::SYSTEM_CALLS
                                                    [(x.orig_rax) as usize]
                                                    .0,
                                            )))
                                            || (expr_negation
                                                && suppress_system_calls.contains(&String::from(
                                                    system_call_names::SYSTEM_CALLS
                                                        [(x.orig_rax) as usize]
                                                        .0,
                                                )))
                                            || suppress_system_calls.len() == 0)
                                    {
                                        failed_system_calls.push(x.orig_rax);

                                        if !config.successful_only
                                            && !config.summary_only
                                            && !config.json
                                        {
                                            if config.syscall_times {
                                                println!(
                                                    "{} = {} <{:.6}>",
                                                    output,
                                                    Red.bold().paint((x.rax as i32).to_string()),
                                                    elapsed
                                                );
                                            } else {
                                                println!(
                                                    "{} = {}",
                                                    output,
                                                    Red.bold().paint((x.rax as i32).to_string())
                                                );
                                            }
                                        }
                                    }
                                    if (x.rax as i32) >= 0 {
                                        if !config.failed_only
                                            && !config.summary_only
                                            && !config.json
                                        {
                                            if config.syscall_times {
                                                println!(
                                                    "{} = {} <{:.6}>",
                                                    output,
                                                    Green.bold().paint((x.rax as i32).to_string()),
                                                    elapsed
                                                );
                                            } else {
                                                println!(
                                                    "{} = {}",
                                                    output,
                                                    Green.bold().paint((x.rax as i32).to_string())
                                                );
                                            }
                                        }
                                    }
                                    if config.json && !config.summary_only && !config.summary {
                                        if (config.successful_only && (x.rax as i32) >= 0)
                                            || (config.failed_only && (x.rax as i32) < 0)
                                            || (!config.failed_only && !config.successful_only)
                                        {
                                            let json = json!({
                                                "syscall": system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0,
                                                "args": arguments,
                                                "result": return_value,
                                                "pid": child.as_raw().to_string(),
                                                "type": "SYSCALL"
                                            });

                                            println!("{}", json);
                                        }
                                    }
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
        syscall_sorted.sort_by(|x, y| x.0.cmp(&y.0));

        let error_map = count_element_function(failed_system_calls);
        let mut number_of_failed_system_calls = 0;
        // Construct summary columns
        for (key, value) in &syscall_sorted {
            println!(
                "{:>6} {:>11} {:>11} {:>9} {:>9} {}",
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        if total_elapsed_time != 0 {
                            format!(
                                "{:.2}",
                                *i as f32 / (total_elapsed_time as f32 / 100 as f32) as f32
                            )
                        } else {
                            format!("0.00")
                        }
                    } else {
                        format!("0.00")
                    }
                },
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        format!("{:.6}", *i as f32 / 1000 as f32)
                    } else {
                        format!("0.000000")
                    }
                },
                {
                    if let Some(i) = system_call_timer_stop.get(key) {
                        format!(
                            "{:.0}",
                            (*i as f32 / 1000 as f32) / (**value as f32) * 1000000 as f32
                        )
                    } else {
                        format!("0")
                    }
                },
                value,
                {
                    if let Some(i) = error_map.get(key) {
                        number_of_failed_system_calls += i;
                        format!("{}", i)
                    } else {
                        format!("")
                    }
                },
                system_call_names::SYSTEM_CALLS[***key as usize].0
            );
        }

        let number_of_successful_system_calls = successful_system_calls.len();

        println!("------ ----------- ----------- --------- --------- ----------------");
        println!(
            "100.00 {:>11.6} {:>11.0} {:>9} {:>9} total",
            total_elapsed_time as f32 / 1000 as f32,
            (total_elapsed_time as f32 / number_of_successful_system_calls as f32) * 1000 as f32,
            total_elapsed_time,
            number_of_failed_system_calls
        );
    }
}

fn run_tracee(config: Config) {
    let mut args: Vec<String> = Vec::new();
    let mut program = String::from("");

    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();
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
        let arg: Vec<String> = token.split("=").map(|s| s.to_string()).collect();

        if arg.len() == 2 {
            cmd.env(arg[0].as_str(), arg[1].as_str());
        } else {
            cmd.env_remove(arg[0].as_str());
        }
    }

    if let Some(user) = users::get_user_by_name(&config.username) {
        cmd.uid(user.uid());
    }

    cmd.exec();

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

        let res: c_long;

        match ptrace::read(pid, address) {
            Ok(c_long) => res = c_long,
            Err(_) => break 'done,
        }

        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {} as i64 LittleEndian: {}", res, err);
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

fn construct_config(matches: clap::ArgMatches) -> Result<Config> {
    let syscall_number = matches.is_present("syscall-number");
    let attach = matches
        .value_of("attach")
        .map(|n| n.parse::<i32>())
        .transpose()
        .context("Failed to parse --process argument")?
        .unwrap_or_default();

    let string_limit = matches
        .value_of("string-limit")
        .map(|n| n.parse::<i32>())
        .transpose()
        .context("Failed to parse --string-limit argument")?
        .unwrap_or_else(|| 32);

    let command: Vec<_> = matches
        .values_of("command")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();

    let env: Vec<_> = matches
        .values_of("env")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();

    let expr: Vec<_> = matches
        .values_of("expr")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();

    let file = matches.value_of("file").unwrap_or_default().to_string();

    let summary_only = matches.is_present("summary-only");

    let summary = matches.is_present("summary");

    let successful_only = matches.is_present("successful-only");

    let failed_only = matches.is_present("failed-only");

    let no_abbrev = matches.is_present("no-abbrev");

    let username = matches.value_of("username").unwrap_or_default().to_string();

    let follow_forks = matches.is_present("follow-forks");

    let syscall_times = matches.is_present("syscall-times");

    let json = matches.is_present("json");

    Ok(Config {
        syscall_number,
        attach,
        command,
        string_limit,
        file,
        summary_only,
        summary,
        successful_only,
        failed_only,
        no_abbrev,
        env,
        username,
        follow_forks,
        syscall_times,
        expr,
        json,
    })
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

/// Add all system_calls from the given categories to the system_calls Vector
fn apply_filter_categories(
    mut system_calls: Vec<String>,
    expr_filter_categories: Vec<String>,
) -> Vec<String> {
    for keyword in expr_filter_categories {
        match keyword.as_str() {
            "file" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_FILE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "process" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_PROCESS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "network" | "net" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_NETWORK[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "signal" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_SIGNAL[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "ipc" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_IPC[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "desc" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_DESC[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "memory" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_MEMORY[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "creds" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_CREDS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "stat" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_STAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "lstat" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_LSTAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "fstat" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_FSTAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "%stat" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_STAT_LIKE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "statfs" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_STATFS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "fstatfs" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_FSTATFS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "%statfs" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_STATFS_LIKE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "clock" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_CLOCK[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "pure" => {
                system_calls = [
                    &system_calls[..],
                    &system_call_names::TRACE_PURE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            _ => panic!("This is not a valid option!"),
        }
    }
    system_calls.sort();
    system_calls.dedup();
    system_calls
}
