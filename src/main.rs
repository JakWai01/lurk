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
    let mut second_invocation = true;
    let mut start: Option<std::time::SystemTime> = None;
    let mut syscall_cache: Vec<u64> = Vec::new();
    let mut error_cache: Vec<u64> = Vec::new();
    let mut set_options: bool = false;
    let mut time_spent: HashMap<u64, u64> = HashMap::new();
    let mut q_mark: Vec<String> = Vec::new();
    let mut slash: Vec<String> = Vec::new();
    let mut filter: Vec<String> = Vec::new();
    let mut is_negation: bool = false;
    let mut keywords: Vec<String> = Vec::new();

    for var in &config.expr {
        let arg: Vec<String> = var.split("=").map(|s| s.to_string()).collect();

        match arg[0].as_str() {
            "t" | "trace" => {
                let mut tiles: Vec<String> =
                    arg[1].as_str().split(",").map(|s| s.to_string()).collect();
                let first_tile: Vec<char> = tiles[0].chars().collect();

                is_negation = first_tile[0] == '!';
                if is_negation {
                    let letters: Vec<char> = tiles[0].chars().collect();
                    tiles[0] = letters[1..].iter().cloned().collect::<String>();
                }

                for tile in tiles {
                    let letter: Vec<char> = tile.chars().collect();
                    match letter[0] {
                        '?' => q_mark.push(letter[1..].iter().cloned().collect::<String>()),
                        '/' => slash.push(letter[1..].iter().cloned().collect::<String>()),
                        '%' => keywords.push(letter[1..].iter().cloned().collect::<String>()),
                        _ => filter.push(letter.iter().cloned().collect::<String>()),
                    }
                }
            }
            _ => panic!("This command is not supported. Please have a look at the syntax."),
        }
    }

    let mut regex_matches: Vec<String> = Vec::new();

    for i in 0..334 {
        let mut is_match: bool = false;
        let current_syscall = system_call_names::SYSTEM_CALLS[i as usize].0;

        for pattern in &slash {
            let re = Regex::new(pattern.as_str()).unwrap();
            if re.is_match(current_syscall) {
                is_match = true;
            }
        }

        if is_match {
            regex_matches.push(String::from(current_syscall));
        }
    }

    let mut concat_vec: Vec<String> = [&regex_matches[..], &filter[..]].concat();

    for keyword in keywords {
        match keyword.as_str() {
            "file" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_FILE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            }
            "process" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_PROCESS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "network" | "net" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_NETWORK[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "signal" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_SIGNAL[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "ipc" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_IPC[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "desc" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_DESC[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "memory" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_MEMORY[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "creds" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_CREDS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "stat" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_STAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "lstat" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_LSTAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "fstat" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_FSTAT[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "%stat" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_STAT_LIKE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "statfs" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_STATFS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "fstatfs" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_FSTATFS[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "%statfs" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_STATFS_LIKE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "clock" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_CLOCK[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            "pure" => {
                concat_vec = [
                    &concat_vec[..],
                    &system_call_names::TRACE_PURE[..]
                        .iter()
                        .map(|e| String::from(system_call_names::SYSTEM_CALLS[*e].0))
                        .collect::<Vec<String>>()[..],
                ]
                .concat();
            },
            _ => panic!("This is not a valid option!"),
        }
    }

    concat_vec.sort();
    concat_vec.dedup();

    loop {
        let mut file: Option<std::fs::File> = None;

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

        wait().unwrap();

        if !set_options {
            if config.follow_forks {
                ptrace::setoptions(
                    child,
                    Options::PTRACE_O_TRACEFORK
                        | Options::PTRACE_O_TRACEVFORK
                        | Options::PTRACE_O_TRACECLONE,
                )
                .unwrap();
            }
            set_options = true;
        }

        let reg;

        match ptrace::getregs(child) {
            Ok(x) => {
                if x.orig_rax < 336 {
                    reg = x.rsi;

                    let syscall_tuple = system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize];

                    let argument_type_array: [system_call_names::SystemCallArgumentType; 6] = [
                        syscall_tuple.1,
                        syscall_tuple.2,
                        syscall_tuple.3,
                        syscall_tuple.4,
                        syscall_tuple.5,
                        syscall_tuple.6,
                    ];

                    let mut output = if config.syscall_number {
                        if !config.file.is_empty() {
                            format!(
                                "[{}] {:>3}:x {}(",
                                child.as_raw().to_string(),
                                x.orig_rax,
                                system_call_names::SYSTEM_CALLS[x.orig_rax as usize].0
                            )
                        } else {
                            format!(
                                "[{}] {:>3}:x {}(",
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

                        match arg {
                            system_call_names::SystemCallArgumentType::Integer => {
                                output.push_str(format!("{:?}", value).as_str());
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
                            }
                            system_call_names::SystemCallArgumentType::Address => {
                                if value == 0 {
                                    output.push_str("NULL");
                                } else {
                                    output.push_str(format!("0x{:x}", value as i32).as_str());
                                }
                            }
                            system_call_names::SystemCallArgumentType::None => {
                                continue;
                            }
                        }
                    }

                    output.push_str(")");

                    if second_invocation || x.orig_rax == 59 || x.orig_rax == 231 {
                        let end = SystemTime::now();
                        let mut elapsed: u128 = 0;

                        if let Some(i) = start {
                            elapsed = end.duration_since(i).unwrap_or_default().as_millis();
                            let syscall = x.orig_rax as u64;

                            if let Some(old_value) = time_spent.get(&syscall) {
                                let new_value = old_value + elapsed as u64;
                                time_spent.insert(syscall, new_value);
                            } else {
                                time_spent.insert(syscall, elapsed as u64);
                            }
                        };
                        if concat_vec.contains(&String::from(
                            system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0,
                        )) && !is_negation
                            || !concat_vec.contains(&String::from(
                                system_call_names::SYSTEM_CALLS[(x.orig_rax) as usize].0,
                            )) && is_negation
                            || concat_vec.len() == 0
                        {
                            if (x.rax as i32).abs() > 32768 {
                                if !config.file.is_empty() {
                                    if let Some(mut fd) = file {
                                        if config.syscall_times {
                                            write!(
                                                &mut fd,
                                                "{} = 0x{:x} <{:.6}> \n",
                                                output, x.rax as i32, elapsed
                                            );
                                        } else {
                                            write!(&mut fd, "{} = 0x{:x}\n", output, x.rax as i32);
                                        }
                                    }
                                } else {
                                    if !config.failed_only && !config.summary_only {
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
                                }
                            } else {
                                if !config.file.is_empty() {
                                    if let Some(mut fd) = file {
                                        if config.syscall_times {
                                            write!(
                                                &mut fd,
                                                "{} = {} <{:.6}>\n",
                                                output, x.rax as i32, elapsed
                                            );
                                        } else {
                                            write!(&mut fd, "{} = {}\n", output, x.rax as i32);
                                        }
                                    }
                                } else {
                                    if (x.rax as i32) < 0
                                        && ((!is_negation
                                            && !q_mark.contains(&String::from(
                                                system_call_names::SYSTEM_CALLS
                                                    [(x.orig_rax) as usize]
                                                    .0,
                                            )))
                                            || (is_negation
                                                && q_mark.contains(&String::from(
                                                    system_call_names::SYSTEM_CALLS
                                                        [(x.orig_rax) as usize]
                                                        .0,
                                                )))
                                            || q_mark.len() == 0)
                                    {
                                        error_cache.push(x.orig_rax);

                                        if !config.successful_only && !config.summary_only {
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
                                    if (x.rax as i32) > 0 {
                                        if !config.failed_only && !config.summary_only {
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
                                }
                            }
                        }

                        second_invocation = false;
                        start = None;

                        if config.summary_only || config.summary {
                            syscall_cache.push(x.orig_rax);
                        }
                    } else {
                        start = Some(SystemTime::now());
                        second_invocation = true;
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

    if config.summary_only || config.summary {
        let mut time = 0;
        for value in time_spent.values() {
            time += value;
        }

        println!("% time     seconds  usecs/call     calls    errors syscall");
        println!("------ ----------- ----------- --------- --------- ----------------");

        let syscall_map = count_element_function(&syscall_cache);
        let mut syscall_sorted: Vec<_> = syscall_map.iter().collect();
        syscall_sorted.sort_by(|x, y| x.0.cmp(&y.0));

        let error_map = count_element_function(error_cache);
        let mut error_count = 0;

        for (key, value) in &syscall_sorted {
            println!(
                "{:>6} {:>11} {:>11} {:>9} {:>9} {}",
                {
                    if let Some(i) = time_spent.get(key) {
                        if time != 0 {
                            format!("{:.2}", *i as f32 / (time as f32 / 100 as f32) as f32)
                        } else {
                            format!("0.00")
                        }
                    } else {
                        format!("0.00")
                    }
                },
                {
                    if let Some(i) = time_spent.get(key) {
                        format!("{:.6}", *i as f32 / 1000 as f32)
                    } else {
                        format!("0.000000")
                    }
                },
                {
                    if let Some(i) = time_spent.get(key) {
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
                        error_count += i;
                        format!("{}", i)
                    } else {
                        format!("")
                    }
                },
                system_call_names::SYSTEM_CALLS[***key as usize].0
            );
        }
        let syscall_length = syscall_cache.len();
        println!("------ ----------- ----------- --------- --------- ----------------");
        println!(
            "100.00 {:>11.6} {:>11.0} {:>9} {:>9} total",
            time as f32 / 1000 as f32,
            (time as f32 / syscall_length as f32) * 1000 as f32,
            time,
            error_count
        )
    }
}

fn run_tracee(config: Config) {
    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    let mut args: Vec<String> = Vec::new();
    let mut program = String::from("");
    for (index, arg) in config.command.iter().enumerate() {
        if index != 0 {
            args.push(String::from(arg));
        } else {
            program = arg.to_string();
        }
    }

    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::null());

    for var in config.env {
        let arg: Vec<String> = var.split("=").map(|s| s.to_string()).collect();

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
