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
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command, Stdio};
use std::time::{SystemTime};
use std::{thread, time};

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

    let mut time_spent: HashMap<u64, u64> = HashMap::new();

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
                                let truncated_string =
                                    truncate(string.as_str(), config.string_limit as usize);
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
                        // Testing the timer since most operations are way to fast
                        thread::sleep(time::Duration::from_millis(1));
                        let end = SystemTime::now();

                        if let Some(i) = start {
                            let elapsed = end.duration_since(i).unwrap_or_default().as_millis();
                            let syscall = x.orig_rax as u64;

                            if let Some(old_value) = time_spent.get(&syscall) {
                                let new_value = old_value + elapsed as u64;
                                time_spent.insert(syscall, new_value);
                            } else {
                                time_spent.insert(syscall, elapsed as u64);
                            }
                        };

                        if (x.rax as i32).abs() > 32768 {
                            if !config.file.is_empty() {
                                if let Some(mut fd) = file {
                                    write!(&mut fd, "{} = 0x{:x}\n", output, x.rax as i32);
                                }
                            } else {
                                if !config.failed_only && !config.summary_only {
                                    println!(
                                        "{} = {}",
                                        output,
                                        Yellow.bold().paint(format!("0x{:x}", x.rax as i32))
                                    );
                                }
                            }
                        } else {
                            if !config.file.is_empty() {
                                if let Some(mut fd) = file {
                                    write!(&mut fd, "{} = {}\n", output, x.rax as i32);
                                }
                            } else {
                                if (x.rax as i32) < 0 {
                                    error_cache.push(x.orig_rax);

                                    if !config.successful_only && !config.summary_only {
                                        println!(
                                            "{} = {}",
                                            output,
                                            Red.bold().paint((x.rax as i32).to_string())
                                        );
                                    }
                                } else {

                                    if !config.failed_only && !config.summary_only {
                                        println!(
                                            "{} = {}",
                                            output,
                                            Green.bold().paint((x.rax as i32).to_string())
                                        );
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
            Err(_) => break,
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
                "{}    {}        {}     {:>5}     {:>5} {}",
                {
                    if let Some(i) = time_spent.get(key) {
                        format!("{:>6.2}", *i as f32 / (time as f32 / 100 as f32) as f32)
                    } else {
                        format!("  0.00")
                    }
                },
                {
                    if let Some(i) = time_spent.get(key) {
                        format!("{:>6.6}", *i as f32/1000 as f32)
                    } else {
                        format!("0.000000")
                    }
                },
                {
                    if let Some(i) = time_spent.get(key) {
                        format!("{:.0}", (*i as f32/1000 as f32)/(**value as f32) * 1000000 as f32)
                    } else {
                        format!("   0")
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
        println!("100.00    {:.6}         {:.0}       {}        {} total", time as f32 / 1000 as f32, (time as f32 / syscall_length as f32) *  1000 as f32, time, error_count)
    }
}

fn run_tracee(config: Config) {
    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    Command::new(config.command).stdout(Stdio::null()).exec();

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

    let command = matches.value_of("command").unwrap_or_default().to_string();

    let file = matches.value_of("file").unwrap_or_default().to_string();

    let summary_only = matches.is_present("summary-only");

    let summary = matches.is_present("summary");

    let successful_only = matches.is_present("successful-only");

    let failed_only = matches.is_present("failed-only");

    Ok(Config {
        syscall_number,
        attach,
        command,
        string_limit,
        file,
        summary_only,
        summary,
        successful_only,
        failed_only
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
