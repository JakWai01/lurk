use crate::system_call_names::{
    SYSTEM_CALLS, TRACE_CLOCK, TRACE_CREDS, TRACE_DESC, TRACE_FILE, TRACE_FSTAT, TRACE_FSTATFS,
    TRACE_IPC, TRACE_LSTAT, TRACE_MEMORY, TRACE_NETWORK, TRACE_PROCESS, TRACE_PURE, TRACE_SIGNAL,
    TRACE_STAT, TRACE_STATFS, TRACE_STATFS_LIKE, TRACE_STAT_LIKE,
};
use clap::Parser;
use regex::Regex;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone, PartialEq, Default)]
#[command(name = "lurk", about, version)]
pub struct Args {
    /// Display system call numbers
    #[arg(short = 'n', long)]
    pub syscall_number: bool,
    /// Attach to a running process
    #[arg(short = 'p', long)]
    pub attach: Option<i32>,
    /// Maximum string argument size to print
    #[arg(short, long)]
    pub string_limit: Option<usize>,
    /// Name of the file to print output to
    #[arg(short = 'o', long)]
    pub file: Option<PathBuf>,
    /// Report a summary instead of the regular output
    #[arg(short = 'c', long)]
    pub summary_only: bool,
    /// Report a summary in addition to the regular output
    #[arg(short = 'C', long, conflicts_with = "summary_only")]
    pub summary: bool,
    /// Print only syscalls that returned without an error code
    #[arg(short = 'z', long)]
    pub successful_only: bool,
    /// Print only syscalls that returned with an error code
    #[arg(short = 'Z', long, conflicts_with = "successful_only")]
    pub failed_only: bool,
    /// Print un-abbreviated versions of strings
    #[arg(short = 'v', long)]
    pub no_abbrev: bool,
    /// --env var=val adds an environment variable. --env var removes an environment variable.
    #[arg(short = 'E', long)]
    pub env: Vec<String>,
    /// Run the command with uid, gid and supplementary groups of username.
    #[arg(short, long)]
    pub username: Option<String>,
    /// Trace child processes as they are created by currently traced processes.
    #[arg(short, long)]
    pub follow_forks: bool,
    /// Show the time spent in system calls in ms.
    #[arg(short = 'T', long)]
    pub syscall_times: bool,
    /// A qualifying expression which modifies which events to trace or how to trace them.
    #[arg(short, long)]
    pub expr: Vec<String>,
    /// Display output in JSON format
    #[arg(short, long)]
    pub json: bool,
    /// Trace command
    #[arg(required_unless_present = "attach")]
    pub command: Vec<String>,
}

impl Args {
    pub(crate) fn create_filter(&self) -> Filter {
        let all_system_calls: HashSet<&'static str> = SYSTEM_CALLS.iter().map(|v| v.0).collect();

        let mut expr_negation = false;
        let mut suppress_system_calls = HashSet::new();
        let mut system_calls = HashSet::new();

        // Sort system calls listed with --expr into their category to handle them accordingly
        for token in &self.expr {
            let mut tokens = token.splitn(2, '=');
            match (tokens.next(), tokens.next()) {
                (Some(token_key), Some(mut token_value))
                    if token_key == "t" || token_key == "trace" =>
                {
                    if let Some(v) = token_value.strip_prefix('!') {
                        token_value = v;
                        expr_negation = true;
                    }

                    for part in token_value.split(',') {
                        if let Some(part) = part.strip_prefix('?') {
                            let val = all_system_calls.get(part);
                            if let Some(val) = val {
                                suppress_system_calls.insert(*val);
                            } else {
                                panic!("System call '{part}' is not valid!");
                            }
                        } else if let Some(part) = part.strip_prefix('/') {
                            if let Ok(pattern) = Regex::new(part) {
                                for system_call in SYSTEM_CALLS.iter() {
                                    let system_call = system_call.0;
                                    if pattern.is_match(system_call) {
                                        system_calls.insert(system_call);
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
                            system_calls.extend(calls);
                        } else {
                            let val = all_system_calls.get(part);
                            if let Some(val) = val {
                                system_calls.insert(val);
                            } else {
                                panic!("System call '{part}' is not valid!");
                            }
                        }
                    }
                }
                _ => panic!("expr {token} is not supported. Please have a look at the syntax."),
            }
        }
        Filter {
            expr_negation,
            suppress_system_calls,
            system_calls,
        }
    }
}

pub struct Filter {
    pub expr_negation: bool,
    pub suppress_system_calls: HashSet<&'static str>,
    pub system_calls: HashSet<&'static str>,
}

impl Filter {
    pub fn show_syscall(&mut self, syscall_id: usize) -> bool {
        let syscall = SYSTEM_CALLS[syscall_id].0;
        self.suppress_system_calls.is_empty()
            || self.suppress_system_calls.contains(syscall) != self.expr_negation
    }
}
