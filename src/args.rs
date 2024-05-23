use crate::arch::{
    TRACE_CLOCK, TRACE_CREDS, TRACE_DESC, TRACE_FILE, TRACE_FSTAT, TRACE_FSTATFS, TRACE_IPC,
    TRACE_LSTAT, TRACE_MEMORY, TRACE_NETWORK, TRACE_PROCESS, TRACE_PURE, TRACE_SIGNAL, TRACE_STAT,
    TRACE_STATFS, TRACE_STATFS_LIKE, TRACE_STAT_LIKE,
};
use crate::syscall_info::RetCode;
use anyhow::bail;
use clap::{Parser, Subcommand};
use libc::pid_t;
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use syscalls::{Sysno, SysnoSet};

#[derive(Parser, Debug, Default)]
#[command(name = "lurk", about, version, allow_external_subcommands = true)]
pub struct Args {
    /// Display system call numbers
    #[arg(short = 'n', long)]
    pub syscall_number: bool,
    /// Attach to a running process
    #[arg(short = 'p', long)]
    pub attach: Option<pid_t>,
    /// Print un-abbreviated versions of strings
    #[arg(short = 'v', long)]
    pub no_abbrev: bool,
    /// Maximum string argument size to print
    #[arg(short, long, conflicts_with = "no_abbrev")]
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
    #[command(subcommand)]
    pub command: Option<ArgCommand>,
}

// The command/subcommand is a bit hacky, but gets the job done:
// https://github.com/clap-rs/clap/discussions/4560#discussioncomment-5392780

#[derive(Subcommand, Debug, PartialEq)]
pub enum ArgCommand {
    /// Trace command
    #[command(external_subcommand)]
    Command(Vec<String>),
}

#[derive(Parser, Debug, PartialEq)]
pub struct ArgAttach {
    /// Attach to a running process with the given pid.
    #[arg(short = 'p', long)]
    pub attach: pid_t,
}

impl Args {
    pub fn create_filter(&self) -> anyhow::Result<Filter> {
        let all_syscall_names: HashMap<&'static str, Sysno> =
            SysnoSet::all().iter().map(|v| (v.name(), v)).collect();
        let mut expr_negation = false;
        let mut system_calls = SysnoSet::empty();

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
                        if let Some(part) = part.strip_prefix('/') {
                            // The '/' prefix followed by a regex pattern to match system calls
                            if let Ok(pattern) = Regex::new(part) {
                                for (syscall, sysno) in &all_syscall_names {
                                    if pattern.is_match(syscall) {
                                        system_calls.insert(*sysno);
                                    }
                                }
                            } else {
                                bail!("Invalid regex pattern: {part}");
                            }
                        } else if let Some(part) = part.strip_prefix('%') {
                            // The '%' prefix followed by the name of a syscalls category to trace
                            system_calls = system_calls.union(match part {
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
                                v => bail!("Category '{v}' is not valid!"),
                            });
                        } else {
                            // The optional '?' prefix will ignore unknown system calls
                            let mut ignore_unknown = false;
                            if let Some(v) = token_value.strip_prefix('?') {
                                token_value = v;
                                ignore_unknown = true;
                            }
                            if let Ok(val) = Sysno::from_str(part) {
                                system_calls.insert(val);
                            } else if !ignore_unknown {
                                bail!("System call '{part}' is not valid!");
                            }
                        }
                    }
                }
                _ => bail!("expr {token} is not supported. Please have a look at the syntax."),
            }
        }
        Ok(Filter {
            ret_code_filter: if self.successful_only {
                FilterRetCode::Oks
            } else if self.failed_only {
                FilterRetCode::Errs
            } else {
                FilterRetCode::All
            },
            sysno_filter: if system_calls.count() == 0 {
                FilterSysno::All
            } else if expr_negation {
                FilterSysno::Except(system_calls)
            } else {
                FilterSysno::Only(system_calls)
            },
        })
    }
}

enum FilterRetCode {
    All,
    Oks,
    Errs,
}

enum FilterSysno {
    All,
    Only(SysnoSet),
    Except(SysnoSet),
}

pub struct Filter {
    ret_code_filter: FilterRetCode,
    sysno_filter: FilterSysno,
}

impl Filter {
    pub fn matches(&mut self, sys_no: Sysno, res: RetCode) -> bool {
        (
            // Should this result code be printed?
            match self.ret_code_filter {
                FilterRetCode::All => true,
                FilterRetCode::Oks => matches!(res, RetCode::Ok(_) | RetCode::Address(_)),
                FilterRetCode::Errs => matches!(res, RetCode::Err(_)),
            }
        ) && (
            // Should this sys_no be printed?
            match &self.sysno_filter {
                FilterSysno::All => true,
                FilterSysno::Only(sysno_set) => sysno_set.contains(sys_no),
                FilterSysno::Except(sysno_set) => !sysno_set.contains(sys_no),
            }
        )
    }

    pub fn all_enabled(&self) -> SysnoSet {
        match &self.sysno_filter {
            FilterSysno::All => SysnoSet::all(),
            FilterSysno::Only(sysno_set) => sysno_set.clone(),
            FilterSysno::Except(sysno_set) => SysnoSet::all().difference(sysno_set),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_simple() {
        let args = Args::parse_from(["lurk", "app"]);
        assert_eq!(
            args.command,
            Some(ArgCommand::Command(vec!["app".to_string()])),
        );
    }
}
