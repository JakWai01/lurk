use clap::Parser;
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
    /// Maximum string size to print
    #[arg(short, long)]
    pub string_limit: Option<usize>,
    /// Name of the file to print output to
    #[arg(short = 'o', long)]
    pub file: Option<PathBuf>,
    /// Report a summary instead of the regular output
    #[arg(short = 'c', long)]
    pub summary_only: bool,
    /// Report a summary in addition to the regular output
    #[arg(short = 'C', long)]
    pub summary: bool,
    /// Print only syscalls that returned without an error code
    #[arg(short = 'z', long)]
    pub successful_only: bool,
    /// Print only syscalls that returned with an error code
    #[arg(short = 'Z', long)]
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
