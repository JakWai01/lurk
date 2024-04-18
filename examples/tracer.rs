use anyhow::{bail, Result};
use console::Style;
use lurk_cli::{args::Args, style::StyleConfig, Tracer};
use nix::unistd::{fork, ForkResult};
use std::io;

fn main() -> Result<()> {
    let command = String::from("/usr/bin/ls");

    let pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            return lurk_cli::run_tracee(&[command], &[], &None);
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(err) => bail!("fork() failed: {err}"),
    };

    let args = Args::default();
    let output = io::stdout();
    let style = StyleConfig {
        pid: Style::new().cyan(),
        syscall: Style::new().white().bold(),
        success: Style::new().green(),
        error: Style::new().red(),
        result: Style::new().yellow(),
        use_colors: true,
    };

    Tracer::new(pid, args, output, style)?.run_tracer()
}
