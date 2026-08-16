use anyhow::Result;
use console::Style;
use lurk_cli::{args::Args, spawn_tracee, style::StyleConfig, Tracer};
use std::io;

fn main() -> Result<()> {
    let command = String::from("/usr/bin/ls");

    let pid = spawn_tracee(&[command], &[], &None)?;

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

    let mut tracer = Tracer::new(pid, args, output, style)?;
    tracer.set_seized_spawn();
    tracer.run_tracer()
}
