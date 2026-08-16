use std::fs::OpenOptions;
use std::io::{self, BufWriter, IsTerminal, Write};

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser};
use lurk_cli::style::StyleConfig;
use nix::unistd::Pid;
use std::process::ExitCode;

use lurk_cli::args::{ArgCommand, Args};
use lurk_cli::{attach_tracees, spawn_tracee_with_options, Tracer};

fn main() -> Result<ExitCode> {
    let config = Args::parse();
    let (pid, tracees, spawned) = if let Some(ArgCommand::Command(command)) = &config.command {
        if command.is_empty() {
            Args::command().print_help()?;
            return Ok(ExitCode::SUCCESS);
        }
        if config.attach.is_some() {
            bail!("The -p/--attach option cannot be used with a command");
        }
        let pid =
            spawn_tracee_with_options(command, &config.env, &config.username, config.follow_forks)?;
        (pid, vec![pid], true)
    } else if let Some(pid) = config.attach {
        let pid = Pid::from_raw(pid);
        let tracees = attach_tracees(pid, config.follow_forks)?;
        (pid, tracees, false)
    } else {
        Args::command().print_help()?;
        return Ok(ExitCode::SUCCESS);
    };

    // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
    let mut style_config = StyleConfig::default();
    let output: Box<dyn Write> = if let Some(filepath) = &config.file {
        style_config.use_colors = false;
        Box::new(BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(filepath)?,
        ))
    } else {
        style_config.use_colors = io::stderr().is_terminal();
        Box::new(std::io::stderr())
    };

    let mut tracer = Tracer::new(pid, config, output, style_config)?;
    if spawned {
        tracer.set_seized_spawn();
    } else {
        tracer.set_attached_tracees(tracees);
    }
    let outcome = tracer.run_tracer_with_outcome()?;
    Ok(ExitCode::from(outcome.exit_code() as u8))
}
