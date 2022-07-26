use clap::{Arg, Command};

pub fn build_app() -> Command<'static> {
    let app = Command::new("lurk")
        .version("0.2.3")
        .trailing_var_arg(true)
        .arg(
            Arg::new("syscall-number")
                .long("syscall-number")
                .short('n')
                .help("Display system call numbers"),
        )
        .arg(
            Arg::new("attach")
                .long("attach")
                .short('p')
                .takes_value(true)
                .help("Attach to a running process"),
        )
        .arg(
            Arg::new("string-limit")
                .long("string-limit")
                .short('s')
                .takes_value(true)
                .help("Maximum string size to print"),
        )
        .arg(
            Arg::new("file")
                .long("file")
                .short('o')
                .takes_value(true)
                .help("Name of the file to print output to"),
        )
        .arg(
            Arg::new("summary-only")
                .long("summary-only")
                .short('c')
                .help("Report a summary instead of the regular output"),
        )
        .arg(
            Arg::new("summary")
                .long("summary")
                .short('C')
                .help("Report a summary in addition to the regular output"),
        )
        .arg(
            Arg::new("successful-only")
                .long("successful-only")
                .short('z')
                .help("Print only syscalls that returned without an error code"),
        )
        .arg(
            Arg::new("failed-only")
                .long("failed-only")
                .short('Z')
                .help("Print only syscalls that returned with an error code"),
        )
        .arg(
            Arg::new("no-abbrev")
                .long("no-abbrev")
                .short('v')
                .help("Print unabbreviated versions of strings"),
        )
        .arg(
            Arg::new("command")
                .help("Trace command")
                .required_unless_present("attach")
                .takes_value(true)
                .multiple_values(true),
        )
        .arg(
            Arg::new("env")
                .help("--env var=val adds an environment variable. --env var removes an environment variable.")
                .long("env")
                .short('E')
                .multiple_occurrences(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("username")
                .help("Run the command with uid, gid and supplementary groups of username.")
                .long("username")
                .short('u')
                .takes_value(true),
        )
        .arg(
            Arg::new("follow-forks")
            .help("Trace child processes as they are created by currently traced processes.")
            .long("follow-forks")
            .short('f')
        )
        .arg(
            Arg::new("syscall-times")
            .help("Show the time spent in system calls in ms.")
            .long("syscall-times")
            .short('T')
        )
        .arg(
            Arg::new("expr")
            .help("A qualifying expression which modifies which events to trace or how to trace them.")
            .long("expr")
            .short('e')
            .multiple_occurrences(true)
            .takes_value(true)
        );
    app
}
