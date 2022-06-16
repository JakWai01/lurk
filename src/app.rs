use clap::{Arg, Command};

pub fn build_app() -> Command<'static> {
    let app = Command::new("lurk")
        .author("Jakob Waibel")
        .arg(
            Arg::new("command")
                .help("Trace command")
                .index(1)
                .required_unless_present("attach"),
        )
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
        );
    app
}
