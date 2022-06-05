use clap::{Arg, Command};

pub fn build_app() -> Command<'static> {
    let app = Command::new("lurk")
        .author("Jakob Waibel")
        .arg(Arg::new("command").help("Trace command").index(1).required_unless_present("process")).arg(
            Arg::new("syscall-number")
                .long("syscall-number")
                .short('n')
                .help("Display system call numbers"),
        )
        .arg(
            Arg::new("process")
                .long("process")
                .short('p')
                .takes_value(true)
                .help("Attach to a running process"),
        );
    app
}
