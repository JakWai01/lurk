use clap::{Arg, Command};

pub fn build_cli() -> Command<'static> {
    let app = Command::new("lurk")
        .arg(
            Arg::new("test")
            .long("test")
            .short('t')
            .help("This is a test")
        );

    app
}