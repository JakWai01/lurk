use clap::{Arg, Command};

pub fn build_app() -> Command<'static> {
    let app = Command::new("lurk")
        .arg(
            Arg::new("number")
                .long("number")
                .short('n')
                .help("Display system call numbers")
        );
    
    app
}