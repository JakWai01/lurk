mod cli;

use std::env;

fn main() {
    let matches = cli::build_cli().get_matches_from(env::args_os());

    println!("{:?}", matches);
}
