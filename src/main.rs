mod app;

use std::env;

fn main() {
    let matches = app::build_app().get_matches_from(env::args_os());

    println!("{:?}", matches);
}
