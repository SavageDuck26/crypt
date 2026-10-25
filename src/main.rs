//! Crypt — command line entry point.
//!
//! All of the logic lives in the library so it can be unit tested without a
//! terminal or a process boundary.

use std::env;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    std::process::exit(crypt::run(&args));
}
