//! Crypt — command line entry point.
//!
//! All of the logic lives in the library so it can be unit tested without a
//! terminal or a process boundary.

use std::env;
use std::ffi::OsString;

fn main() {
    // `args_os`, not `args`: a path with bytes that are not valid UTF-8 is still
    // a usable path, and `env::args` panics on the first such byte instead.
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    std::process::exit(crypt::run_os(&args));
}
