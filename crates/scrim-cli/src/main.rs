//! `scrim` binary entry point.

#![allow(clippy::question_mark)]

use std::process::ExitCode;

fn main() -> ExitCode {
    scrim_cli::main_entry()
}
