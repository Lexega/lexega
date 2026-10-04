// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Command-line interface for the Lexega recognition engine.
//!
//! [`run`] dispatches a command line to its driver. A driver owns argument
//! parsing, file discovery, output and exit codes; whatever varies by
//! build goes through the [`extension::Extension`] it is handed.
//! [`recognition::Recognition`] is the extension of the recognition build.

pub mod artifacts;
pub mod ci_env;
pub mod cmd_analyze;
pub mod cmd_catalog;
pub mod cmd_ci;
pub mod cmd_fmt;
pub mod cmd_review;
pub mod color;
pub mod extension;
pub mod git;
pub mod io;
pub mod output;
pub mod pr_comment;
pub mod recognition;
pub mod types;
pub mod usage;

use std::process;

use extension::Extension;

/// Run the command line `args`, program name first.
pub fn run(args: Vec<String>, ext: &dyn Extension) {
    install_broken_pipe_guard();
    dispatch(&expand_long_opt_eq(args), ext);
}

/// Run the command `args[1]` names. The extension's commands take
/// precedence over the built-in ones of the same name.
pub fn dispatch(args: &[String], ext: &dyn Extension) {
    let program = args.first().map(String::as_str).unwrap_or("lexega");
    let Some(command) = args.get(1).map(String::as_str) else {
        ext.usage(program);
        process::exit(1);
    };
    if ext.run_command(command, args) {
        return;
    }
    match command {
        "fmt" | "format" => cmd_fmt::handle_fmt_command(args, ext),
        "analyze" | "risk" => cmd_analyze::handle_risk_command(args, ext),
        "ci" => cmd_ci::handle_ci_command(args, ext),
        "review" => cmd_review::handle_review_command(args, ext),
        "catalog" => cmd_catalog::handle_catalog_command(args),
        "--licenses" => print!("{}", include_str!("../THIRD_PARTY_LICENSES.txt")),
        "-h" | "--help" | "help" => ext.usage(program),
        "-V" | "--version" | "version" => println!("{}", ext.version()),
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!();
            ext.usage(program);
            process::exit(1);
        }
    }
}

/// True when a panic message is std's stdout/stderr broken-pipe write failure.
/// Rust ignores SIGPIPE, so a reader closing the pipe (`… | head`, quitting
/// `less`) surfaces as `print!`/`println!` panicking. The `"failed printing to
/// std"` prefix is std's own fixed text (locale-independent); the EPIPE marker
/// (`Broken pipe` / `os error 32`) distinguishes a closed pipe from a real
/// output error (e.g. disk full), which must still surface.
fn is_broken_pipe_message(msg: &str) -> bool {
    msg.starts_with("failed printing to std")
        && (msg.contains("Broken pipe") || msg.contains("os error 32"))
}

/// Install a panic hook that turns std's broken-pipe write panic into a clean
/// SIGPIPE-style exit (141) instead of the default panic (exit 101 with a
/// stack-trace-y message). Every other panic is delegated to the default hook,
/// so real bugs still surface unchanged.
fn install_broken_pipe_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied());
        if msg.is_some_and(is_broken_pipe_message) {
            process::exit(141);
        }
        default_hook(info);
    }));
}

/// Expand GNU-style `--key=value` long options into separate `--key` and `value`
/// tokens, so every subcommand's space-separated arg loop accepts both spellings
/// (`--dialect=postgresql` and `--dialect postgresql`). Splits at the first `=`
/// only; short options and plain values (e.g. `--var KEY=VALUE`'s `KEY=VALUE`,
/// which does not start with `--`) are untouched. A bare `--` ends option
/// processing — following tokens pass through verbatim — preserving
/// end-of-options semantics.
fn expand_long_opt_eq(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut end_of_opts = false;
    for arg in args {
        if !end_of_opts && arg == "--" {
            end_of_opts = true;
            out.push(arg);
            continue;
        }
        if !end_of_opts && arg.starts_with("--") {
            if let Some((key, value)) = arg.split_once('=') {
                out.push(key.to_string());
                out.push(value.to_string());
                continue;
            }
        }
        out.push(arg);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{expand_long_opt_eq, is_broken_pipe_message};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_stdout_and_stderr_broken_pipe_panics() {
        assert!(is_broken_pipe_message(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(is_broken_pipe_message(
            "failed printing to stderr: Broken pipe (os error 32)"
        ));
    }

    #[test]
    fn ignores_non_broken_pipe_output_errors() {
        // A real output failure must still surface as a panic, not a silent exit.
        assert!(!is_broken_pipe_message(
            "failed printing to stdout: No space left on device (os error 28)"
        ));
    }

    #[test]
    fn ignores_unrelated_panics() {
        assert!(!is_broken_pipe_message("index out of bounds"));
        assert!(!is_broken_pipe_message(""));
    }

    #[test]
    fn splits_long_opt_equals_into_two_tokens() {
        assert_eq!(
            expand_long_opt_eq(v(&["bin", "analyze", "--dialect=postgresql", "f.sql"])),
            v(&["bin", "analyze", "--dialect", "postgresql", "f.sql"])
        );
    }

    #[test]
    fn splits_only_at_first_equals() {
        assert_eq!(
            expand_long_opt_eq(v(&["bin", "analyze", "--var=KEY=VALUE"])),
            v(&["bin", "analyze", "--var", "KEY=VALUE"])
        );
    }

    #[test]
    fn leaves_space_form_and_value_tokens_untouched() {
        // `--var KEY=VALUE`: the value token does not start with `--`.
        assert_eq!(
            expand_long_opt_eq(v(&["bin", "analyze", "--var", "KEY=VALUE", "--stdin"])),
            v(&["bin", "analyze", "--var", "KEY=VALUE", "--stdin"])
        );
    }

    #[test]
    fn does_not_split_after_end_of_options() {
        assert_eq!(
            expand_long_opt_eq(v(&["bin", "catalog", "--", "--weird=name.sql"])),
            v(&["bin", "catalog", "--", "--weird=name.sql"])
        );
    }

    #[test]
    fn leaves_short_opts_and_bare_long_flags_untouched() {
        assert_eq!(
            expand_long_opt_eq(v(&["bin", "analyze", "-r", "--stdin", "--version"])),
            v(&["bin", "analyze", "-r", "--stdin", "--version"])
        );
    }
}
