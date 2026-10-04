// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `review` command: `analyze` scoped to the SQL files a commit range
//! changes, read at the range's head, with an optional pull-request
//! comment.

use std::process;

use super::cmd_analyze::{run, Scope};
use super::extension::Extension;
use super::usage::print_review_usage;

pub fn handle_review_command(args: &[String], ext: &dyn Extension) {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_review_usage(&args[0]);
        return;
    }
    let Some(range) = args.get(2) else {
        print_review_usage(&args[0]);
        process::exit(1);
    };
    let Some((base, head)) = range.split_once("..") else {
        eprintln!("Error: commit range must be in format 'base..head' (e.g., main..HEAD)");
        process::exit(1);
    };
    run(
        args,
        ext,
        Scope::Change {
            base: base.to_string(),
            head: head.to_string(),
        },
    );
}
