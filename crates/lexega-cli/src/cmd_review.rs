// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `review` command: `analyze` scoped to the SQL files a commit range
//! changes, read at the range's head, with an optional pull-request
//! comment.

use std::process;

use super::cmd_analyze::{run, Scope};
use super::extension::Extension;
use super::git::CommitRange;
use super::usage::print_review_usage;

pub fn handle_review_command(args: &[String], ext: &dyn Extension) {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_review_usage(&args[0], ext);
        return;
    }
    let Some(range) = args.get(2) else {
        print_review_usage(&args[0], ext);
        process::exit(1);
    };
    let range = CommitRange::resolve(range).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        process::exit(1);
    });
    run(args, ext, Scope::Change(range));
}
