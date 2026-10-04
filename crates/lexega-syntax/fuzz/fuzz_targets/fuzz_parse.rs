// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fuzz target: Parser
//!
//! Ensures `try_parse_script_from_str()` never panics on arbitrary input.
//! The parser may return `Err(ParseError)`, but must never crash.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Parser must gracefully handle any input — return Ok or Err, never panic.
    let _ = lexega_syntax::try_parse_script_from_str(data);
});
