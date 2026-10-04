// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fuzz target: Formatter
//!
//! Ensures `format_sql_with_config()` never panics on arbitrary input.
//! The formatter may return `Err(ParseError)`, but must never crash.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lexega_syntax::FormatterConfig;

fuzz_target!(|data: &str| {
    // Formatter must handle arbitrary input without panicking.
    let _ = lexega_syntax::format_sql_with_config(data, &FormatterConfig::default());
});
