// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fuzz target: Multi-dialect tokenization and parsing
//!
//! Tests that tokenization and parsing never panic across all supported dialects.
//! Uses the first byte of fuzzer input to select a dialect, then exercises
//! the remaining bytes as SQL source.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::parser::try_parse_script_with_dialect;
use lexega_syntax::dialect::{
    SnowflakeDialect, PostgresDialect, BigQueryDialect,
    MySqlDialect, MsSqlDialect, DatabricksDialect, Dialect,
};

/// Select a dialect based on a discriminant byte (0-5).
fn select_dialect(byte: u8) -> &'static dyn Dialect {
    match byte % 6 {
        0 => &SnowflakeDialect,
        1 => &PostgresDialect,
        2 => &BigQueryDialect,
        3 => &MySqlDialect,
        4 => &MsSqlDialect,
        5 => &DatabricksDialect,
        _ => unreachable!(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte for dialect selection + 1 byte for SQL
    if data.len() < 2 {
        return;
    }

    let dialect = select_dialect(data[0]);
    let sql = match std::str::from_utf8(&data[1..]) {
        Ok(s) => s,
        Err(_) => return, // Skip non-UTF8 input
    };

    // Tokenize with the selected dialect — must not panic
    let lex_result = tokenize_with_dialect(sql, dialect);

    // Parse with the selected dialect — must not panic
    let _ = try_parse_script_with_dialect(sql, &lex_result.tokens, dialect);
});
