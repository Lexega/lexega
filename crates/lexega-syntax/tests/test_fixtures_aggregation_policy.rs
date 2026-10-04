// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for AGGREGATION POLICY statements.
//!
//! Tests cover:
//! - CREATE AGGREGATION POLICY with various body expressions
//! - ALTER AGGREGATION POLICY (RENAME TO, SET BODY, SET/UNSET TAG, SET/UNSET COMMENT)
//! - DROP AGGREGATION POLICY

use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};
use std::fs;

#[test]
fn test_aggregation_policy() {
    let sql = fs::read_to_string("tests/fixtures/test_aggregation_policy.sql")
        .expect("failed to read test_aggregation_policy.sql");

    let parsed = parse_sql(&sql);
    assert!(
        parsed.is_ok(),
        "test_aggregation_policy.sql should parse successfully: {:?}",
        parsed.err()
    );

    let formatted = format_sql_with_config(&sql, &FormatterConfig::default())
        .expect("test_aggregation_policy.sql should format successfully");

    verify_formatting_safe(&sql, &formatted)
        .expect("test_aggregation_policy.sql formatting should be safe");
}
