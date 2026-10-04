// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{parser::parse_select_from_tokens, tokenize};

fn main() {
    // Valid: NULLS FIRST
    let sql1 = "SELECT * FROM t ORDER BY col NULLS FIRST";
    let tokens1 = tokenize(sql1);
    let result1 = parse_select_from_tokens(sql1, &tokens1.tokens);
    println!(
        "Test 1 - NULLS FIRST: {}",
        if result1.is_some() { "PASS" } else { "FAIL" }
    );

    // Valid: NULLS LAST
    let sql2 = "SELECT * FROM t ORDER BY col NULLS LAST";
    let tokens2 = tokenize(sql2);
    let result2 = parse_select_from_tokens(sql2, &tokens2.tokens);
    println!(
        "Test 2 - NULLS LAST: {}",
        if result2.is_some() { "PASS" } else { "FAIL" }
    );

    // Invalid: NULLS GARBAGE (should fail now)
    let sql3 = "SELECT * FROM t ORDER BY col NULLS GARBAGE";
    let tokens3 = tokenize(sql3);
    let result3 = parse_select_from_tokens(sql3, &tokens3.tokens);
    println!(
        "Test 3 - NULLS GARBAGE: {}",
        if result3.is_none() {
            "PASS (correctly rejected)"
        } else {
            "FAIL (should have rejected)"
        }
    );
}
