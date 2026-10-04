// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Golden and gap-inventory harness for T-SQL governance statements: the
//! golden fixture must parse fully typed (0 opaque), and the KNOWN_GAPS list
//! names the governance constructs that fall to `OpaqueContent`.

use lexega_syntax::{parse_sql_with_dialect, AstStmt, MsSqlDialect};

const GOLDEN: &str = include_str!("fixtures/mssql_governance_golden.sql");

fn opaque_snippets(sql: &str) -> Vec<String> {
    let script = parse_sql_with_dialect(sql, &MsSqlDialect).expect("parse");
    script
        .stmts
        .iter()
        .filter_map(|stmt| {
            if let AstStmt::OpaqueContent { span, .. } = stmt {
                let snippet = sql
                    .get(span.start as usize..span.end as usize)
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                Some(format!("byte {}: {snippet}", span.start))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn governance_golden_has_zero_opaque_statements() {
    let opaque = opaque_snippets(GOLDEN);
    assert!(
        opaque.is_empty(),
        "governance golden fixture must parse fully typed; opaque statements:\n{}",
        opaque.join("\n")
    );
}

/// Governance-relevant T-SQL constructs that still fall to
/// `OpaqueContent` (or partially do). One entry per construct family.
/// When you implement one, move its SQL into the golden fixture and
/// remove the entry here — the assertion below forces the bookkeeping.
const KNOWN_GAPS: &[(&str, &str)] = &[
    ("save transaction", "SAVE TRANSACTION before_purge;"),
    (
        "partition function",
        "CREATE PARTITION FUNCTION pf_year (DATE) AS RANGE RIGHT FOR VALUES ('2024-01-01');",
    ),
];

#[test]
fn governance_known_gap_inventory() {
    let mut still_opaque = Vec::new();
    let mut now_typed = Vec::new();
    for (label, sql) in KNOWN_GAPS {
        let opaque = opaque_snippets(sql);
        if opaque.is_empty() {
            now_typed.push(*label);
        } else {
            still_opaque.push(*label);
        }
    }
    assert!(
        now_typed.is_empty(),
        "constructs no longer opaque — move them into the golden fixture \
         and remove from KNOWN_GAPS: {now_typed:?} (still opaque: {still_opaque:?})"
    );
    assert_eq!(
        still_opaque.len(),
        KNOWN_GAPS.len(),
        "gap inventory drifted: {still_opaque:?}"
    );
}
