// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! A row-selecting predicate that keeps every row leaves a write
//! unbounded, however the predicate is spelled.

use std::collections::BTreeSet;

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;

fn rule_ids(sql: &str) -> BTreeSet<String> {
    let report = analyze_risk(sql).expect("analysis succeeds");
    report
        .signals
        .iter()
        .map(|signal| {
            let RuleMatch::Analysis(analysis) = signal;
            analysis.matched_rule.clone()
        })
        .collect()
}

#[test]
fn a_constant_comparison_leaves_a_delete_unbounded() {
    let ids = rule_ids("DELETE FROM orders WHERE 1 = 1;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_true_literal_leaves_an_update_unbounded() {
    let ids = rule_ids("UPDATE orders SET status = 'x' WHERE TRUE;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_disjunction_covering_null_and_non_null_is_every_row() {
    let ids = rule_ids("DELETE FROM orders WHERE batch_id IS NULL OR batch_id IS NOT NULL;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn merge_on_true_is_an_unbounded_write() {
    let ids = rule_ids("MERGE INTO orders t USING staging s ON TRUE WHEN MATCHED THEN DELETE;");
    assert!(ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
    assert!(!ids.contains("DML-MERGE-DELETE"), "{ids:?}");
}

#[test]
fn a_real_filter_stays_bounded() {
    let ids = rule_ids("DELETE FROM orders WHERE region = 'EU';");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn is_not_null_alone_is_not_every_row() {
    // Rows where the column is NULL survive unless it is proven non-null.
    let ids = rule_ids("DELETE FROM orders WHERE deleted_at IS NOT NULL;");
    assert!(!ids.contains("DML-WRITE-UNBOUNDED"), "{ids:?}");
}

#[test]
fn a_predicate_on_the_current_date_is_reported() {
    let ids = rule_ids("SELECT id FROM orders WHERE created_at > CURRENT_DATE;");
    assert!(ids.contains("INFO-Q-PRED-TEMPORAL"), "{ids:?}");
}
