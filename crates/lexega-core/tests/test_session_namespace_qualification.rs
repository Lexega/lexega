// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! In-script `USE DATABASE` / `USE SCHEMA` sets the default namespace
//! that later *bare* table references resolve under, folded per
//! statement position (the same `ScriptContextFold` that tracks the
//! active role).
//!
//! The observable is `DML-WRITE-XSCHEMA`, which fires only when a write
//! and a read span two distinct schemas. The same `INSERT ... FROM s`
//! (bare `s`) flips between firing and silent purely by the preceding
//! `USE SCHEMA` target — isolating the qualification effect.

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

const XSCHEMA: &str = "DML-WRITE-XSCHEMA";

fn rule_ids(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    report
        .signals
        .iter()
        .filter_map(|m| match m {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

#[test]
fn use_schema_qualifies_bare_read_into_cross_schema() {
    // `USE SCHEMA core` qualifies the bare `s` to core.s; the write
    // target sandbox.t is a different schema → cross-schema fires.
    let ids = rule_ids("USE SCHEMA core;\nINSERT INTO sandbox.t (a) SELECT a FROM s;");
    assert!(
        ids.contains(XSCHEMA),
        "expected cross-schema fire; ids={:?}",
        ids
    );
}

#[test]
fn use_schema_qualifies_bare_read_into_same_schema() {
    // Same INSERT, but `USE SCHEMA sandbox` qualifies `s` to sandbox.s —
    // identical schema to the write → silent. Only the USE SCHEMA target
    // differs from the firing case, isolating the qualification.
    let ids = rule_ids("USE SCHEMA sandbox;\nINSERT INTO sandbox.t (a) SELECT a FROM s;");
    assert!(
        !ids.contains(XSCHEMA),
        "expected silence under same-schema qualification; ids={:?}",
        ids
    );
}

#[test]
fn use_database_and_schema_compose_for_qualification() {
    // `USE DATABASE d1; USE SCHEMA core` — the db side fills both refs and
    // the schema side qualifies the bare `s` to core; the write sandbox.t
    // is a different schema → cross-schema fires. Exercises the db + schema
    // timeline composing through one fold.
    let ids =
        rule_ids("USE DATABASE d1;\nUSE SCHEMA core;\nINSERT INTO sandbox.t (a) SELECT a FROM s;");
    assert!(
        ids.contains(XSCHEMA),
        "expected cross-schema fire; ids={:?}",
        ids
    );
}
