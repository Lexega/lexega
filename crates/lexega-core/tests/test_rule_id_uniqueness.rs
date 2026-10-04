// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Regression test: ensures no two built-in rules share the same ID.
//!
//! Duplicate rule IDs cause one rule to silently shadow the other, producing
//! incorrect risk analysis results. `load_v1_rules` rejects duplicates with
//! `LoadError::DuplicateRuleId`, so a successful load of the built-in corpus
//! is sufficient to certify uniqueness.

#[test]
fn builtin_rules_have_unique_ids() {
    let _rules = lexega_core::rules::all_builtin_rules().expect("built-in corpus loads");
    // If we reached this point, `load_v1_rules` accepted the corpus without
    // tripping `LoadError::DuplicateRuleId`.
}
