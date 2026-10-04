// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake TAG lifecycle statements.
//!
//! Covers parsing/formatting round-trips for CREATE / ALTER / DROP /
//! UNDROP TAG and the SNW-TAG-* / INFO-SNW-TAG-* governance rules,
//! including the tag-based masking association (`ALTER TAG … SET/UNSET
//! MASKING POLICY`).

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

// ───────────────────────── formatting ─────────────────────────

#[test]
fn test_create_tag_basic() {
    assert_formats_safe("CREATE TAG cost_center;");
}

#[test]
fn test_create_tag_all_variants() {
    assert_formats_safe(
        "CREATE OR REPLACE TAG cost_center;\n\
         CREATE TAG IF NOT EXISTS db1.sch1.cost_center;\n\
         CREATE TAG \"My Tag\" ALLOWED_VALUES 'finance', 'engineering', '';\n\
         CREATE TAG sch1.pii_level ALLOWED_VALUES 'low', 'high' COMMENT = 'sensitivity tier';\n\
         CREATE TAG t_prop PROPAGATE = ON_DEPENDENCY_AND_DATA_MOVEMENT COMMENT = 'lineage tag';\n\
         CREATE TAG t_prop2 ALLOWED_VALUES 'a', 'b' PROPAGATE = ON_DATA_MOVEMENT ON_CONFLICT = ALLOWED_VALUES_SEQUENCE;\n\
         CREATE TAG t_prop3 PROPAGATE = ON_DEPENDENCY ON_CONFLICT = 'pick_first';",
    );
}

#[test]
fn test_alter_tag_all_variants() {
    assert_formats_safe(
        "ALTER TAG cost_center RENAME TO cc_tag;\n\
         ALTER TAG IF EXISTS db1.sch1.cost_center RENAME TO db1.sch1.cc_tag;\n\
         ALTER TAG cost_center ADD ALLOWED_VALUES 'sales', 'hr';\n\
         ALTER TAG cost_center DROP ALLOWED_VALUES 'hr';\n\
         ALTER TAG cost_center SET ALLOWED_VALUES 'x', 'y' PROPAGATE = ON_DEPENDENCY COMMENT = 'updated';\n\
         ALTER TAG cost_center SET COMMENT = 'only comment';\n\
         ALTER TAG cost_center UNSET ALLOWED_VALUES;\n\
         ALTER TAG cost_center UNSET PROPAGATE;\n\
         ALTER TAG cost_center UNSET ON_CONFLICT;\n\
         ALTER TAG IF EXISTS cost_center UNSET COMMENT;\n\
         ALTER TAG proj_tag UNSET DCM PROJECT;",
    );
}

#[test]
fn test_alter_tag_masking_policy_variants() {
    assert_formats_safe(
        "ALTER TAG sch1.pii_level SET MASKING POLICY mask_str;\n\
         ALTER TAG sch1.pii_level SET MASKING POLICY db1.sch1.mask_str, MASKING POLICY mask_num FORCE;\n\
         ALTER TAG sch1.pii_level UNSET MASKING POLICY mask_str;\n\
         ALTER TAG sch1.pii_level UNSET MASKING POLICY mask_str, MASKING POLICY mask_num;",
    );
}

#[test]
fn test_drop_undrop_tag() {
    assert_formats_safe(
        "DROP TAG cost_center;\n\
         DROP TAG IF EXISTS db1.sch1.cost_center;\n\
         UNDROP TAG cost_center;",
    );
}

#[test]
fn test_tag_multi_statement() {
    assert_formats_safe(
        "CREATE TAG t1;\n\
         CREATE TAG t2;\n\
         CREATE TAG t3;",
    );
}

// ───────────────────────── governance rules ─────────────────────────

#[test]
fn test_create_tag_info_signal() {
    let rules = analyze_and_get_rules("CREATE TAG pii_level ALLOWED_VALUES 'low', 'high';");
    assert!(
        rules.contains("INFO-SNW-TAG-CREATE"),
        "CREATE TAG should fire INFO-SNW-TAG-CREATE, got {rules:?}"
    );
}

#[test]
fn test_tag_masking_policy_attach() {
    let rules = analyze_and_get_rules("ALTER TAG pii_level SET MASKING POLICY mp_str;");
    assert!(
        rules.contains("SNW-TAG-MASK-ADD"),
        "SET MASKING POLICY on tag should fire SNW-TAG-MASK-ADD, got {rules:?}"
    );
    assert!(
        !rules.contains("SNW-TAG-MASK-FORCE"),
        "no FORCE present, got {rules:?}"
    );
}

#[test]
fn test_tag_masking_policy_force() {
    let rules = analyze_and_get_rules(
        "ALTER TAG pii_level SET MASKING POLICY db1.sch1.mp_str, MASKING POLICY mp_num FORCE;",
    );
    assert!(rules.contains("SNW-TAG-MASK-ADD"), "got {rules:?}");
    assert!(
        rules.contains("SNW-TAG-MASK-FORCE"),
        "FORCE replacement should fire SNW-TAG-MASK-FORCE, got {rules:?}"
    );
}

#[test]
fn test_tag_masking_policy_detach_critical() {
    let report = analyze_risk("ALTER TAG pii_level UNSET MASKING POLICY mp_str;")
        .expect("should analyze successfully");
    let rules = extract_rule_ids(&report.signals);
    assert!(
        rules.contains("SNW-TAG-MASK-RMV"),
        "UNSET MASKING POLICY on tag should fire SNW-TAG-MASK-RMV, got {rules:?}"
    );
    assert!(
        report.summary.critical_count >= 1,
        "tag-level unmasking should be critical"
    );
}

#[test]
fn test_tag_allowed_values_loosening() {
    let rules = analyze_and_get_rules("ALTER TAG cost_center DROP ALLOWED_VALUES 'hr';");
    assert!(rules.contains("SNW-TAG-ALLOWED-RMV"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER TAG cost_center UNSET ALLOWED_VALUES;");
    assert!(rules.contains("SNW-TAG-ALLOWED-UNSET"), "got {rules:?}");
}

#[test]
fn test_tag_rename_and_propagate() {
    let rules = analyze_and_get_rules("ALTER TAG cost_center RENAME TO cc;");
    assert!(rules.contains("SNW-TAG-RENAME"), "got {rules:?}");

    let rules = analyze_and_get_rules("ALTER TAG cost_center UNSET PROPAGATE;");
    assert!(rules.contains("SNW-TAG-PROPAGATE-OFF"), "got {rules:?}");
}

#[test]
fn test_drop_tag_high() {
    let rules = analyze_and_get_rules("DROP TAG IF EXISTS db1.sch1.pii_level;");
    assert!(
        rules.contains("SNW-TAG-DROP"),
        "DROP TAG should fire SNW-TAG-DROP, got {rules:?}"
    );
}

#[test]
fn test_undrop_tag_info() {
    let rules = analyze_and_get_rules("UNDROP TAG pii_level;");
    assert!(
        rules.contains("INFO-SNW-TAG-UNDROP"),
        "UNDROP TAG should fire INFO-SNW-TAG-UNDROP, got {rules:?}"
    );
}

// ───────────────────────── negative cases ─────────────────────────

#[test]
fn test_tag_attachment_does_not_fire_lifecycle_rules() {
    // SET TAG on another object is an attachment, not tag lifecycle.
    let rules = analyze_and_get_rules("ALTER TABLE t1 SET TAG cost_center = 'finance';");
    assert!(
        !rules.contains("SNW-TAG-MASK-RMV") && !rules.contains("SNW-TAG-DROP"),
        "tag attachment must not fire tag lifecycle rules, got {rules:?}"
    );
}

#[test]
fn test_alter_tag_set_comment_only_fires_nothing_destructive() {
    let rules = analyze_and_get_rules("ALTER TAG cost_center SET COMMENT = 'docs';");
    assert!(
        !rules.contains("SNW-TAG-MASK-RMV")
            && !rules.contains("SNW-TAG-ALLOWED-UNSET")
            && !rules.contains("SNW-TAG-DROP"),
        "comment-only change must not fire destructive rules, got {rules:?}"
    );
}

#[test]
fn test_drop_table_does_not_fire_tag_drop() {
    let rules = analyze_and_get_rules("DROP TABLE t1;");
    assert!(
        !rules.contains("SNW-TAG-DROP"),
        "DROP TABLE must not fire SNW-TAG-DROP, got {rules:?}"
    );
}
