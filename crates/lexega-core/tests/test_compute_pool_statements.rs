// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP COMPUTE POOL` statement
//! family (Snowpark Container Services capacity): property-bag parsing into
//! `ddl.compute_pool` facts, the SNW-CMPPOOL-* rules, the ALTER
//! SET/UNSET/SUSPEND/RESUME/STOP actions, and byte-exact formatting.

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

#[test]
fn test_create_gpu_compute_pool_fires_new_and_gpu() {
    let rules = analyze_and_get_rules(
        "CREATE COMPUTE POOL p MIN_NODES=1 MAX_NODES=5 INSTANCE_FAMILY=GPU_NV_S AUTO_RESUME=TRUE;",
    );
    assert!(rules.contains("SNW-CMPPOOL-NEW"), "got {rules:?}");
    assert!(rules.contains("SNW-CMPPOOL-GPU"), "got {rules:?}");
}

#[test]
fn test_create_cpu_compute_pool_fires_new_only() {
    // CPU instance family: recognition fires, the GPU cost rule does not —
    // the verdict is YAML data keyed on the instance-family value.
    let rules = analyze_and_get_rules(
        "CREATE COMPUTE POOL p MIN_NODES=1 MAX_NODES=2 INSTANCE_FAMILY=CPU_X64_S;",
    );
    assert!(rules.contains("SNW-CMPPOOL-NEW"), "got {rules:?}");
    assert!(!rules.contains("SNW-CMPPOOL-GPU"), "got {rules:?}");
}

#[test]
fn test_alter_set_gpu_fires_gpu_rule() {
    let rules = analyze_and_get_rules("ALTER COMPUTE POOL p SET INSTANCE_FAMILY=GPU_NV_M;");
    assert!(rules.contains("SNW-CMPPOOL-GPU"), "got {rules:?}");
}

#[test]
fn test_alter_lifecycle_actions_parse_without_findings() {
    // SUSPEND / RESUME / STOP ALL are operational; they parse (not opaque)
    // and raise no compute-pool cost finding.
    for sql in [
        "ALTER COMPUTE POOL p SUSPEND;",
        "ALTER COMPUTE POOL p RESUME;",
        "ALTER COMPUTE POOL p STOP ALL;",
    ] {
        let rules = analyze_and_get_rules(sql);
        assert!(!rules.contains("SNW-CMPPOOL-GPU"), "{sql}: got {rules:?}");
        assert!(!rules.contains("SNW-CMPPOOL-NEW"), "{sql}: got {rules:?}");
    }
}

#[test]
fn test_drop_compute_pool_analyzes() {
    // DROP COMPUTE POOL routes through the generic Drop gated on the
    // two-word object type; it must analyze cleanly.
    let report = analyze_risk("DROP COMPUTE POOL p;").expect("should analyze");
    let _ = report;
}

#[test]
fn test_compute_pool_forms_format_safe() {
    assert_formats_safe(
        "CREATE COMPUTE POOL p MIN_NODES=1 MAX_NODES=5 INSTANCE_FAMILY=GPU_NV_S AUTO_RESUME=TRUE;",
    );
    assert_formats_safe("ALTER COMPUTE POOL p SET MAX_NODES=10;");
    assert_formats_safe("ALTER COMPUTE POOL p STOP ALL;");
    assert_formats_safe("DROP COMPUTE POOL p;");
}
