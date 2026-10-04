// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `EXECUTE IMMEDIATE FROM <file>` recognition and the
//! SNW-EXECIMM-FROM-STAGE rule. The statement executes SQL loaded from a
//! stage file (an external/file-based code-execution surface). Recognition
//! emits the location kind + whether it executes (`DRY_RUN`); the danger
//! verdict is the YAML rule, gated on `executes: true` — so DRY_RUN = TRUE
//! reverses the finding without a recompile.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .signals
            .iter()
            .filter_map(|f| match f {
                RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
            })
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

fn skipped(sql: &str) -> usize {
    analyze_risk(sql)
        .expect("should analyze")
        .summary
        .statements_skipped
}

// ── Recognition / coverage ──────────────────────────────────────────────

#[test]
fn stage_path_is_analyzed_not_opaque() {
    // Statement reaches the analyzer (not OpaqueContent / Unrecognized).
    assert_eq!(
        skipped("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;"),
        0
    );
}

#[test]
fn namespace_qualified_stage_path_is_analyzed() {
    assert_eq!(
        skipped("EXECUTE IMMEDIATE FROM @db.sch.my_stage/path/file.sql;"),
        0
    );
}

// ── SNW-EXECIMM-FROM-STAGE rule ─────────────────────────────────────────

#[test]
fn stage_path_executes_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;");
    assert!(
        rules.contains("SNW-EXECIMM-FROM-STAGE"),
        "stage-file execution should flag — if absent, parser may have produced OpaqueContent"
    );
}

#[test]
fn namespace_qualified_stage_path_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @db.sch.my_stage/path/file.sql;");
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn stage_path_with_using_flags() {
    let rules = analyze_and_get_rules(
        "EXECUTE IMMEDIATE FROM @my_stage/file.sql USING (env => 'prod', n => 42);",
    );
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn dry_run_false_still_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/file.sql DRY_RUN = FALSE;");
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

// ── Policy-as-data: the `executes` gate reverses the finding ─────────────

#[test]
fn dry_run_true_does_not_flag() {
    // DRY_RUN = TRUE renders the template without executing — recognition
    // sets executes:false, so the rule (gated on executes:true) must not fire.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/file.sql DRY_RUN = TRUE;");
    assert!(
        !rules.contains("SNW-EXECIMM-FROM-STAGE"),
        "DRY_RUN = TRUE must suppress the execution finding"
    );
}

#[test]
fn relative_path_does_not_flag_stage_rule() {
    // The stage rule is scoped to stage paths; a quoted relative path is a
    // different location kind.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM './scripts/file.sql';");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn dollar_quoted_relative_path_does_not_flag_stage_rule() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM $$./scripts/file.sql$$;");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn inline_execute_immediate_does_not_flag_stage_rule() {
    // The inline string surface is a different statement; the stage rule
    // must not fire on it.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE 'SELECT 1';");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

// ── Formatting: byte-exact round-trip ───────────────────────────────────

fn assert_format_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn format_stage_path() {
    assert_format_safe("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;");
}

#[test]
fn format_all_clauses() {
    assert_format_safe(
        "EXECUTE IMMEDIATE FROM @my_stage/file.sql USING (env => 'prod') DRY_RUN = TRUE;",
    );
}

#[test]
fn format_relative_path() {
    assert_format_safe("EXECUTE IMMEDIATE FROM '../up/file.sql';");
}

#[test]
fn format_multi_statement() {
    // Catches NodeId-collision / span bugs across repeated statements.
    assert_format_safe(
        "EXECUTE IMMEDIATE FROM @s1/a.sql;\nEXECUTE IMMEDIATE FROM @s2/b.sql DRY_RUN = TRUE;\n",
    );
}
