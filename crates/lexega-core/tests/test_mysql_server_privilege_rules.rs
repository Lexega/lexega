// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL server-wide privileges (`SUPER`, `FILE`, `PROCESS`) and the
//! `LOAD_FILE()` server-file read. The grant rules read the privilege
//! names of `privilege.privileges`; the function rule reads
//! `query.function_calls`. Which names matter is YAML policy.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::mysql;

const GRANT_RULES: [&str; 3] = ["MYSQL-GRT-SUPER", "MYSQL-GRT-FILE", "MYSQL-GRT-PROCESS"];

/// Findings, then context entries.
fn analyze(sql: &str) -> Vec<(String, RiskLevel)> {
    let config = AnalysisConfig {
        dialect: Some(mysql()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analyze");
    report
        .entries()
        .map(|s| match s {
            RuleMatch::Analysis(g) => (g.matched_rule.clone(), g.risk_level),
        })
        .collect()
}

fn assert_fires_at(sql: &str, rule_id: &str, level: RiskLevel) {
    let findings = analyze(sql);
    assert!(
        findings.iter().any(|(id, l)| id == rule_id && *l == level),
        "{rule_id} should fire at {level:?} on: {sql}\nGot: {findings:?}"
    );
}

fn assert_silent(sql: &str, rule_id: &str) {
    let findings = analyze(sql);
    assert!(
        !findings.iter().any(|(id, _)| id == rule_id),
        "{rule_id} should not fire on: {sql}\nGot: {findings:?}"
    );
}

// ── Grants ──────────────────────────────────────────────────────────────────

#[test]
fn grant_super_fires_critical() {
    let sql = "GRANT SUPER ON *.* TO 'ops'@'localhost';";
    assert_fires_at(sql, "MYSQL-GRT-SUPER", RiskLevel::Critical);
    assert_silent(sql, "MYSQL-GRT-FILE");
    assert_silent(sql, "MYSQL-GRT-PROCESS");
}

#[test]
fn grant_file_fires_high() {
    let sql = "GRANT FILE ON *.* TO 'app'@'%';";
    assert_fires_at(sql, "MYSQL-GRT-FILE", RiskLevel::High);
    assert_silent(sql, "MYSQL-GRT-SUPER");
    assert_silent(sql, "MYSQL-GRT-PROCESS");
}

#[test]
fn grant_process_fires_medium() {
    let sql = "GRANT PROCESS ON *.* TO 'monitor'@'10.0.0.%';";
    assert_fires_at(sql, "MYSQL-GRT-PROCESS", RiskLevel::Medium);
    assert_silent(sql, "MYSQL-GRT-SUPER");
    assert_silent(sql, "MYSQL-GRT-FILE");
}

#[test]
fn each_privilege_of_a_list_fires_its_rule() {
    let sql = "GRANT SELECT, super, File, PROCESS ON *.* TO 'ops'@'localhost';";
    assert_fires_at(sql, "MYSQL-GRT-SUPER", RiskLevel::Critical);
    assert_fires_at(sql, "MYSQL-GRT-FILE", RiskLevel::High);
    assert_fires_at(sql, "MYSQL-GRT-PROCESS", RiskLevel::Medium);
}

#[test]
fn grant_to_a_role_fires() {
    assert_fires_at(
        "GRANT FILE ON *.* TO `etl_role`;",
        "MYSQL-GRT-FILE",
        RiskLevel::High,
    );
}

#[test]
fn other_grants_and_revokes_are_silent() {
    for sql in [
        "GRANT SELECT, INSERT ON shop.* TO 'app'@'%';",
        "GRANT EXECUTE ON PROCEDURE shop.process_order TO 'app'@'%';",
        "REVOKE SUPER, FILE, PROCESS ON *.* FROM 'ops'@'localhost';",
        // The words as object names, not privileges.
        "GRANT SELECT ON shop.file TO 'app'@'%';",
        "GRANT SELECT ON process.super TO 'app'@'%';",
    ] {
        for rule_id in GRANT_RULES {
            assert_silent(sql, rule_id);
        }
    }
}

// ── LOAD_FILE() ─────────────────────────────────────────────────────────────

#[test]
fn load_file_fires_high_wherever_it_is_called() {
    for sql in [
        "SELECT LOAD_FILE('/etc/passwd');",
        "SELECT load_file(@path) AS content;",
        "INSERT INTO docs (body) VALUES (LOAD_FILE('/var/lib/mysql-files/a.txt'));",
        "UPDATE docs SET body = LOAD_FILE('/var/lib/mysql-files/a.txt') WHERE id = 1;",
        "SELECT id FROM docs WHERE body = (SELECT LOAD_FILE('/var/lib/mysql-files/a.txt'));",
        "SELECT HEX(LOAD_FILE('/var/lib/mysql/mysql/user.MYD'));",
    ] {
        assert_fires_at(sql, "MYSQL-LOAD-FILE", RiskLevel::High);
    }
}

#[test]
fn load_file_as_a_name_or_text_is_silent() {
    for sql in [
        "SELECT load_file FROM imports;",
        "SELECT load_file_name FROM imports;",
        "SELECT 'LOAD_FILE(''/etc/passwd'')' AS note;",
        "SELECT LENGTH(body) FROM docs;",
    ] {
        assert_silent(sql, "MYSQL-LOAD-FILE");
    }
}
