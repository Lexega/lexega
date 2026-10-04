// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake Native Apps families: `CREATE / ALTER / DROP
//! APPLICATION` and `… APPLICATION PACKAGE`. Covers the SNW-APP-* / SNW-APPPKG-*
//! rules, the install-source provenance + DEBUG_MODE / DISTRIBUTION recognition
//! primitives, the APPLICATION-ROLE (T-SQL principal) dispatch regression, and
//! byte-exact formatting.

use lexega_core::api::analyze_risk;
use lexega_core::ast::AstStmt;
use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig,
};
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

fn slice(sql: &str, start: u32, end: u32) -> &str {
    &sql[start as usize..end as usize]
}

#[test]
fn test_create_application_fires_new() {
    let rules = analyze_and_get_rules("CREATE APPLICATION app FROM APPLICATION PACKAGE pkg;");
    assert!(rules.contains("INFO-SNW-APP-NEW"), "got {rules:?}");
}

#[test]
fn test_create_application_package_fires_new() {
    let rules = analyze_and_get_rules("CREATE APPLICATION PACKAGE pkg COMMENT = 'p';");
    assert!(rules.contains("INFO-SNW-APPPKG-NEW"), "got {rules:?}");
}

#[test]
fn test_from_listing_discriminates() {
    let listing = analyze_and_get_rules("CREATE APPLICATION app FROM LISTING lst;");
    assert!(listing.contains("SNW-APP-FROM-LISTING"), "got {listing:?}");
    let package = analyze_and_get_rules("CREATE APPLICATION app FROM APPLICATION PACKAGE pkg;");
    assert!(
        !package.contains("SNW-APP-FROM-LISTING"),
        "package install must not fire FROM-LISTING, got {package:?}"
    );
}

#[test]
fn test_debug_mode_discriminates() {
    let on = analyze_and_get_rules(
        "CREATE APPLICATION app FROM APPLICATION PACKAGE pkg DEBUG_MODE = TRUE;",
    );
    assert!(on.contains("SNW-APP-DEBUG-MODE"), "got {on:?}");
    let off = analyze_and_get_rules(
        "CREATE APPLICATION app FROM APPLICATION PACKAGE pkg DEBUG_MODE = FALSE;",
    );
    assert!(!off.contains("SNW-APP-DEBUG-MODE"), "got {off:?}");
    // Fires on ALTER … SET too.
    let altered = analyze_and_get_rules("ALTER APPLICATION app SET DEBUG_MODE = TRUE;");
    assert!(altered.contains("SNW-APP-DEBUG-MODE"), "got {altered:?}");
}

#[test]
fn test_distribution_external_discriminates() {
    let ext = analyze_and_get_rules("CREATE APPLICATION PACKAGE pkg DISTRIBUTION = EXTERNAL;");
    assert!(
        ext.contains("SNW-APPPKG-DISTRIBUTION-EXTERNAL"),
        "got {ext:?}"
    );
    let int = analyze_and_get_rules("CREATE APPLICATION PACKAGE pkg DISTRIBUTION = INTERNAL;");
    assert!(
        !int.contains("SNW-APPPKG-DISTRIBUTION-EXTERNAL"),
        "got {int:?}"
    );
    // Fires on ALTER … SET too.
    let altered =
        analyze_and_get_rules("ALTER APPLICATION PACKAGE pkg SET DISTRIBUTION = EXTERNAL;");
    assert!(
        altered.contains("SNW-APPPKG-DISTRIBUTION-EXTERNAL"),
        "got {altered:?}"
    );
}

#[test]
fn test_application_role_still_routes_to_principal() {
    // The APPLICATION dispatch must not capture the CREATE/ALTER APPLICATION
    // ROLE (T-SQL principal) forms.
    let create = parse_sql("CREATE APPLICATION ROLE ar;").expect("parse");
    assert!(
        !matches!(create.stmts.first(), Some(AstStmt::CreateApplication(_))),
        "CREATE APPLICATION ROLE must not parse as CreateApplication"
    );
    let alter = parse_sql("ALTER APPLICATION ROLE ar RENAME TO ar2;").expect("parse");
    assert!(
        !matches!(alter.stmts.first(), Some(AstStmt::AlterApplication(_))),
        "ALTER APPLICATION ROLE must not parse as AlterApplication"
    );
}

#[test]
fn test_source_provenance_extracted() {
    let pkg_sql = "CREATE APPLICATION app FROM APPLICATION PACKAGE my.pkg;";
    let script = parse_sql(pkg_sql).expect("parse");
    let AstStmt::CreateApplication(a) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateApplication");
    };
    assert!(!a.from_listing, "package install is not from a listing");
    let span = a.source_name_span.expect("source name captured");
    assert_eq!(slice(pkg_sql, span.start, span.end), "my.pkg");

    let lst_sql = "CREATE APPLICATION app FROM LISTING mylst;";
    let script = parse_sql(lst_sql).expect("parse");
    let AstStmt::CreateApplication(a) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateApplication");
    };
    assert!(a.from_listing, "listing install");
    let span = a.source_name_span.expect("source name captured");
    assert_eq!(slice(lst_sql, span.start, span.end), "mylst");
}

#[test]
fn test_alter_upgrade_other_fires_nothing() {
    // UPGRADE is recognized (Other) and consumed — not fragmented, fires no
    // APP rules.
    let rules = analyze_and_get_rules("ALTER APPLICATION app UPGRADE;");
    assert!(!rules.iter().any(|r| r.contains("APP")), "got {rules:?}");
    let report = analyze_risk("ALTER APPLICATION PACKAGE pkg ADD VERSION v1 USING '@s';")
        .expect("should analyze");
    let _ = report;
}

#[test]
fn test_drop_both_analyze() {
    assert!(analyze_risk("DROP APPLICATION app;").is_ok());
    assert!(analyze_risk("DROP APPLICATION PACKAGE pkg;").is_ok());
}

#[test]
fn test_forms_format_safe() {
    assert_formats_safe(
        "CREATE APPLICATION app FROM APPLICATION PACKAGE pkg USING '@stage/v1' DEBUG_MODE = TRUE COMMENT = 'a';",
    );
    assert_formats_safe("CREATE APPLICATION app2 FROM LISTING lst;");
    assert_formats_safe("CREATE APPLICATION PACKAGE pkg COMMENT = 'p' DISTRIBUTION = EXTERNAL;");
    assert_formats_safe("ALTER APPLICATION app SET DEBUG_MODE = FALSE;");
    assert_formats_safe("ALTER APPLICATION IF EXISTS app UPGRADE;");
    assert_formats_safe("ALTER APPLICATION PACKAGE pkg SET DISTRIBUTION = INTERNAL;");
    assert_formats_safe("DROP APPLICATION app;");
    assert_formats_safe("DROP APPLICATION PACKAGE pkg;");
}
