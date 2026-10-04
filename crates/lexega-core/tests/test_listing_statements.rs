// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the Snowflake `CREATE / ALTER / DROP LISTING` family (Marketplace /
//! data-exchange exposure). Covers the SNW-LISTING-* rules, the EXTERNAL /
//! PUBLISH recognition primitives, that the `AS <manifest>` `$$` body is
//! consumed (not fragmented), the EXTERNAL-dispatch regression (EXTERNAL TABLE /
//! VOLUME unaffected), and byte-exact formatting.

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
fn test_create_listing_fires_new() {
    let rules = analyze_and_get_rules("CREATE LISTING lst SHARE s AS 'manifest';");
    assert!(rules.contains("INFO-SNW-LISTING-NEW"), "got {rules:?}");
}

#[test]
fn test_external_discriminates() {
    let ext = analyze_and_get_rules("CREATE EXTERNAL LISTING lst SHARE s AS 'manifest';");
    assert!(ext.contains("SNW-LISTING-EXTERNAL"), "got {ext:?}");
    let int = analyze_and_get_rules("CREATE LISTING lst SHARE s AS 'manifest';");
    assert!(
        !int.contains("SNW-LISTING-EXTERNAL"),
        "internal listing must not fire EXTERNAL, got {int:?}"
    );
}

#[test]
fn test_publish_discriminates() {
    let on = analyze_and_get_rules("CREATE LISTING lst SHARE s AS 'm' PUBLISH = TRUE;");
    assert!(on.contains("SNW-LISTING-PUBLISH"), "got {on:?}");
    let off = analyze_and_get_rules("CREATE LISTING lst SHARE s AS 'm' PUBLISH = FALSE;");
    assert!(!off.contains("SNW-LISTING-PUBLISH"), "got {off:?}");
    // Fires on ALTER … SET too.
    let altered = analyze_and_get_rules("ALTER LISTING lst SET PUBLISH = TRUE;");
    assert!(altered.contains("SNW-LISTING-PUBLISH"), "got {altered:?}");
}

#[test]
fn test_external_table_volume_still_route_correctly() {
    // The EXTERNAL LISTING arm must not capture EXTERNAL TABLE / EXTERNAL
    // VOLUME.
    let table = parse_sql("CREATE EXTERNAL TABLE et (c int) LOCATION = '@s';").expect("parse");
    assert!(
        !matches!(table.stmts.first(), Some(AstStmt::CreateListing(_))),
        "EXTERNAL TABLE must not parse as CreateListing"
    );
    let volume = parse_sql("CREATE EXTERNAL VOLUME ev STORAGE_LOCATIONS = ();").expect("parse");
    assert!(
        !matches!(volume.stmts.first(), Some(AstStmt::CreateListing(_))),
        "EXTERNAL VOLUME must not parse as CreateListing"
    );
}

#[test]
fn test_dollar_manifest_not_fragmented() {
    // The $$ manifest body — which may contain a `;` — must be consumed as part
    // of the listing, not fragmented into standalone statements.
    let sql = "CREATE EXTERNAL LISTING l SHARE s AS $$ title: x; desc: y $$ PUBLISH = TRUE;";
    let script = parse_sql(sql).expect("parse");
    assert_eq!(
        script.stmts.len(),
        1,
        "the $$ manifest (with a ;) must not fragment, got {} stmts",
        script.stmts.len()
    );
    assert!(matches!(
        script.stmts.first(),
        Some(AstStmt::CreateListing(_))
    ));
}

#[test]
fn test_shared_object_and_external_extracted() {
    let sql = "CREATE EXTERNAL LISTING lst SHARE my_share AS 'm';";
    let script = parse_sql(sql).expect("parse");
    let AstStmt::CreateListing(l) = script.stmts.first().expect("one stmt") else {
        panic!("expected CreateListing");
    };
    assert!(l.is_external, "EXTERNAL keyword captured");
    let span = l.shared_object_span.expect("shared object captured");
    assert_eq!(slice(sql, span.start, span.end), "my_share");
}

#[test]
fn test_alter_other_fires_nothing() {
    let rules = analyze_and_get_rules("ALTER LISTING lst UNPUBLISH;");
    assert!(
        !rules.iter().any(|r| r.contains("LISTING")),
        "got {rules:?}"
    );
    // An ALTER … AS $$ manifest update must also not fragment.
    let script = parse_sql("ALTER LISTING lst AS $$ title: z; q: 1 $$;").expect("parse");
    assert_eq!(script.stmts.len(), 1, "alter manifest must not fragment");
}

#[test]
fn test_drop_listing_analyzes() {
    assert!(analyze_risk("DROP LISTING lst;").is_ok());
}

#[test]
fn test_forms_format_safe() {
    assert_formats_safe("CREATE EXTERNAL LISTING lst SHARE my_share AS $$ title: My Data; desc: x $$ PUBLISH = TRUE COMMENT = 'c';");
    assert_formats_safe(
        "CREATE LISTING lst2 APPLICATION PACKAGE pkg AS 'manifest' REVIEW = FALSE;",
    );
    assert_formats_safe("ALTER LISTING lst SET PUBLISH = FALSE;");
    assert_formats_safe("ALTER LISTING IF EXISTS lst UNPUBLISH;");
    assert_formats_safe("DROP LISTING lst;");
}
