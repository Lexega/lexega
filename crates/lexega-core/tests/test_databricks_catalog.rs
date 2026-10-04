// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE / ALTER / DROP CATALOG (Databricks Unity Catalog DDL).
//!
//! Covers:
//! - CREATE CATALOG with all clauses (COMMENT, MANAGED LOCATION, USING SHARE,
//!   USING CONNECTION, DEFAULT COLLATION, OPTIONS, IF NOT EXISTS, FOREIGN)
//! - ALTER CATALOG actions (OWNER TO, SET/UNSET TAGS, ENABLE/DISABLE/INHERIT
//!   PREDICTIVE OPTIMIZATION, DEFAULT COLLATION, OPTIONS, catalog-less ALTER)
//! - DROP CATALOG with CASCADE, RESTRICT, IF EXISTS
//! - Formatting (semantic preservation via verify_formatting_safe)
//! - Risk analysis (signal generation and evidence counts)

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    analyzer::AnalysisConfig, format_sql_with_config, parse_sql_with_dialect,
    verify_formatting_safe, AstStmt, DatabricksDialect, FormatterConfig,
};
use std::sync::Arc;

fn dbx_config() -> FormatterConfig {
    FormatterConfig {
        dialect: lexega_core::dialect::databricks(),
        ..Default::default()
    }
}

fn dbx_format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &dbx_config())
        .unwrap_or_else(|e| panic!("Failed to format:\n{}\nError: {:?}", sql, e));
    verify_formatting_safe(sql, &formatted).unwrap_or_else(|e| {
        panic!(
            "Safety check failed:\n{}\n→\n{}\nError: {}",
            sql, formatted, e
        )
    });
    formatted
}

fn dbx_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(DatabricksDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

fn has_signal(report: &lexega_core::analyzer::AnalysisReport, rule_id: &str) -> bool {
    report
        .signals
        .iter()
        .any(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == rule_id))
}

fn parses_as_create_catalog(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::CreateCatalog(_)))
}

fn parses_as_alter_catalog(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::AlterCatalog(_)))
}

fn parses_as_drop_catalog(sql: &str) -> bool {
    let script = parse_sql_with_dialect(sql, &DatabricksDialect).expect("should parse");
    for s in &script.stmts {
        assert!(
            !matches!(s, AstStmt::OpaqueContent { .. }),
            "Statement parsed as OpaqueContent (parse failure):\n{}",
            sql
        );
    }
    script
        .stmts
        .iter()
        .any(|s| matches!(s, AstStmt::DropCatalog(_)))
}

// ============================================================================
// CREATE CATALOG — Parsing
// ============================================================================

#[test]
fn parse_create_catalog_basic() {
    assert!(parses_as_create_catalog("CREATE CATALOG my_catalog;"));
}

#[test]
fn parse_create_catalog_if_not_exists() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG IF NOT EXISTS my_catalog;"
    ));
}

#[test]
fn parse_create_catalog_with_comment() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG my_catalog COMMENT 'Production catalog';"
    ));
}

#[test]
fn parse_create_catalog_with_managed_location() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG my_catalog MANAGED LOCATION 's3://my-bucket/path';"
    ));
}

#[test]
fn parse_create_catalog_with_default_collation() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG my_catalog DEFAULT COLLATION 'utf8_general_ci';"
    ));
}

#[test]
fn parse_create_catalog_with_options() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG my_catalog OPTIONS (owner = 'data_team', env = 'prod');"
    ));
}

#[test]
fn parse_create_catalog_with_all_clauses() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG IF NOT EXISTS analytics
            MANAGED LOCATION 's3://bucket/analytics'
            COMMENT 'Analytics catalog'
            DEFAULT COLLATION 'en_US'
            OPTIONS (team = 'data');"
    ));
}

#[test]
fn parse_create_foreign_catalog_using_connection() {
    assert!(parses_as_create_catalog(
        "CREATE FOREIGN CATALOG ext_catalog USING CONNECTION my_conn;"
    ));
}

#[test]
fn parse_create_foreign_catalog_using_share() {
    assert!(parses_as_create_catalog(
        "CREATE FOREIGN CATALOG shared_catalog USING SHARE 'provider.share1';"
    ));
}

#[test]
fn parse_create_foreign_catalog_with_options() {
    assert!(parses_as_create_catalog(
        "CREATE FOREIGN CATALOG ext_catalog
            USING CONNECTION my_conn
            OPTIONS (database = 'remote_db')
            COMMENT 'External catalog via connection';"
    ));
}

#[test]
fn parse_create_catalog_qualified_name() {
    assert!(parses_as_create_catalog(
        "CREATE CATALOG workspace.my_catalog;"
    ));
}

#[test]
fn parse_create_catalog_backtick_quoted() {
    assert!(parses_as_create_catalog("CREATE CATALOG `my-catalog`;"));
}

// ============================================================================
// ALTER CATALOG — Parsing
// ============================================================================

#[test]
fn parse_alter_catalog_owner_to() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog OWNER TO `data_admins`;"
    ));
}

#[test]
fn parse_alter_catalog_set_tags() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog SET TAGS ('env' = 'prod', 'team' = 'analytics');"
    ));
}

#[test]
fn parse_alter_catalog_unset_tags() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog UNSET TAGS ('env', 'team');"
    ));
}

#[test]
fn parse_alter_catalog_enable_predictive_optimization() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog ENABLE PREDICTIVE OPTIMIZATION;"
    ));
}

#[test]
fn parse_alter_catalog_disable_predictive_optimization() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog DISABLE PREDICTIVE OPTIMIZATION;"
    ));
}

#[test]
fn parse_alter_catalog_inherit_predictive_optimization() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog INHERIT PREDICTIVE OPTIMIZATION;"
    ));
}

#[test]
fn parse_alter_catalog_default_collation() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog DEFAULT COLLATION 'utf8_binary';"
    ));
}

#[test]
fn parse_alter_catalog_options() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG my_catalog OPTIONS (opt1 = 'val1');"
    ));
}

#[test]
fn parse_alter_catalog_no_name() {
    // ALTER CATALOG without a name defaults to hive_metastore
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG SET TAGS ('env' = 'staging');"
    ));
}

#[test]
fn parse_alter_catalog_no_name_owner_to() {
    assert!(parses_as_alter_catalog(
        "ALTER CATALOG OWNER TO `admin_group`;"
    ));
}

// ============================================================================
// DROP CATALOG — Parsing
// ============================================================================

#[test]
fn parse_drop_catalog_basic() {
    assert!(parses_as_drop_catalog("DROP CATALOG my_catalog;"));
}

#[test]
fn parse_drop_catalog_if_exists() {
    assert!(parses_as_drop_catalog("DROP CATALOG IF EXISTS my_catalog;"));
}

#[test]
fn parse_drop_catalog_cascade() {
    assert!(parses_as_drop_catalog("DROP CATALOG my_catalog CASCADE;"));
}

#[test]
fn parse_drop_catalog_restrict() {
    assert!(parses_as_drop_catalog("DROP CATALOG my_catalog RESTRICT;"));
}

#[test]
fn parse_drop_catalog_if_exists_cascade() {
    assert!(parses_as_drop_catalog(
        "DROP CATALOG IF EXISTS staging_catalog CASCADE;"
    ));
}

#[test]
fn parse_drop_catalog_qualified() {
    assert!(parses_as_drop_catalog(
        "DROP CATALOG workspace.old_catalog;"
    ));
}

#[test]
fn parse_drop_catalog_backtick_quoted() {
    assert!(parses_as_drop_catalog("DROP CATALOG `my-old-catalog`;"));
}

// ============================================================================
// Formatting — Semantic Preservation
// ============================================================================

#[test]
fn format_create_catalog_basic() {
    dbx_format_and_verify("CREATE CATALOG my_catalog;");
}

#[test]
fn format_create_catalog_all_clauses() {
    dbx_format_and_verify(
        "CREATE CATALOG IF NOT EXISTS analytics
            MANAGED LOCATION 's3://bucket/analytics'
            COMMENT 'Analytics catalog'
            DEFAULT COLLATION 'en_US'
            OPTIONS (team = 'data');",
    );
}

#[test]
fn format_create_foreign_catalog() {
    dbx_format_and_verify(
        "CREATE FOREIGN CATALOG ext_cat
            USING CONNECTION conn1
            OPTIONS (database = 'ext_db')
            COMMENT 'External';",
    );
}

#[test]
fn format_alter_catalog_owner() {
    dbx_format_and_verify("ALTER CATALOG my_catalog OWNER TO `data_team`;");
}

#[test]
fn format_alter_catalog_set_tags() {
    dbx_format_and_verify("ALTER CATALOG my_catalog SET TAGS ('env' = 'prod', 'tier' = 'gold');");
}

#[test]
fn format_alter_catalog_no_name() {
    dbx_format_and_verify("ALTER CATALOG SET TAGS ('env' = 'staging');");
}

#[test]
fn format_alter_catalog_predictive_opt() {
    dbx_format_and_verify("ALTER CATALOG my_catalog ENABLE PREDICTIVE OPTIMIZATION;");
    dbx_format_and_verify("ALTER CATALOG my_catalog DISABLE PREDICTIVE OPTIMIZATION;");
    dbx_format_and_verify("ALTER CATALOG my_catalog INHERIT PREDICTIVE OPTIMIZATION;");
}

#[test]
fn format_drop_catalog_cascade() {
    dbx_format_and_verify("DROP CATALOG IF EXISTS staging_catalog CASCADE;");
}

#[test]
fn format_drop_catalog_restrict() {
    dbx_format_and_verify("DROP CATALOG my_catalog RESTRICT;");
}

// ============================================================================
// Risk Analysis — Signal Generation
// ============================================================================

#[test]
fn signal_create_catalog() {
    let report = dbx_analyze("CREATE CATALOG my_catalog;");
    assert!(
        has_signal(&report, "DBX-CAT-NEW"),
        "Should emit DBX-CAT-NEW (Catalog Created). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_create_foreign_catalog() {
    let report = dbx_analyze("CREATE FOREIGN CATALOG ext USING CONNECTION my_conn;");
    assert!(
        has_signal(&report, "DBX-CAT-NEW"),
        "Foreign catalog should also emit DBX-CAT-NEW. Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_alter_catalog_owner_to() {
    let report = dbx_analyze("ALTER CATALOG my_catalog OWNER TO `admins`;");
    assert!(
        has_signal(&report, "DBX-CAT-OWNER-CHG"),
        "Should emit DBX-CAT-OWNER-CHG (Ownership Transfer). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_drop_catalog_cascade() {
    let report = dbx_analyze("DROP CATALOG my_catalog CASCADE;");
    assert!(
        has_signal(&report, "DBX-CAT-CASCADE-DROP"),
        "Should emit DBX-CAT-CASCADE-DROP (CASCADE drop — Critical). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_drop_catalog_without_cascade() {
    let report = dbx_analyze("DROP CATALOG my_catalog;");
    assert!(
        has_signal(&report, "DBX-CAT-DROP"),
        "Should emit DBX-CAT-DROP (Drop — High). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_drop_catalog_restrict() {
    let report = dbx_analyze("DROP CATALOG my_catalog RESTRICT;");
    assert!(
        has_signal(&report, "DBX-CAT-DROP"),
        "RESTRICT is non-cascade, should emit DBX-CAT-DROP. Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_alter_catalog_set_tags() {
    let report = dbx_analyze("ALTER CATALOG my_catalog SET TAGS ('env' = 'prod');");
    assert!(
        has_signal(&report, "DBX-CAT-TAG-CHG"),
        "Should emit DBX-CAT-TAG-CHG (Tags Modified). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_alter_catalog_unset_tags() {
    let report = dbx_analyze("ALTER CATALOG my_catalog UNSET TAGS ('env');");
    assert!(
        has_signal(&report, "DBX-CAT-TAG-RMV"),
        "Should emit DBX-CAT-TAG-RMV (Tags Removed). Signals: {:?}",
        report.signals
    );
}

#[test]
fn signal_alter_catalog_predictive_optimization() {
    let report = dbx_analyze("ALTER CATALOG my_catalog ENABLE PREDICTIVE OPTIMIZATION;");
    assert!(
        has_signal(&report, "DBX-CAT-PREDOPT-CHG"),
        "Should emit DBX-CAT-PREDOPT-CHG (Predictive Optimization Changed). Signals: {:?}",
        report.signals
    );

    let report2 = dbx_analyze("ALTER CATALOG my_catalog DISABLE PREDICTIVE OPTIMIZATION;");
    assert!(
        has_signal(&report2, "DBX-CAT-PREDOPT-CHG"),
        "DISABLE should also emit DBX-CAT-PREDOPT-CHG. Signals: {:?}",
        report2.signals
    );

    let report3 = dbx_analyze("ALTER CATALOG my_catalog INHERIT PREDICTIVE OPTIMIZATION;");
    assert!(
        has_signal(&report3, "DBX-CAT-PREDOPT-CHG"),
        "INHERIT should also emit DBX-CAT-PREDOPT-CHG. Signals: {:?}",
        report3.signals
    );
}

// ============================================================================
// Multi-statement — Evidence Counting
// ============================================================================

#[test]
fn multi_statement_evidence_count() {
    let sql = r#"
        CREATE CATALOG cat1;
        ALTER CATALOG cat1 OWNER TO `admin`;
        DROP CATALOG IF EXISTS cat2 CASCADE;
    "#;
    let report = dbx_analyze(sql);

    // Should have all three signal types
    assert!(has_signal(&report, "DBX-CAT-NEW"), "Missing CREATE signal");
    assert!(
        has_signal(&report, "DBX-CAT-OWNER-CHG"),
        "Missing OWNER TO signal"
    );
    assert!(
        has_signal(&report, "DBX-CAT-CASCADE-DROP"),
        "Missing CASCADE DROP signal"
    );

    // At least one critical (CASCADE drop)
    assert!(
        report.summary.critical_count >= 1,
        "Expected at least 1 critical signal for CASCADE drop, got {}",
        report.summary.critical_count
    );
}

#[test]
fn multi_statement_drops() {
    let sql = r#"
        DROP CATALOG cat1;
        DROP CATALOG cat2;
        DROP CATALOG cat3;
    "#;
    let report = dbx_analyze(sql);

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|s| matches!(s, RuleMatch::Analysis(g) if g.matched_rule == "DBX-CAT-DROP"))
        .map(|s| {
            let RuleMatch::Analysis(ref p) = s;
            p.evidence_count.unwrap_or(1)
        })
        .sum();
    assert!(
        total_evidence >= 3,
        "Should have evidence for all 3 DROPs, got {}",
        total_evidence
    );
}

// ============================================================================
// Negative Tests — Safe Patterns (no false positives)
// ============================================================================

#[test]
fn no_signal_for_select() {
    let report = dbx_analyze("SELECT 1;");
    assert!(
        !has_signal(&report, "DBX-CAT-NEW"),
        "SELECT should not emit any catalog signal"
    );
    assert!(
        !has_signal(&report, "DBX-CAT-DROP"),
        "SELECT should not emit any catalog signal"
    );
}

// ============================================================================
// AST Field Verification
// ============================================================================

#[test]
fn ast_create_catalog_fields() {
    let script = parse_sql_with_dialect(
        "CREATE FOREIGN CATALOG IF NOT EXISTS ext_cat
            USING CONNECTION my_conn
            MANAGED LOCATION 's3://bucket'
            COMMENT 'description';",
        &DatabricksDialect,
    )
    .expect("should parse");

    let stmt = &script.stmts[0];
    if let AstStmt::CreateCatalog(c) = stmt {
        assert!(c.is_foreign, "Should be foreign catalog");
        assert!(c.if_not_exists, "Should have IF NOT EXISTS");
        assert!(
            c.using_connection_span.is_some(),
            "Should have USING CONNECTION"
        );
        assert!(
            c.managed_location_span.is_some(),
            "Should have MANAGED LOCATION"
        );
        assert!(c.comment_span.is_some(), "Should have COMMENT");
    } else {
        panic!(
            "Expected CreateCatalog, got {:?}",
            std::mem::discriminant(stmt)
        );
    }
}

#[test]
fn ast_alter_catalog_owner_to_fields() {
    let script = parse_sql_with_dialect(
        "ALTER CATALOG my_catalog OWNER TO `admin_group`;",
        &DatabricksDialect,
    )
    .expect("should parse");

    let stmt = &script.stmts[0];
    if let AstStmt::AlterCatalog(a) = stmt {
        assert!(a.catalog_name_span.is_some(), "Should have catalog name");
        assert!(
            matches!(
                a.action_kind,
                lexega_core::ast::AlterCatalogActionKind::OwnerTo
            ),
            "Action should be OwnerTo"
        );
    } else {
        panic!(
            "Expected AlterCatalog, got {:?}",
            std::mem::discriminant(stmt)
        );
    }
}

#[test]
fn ast_alter_catalog_no_name() {
    let script = parse_sql_with_dialect(
        "ALTER CATALOG SET TAGS ('env' = 'prod');",
        &DatabricksDialect,
    )
    .expect("should parse");

    let stmt = &script.stmts[0];
    if let AstStmt::AlterCatalog(a) = stmt {
        assert!(
            a.catalog_name_span.is_none(),
            "Should have no catalog name (defaults to hive_metastore)"
        );
        assert!(
            matches!(
                a.action_kind,
                lexega_core::ast::AlterCatalogActionKind::SetTags
            ),
            "Action should be SetTags"
        );
    } else {
        panic!(
            "Expected AlterCatalog, got {:?}",
            std::mem::discriminant(stmt)
        );
    }
}

#[test]
fn ast_drop_catalog_cascade_fields() {
    let script = parse_sql_with_dialect(
        "DROP CATALOG IF EXISTS staging CASCADE;",
        &DatabricksDialect,
    )
    .expect("should parse");

    let stmt = &script.stmts[0];
    if let AstStmt::DropCatalog(d) = stmt {
        assert!(d.if_exists, "Should have IF EXISTS");
        assert!(d.cascade, "Should have CASCADE");
        assert!(!d.restrict, "Should not have RESTRICT");
    } else {
        panic!(
            "Expected DropCatalog, got {:?}",
            std::mem::discriminant(stmt)
        );
    }
}

#[test]
fn ast_drop_catalog_restrict_fields() {
    let script = parse_sql_with_dialect("DROP CATALOG my_catalog RESTRICT;", &DatabricksDialect)
        .expect("should parse");

    let stmt = &script.stmts[0];
    if let AstStmt::DropCatalog(d) = stmt {
        assert!(!d.cascade, "Should not have CASCADE");
        assert!(d.restrict, "Should have RESTRICT");
    } else {
        panic!(
            "Expected DropCatalog, got {:?}",
            std::mem::discriminant(stmt)
        );
    }
}

// ============================================================================
// DBX-GRT-CAT-ALLPRIV: GRANT ALL ON CATALOG
// ============================================================================

#[test]
fn risk_dbx_grant_all_on_catalog_triggers_dbx_c018() {
    let sql = "GRANT ALL PRIVILEGES ON CATALOG my_catalog TO my_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT ALL ON CATALOG should trigger DBX-GRT-CAT-ALLPRIV. Signals: {:?}",
        report.signals
    );
}

#[test]
fn risk_dbx_grant_all_on_catalog_no_privs_keyword() {
    // "GRANT ALL ON CATALOG" (without the word PRIVILEGES)
    let sql = "GRANT ALL ON CATALOG unity_catalog TO admin_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT ALL ON CATALOG (without PRIVILEGES keyword) should still trigger DBX-GRT-CAT-ALLPRIV. Signals: {:?}",
        report.signals
    );
}

#[test]
fn risk_dbx_grant_all_on_catalog_also_triggers_grant_all_priv() {
    // Should fire BOTH the generic GRT-ALL-PRIV (grant all) and the specific DBX-GRT-CAT-ALLPRIV
    let sql = "GRANT ALL PRIVILEGES ON CATALOG my_catalog TO my_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "GRT-ALL-PRIV"),
        "GRANT ALL ON CATALOG should also trigger generic GRT-ALL-PRIV"
    );
    assert!(
        has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT ALL ON CATALOG should trigger DBX-GRT-CAT-ALLPRIV"
    );
}

#[test]
fn risk_dbx_grant_select_on_catalog_does_not_trigger_dbx_c018() {
    // Specific privilege on CATALOG should NOT trigger the ALL PRIVILEGES rule
    let sql = "GRANT USE CATALOG ON CATALOG my_catalog TO analyst_role;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT USE CATALOG (not ALL) should NOT trigger DBX-GRT-CAT-ALLPRIV"
    );
}

#[test]
fn risk_dbx_grant_all_on_schema_does_not_trigger_dbx_c018() {
    // GRANT ALL on a different object type should NOT trigger catalog-specific rule
    let sql = "GRANT ALL PRIVILEGES ON SCHEMA my_catalog.my_schema TO my_role;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT ALL ON SCHEMA should NOT trigger DBX-GRT-CAT-ALLPRIV (catalog-specific)"
    );
}

#[test]
fn risk_dbx_grant_all_on_database_does_not_trigger_dbx_c018() {
    let sql = "GRANT ALL PRIVILEGES ON DATABASE my_db TO my_role;";
    let report = dbx_analyze(sql);

    assert!(
        !has_signal(&report, "DBX-GRT-CAT-ALLPRIV"),
        "GRANT ALL ON DATABASE should NOT trigger DBX-GRT-CAT-ALLPRIV"
    );
}

#[test]
fn risk_dbx_grant_manage_on_catalog_triggers_dbx_c053() {
    let sql = "GRANT MANAGE ON CATALOG my_catalog TO my_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-GRT-CAT-MANAGE"),
        "GRANT MANAGE ON CATALOG should trigger DBX-GRT-CAT-MANAGE"
    );
}

#[test]
fn risk_dbx_grant_manage_on_schema_triggers_dbx_c054() {
    let sql = "GRANT MANAGE ON SCHEMA my_catalog.analytics TO data_admin;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-GRT-SCHEMA-MANAGE"),
        "GRANT MANAGE ON SCHEMA should trigger DBX-GRT-SCHEMA-MANAGE"
    );
}

#[test]
fn risk_dbx_grant_manage_on_volume_triggers_grt_vol_manage() {
    let sql = "GRANT MANAGE ON VOLUME my_catalog.analytics.raw_volume TO storage_admin;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-GRT-VOL-MANAGE"),
        "GRANT MANAGE ON VOLUME should trigger DBX-GRT-VOL-MANAGE"
    );
}

#[test]
fn risk_dbx_revoke_all_on_catalog_triggers_rvk_cat_allpriv() {
    let sql = "REVOKE ALL PRIVILEGES ON CATALOG my_catalog FROM my_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-RVK-CAT-ALLPRIV"),
        "REVOKE ALL PRIVILEGES ON CATALOG should trigger DBX-RVK-CAT-ALLPRIV"
    );
}

#[test]
fn risk_dbx_revoke_manage_on_catalog_triggers_rvk_cat_manage() {
    let sql = "REVOKE MANAGE ON CATALOG my_catalog FROM my_role;";
    let report = dbx_analyze(sql);

    assert!(
        has_signal(&report, "DBX-RVK-CAT-MANAGE"),
        "REVOKE MANAGE ON CATALOG should trigger DBX-RVK-CAT-MANAGE"
    );
}
