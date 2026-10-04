// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for MSSQL SQL Server 2025 statement support and risk signals.
///
/// Tests cover:
///   1. Parsing produces correct AST variants (not OpaqueContent)
///   2. Formatting preserves semantic tokens
///   3. Risk analysis emits correct security/governance signals
///   4. Multi-statement evidence counting
///   5. |= compound assignment lexer token
use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::ast::AstStmt;
use lexega_core::dialect::mssql;
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig, MsSqlDialect};
use std::collections::HashSet;
use std::sync::Arc;

// ============================================================================
// Helpers
// ============================================================================

fn mssql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mssql();
    config
}

fn parse_mssql(sql: &str) -> Vec<AstStmt> {
    let dialect = mssql();
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("Parse failed: {}\nSQL: {}", e, sql));
    script.stmts
}

fn ast_variant_name(stmt: &AstStmt) -> &'static str {
    use lexega_core::ast::types::PrincipalKind;
    match stmt {
        AstStmt::MssqlCreateExternalModel(_) => "MssqlCreateExternalModel",
        AstStmt::MssqlAlterExternalModel(_) => "MssqlAlterExternalModel",
        AstStmt::MssqlDropExternalModel(_) => "MssqlDropExternalModel",
        AstStmt::MssqlCreateVectorIndex(_) => "MssqlCreateVectorIndex",
        AstStmt::CreatePrincipal(p) => match p.principal_kind {
            PrincipalKind::User => "CreatePrincipal(User)",
            PrincipalKind::Role => "CreatePrincipal(Role)",
            PrincipalKind::Login => "CreatePrincipal(Login)",
            PrincipalKind::Group => "CreatePrincipal(Group)",
            PrincipalKind::ApplicationRole => "CreatePrincipal(ApplicationRole)",
            PrincipalKind::DatabaseRole => "CreatePrincipal(DatabaseRole)",
        },
        AstStmt::OpaqueContent { .. } => "OpaqueContent",
        _ => "Other",
    }
}

fn format_verify(sql: &str) {
    let config = mssql_config();
    let formatted = format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed: {}\nSQL: {}", e, sql));
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "Verification failed: {}\nOriginal: {}\nFormatted: {}",
                e, sql, formatted
            )
        });
}

fn format_verify_variant(sql: &str, expected_variant: &str) {
    let stmts = parse_mssql(sql);
    assert!(!stmts.is_empty(), "Should parse at least one statement");
    let variant = ast_variant_name(&stmts[0]);
    assert_eq!(
        variant, expected_variant,
        "Expected AST variant {}, got {} — parser likely fell back to OpaqueContent\nSQL: {}",
        expected_variant, variant, sql
    );
    format_verify(sql);
}

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_mssql(sql: &str) -> HashSet<String> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(MsSqlDialect));
    match analyze_risk_with_policy_config(sql, &config) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Risk analysis error (MSSQL dialect): {:?}", e);
            HashSet::new()
        }
    }
}

fn analyze_mssql_report(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(MsSqlDialect));
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

// ============================================================================
// CREATE EXTERNAL MODEL — Parsing
// ============================================================================

#[test]
fn test_create_external_model_basic() {
    format_verify_variant(
        "CREATE EXTERNAL MODEL my_gpt WITH (LOCATION = 'https://myendpoint.openai.azure.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'text-embedding-ada-002');",
        "MssqlCreateExternalModel",
    );
}

#[test]
fn test_create_external_model_with_authorization() {
    format_verify_variant(
        "CREATE EXTERNAL MODEL my_model AUTHORIZATION dbo WITH (LOCATION = 'https://endpoint.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'gpt-4', CREDENTIAL = my_cred);",
        "MssqlCreateExternalModel",
    );
}

#[test]
fn test_create_external_model_with_all_options() {
    format_verify_variant(
        "CREATE EXTERNAL MODEL my_model WITH (LOCATION = 'https://endpoint.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = COMPLETIONS, MODEL = 'gpt-4o', CREDENTIAL = azure_cred, PARAMETERS = '{\"temperature\": 0.7}');",
        "MssqlCreateExternalModel",
    );
}

// ============================================================================
// ALTER EXTERNAL MODEL — Parsing
// ============================================================================

#[test]
fn test_alter_external_model_basic() {
    format_verify_variant(
        "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new-endpoint.com/', MODEL = 'gpt-4o');",
        "MssqlAlterExternalModel",
    );
}

// ============================================================================
// DROP EXTERNAL MODEL — Parsing
// ============================================================================

#[test]
fn test_drop_external_model_basic() {
    format_verify_variant("DROP EXTERNAL MODEL my_model;", "MssqlDropExternalModel");
}

#[test]
fn test_drop_external_model_if_exists() {
    format_verify_variant(
        "DROP EXTERNAL MODEL IF EXISTS my_model;",
        "MssqlDropExternalModel",
    );
}

// ============================================================================
// CREATE VECTOR INDEX — Parsing
// ============================================================================

#[test]
fn test_create_vector_index_basic() {
    format_verify_variant(
        "CREATE VECTOR INDEX idx_embedding ON dbo.articles(content_embedding) WITH (METRIC = 'cosine', TYPE = 'DiskANN');",
        "MssqlCreateVectorIndex",
    );
}

#[test]
fn test_create_vector_index_with_maxdop() {
    format_verify_variant(
        "CREATE VECTOR INDEX idx_vec ON my_table(vec_col) WITH (METRIC = 'dot', TYPE = 'DiskANN', MAXDOP = 4);",
        "MssqlCreateVectorIndex",
    );
}

#[test]
fn test_create_vector_index_on_filegroup() {
    format_verify_variant(
        "CREATE VECTOR INDEX idx_vec ON my_table(embedding) WITH (METRIC = 'euclidean', TYPE = 'DiskANN') ON vector_fg;",
        "MssqlCreateVectorIndex",
    );
}

#[test]
fn test_create_vector_index_minimal() {
    // Without WITH clause — just index on table(column)
    format_verify_variant(
        "CREATE VECTOR INDEX idx_v ON t(c);",
        "MssqlCreateVectorIndex",
    );
}

// ============================================================================
// CREATE LOGIN — Parsing
// ============================================================================

#[test]
fn test_create_login_from_external_provider() {
    format_verify_variant(
        "CREATE LOGIN [bob@contoso.com] FROM EXTERNAL PROVIDER;",
        "CreatePrincipal(Login)",
    );
}

#[test]
fn test_create_login_with_object_id() {
    format_verify_variant(
        "CREATE LOGIN [myapp] FROM EXTERNAL PROVIDER WITH OBJECT_ID = '11111111-2222-3333-4444-555555555555', TYPE = X;",
        "CreatePrincipal(Login)",
    );
}

#[test]
fn test_create_login_with_password() {
    format_verify_variant(
        "CREATE LOGIN new_user WITH PASSWORD = 'StrongP@ss1';",
        "CreatePrincipal(Login)",
    );
}

// ============================================================================
// CREATE USER — Parsing
// ============================================================================

#[test]
fn test_create_user_from_external_provider() {
    format_verify_variant(
        "CREATE USER [bob@contoso.com] FROM EXTERNAL PROVIDER;",
        "CreatePrincipal(User)",
    );
}

#[test]
fn test_create_user_with_object_id() {
    format_verify_variant(
        "CREATE USER [myapp] FROM EXTERNAL PROVIDER WITH OBJECT_ID = '11111111-2222-3333-4444-555555555555', TYPE = E;",
        "CreatePrincipal(User)",
    );
}

#[test]
fn test_create_user_for_login() {
    format_verify_variant(
        "CREATE USER app_user FOR LOGIN app_login;",
        "CreatePrincipal(User)",
    );
}

#[test]
fn test_create_user_without_login() {
    format_verify_variant(
        "CREATE USER svc_account WITHOUT LOGIN;",
        "CreatePrincipal(User)",
    );
}

// ============================================================================
// |= Compound Assignment — Lexer/Parser
// ============================================================================

#[test]
fn test_pipe_eq_in_set() {
    // |= is bitwise OR assignment in T-SQL
    format_verify("SET @flags |= 0x04;");
}

#[test]
fn test_pipe_eq_in_update() {
    format_verify("UPDATE t SET permissions |= 8 WHERE user_id = 1;");
}

// ============================================================================
// VECTOR_SEARCH TVF — Parsing
// ============================================================================

#[test]
fn test_vector_search_tvf_in_from() {
    format_verify(
        "SELECT vs.* FROM VECTOR_SEARCH(TABLE = dbo.articles AS a, COLUMN = embedding, SIMILAR_TO = @query_vec, METRIC = 'cosine', TOP_N = 10) AS vs;",
    );
}

// ============================================================================
// REGEXP_MATCHES TVF — Parsing
// ============================================================================

#[test]
fn test_regexp_matches_tvf() {
    format_verify("SELECT r.* FROM REGEXP_MATCHES(col1, 'pattern') AS r;");
}

// ============================================================================
// CREATE EXTERNAL MODEL — Risk Signals
// ============================================================================

#[test]
fn test_create_external_model_emits_created_signal() {
    let rules = analyze_mssql(
        "CREATE EXTERNAL MODEL my_gpt WITH (LOCATION = 'https://endpoint.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'ada-002');",
    );
    assert!(
        rules.contains("MSSQL-EXTMDL-NEW"),
        "MSSQL-EXTMDL-NEW should fire for CREATE EXTERNAL MODEL. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_external_model_emits_remote_signal() {
    let rules = analyze_mssql(
        "CREATE EXTERNAL MODEL my_gpt WITH (LOCATION = 'https://endpoint.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'ada-002');",
    );
    assert!(
        rules.contains("MSSQL-EXTMDL-RMT"),
        "MSSQL-EXTMDL-RMT should fire for CREATE EXTERNAL MODEL (remote connection). Got: {:?}",
        rules
    );
}

#[test]
fn test_alter_external_model_emits_modified_signal() {
    let rules = analyze_mssql(
        "ALTER EXTERNAL MODEL my_model SET (LOCATION = 'https://new.com/', MODEL = 'gpt-4o');",
    );
    assert!(
        rules.contains("MSSQL-EXTMDL-CHG"),
        "MSSQL-EXTMDL-CHG should fire for ALTER EXTERNAL MODEL. Got: {:?}",
        rules
    );
}

#[test]
fn test_drop_external_model_emits_dropped_signal() {
    let rules = analyze_mssql("DROP EXTERNAL MODEL my_model;");
    assert!(
        rules.contains("INFO-MSSQL-EXTMDL-DROP"),
        "INFO-MSSQL-EXTMDL-DROP should fire for DROP EXTERNAL MODEL. Got: {:?}",
        rules
    );
}

// ============================================================================
// CREATE EXTERNAL MODEL — Multi-statement evidence
// ============================================================================

#[test]
fn test_create_external_model_multi_statement_evidence() {
    let report = analyze_mssql_report(
        "CREATE EXTERNAL MODEL m1 WITH (LOCATION = 'https://a.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'a');\nCREATE EXTERNAL MODEL m2 WITH (LOCATION = 'https://b.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'b');",
    );

    let total_evidence: usize = report
        .signals
        .iter()
        .filter(|f| matches!(f, RuleMatch::Analysis(g) if g.matched_rule == "MSSQL-EXTMDL-NEW"))
        .map(|f| match f {
            RuleMatch::Analysis(g) => g.evidence_count.unwrap_or(1),
        })
        .sum();

    assert!(
        total_evidence >= 2,
        "Should have evidence for each CREATE EXTERNAL MODEL. Got evidence: {}",
        total_evidence
    );
}

// ============================================================================
// CREATE VECTOR INDEX — Risk Signals
// ============================================================================

#[test]
fn test_create_vector_index_emits_signal() {
    let rules = analyze_mssql(
        "CREATE VECTOR INDEX idx_embedding ON dbo.articles(content_embedding) WITH (METRIC = 'cosine', TYPE = 'DiskANN');",
    );
    assert!(
        rules.contains("INFO-MSSQL-VECIDX-NEW"),
        "INFO-MSSQL-VECIDX-NEW should fire for CREATE VECTOR INDEX. Got: {:?}",
        rules
    );
}

// ============================================================================
// CREATE LOGIN — Risk Signals
// ============================================================================

#[test]
fn test_create_login_emits_created_signal() {
    let rules = analyze_mssql("CREATE LOGIN new_admin WITH PASSWORD = 'P@ss123';");
    assert!(
        rules.contains("MSSQL-LOGIN-NEW"),
        "MSSQL-LOGIN-NEW should fire for CREATE LOGIN. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_login_external_emits_remote_signal() {
    let rules = analyze_mssql("CREATE LOGIN [bob@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        rules.contains("MSSQL-LOGIN-NEW"),
        "MSSQL-LOGIN-NEW should fire. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-LOGIN-EXT"),
        "MSSQL-LOGIN-EXT should fire for FROM EXTERNAL PROVIDER. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_login_with_object_id_emits_remote_signal() {
    let rules = analyze_mssql(
        "CREATE LOGIN [myapp] FROM EXTERNAL PROVIDER WITH OBJECT_ID = '12345', TYPE = X;",
    );
    assert!(
        rules.contains("MSSQL-LOGIN-EXT"),
        "MSSQL-LOGIN-EXT should fire for EXTERNAL PROVIDER WITH OBJECT_ID. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_login_password_no_external_signal() {
    let rules = analyze_mssql("CREATE LOGIN new_user WITH PASSWORD = 'StrongP@ss1';");
    assert!(
        !rules.contains("MSSQL-LOGIN-EXT"),
        "MSSQL-LOGIN-EXT should NOT fire for password-based login. Got: {:?}",
        rules
    );
}

// ============================================================================
// CREATE USER — Risk Signals
// ============================================================================

#[test]
fn test_create_user_emits_created_signal() {
    let rules = analyze_mssql("CREATE USER app_user FOR LOGIN app_login;");
    assert!(
        rules.contains("MSSQL-USER-NEW"),
        "MSSQL-USER-NEW should fire for CREATE USER. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_user_external_emits_remote_signal() {
    let rules = analyze_mssql("CREATE USER [bob@contoso.com] FROM EXTERNAL PROVIDER;");
    assert!(
        rules.contains("MSSQL-USER-NEW"),
        "MSSQL-USER-NEW should fire. Got: {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-USER-EXT"),
        "MSSQL-USER-EXT should fire for FROM EXTERNAL PROVIDER. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_user_for_login_no_external_signal() {
    let rules = analyze_mssql("CREATE USER app_user FOR LOGIN app_login;");
    assert!(
        !rules.contains("MSSQL-USER-EXT"),
        "MSSQL-USER-EXT should NOT fire for FOR LOGIN user. Got: {:?}",
        rules
    );
}

#[test]
fn test_create_user_without_login_no_external_signal() {
    let rules = analyze_mssql("CREATE USER svc_account WITHOUT LOGIN;");
    assert!(
        !rules.contains("MSSQL-USER-EXT"),
        "MSSQL-USER-EXT should NOT fire for WITHOUT LOGIN user. Got: {:?}",
        rules
    );
}

// ============================================================================
// Multi-statement mixed scenario
// ============================================================================

#[test]
fn test_mixed_mssql_2025_multi_statement() {
    let sql = r#"
CREATE EXTERNAL MODEL embedding_model
  WITH (LOCATION = 'https://oai.azure.com/', API_FORMAT = 'OPEN_AI', MODEL_TYPE = EMBEDDINGS, MODEL = 'ada-002');

CREATE VECTOR INDEX idx_articles ON dbo.articles(embedding)
  WITH (METRIC = 'cosine', TYPE = 'DiskANN');

CREATE LOGIN [svc@contoso.com] FROM EXTERNAL PROVIDER
  WITH OBJECT_ID = 'aabbccdd', TYPE = X;

CREATE USER [svc@contoso.com] FROM EXTERNAL PROVIDER
  WITH OBJECT_ID = 'aabbccdd', TYPE = X;
"#;

    let report = analyze_mssql_report(sql);
    let rules = extract_rule_ids(&report.signals);

    // All expected signals should fire
    assert!(
        rules.contains("MSSQL-EXTMDL-NEW"),
        "Missing MSSQL-EXTMDL-NEW in {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-EXTMDL-RMT"),
        "Missing MSSQL-EXTMDL-RMT in {:?}",
        rules
    );
    assert!(
        rules.contains("INFO-MSSQL-VECIDX-NEW"),
        "Missing INFO-MSSQL-VECIDX-NEW in {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-LOGIN-NEW"),
        "Missing MSSQL-LOGIN-NEW in {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-LOGIN-EXT"),
        "Missing MSSQL-LOGIN-EXT in {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-USER-NEW"),
        "Missing MSSQL-USER-NEW in {:?}",
        rules
    );
    assert!(
        rules.contains("MSSQL-USER-EXT"),
        "Missing MSSQL-USER-EXT in {:?}",
        rules
    );
}
