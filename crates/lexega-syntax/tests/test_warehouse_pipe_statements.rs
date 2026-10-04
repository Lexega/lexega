// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CREATE/ALTER/DROP WAREHOUSE and PIPE statement parsing,
//! INSERT OR REPLACE and the |> pipe operator.

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn format_and_verify(sql: &str) -> String {
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .unwrap_or_else(|e| panic!("should format successfully: {e}\nSQL: {sql}"));
    verify_formatting_safe(sql, &formatted)
        .unwrap_or_else(|e| panic!("formatting should be safe: {e}\nSQL: {sql}"));
    formatted
}

// ==========================================================================
// CREATE WAREHOUSE
// ==========================================================================

#[test]
fn test_create_warehouse_basic() {
    format_and_verify("CREATE WAREHOUSE my_wh;");
}

#[test]
fn test_create_warehouse_or_replace() {
    format_and_verify("CREATE OR REPLACE WAREHOUSE my_wh;");
}

#[test]
fn test_create_warehouse_if_not_exists() {
    format_and_verify("CREATE WAREHOUSE IF NOT EXISTS my_wh;");
}

#[test]
fn test_create_warehouse_with_properties() {
    format_and_verify(
        "CREATE WAREHOUSE my_wh
          WAREHOUSE_SIZE = 'LARGE'
          AUTO_SUSPEND = 300
          AUTO_RESUME = TRUE
          INITIALLY_SUSPENDED = TRUE;",
    );
}

#[test]
fn test_create_warehouse_full_properties() {
    format_and_verify(
        "CREATE OR REPLACE WAREHOUSE etl_wh
          WAREHOUSE_SIZE = 'XLARGE'
          AUTO_SUSPEND = 600
          AUTO_RESUME = TRUE
          INITIALLY_SUSPENDED = FALSE
          RESOURCE_MONITOR = my_monitor
          COMMENT = 'ETL warehouse'
          ENABLE_QUERY_ACCELERATION = TRUE
          QUERY_ACCELERATION_MAX_SCALE_FACTOR = 8
          MAX_CONCURRENCY_LEVEL = 8
          STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = 600
          STATEMENT_TIMEOUT_IN_SECONDS = 1200
          WAREHOUSE_TYPE = 'STANDARD'
          MIN_CLUSTER_COUNT = 1
          MAX_CLUSTER_COUNT = 3
          SCALING_POLICY = 'ECONOMY';",
    );
}

#[test]
fn test_create_warehouse_with_tag() {
    format_and_verify(
        "CREATE WAREHOUSE my_wh
          WAREHOUSE_SIZE = 'SMALL'
          TAG (team = 'data', env = 'prod');",
    );
}

#[test]
fn test_create_warehouse_qualified_name() {
    format_and_verify("CREATE WAREHOUSE my_db.my_wh;");
}

#[test]
fn test_create_warehouse_unknown_properties() {
    // Unknown properties should be preserved, not error
    format_and_verify(
        "CREATE WAREHOUSE my_wh
          WAREHOUSE_SIZE = 'SMALL'
          SOME_FUTURE_PROP = 'value';",
    );
}

// ==========================================================================
// ALTER WAREHOUSE
// ==========================================================================

#[test]
fn test_alter_warehouse_suspend() {
    format_and_verify("ALTER WAREHOUSE my_wh SUSPEND;");
}

#[test]
fn test_alter_warehouse_resume() {
    format_and_verify("ALTER WAREHOUSE my_wh RESUME;");
}

#[test]
fn test_alter_warehouse_resume_if_suspended() {
    format_and_verify("ALTER WAREHOUSE my_wh RESUME IF SUSPENDED;");
}

#[test]
fn test_alter_warehouse_abort_all_queries() {
    format_and_verify("ALTER WAREHOUSE my_wh ABORT ALL QUERIES;");
}

#[test]
fn test_alter_warehouse_rename_to() {
    format_and_verify("ALTER WAREHOUSE my_wh RENAME TO new_wh;");
}

#[test]
fn test_alter_warehouse_set_properties() {
    format_and_verify("ALTER WAREHOUSE my_wh SET WAREHOUSE_SIZE = 'LARGE' AUTO_SUSPEND = 600;");
}

#[test]
fn test_alter_warehouse_unset_properties() {
    format_and_verify("ALTER WAREHOUSE my_wh UNSET AUTO_SUSPEND, AUTO_RESUME;");
}

#[test]
fn test_alter_warehouse_set_tag() {
    format_and_verify("ALTER WAREHOUSE my_wh SET TAG team = 'data', env = 'prod';");
}

#[test]
fn test_alter_warehouse_unset_tag() {
    format_and_verify("ALTER WAREHOUSE my_wh UNSET TAG team, env;");
}

#[test]
fn test_alter_warehouse_if_exists() {
    format_and_verify("ALTER WAREHOUSE IF EXISTS my_wh SUSPEND;");
}

// ==========================================================================
// DROP WAREHOUSE
// ==========================================================================

#[test]
fn test_drop_warehouse_basic() {
    format_and_verify("DROP WAREHOUSE my_wh;");
}

#[test]
fn test_drop_warehouse_if_exists() {
    format_and_verify("DROP WAREHOUSE IF EXISTS my_wh;");
}

#[test]
fn test_drop_warehouse_qualified() {
    format_and_verify("DROP WAREHOUSE IF EXISTS my_db.my_wh;");
}

// ==========================================================================
// CREATE PIPE
// ==========================================================================

#[test]
fn test_create_pipe_basic() {
    format_and_verify("CREATE PIPE my_pipe AS COPY INTO my_table FROM @my_stage;");
}

#[test]
fn test_create_pipe_or_replace() {
    format_and_verify("CREATE OR REPLACE PIPE my_pipe AS COPY INTO my_table FROM @my_stage;");
}

#[test]
fn test_create_pipe_if_not_exists() {
    format_and_verify("CREATE PIPE IF NOT EXISTS my_pipe AS COPY INTO my_table FROM @my_stage;");
}

#[test]
fn test_create_pipe_with_properties() {
    format_and_verify(
        "CREATE PIPE my_pipe
          AUTO_INGEST = TRUE
          COMMENT = 'Ingest pipe'
          AS COPY INTO my_table FROM @my_stage;",
    );
}

#[test]
fn test_create_pipe_with_integration() {
    format_and_verify(
        "CREATE PIPE my_pipe
          AUTO_INGEST = TRUE
          INTEGRATION = 'my_int'
          ERROR_INTEGRATION = 'my_err_int'
          AS COPY INTO my_table FROM @my_stage;",
    );
}

#[test]
fn test_create_pipe_with_aws_sns() {
    format_and_verify(
        "CREATE PIPE my_pipe
          AUTO_INGEST = TRUE
          AWS_SNS_TOPIC = 'arn:aws:sns:us-east-1:123456789:my_topic'
          AS COPY INTO my_table FROM @my_stage;",
    );
}

// ==========================================================================
// ALTER PIPE
// ==========================================================================

#[test]
fn test_alter_pipe_set_property() {
    format_and_verify("ALTER PIPE my_pipe SET PIPE_EXECUTION_PAUSED = TRUE;");
}

#[test]
fn test_alter_pipe_set_tag() {
    format_and_verify("ALTER PIPE my_pipe SET TAG team = 'data';");
}

#[test]
fn test_alter_pipe_unset_tag() {
    format_and_verify("ALTER PIPE my_pipe UNSET TAG team;");
}

#[test]
fn test_alter_pipe_refresh() {
    format_and_verify("ALTER PIPE my_pipe REFRESH;");
}

#[test]
fn test_alter_pipe_refresh_with_prefix() {
    format_and_verify("ALTER PIPE my_pipe REFRESH PREFIX = 'path/to/data';");
}

#[test]
fn test_alter_pipe_refresh_with_modified_before() {
    format_and_verify(
        "ALTER PIPE my_pipe REFRESH PREFIX = 'path/' MODIFIED_BEFORE = '2024-01-01T00:00:00Z';",
    );
}

#[test]
fn test_alter_pipe_if_exists() {
    format_and_verify("ALTER PIPE IF EXISTS my_pipe REFRESH;");
}

// ==========================================================================
// DROP PIPE
// ==========================================================================

#[test]
fn test_drop_pipe_basic() {
    format_and_verify("DROP PIPE my_pipe;");
}

#[test]
fn test_drop_pipe_if_exists() {
    format_and_verify("DROP PIPE IF EXISTS my_pipe;");
}

// ==========================================================================
// Multi-statement tests (critical for NodeId collision detection)
// ==========================================================================

#[test]
fn test_warehouse_multi_statement() {
    format_and_verify(
        "CREATE WAREHOUSE wh1 WAREHOUSE_SIZE = 'SMALL';
         ALTER WAREHOUSE wh1 SET AUTO_SUSPEND = 300;
         ALTER WAREHOUSE wh1 SUSPEND;
         DROP WAREHOUSE IF EXISTS wh1;",
    );
}

#[test]
fn test_pipe_multi_statement() {
    format_and_verify(
        "CREATE PIPE pipe1 AS COPY INTO t1 FROM @stage1;
         ALTER PIPE pipe1 SET TAG team = 'data';
         ALTER PIPE pipe1 REFRESH;
         DROP PIPE IF EXISTS pipe1;",
    );
}

#[test]
fn test_mixed_warehouse_pipe_statements() {
    format_and_verify(
        "CREATE WAREHOUSE etl_wh WAREHOUSE_SIZE = 'LARGE';
         CREATE PIPE ingest_pipe AUTO_INGEST = TRUE AS COPY INTO t1 FROM @s1;
         ALTER WAREHOUSE etl_wh RESUME;
         ALTER PIPE ingest_pipe REFRESH;
         DROP PIPE IF EXISTS ingest_pipe;
         DROP WAREHOUSE IF EXISTS etl_wh;",
    );
}

// ==========================================================================
// INSERT OR REPLACE (Databricks)
// ==========================================================================

#[test]
fn test_insert_or_replace_basic() {
    format_and_verify("INSERT OR REPLACE INTO my_table VALUES (1, 'test');");
}

#[test]
fn test_insert_or_replace_with_columns() {
    format_and_verify("INSERT OR REPLACE INTO my_table (id, name) VALUES (1, 'test');");
}

#[test]
fn test_insert_or_replace_select() {
    format_and_verify("INSERT OR REPLACE INTO target_table SELECT * FROM source_table;");
}

#[test]
fn test_regular_insert_still_works() {
    // Ensure existing INSERT isn't broken
    format_and_verify("INSERT INTO my_table VALUES (1, 'test');");
}

#[test]
fn test_insert_overwrite_still_works() {
    // Ensure existing INSERT OVERWRITE isn't broken
    format_and_verify("INSERT OVERWRITE INTO my_table SELECT * FROM t;");
}

// ==========================================================================
// |> pipe operator (lexer)
// ==========================================================================

#[test]
fn test_pipe_operator_tokenization() {
    use lexega_syntax::lexer::tokenize;
    let result = tokenize("SELECT * FROM t |> WHERE x > 1");
    // Should NOT have Unknown tokens — |> should be a valid operator
    let has_unknown = result
        .tokens
        .iter()
        .any(|t| matches!(t.kind, lexega_syntax::TokenKind::Unknown));
    assert!(
        !has_unknown,
        "Pipe operator |> should be tokenized as Operator, not Unknown"
    );

    // Verify it's an Operator::PipeGt
    let has_pipe_gt = result.tokens.iter().any(|t| {
        matches!(
            t.kind,
            lexega_syntax::TokenKind::Operator(lexega_syntax::lexer::Operator::PipeGt)
        )
    });
    assert!(has_pipe_gt, "Expected Operator::PipeGt token for |>");
}

#[test]
fn test_pipe_pipe_still_works() {
    // Ensure || (string concat) still works
    use lexega_syntax::lexer::tokenize;
    let result = tokenize("SELECT 'a' || 'b'");
    let has_pipe_pipe = result.tokens.iter().any(|t| {
        matches!(
            t.kind,
            lexega_syntax::TokenKind::Operator(lexega_syntax::lexer::Operator::PipePipe)
        )
    });
    assert!(
        has_pipe_pipe,
        "String concat || should still produce PipePipe"
    );
}

#[test]
fn test_pipe_operator_formatting() {
    // The formatter should preserve |> as-is (span-based)
    format_and_verify("SELECT * FROM t |> WHERE x > 1;");
}
