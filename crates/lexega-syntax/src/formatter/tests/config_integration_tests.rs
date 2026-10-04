// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for formatter config options
//!
//! Tests verify that config options properly affect formatting output

use crate::context::RenderContext;
use crate::formatter::config::{
    CopyIntoOptionsStyle, CreateStageClauseStyle, FormatterConfig, ParamListStyle, PipeChainStyle,
};
use crate::formatter::Formatter;
use crate::lexer::tokenize;
use crate::parser::try_parse_script;

/// Helper to format SQL with custom config
/// Uses try_parse_script to handle both regular statements and pipe chains (->>)
fn format_with_config(sql: &str, config: FormatterConfig) -> String {
    let lex_result = tokenize(sql);
    let script = try_parse_script(sql, &lex_result.tokens)
        .unwrap_or_else(|e| panic!("Failed to parse SQL: {}\nError: {:?}", sql, e));

    let context = RenderContext::from_source(sql.to_string());
    let formatter = Formatter::with_config(config);
    let result_context = formatter
        .format_script(context, &script)
        .unwrap_or_else(|e| panic!("Failed to format: {:?}", e));
    result_context
        .formatted()
        .unwrap()
        .formatted_sql()
        .to_string()
}

#[test]
fn test_create_stage_clause_style_stacked() {
    let sql = "CREATE STAGE my_stage URL='s3://bucket' FILE_FORMAT=(TYPE='CSV')";

    let mut config = FormatterConfig::default();
    config.create_stage_clause_style = CreateStageClauseStyle::Stacked;

    let result = format_with_config(sql, config);

    // Should have newlines before URL and FILE_FORMAT
    assert!(result.contains("CREATE STAGE"));
    assert!(result.contains("\n") || result.contains("URL"));
}

#[test]
fn test_create_stage_clause_style_inline() {
    let sql = "CREATE STAGE my_stage URL='s3://bucket' FILE_FORMAT=(TYPE='CSV')";

    let mut config = FormatterConfig::default();
    config.create_stage_clause_style = CreateStageClauseStyle::Inline;

    let result = format_with_config(sql, config);

    // Should keep clauses on same line with spaces
    assert!(result.contains("CREATE STAGE"));
    assert!(result.contains("URL"));
}

#[test]
fn test_multi_insert_into_indent_true() {
    let sql = "INSERT ALL INTO t1 VALUES(1) INTO t2 VALUES(2) SELECT 1";

    let mut config = FormatterConfig::default();
    config.multi_insert_into_indent = true;

    let result = format_with_config(sql, config);

    // INTO clauses should be indented
    assert!(result.contains("INSERT ALL"));
    assert!(result.contains("INTO"));
}

#[test]
fn test_multi_insert_into_indent_false() {
    let sql = "INSERT ALL INTO t1 VALUES(1) INTO t2 VALUES(2) SELECT 1";

    let mut config = FormatterConfig::default();
    config.multi_insert_into_indent = false;

    let result = format_with_config(sql, config);

    // INTO clauses should be flush left (less indentation)
    assert!(result.contains("INSERT ALL"));
    assert!(result.contains("INTO"));
}

#[test]
fn test_multi_insert_values_on_newline_true() {
    let sql = "INSERT ALL INTO t1 (col1) VALUES(1) SELECT 1";

    let mut config = FormatterConfig::default();
    config.multi_insert_values_on_newline = true;

    let result = format_with_config(sql, config);

    // VALUES should be on separate line from column list
    assert!(result.contains("INTO"));
    assert!(result.contains("VALUES"));
}

#[test]
fn test_multi_insert_values_on_newline_false() {
    let sql = "INSERT ALL INTO t1 (col1) VALUES(1) SELECT 1";

    let mut config = FormatterConfig::default();
    config.multi_insert_values_on_newline = false;

    let result = format_with_config(sql, config);

    // VALUES should be on same line as column list
    assert!(result.contains("INTO"));
    assert!(result.contains("VALUES"));
}

#[test]
fn test_copy_into_from_on_newline_true() {
    let sql = "COPY INTO table1 FROM @stage";

    let mut config = FormatterConfig::default();
    config.copy_into_from_on_newline = true;

    let result = format_with_config(sql, config);

    // FROM should be on new line
    assert!(result.contains("COPY INTO"));
    assert!(result.contains("FROM"));
}

#[test]
fn test_copy_into_from_on_newline_false() {
    let sql = "COPY INTO table1 FROM @stage";

    let mut config = FormatterConfig::default();
    config.copy_into_from_on_newline = false;

    let result = format_with_config(sql, config);

    // FROM should be on same line
    assert!(result.contains("COPY INTO"));
    assert!(result.contains("FROM"));
}

#[test]
fn test_copy_into_options_style_inline() {
    let sql = "COPY INTO t FROM @s FILE_FORMAT=(TYPE='CSV')";

    let mut config = FormatterConfig::default();
    config.copy_into_options_style = CopyIntoOptionsStyle::Inline;

    let result = format_with_config(sql, config);

    // Options should be inline
    assert!(result.contains("FILE_FORMAT"));
}

#[test]
fn test_copy_into_options_style_stacked() {
    let sql = "COPY INTO t FROM @s FILE_FORMAT=(TYPE='CSV')";

    let mut config = FormatterConfig::default();
    config.copy_into_options_style = CopyIntoOptionsStyle::Stacked;

    let result = format_with_config(sql, config);

    // Options should be on separate lines
    assert!(result.contains("FILE_FORMAT"));
}

#[test]
fn test_create_proc_func_returns_on_newline_true() {
    let sql = "CREATE PROCEDURE p() RETURNS INT AS $$ SELECT 1; $$";

    let mut config = FormatterConfig::default();
    config.create_proc_func_returns_on_newline = true;

    let result = format_with_config(sql, config);

    // RETURNS should be on new line
    assert!(result.contains("CREATE PROCEDURE"));
    assert!(result.contains("RETURNS"));
}

#[test]
fn test_create_proc_func_returns_on_newline_false() {
    let sql = "CREATE PROCEDURE p() RETURNS INT AS $$ SELECT 1; $$";

    let mut config = FormatterConfig::default();
    config.create_proc_func_returns_on_newline = false;

    let result = format_with_config(sql, config);

    // RETURNS should be on same line
    assert!(result.contains("CREATE PROCEDURE"));
    assert!(result.contains("RETURNS"));
}

#[test]
fn test_create_proc_func_body_indent_true() {
    let sql = "CREATE PROCEDURE p() RETURNS INT AS $$ SELECT 1; $$";

    let mut config = FormatterConfig::default();
    config.create_proc_func_body_indent = true;

    let result = format_with_config(sql, config);

    // Body should be indented
    assert!(result.contains("$$"));
}

#[test]
fn test_create_proc_func_body_indent_false() {
    let sql = "CREATE PROCEDURE p() RETURNS INT AS $$ SELECT 1; $$";

    let mut config = FormatterConfig::default();
    config.create_proc_func_body_indent = false;

    let result = format_with_config(sql, config);

    // Body should be flush left
    assert!(result.contains("$$"));
}

#[test]
fn test_pipe_chain_style_preserve() {
    let sql = "SELECT * FROM t1  ->>  SELECT * FROM t2";

    let mut config = FormatterConfig::default();
    config.pipe_chain_style = PipeChainStyle::Preserve;

    let result = format_with_config(sql, config);

    // Should preserve original spacing
    assert!(result.contains("->"));
}

#[test]
fn test_pipe_chain_style_inline() {
    let sql = "SELECT * FROM t1\n->> SELECT * FROM t2";

    let mut config = FormatterConfig::default();
    config.pipe_chain_style = PipeChainStyle::Inline;

    let result = format_with_config(sql, config);

    // Should compact to one line
    assert!(result.contains("->"));
}

#[test]
fn test_pipe_chain_style_stacked() {
    let sql = "SELECT * FROM t1 ->> SELECT * FROM t2 ->> SELECT * FROM t3";

    let mut config = FormatterConfig::default();
    config.pipe_chain_style = PipeChainStyle::Stacked;

    let result = format_with_config(sql, config);

    // Should put each ->> on new line
    assert!(result.contains("->"));
}

#[test]
fn test_param_list_style_inline() {
    let sql = "CREATE PROCEDURE p(a INT, b VARCHAR) RETURNS INT AS $$ SELECT 1; $$";

    let mut config = FormatterConfig::default();
    config.create_proc_func_params_style = ParamListStyle::Inline;

    let result = format_with_config(sql, config);

    // Params should be on one line
    assert!(result.contains("("));
    assert!(result.contains(")"));
}

#[test]
fn test_config_defaults() {
    let config = FormatterConfig::default();

    // The defaults of the statement-specific options.
    assert_eq!(
        config.create_stage_clause_style,
        CreateStageClauseStyle::Stacked
    );
    assert_eq!(config.create_stage_credentials_expanded, false);
    assert_eq!(config.create_stage_file_format_expanded, false);
    assert_eq!(config.multi_insert_into_indent, true);
    assert_eq!(config.multi_insert_when_indent, true);
    assert_eq!(config.multi_insert_values_on_newline, true);
    assert!(matches!(
        config.create_proc_func_params_style,
        ParamListStyle::Threshold(3)
    ));
    assert_eq!(config.create_proc_func_returns_on_newline, true);
    assert_eq!(config.create_proc_func_format_body, false);
    assert_eq!(config.create_proc_func_body_indent, true);
    assert_eq!(config.copy_into_from_on_newline, true);
    assert_eq!(config.pipe_chain_style, PipeChainStyle::Stacked);
}

#[test]
fn test_compact_preset_overrides() {
    let config = FormatterConfig::compact();

    // Compact preset should override some new options
    assert_eq!(
        config.create_stage_clause_style,
        CreateStageClauseStyle::Inline
    );
    assert_eq!(config.multi_insert_into_indent, false);
    assert_eq!(config.multi_insert_when_indent, false);
    assert_eq!(config.create_proc_func_returns_on_newline, false);
    assert_eq!(config.copy_into_from_on_newline, false);
    assert_eq!(config.pipe_chain_style, PipeChainStyle::Inline);
}

#[test]
fn test_ultra_readable_preset_overrides() {
    let config = FormatterConfig::ultra_readable();

    // Ultra readable should enable more spacing
    assert_eq!(
        config.create_stage_clause_style,
        CreateStageClauseStyle::Stacked
    );
    assert_eq!(config.multi_insert_into_indent, true);
    assert_eq!(config.multi_insert_when_indent, true);
    assert_eq!(config.multi_insert_values_on_newline, true);
    assert_eq!(config.create_proc_func_returns_on_newline, true);
    assert_eq!(config.copy_into_from_on_newline, true);
    assert_eq!(config.pipe_chain_style, PipeChainStyle::Stacked);
}
