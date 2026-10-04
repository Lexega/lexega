// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Comprehensive tests for all FormatterConfig options

use lexega_syntax::{
    ArrayLiteralStyle, BooleanOperatorPosition, CommaStyle, CopyIntoOptionsStyle,
    CreateStageClauseStyle, CteIndentStyle, FlattenStyle, FormatterConfig, IdentifierCase,
    IndentStyle, KeywordCase, MatchRecognizeDefineStyle, MatchRecognizeFormat,
    MatchRecognizeMeasuresStyle, NewlineStyle, ObjectLiteralStyle, ParamListStyle,
    ParenthesizedExprStyle, PipeChainStyle, SubqueryParenStyle, WindowFrameStyle,
};
use std::fs;
use tempfile::TempDir;

// ============================================================================
// ENUM VARIANT TESTS - Test all possible values for each enum type
// ============================================================================

#[test]
fn test_keyword_case_all_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("upper", KeywordCase::Upper),
        ("lower", KeywordCase::Lower),
        ("title", KeywordCase::Title),
        ("preserve", KeywordCase::Preserve),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(&config_path, format!("keyword_case = \"{}\"", variant_str)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.keyword_case) {
            (KeywordCase::Upper, KeywordCase::Upper) => true,
            (KeywordCase::Lower, KeywordCase::Lower) => true,
            (KeywordCase::Title, KeywordCase::Title) => true,
            (KeywordCase::Preserve, KeywordCase::Preserve) => true,
            _ => false,
        };

        assert!(matches, "Failed for keyword_case = '{}'", variant_str);
    }
}

#[test]
fn test_identifier_case_all_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("upper", IdentifierCase::Upper),
        ("lower", IdentifierCase::Lower),
        ("preserve", IdentifierCase::Preserve),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("identifier_case = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.identifier_case) {
            (IdentifierCase::Upper, IdentifierCase::Upper) => true,
            (IdentifierCase::Lower, IdentifierCase::Lower) => true,
            (IdentifierCase::Preserve, IdentifierCase::Preserve) => true,
            _ => false,
        };

        assert!(matches, "Failed for identifier_case = '{}'", variant_str);
    }
}

#[test]
fn test_indent_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Test spaces with different sizes
    for spaces in [2, 4, 8] {
        let toml = format!("indent_style = {{ spaces = {} }}", spaces);
        fs::write(&config_path, &toml).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        match config.indent_style {
            IndentStyle::Spaces(n) => assert_eq!(n, spaces),
            _ => panic!("Expected Spaces({}), got {:?}", spaces, config.indent_style),
        }
    }

    // Test tabs
    fs::write(&config_path, "indent_style = \"tabs\"").unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(config.indent_style, IndentStyle::Tabs));
}

#[test]
fn test_newline_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("unix", NewlineStyle::Unix),
        ("windows", NewlineStyle::Windows),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(&config_path, format!("newline_style = \"{}\"", variant_str)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.newline_style) {
            (NewlineStyle::Unix, NewlineStyle::Unix) => true,
            (NewlineStyle::Windows, NewlineStyle::Windows) => true,
            _ => false,
        };

        assert!(matches, "Failed for newline_style = '{}'", variant_str);
    }
}

#[test]
fn test_comma_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("trailing", CommaStyle::Trailing),
        ("leading", CommaStyle::Leading),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(&config_path, format!("comma_style = \"{}\"", variant_str)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.comma_style) {
            (CommaStyle::Trailing, CommaStyle::Trailing) => true,
            (CommaStyle::Leading, CommaStyle::Leading) => true,
            _ => false,
        };

        assert!(matches, "Failed for comma_style = '{}'", variant_str);
    }
}

#[test]
fn test_boolean_operator_position_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("end", BooleanOperatorPosition::End),
        ("start", BooleanOperatorPosition::Start),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("boolean_operator_position = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.boolean_operator_position) {
            (BooleanOperatorPosition::End, BooleanOperatorPosition::End) => true,
            (BooleanOperatorPosition::Start, BooleanOperatorPosition::Start) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for boolean_operator_position = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_parenthesized_expr_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("compact", ParenthesizedExprStyle::Compact),
        ("expanded", ParenthesizedExprStyle::Expanded),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("parenthesized_expr_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.parenthesized_expr_style) {
            (ParenthesizedExprStyle::Compact, ParenthesizedExprStyle::Compact) => true,
            (ParenthesizedExprStyle::Expanded, ParenthesizedExprStyle::Expanded) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for parenthesized_expr_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_window_frame_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("compact", WindowFrameStyle::Compact),
        ("expanded", WindowFrameStyle::Expanded),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("window_frame_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.window_frame_style) {
            (WindowFrameStyle::Compact, WindowFrameStyle::Compact) => true,
            (WindowFrameStyle::Expanded, WindowFrameStyle::Expanded) => true,
            _ => false,
        };

        assert!(matches, "Failed for window_frame_style = '{}'", variant_str);
    }
}

#[test]
fn test_cte_indent_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("standard", CteIndentStyle::Standard),
        ("flush_left", CteIndentStyle::FlushLeft),
        ("double_indent", CteIndentStyle::DoubleIndent),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("cte_indent_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.cte_indent_style) {
            (CteIndentStyle::Standard, CteIndentStyle::Standard) => true,
            (CteIndentStyle::FlushLeft, CteIndentStyle::FlushLeft) => true,
            (CteIndentStyle::DoubleIndent, CteIndentStyle::DoubleIndent) => true,
            _ => false,
        };

        assert!(matches, "Failed for cte_indent_style = '{}'", variant_str);
    }
}

#[test]
fn test_subquery_paren_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("same_line", SubqueryParenStyle::SameLine),
        ("new_line", SubqueryParenStyle::NewLine),
        ("new_line_closing", SubqueryParenStyle::NewLineClosing),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("subquery_paren_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.subquery_paren_style) {
            (SubqueryParenStyle::SameLine, SubqueryParenStyle::SameLine) => true,
            (SubqueryParenStyle::NewLine, SubqueryParenStyle::NewLine) => true,
            (SubqueryParenStyle::NewLineClosing, SubqueryParenStyle::NewLineClosing) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for subquery_paren_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_flatten_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("inline", FlattenStyle::Inline),
        ("stacked", FlattenStyle::Stacked),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(&config_path, format!("flatten_style = \"{}\"", variant_str)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.flatten_style) {
            (FlattenStyle::Inline, FlattenStyle::Inline) => true,
            (FlattenStyle::Stacked, FlattenStyle::Stacked) => true,
            _ => false,
        };

        assert!(matches, "Failed for flatten_style = '{}'", variant_str);
    }
}

#[test]
fn test_copy_into_options_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("inline", CopyIntoOptionsStyle::Inline),
        ("stacked", CopyIntoOptionsStyle::Stacked),
        ("grouped", CopyIntoOptionsStyle::Grouped),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("copy_into_options_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.copy_into_options_style) {
            (CopyIntoOptionsStyle::Inline, CopyIntoOptionsStyle::Inline) => true,
            (CopyIntoOptionsStyle::Stacked, CopyIntoOptionsStyle::Stacked) => true,
            (CopyIntoOptionsStyle::Grouped, CopyIntoOptionsStyle::Grouped) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for copy_into_options_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_match_recognize_format_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("compact", MatchRecognizeFormat::Compact),
        ("expanded", MatchRecognizeFormat::Expanded),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("match_recognize_format = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.match_recognize_format) {
            (MatchRecognizeFormat::Compact, MatchRecognizeFormat::Compact) => true,
            (MatchRecognizeFormat::Expanded, MatchRecognizeFormat::Expanded) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for match_recognize_format = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_match_recognize_measures_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Test Inline variant
    fs::write(&config_path, "match_recognize_measures_style = \"inline\"").unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.match_recognize_measures_style,
        MatchRecognizeMeasuresStyle::Inline
    ));

    // Test OnePerLine variant
    fs::write(
        &config_path,
        "match_recognize_measures_style = \"one_per_line\"",
    )
    .unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.match_recognize_measures_style,
        MatchRecognizeMeasuresStyle::OnePerLine
    ));

    // Test Threshold variant with different values
    for threshold in [2, 3, 5, 10] {
        let toml = format!(
            "match_recognize_measures_style = {{ threshold = {} }}",
            threshold
        );
        fs::write(&config_path, &toml).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        match config.match_recognize_measures_style {
            MatchRecognizeMeasuresStyle::Threshold(n) => assert_eq!(n, threshold),
            _ => panic!("Expected Threshold({})", threshold),
        }
    }
}

#[test]
fn test_match_recognize_define_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Test Inline variant
    fs::write(&config_path, "match_recognize_define_style = \"inline\"").unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.match_recognize_define_style,
        MatchRecognizeDefineStyle::Inline
    ));

    // Test OnePerLine variant
    fs::write(
        &config_path,
        "match_recognize_define_style = \"one_per_line\"",
    )
    .unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.match_recognize_define_style,
        MatchRecognizeDefineStyle::OnePerLine
    ));

    // Test Threshold variant with different values
    for threshold in [2, 3, 5, 10] {
        let toml = format!(
            "match_recognize_define_style = {{ threshold = {} }}",
            threshold
        );
        fs::write(&config_path, &toml).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        match config.match_recognize_define_style {
            MatchRecognizeDefineStyle::Threshold(n) => assert_eq!(n, threshold),
            _ => panic!("Expected Threshold({})", threshold),
        }
    }
}

#[test]
fn test_array_literal_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("inline", ArrayLiteralStyle::Inline),
        ("multiline", ArrayLiteralStyle::Multiline),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("array_literal_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.array_literal_style) {
            (ArrayLiteralStyle::Inline, ArrayLiteralStyle::Inline) => true,
            (ArrayLiteralStyle::Multiline, ArrayLiteralStyle::Multiline) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for array_literal_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_object_literal_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("inline", ObjectLiteralStyle::Inline),
        ("multiline", ObjectLiteralStyle::Multiline),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("object_literal_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.object_literal_style) {
            (ObjectLiteralStyle::Inline, ObjectLiteralStyle::Inline) => true,
            (ObjectLiteralStyle::Multiline, ObjectLiteralStyle::Multiline) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for object_literal_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_create_stage_clause_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("stacked", CreateStageClauseStyle::Stacked),
        ("inline", CreateStageClauseStyle::Inline),
        ("grouped", CreateStageClauseStyle::Grouped),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("create_stage_clause_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.create_stage_clause_style) {
            (CreateStageClauseStyle::Stacked, CreateStageClauseStyle::Stacked) => true,
            (CreateStageClauseStyle::Inline, CreateStageClauseStyle::Inline) => true,
            (CreateStageClauseStyle::Grouped, CreateStageClauseStyle::Grouped) => true,
            _ => false,
        };

        assert!(
            matches,
            "Failed for create_stage_clause_style = '{}'",
            variant_str
        );
    }
}

#[test]
fn test_param_list_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Test Inline variant
    fs::write(&config_path, "create_proc_func_params_style = \"inline\"").unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.create_proc_func_params_style,
        ParamListStyle::Inline
    ));

    // Test OnePerLine variant
    fs::write(
        &config_path,
        "create_proc_func_params_style = \"one_per_line\"",
    )
    .unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    assert!(matches!(
        config.create_proc_func_params_style,
        ParamListStyle::OnePerLine
    ));

    // Test Threshold variant with different values
    for threshold in [2, 3, 5, 10] {
        let toml = format!(
            "create_proc_func_params_style = {{ threshold = {} }}",
            threshold
        );
        fs::write(&config_path, &toml).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        match config.create_proc_func_params_style {
            ParamListStyle::Threshold(n) => assert_eq!(n, threshold),
            _ => panic!("Expected Threshold({})", threshold),
        }
    }
}

#[test]
fn test_pipe_chain_style_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_cases = vec![
        ("preserve", PipeChainStyle::Preserve),
        ("inline", PipeChainStyle::Inline),
        ("stacked", PipeChainStyle::Stacked),
    ];

    for (variant_str, expected_variant) in test_cases {
        fs::write(
            &config_path,
            format!("pipe_chain_style = \"{}\"", variant_str),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected_variant, &config.pipe_chain_style) {
            (PipeChainStyle::Preserve, PipeChainStyle::Preserve) => true,
            (PipeChainStyle::Inline, PipeChainStyle::Inline) => true,
            (PipeChainStyle::Stacked, PipeChainStyle::Stacked) => true,
            _ => false,
        };

        assert!(matches, "Failed for pipe_chain_style = '{}'", variant_str);
    }
}

// ============================================================================
// BOOLEAN FIELD TESTS - Test all boolean configuration options
// ============================================================================

#[test]
fn test_all_boolean_fields() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // List of all boolean fields in FormatterConfig
    let boolean_fields = vec![
        "align_keywords",
        "trailing_commas",
        "clauses_on_newlines",
        "select_items_on_newlines",
        "where_conditions_on_newlines",
        "joins_on_newlines",
        "group_by_items_on_newlines",
        "order_by_items_on_newlines",
        "from_tables_on_newlines",
        "spaces_around_operators",
        "space_after_comma",
        "align_select_aliases",
        "align_joins",
        "align_join_conditions",
        "join_on_clause_on_newline",
        "indent_join_on_clause",
        "align_column_definitions",
        "align_update_set",
        "insert_values_on_newlines",
        "delete_using_on_newlines",
        "align_merge_actions",
        "indent_select_items",
        "indent_from_tables",
        "indent_group_by_items",
        "indent_order_by_items",
        "indent_subqueries",
        "uppercase_boolean_operators",
        "semicolon_on_newline",
        "indent_case_then",
        "normalize_join_keywords",
        "scripting_statement_spacing",
        "declare_on_newlines",
        "indent_declare_section",
        "blank_line_after_declare",
        "cursor_query_on_newline",
        "indent_cursor_query",
        "loop_body_on_newlines",
        "indent_loop_body",
        "if_branches_on_newlines",
        "indent_if_body",
        "compact_simple_select",
        "case_when_aligned",
        "case_style_compact",
        "case_expression_on_newline",
        "window_function_on_newline",
        "indent_window_function_clauses",
        "partition_by_on_newline",
        "order_by_in_window_on_newline",
        "cte_name_on_newline",
        "match_recognize_on_newline",
        "create_stage_credentials_expanded",
        "create_stage_file_format_expanded",
        "multi_insert_into_indent",
        "multi_insert_when_indent",
        "multi_insert_values_on_newline",
        "create_proc_func_returns_on_newline",
        "create_proc_func_format_body",
        "create_proc_func_body_indent",
        "copy_into_from_on_newline",
        "jinja_format_sql_content",
        "jinja_indent_delimiters",
        "jinja_preserve_original",
        "skip_verification",
    ];

    // Test each boolean field with both true and false
    for field in &boolean_fields {
        // Test true
        fs::write(&config_path, format!("{} = true", field)).unwrap();
        let config_true = FormatterConfig::from_toml_file(&config_path).unwrap();

        // Test false
        fs::write(&config_path, format!("{} = false", field)).unwrap();
        let config_false = FormatterConfig::from_toml_file(&config_path).unwrap();

        // Both should parse successfully (specific validation happens elsewhere)
        // Just verify they loaded without error
        drop(config_true);
        drop(config_false);
    }
}

// ============================================================================
// NUMERIC FIELD TESTS - Test all numeric configuration options
// ============================================================================

#[test]
fn test_max_line_length_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 80, 100, 120, 200];

    for value in test_values {
        fs::write(&config_path, format!("max_line_length = {}", value)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.max_line_length, value);
    }
}

#[test]
fn test_alias_align_max_width_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 30, 50, 60, 100];

    for value in test_values {
        fs::write(&config_path, format!("alias_align_max_width = {}", value)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.alias_align_max_width, value);
    }
}

#[test]
fn test_in_list_threshold_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 3, 5, 10, 20];

    for value in test_values {
        fs::write(&config_path, format!("in_list_threshold = {}", value)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.in_list_threshold, value);
    }
}

#[test]
fn test_in_list_items_per_line_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 1, 3, 5, 10];

    for value in test_values {
        fs::write(&config_path, format!("in_list_items_per_line = {}", value)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.in_list_items_per_line, value);
    }
}

#[test]
fn test_array_literal_threshold_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 3, 5, 10];

    for value in test_values {
        fs::write(&config_path, format!("array_literal_threshold = {}", value)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.array_literal_threshold, value);
    }
}

#[test]
fn test_jinja_content_indent_level_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let test_values = vec![0, 1, 2, 4];

    for value in test_values {
        fs::write(
            &config_path,
            format!("jinja_content_indent_level = {}", value),
        )
        .unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.jinja_content_indent_level, value);
    }
}

// ============================================================================
// COMBINATION TESTS - Test multiple options together
// ============================================================================

#[test]
fn test_multiple_options_combination() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
keyword_case = "lower"
identifier_case = "upper"
comma_style = "leading"
max_line_length = 120
align_keywords = true
trailing_commas = false
clauses_on_newlines = true
select_items_on_newlines = false
boolean_operator_position = "start"
window_frame_style = "expanded"
cte_indent_style = "flush_left"
array_literal_threshold = 3
in_list_threshold = 10
jinja_content_indent_level = 2
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert!(matches!(config.keyword_case, KeywordCase::Lower));
    assert!(matches!(config.identifier_case, IdentifierCase::Upper));
    assert!(matches!(config.comma_style, CommaStyle::Leading));
    assert_eq!(config.max_line_length, 120);
    assert!(config.align_keywords);
    assert!(!config.trailing_commas);
    assert!(config.clauses_on_newlines);
    assert!(!config.select_items_on_newlines);
    assert!(matches!(
        config.boolean_operator_position,
        BooleanOperatorPosition::Start
    ));
    assert!(matches!(
        config.window_frame_style,
        WindowFrameStyle::Expanded
    ));
    assert!(matches!(config.cte_indent_style, CteIndentStyle::FlushLeft));
    assert_eq!(config.array_literal_threshold, 3);
    assert_eq!(config.in_list_threshold, 10);
    assert_eq!(config.jinja_content_indent_level, 2);
}

#[test]
fn test_defaults_for_unspecified_options() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Only specify a few options
    let toml_content = r#"
keyword_case = "lower"
max_line_length = 80
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    // Verify specified options
    assert!(matches!(config.keyword_case, KeywordCase::Lower));
    assert_eq!(config.max_line_length, 80);

    // Verify defaults for unspecified options
    let defaults = FormatterConfig::default();
    assert!(matches!(config.identifier_case, IdentifierCase::Preserve));
    assert_eq!(config.identifier_case, defaults.identifier_case);
    assert_eq!(config.comma_style, defaults.comma_style);
    assert_eq!(config.align_keywords, defaults.align_keywords);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_zero_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
max_line_length = 0
alias_align_max_width = 0
in_list_threshold = 0
in_list_items_per_line = 0
array_literal_threshold = 0
jinja_content_indent_level = 0
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert_eq!(config.max_line_length, 0);
    assert_eq!(config.alias_align_max_width, 0);
    assert_eq!(config.in_list_threshold, 0);
    assert_eq!(config.in_list_items_per_line, 0);
    assert_eq!(config.array_literal_threshold, 0);
    assert_eq!(config.jinja_content_indent_level, 0);
}

#[test]
fn test_large_numeric_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
max_line_length = 999999
alias_align_max_width = 9999
in_list_threshold = 1000
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert_eq!(config.max_line_length, 999999);
    assert_eq!(config.alias_align_max_width, 9999);
    assert_eq!(config.in_list_threshold, 1000);
}

#[test]
fn test_empty_config_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Empty file should use all defaults
    fs::write(&config_path, "").unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();
    let defaults = FormatterConfig::default();

    assert_eq!(config.keyword_case, defaults.keyword_case);
    assert_eq!(config.identifier_case, defaults.identifier_case);
    assert_eq!(config.max_line_length, defaults.max_line_length);
}

#[test]
fn test_config_with_comments() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
# This is a comment
keyword_case = "lower"  # inline comment
# Another comment
identifier_case = "upper"
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert!(matches!(config.keyword_case, KeywordCase::Lower));
    assert!(matches!(config.identifier_case, IdentifierCase::Upper));
}

#[test]
fn test_invalid_enum_value() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Invalid keyword_case value
    fs::write(&config_path, "keyword_case = \"invalid_value\"").unwrap();
    let result = FormatterConfig::from_toml_file(&config_path);

    assert!(result.is_err(), "Should fail with invalid enum value");
}

#[test]
fn test_invalid_numeric_value() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Negative value for usize field
    fs::write(&config_path, "max_line_length = -100").unwrap();
    let result = FormatterConfig::from_toml_file(&config_path);

    assert!(result.is_err(), "Should fail with negative value for usize");
}

#[test]
fn test_mixed_case_sensitivity() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // TOML keys are case-sensitive, so this should work
    fs::write(&config_path, "keyword_case = \"UPPER\"").unwrap();
    let result = FormatterConfig::from_toml_file(&config_path);

    // This should fail because "UPPER" != "upper"
    assert!(result.is_err(), "Enum values should be case-sensitive");
}
