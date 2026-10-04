// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Individual tests for each config field to ensure complete coverage

use lexega_syntax::FormatterConfig;
use std::fs;
use tempfile::TempDir;

// Helper macro to test a boolean field
macro_rules! test_bool_field {
    ($test_name:ident, $field:ident) => {
        #[test]
        fn $test_name() {
            let temp_dir = TempDir::new().unwrap();
            let config_path = temp_dir.path().join(".lexega.toml");

            // Test true
            fs::write(&config_path, format!("{} = true", stringify!($field))).unwrap();
            let config = FormatterConfig::from_toml_file(&config_path).unwrap();
            assert!(config.$field, "{} should be true", stringify!($field));

            // Test false
            fs::write(&config_path, format!("{} = false", stringify!($field))).unwrap();
            let config = FormatterConfig::from_toml_file(&config_path).unwrap();
            assert!(!config.$field, "{} should be false", stringify!($field));
        }
    };
}

// ============================================================================
// BOOLEAN FIELD TESTS - Individual test for each boolean field
// ============================================================================

test_bool_field!(test_align_keywords, align_keywords);
test_bool_field!(test_trailing_commas, trailing_commas);
test_bool_field!(test_clauses_on_newlines, clauses_on_newlines);
test_bool_field!(test_select_items_on_newlines, select_items_on_newlines);
test_bool_field!(
    test_where_conditions_on_newlines,
    where_conditions_on_newlines
);
test_bool_field!(test_joins_on_newlines, joins_on_newlines);
test_bool_field!(test_group_by_items_on_newlines, group_by_items_on_newlines);
test_bool_field!(test_order_by_items_on_newlines, order_by_items_on_newlines);
test_bool_field!(test_from_tables_on_newlines, from_tables_on_newlines);
test_bool_field!(test_spaces_around_operators, spaces_around_operators);
test_bool_field!(test_space_after_comma, space_after_comma);
test_bool_field!(test_align_select_aliases, align_select_aliases);
test_bool_field!(test_align_joins, align_joins);
test_bool_field!(test_align_join_conditions, align_join_conditions);
test_bool_field!(test_join_on_clause_on_newline, join_on_clause_on_newline);
test_bool_field!(test_indent_join_on_clause, indent_join_on_clause);
test_bool_field!(test_align_column_definitions, align_column_definitions);
test_bool_field!(test_align_update_set, align_update_set);
test_bool_field!(test_insert_values_on_newlines, insert_values_on_newlines);
test_bool_field!(test_delete_using_on_newlines, delete_using_on_newlines);
test_bool_field!(test_align_merge_actions, align_merge_actions);
test_bool_field!(test_indent_select_items, indent_select_items);
test_bool_field!(test_indent_from_tables, indent_from_tables);
test_bool_field!(test_indent_group_by_items, indent_group_by_items);
test_bool_field!(test_indent_order_by_items, indent_order_by_items);
test_bool_field!(test_indent_subqueries, indent_subqueries);
test_bool_field!(
    test_uppercase_boolean_operators,
    uppercase_boolean_operators
);
test_bool_field!(test_semicolon_on_newline, semicolon_on_newline);
test_bool_field!(test_indent_case_then, indent_case_then);
test_bool_field!(test_normalize_join_keywords, normalize_join_keywords);
test_bool_field!(
    test_scripting_statement_spacing,
    scripting_statement_spacing
);
test_bool_field!(test_declare_on_newlines, declare_on_newlines);
test_bool_field!(test_indent_declare_section, indent_declare_section);
test_bool_field!(test_blank_line_after_declare, blank_line_after_declare);
test_bool_field!(test_cursor_query_on_newline, cursor_query_on_newline);
test_bool_field!(test_indent_cursor_query, indent_cursor_query);
test_bool_field!(test_loop_body_on_newlines, loop_body_on_newlines);
test_bool_field!(test_indent_loop_body, indent_loop_body);
test_bool_field!(test_if_branches_on_newlines, if_branches_on_newlines);
test_bool_field!(test_indent_if_body, indent_if_body);
test_bool_field!(test_compact_simple_select, compact_simple_select);
test_bool_field!(test_case_when_aligned, case_when_aligned);
test_bool_field!(test_case_style_compact, case_style_compact);
test_bool_field!(test_case_expression_on_newline, case_expression_on_newline);
test_bool_field!(test_window_function_on_newline, window_function_on_newline);
test_bool_field!(
    test_indent_window_function_clauses,
    indent_window_function_clauses
);
test_bool_field!(test_partition_by_on_newline, partition_by_on_newline);
test_bool_field!(
    test_order_by_in_window_on_newline,
    order_by_in_window_on_newline
);
test_bool_field!(test_cte_name_on_newline, cte_name_on_newline);
test_bool_field!(test_match_recognize_on_newline, match_recognize_on_newline);
test_bool_field!(
    test_create_stage_credentials_expanded,
    create_stage_credentials_expanded
);
test_bool_field!(
    test_create_stage_file_format_expanded,
    create_stage_file_format_expanded
);
test_bool_field!(test_multi_insert_into_indent, multi_insert_into_indent);
test_bool_field!(test_multi_insert_when_indent, multi_insert_when_indent);
test_bool_field!(
    test_multi_insert_values_on_newline,
    multi_insert_values_on_newline
);
test_bool_field!(
    test_create_proc_func_returns_on_newline,
    create_proc_func_returns_on_newline
);
test_bool_field!(
    test_create_proc_func_format_body,
    create_proc_func_format_body
);
test_bool_field!(
    test_create_proc_func_body_indent,
    create_proc_func_body_indent
);
test_bool_field!(test_copy_into_from_on_newline, copy_into_from_on_newline);
test_bool_field!(test_jinja_format_sql_content, jinja_format_sql_content);
test_bool_field!(test_jinja_indent_delimiters, jinja_indent_delimiters);
test_bool_field!(test_jinja_preserve_original, jinja_preserve_original);
test_bool_field!(test_skip_verification, skip_verification);
