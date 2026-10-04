// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter configuration

use crate::dialect::{DialectRef, SnowflakeDialect};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Formatter configuration options
#[derive(Debug, Clone)]
pub struct FormatterConfig {
    /// Keyword case style
    pub keyword_case: KeywordCase,

    /// Identifier case style (table/column names)
    pub identifier_case: IdentifierCase,

    /// Indentation style
    pub indent_style: IndentStyle,

    /// Newline style
    pub newline_style: NewlineStyle,

    /// Maximum line length (0 = no limit)
    pub max_line_length: usize,

    /// SQL dialect to use (default: Snowflake)
    /// Note: This field is skipped during serialization/deserialization
    pub dialect: DialectRef,

    /// Whether to align keywords in SELECT clauses
    pub align_keywords: bool,

    /// Whether to add trailing commas
    pub trailing_commas: bool,

    // Advanced formatting options (for future implementation)
    /// Comma placement style
    pub comma_style: CommaStyle,

    /// Put SQL clauses on newlines
    pub clauses_on_newlines: bool,

    /// Put SELECT items on separate lines
    pub select_items_on_newlines: bool,

    /// Put WHERE conditions on separate lines
    pub where_conditions_on_newlines: bool,

    /// Put JOINs on separate lines
    pub joins_on_newlines: bool,

    /// Put GROUP BY items on separate lines
    pub group_by_items_on_newlines: bool,

    /// Put ORDER BY items on separate lines
    pub order_by_items_on_newlines: bool,

    /// Put FROM tables on separate lines
    pub from_tables_on_newlines: bool,

    /// Add spaces around operators
    pub spaces_around_operators: bool,

    /// Add space after commas
    pub space_after_comma: bool,

    /// Align SELECT items vertically
    pub align_select_aliases: bool,

    /// Maximum width for alias alignment (0 = no limit)
    /// Expressions wider than this get minimum spacing instead of alignment
    pub alias_align_max_width: usize,

    /// Align JOIN clauses
    pub align_joins: bool,

    /// Align ON/USING clauses in JOINs
    pub align_join_conditions: bool,

    /// Put JOIN ON/USING clauses on newline
    pub join_on_clause_on_newline: bool,

    /// Indent JOIN ON/USING clauses
    pub indent_join_on_clause: bool,

    /// Where to place boolean operators (AND/OR) in multiline expressions
    pub boolean_operator_position: BooleanOperatorPosition,

    /// Align column definitions in CREATE TABLE
    pub align_column_definitions: bool,

    /// Align UPDATE SET assignments (align = operators)
    pub align_update_set: bool,

    /// Put INSERT VALUES rows on separate lines
    pub insert_values_on_newlines: bool,

    /// Put DELETE USING tables on separate lines
    pub delete_using_on_newlines: bool,

    /// Align MERGE action keywords (UPDATE/DELETE/INSERT)
    pub align_merge_actions: bool,

    /// Indent SELECT list items when on multiple lines
    pub indent_select_items: bool,

    /// Indent FROM tables when on multiple lines
    pub indent_from_tables: bool,

    /// Indent GROUP BY items when on multiple lines
    pub indent_group_by_items: bool,

    /// Indent ORDER BY items when on multiple lines
    pub indent_order_by_items: bool,

    /// Indent subqueries
    pub indent_subqueries: bool,

    /// Uppercase boolean operators (AND, OR, NOT)
    pub uppercase_boolean_operators: bool,

    /// Put semicolons on newline
    pub semicolon_on_newline: bool,

    /// Indent CASE THEN/ELSE
    pub indent_case_then: bool,

    /// Parenthesized expression style
    pub parenthesized_expr_style: ParenthesizedExprStyle,

    /// Normalize JOIN keywords (INNER JOIN vs JOIN)
    pub normalize_join_keywords: bool,

    /// Add spacing between scripting statements
    pub scripting_statement_spacing: bool,

    /// Put DECLARE statements on separate lines in blocks
    pub declare_on_newlines: bool,

    /// Indent DECLARE section content
    pub indent_declare_section: bool,

    /// Add blank line after DECLARE section
    pub blank_line_after_declare: bool,

    /// Put cursor query on newline after CURSOR FOR
    pub cursor_query_on_newline: bool,

    /// Indent cursor query
    pub indent_cursor_query: bool,

    /// Put loop body statements on newlines (WHILE, FOR, LOOP, REPEAT)
    pub loop_body_on_newlines: bool,

    /// Indent loop body statements
    pub indent_loop_body: bool,

    /// Put IF/ELSEIF branches on newlines
    pub if_branches_on_newlines: bool,

    /// Indent IF branch bodies
    pub indent_if_body: bool,

    /// Compact simple SELECT statements
    pub compact_simple_select: bool,

    /// Align CASE WHEN clauses
    pub case_when_aligned: bool,

    /// Compact CASE style
    pub case_style_compact: bool,

    /// Put CASE expression on newline
    pub case_expression_on_newline: bool,

    /// Threshold for IN list to go multiline
    pub in_list_threshold: usize,

    /// Items per line in IN lists (0 = inline, N = multiline with N items per line)
    pub in_list_items_per_line: usize,

    /// Put window function on newline
    pub window_function_on_newline: bool,

    /// Indent window function clauses
    pub indent_window_function_clauses: bool,

    /// PARTITION BY on newline
    pub partition_by_on_newline: bool,

    /// ORDER BY in window on newline
    pub order_by_in_window_on_newline: bool,

    /// Window frame style
    pub window_frame_style: WindowFrameStyle,

    /// CTE on newline
    pub cte_name_on_newline: bool,

    /// CTE indent style
    pub cte_indent_style: CteIndentStyle,

    /// Subquery parenthesis style
    pub subquery_paren_style: SubqueryParenStyle,

    /// FLATTEN style
    pub flatten_style: FlattenStyle,

    /// COPY INTO options style
    pub copy_into_options_style: CopyIntoOptionsStyle,

    /// MATCH_RECOGNIZE format
    pub match_recognize_format: MatchRecognizeFormat,

    /// Put MATCH_RECOGNIZE on new line after table name
    pub match_recognize_on_newline: bool,

    /// MATCH_RECOGNIZE MEASURES clause style
    pub match_recognize_measures_style: MatchRecognizeMeasuresStyle,

    /// MATCH_RECOGNIZE DEFINE clause style
    pub match_recognize_define_style: MatchRecognizeDefineStyle,

    /// Array literal style
    pub array_literal_style: ArrayLiteralStyle,

    /// Array literal threshold for multiline
    pub array_literal_threshold: usize,

    /// Object literal style
    pub object_literal_style: ObjectLiteralStyle,

    // CREATE STAGE options
    /// CREATE STAGE clause layout style
    pub create_stage_clause_style: CreateStageClauseStyle,

    /// Expand CREDENTIALS clause with nested indentation
    pub create_stage_credentials_expanded: bool,

    /// Expand FILE_FORMAT options
    pub create_stage_file_format_expanded: bool,

    // MULTI INSERT options
    /// Indent INTO clauses under INSERT ALL/FIRST
    pub multi_insert_into_indent: bool,

    /// Indent WHEN clauses
    pub multi_insert_when_indent: bool,

    /// Put VALUES clause on new line after column list
    pub multi_insert_values_on_newline: bool,

    // CREATE PROCEDURE/FUNCTION options
    /// Parameter list formatting style
    pub create_proc_func_params_style: ParamListStyle,

    /// Put RETURNS clause on new line
    pub create_proc_func_returns_on_newline: bool,

    /// Parse and format SQL body (for SQL language procedures/functions)
    pub create_proc_func_format_body: bool,

    /// Indent procedure/function body
    pub create_proc_func_body_indent: bool,

    // COPY INTO options
    /// Put FROM clause on new line
    pub copy_into_from_on_newline: bool,

    // PIPE CHAIN options
    /// Pipe chain formatting style
    pub pipe_chain_style: PipeChainStyle,

    // JINJA TEMPLATE options
    /// Format SQL content inside Jinja blocks (if/for/etc)
    pub jinja_format_sql_content: bool,

    /// Indent Jinja delimiters ({% if %}, {% else %}, etc.) relative to surrounding SQL
    pub jinja_indent_delimiters: bool,

    /// Additional indent level for SQL content inside Jinja branches
    pub jinja_content_indent_level: usize,

    /// Preserve original Jinja block spacing (extract as-is)
    pub jinja_preserve_original: bool,

    /// Skip formatting verification (for debugging)
    pub skip_verification: bool,
}

impl Default for FormatterConfig {
    fn default() -> Self {
        Self {
            keyword_case: KeywordCase::Upper,
            identifier_case: IdentifierCase::Preserve,
            indent_style: IndentStyle::Spaces(4),
            newline_style: NewlineStyle::Unix,
            max_line_length: 0,
            dialect: Arc::new(SnowflakeDialect),
            align_keywords: false,
            trailing_commas: false,
            comma_style: CommaStyle::Trailing,
            clauses_on_newlines: true,
            select_items_on_newlines: true,
            where_conditions_on_newlines: true,
            joins_on_newlines: true,
            group_by_items_on_newlines: true,
            order_by_items_on_newlines: true,
            from_tables_on_newlines: false,
            spaces_around_operators: true,
            space_after_comma: true,
            align_select_aliases: true,
            alias_align_max_width: 60,
            align_joins: true,
            align_join_conditions: true,
            join_on_clause_on_newline: true,
            indent_join_on_clause: true,
            boolean_operator_position: BooleanOperatorPosition::Start,
            align_column_definitions: false,
            align_update_set: false,
            insert_values_on_newlines: true,
            delete_using_on_newlines: false,
            align_merge_actions: false,
            indent_select_items: true,
            indent_from_tables: true,
            indent_group_by_items: true,
            indent_order_by_items: true,
            indent_subqueries: true,
            uppercase_boolean_operators: true,
            semicolon_on_newline: false,
            indent_case_then: true,
            parenthesized_expr_style: ParenthesizedExprStyle::Expanded,
            normalize_join_keywords: false,
            scripting_statement_spacing: true,
            declare_on_newlines: true,
            indent_declare_section: true,
            blank_line_after_declare: true,
            cursor_query_on_newline: true,
            indent_cursor_query: true,
            loop_body_on_newlines: true,
            indent_loop_body: true,
            if_branches_on_newlines: true,
            indent_if_body: true,
            compact_simple_select: false,
            case_when_aligned: true,
            case_style_compact: false,
            case_expression_on_newline: true,
            in_list_threshold: 5,
            in_list_items_per_line: 0,
            window_function_on_newline: true,
            indent_window_function_clauses: true,
            partition_by_on_newline: true,
            order_by_in_window_on_newline: true,
            window_frame_style: WindowFrameStyle::Compact,
            cte_name_on_newline: true,
            cte_indent_style: CteIndentStyle::Standard,
            subquery_paren_style: SubqueryParenStyle::SameLine,
            flatten_style: FlattenStyle::Inline,
            copy_into_options_style: CopyIntoOptionsStyle::Stacked,
            match_recognize_format: MatchRecognizeFormat::Expanded,
            match_recognize_on_newline: true,
            match_recognize_measures_style: MatchRecognizeMeasuresStyle::OnePerLine,
            match_recognize_define_style: MatchRecognizeDefineStyle::OnePerLine,
            array_literal_style: ArrayLiteralStyle::Inline,
            array_literal_threshold: 5,
            object_literal_style: ObjectLiteralStyle::Inline,
            create_stage_clause_style: CreateStageClauseStyle::Stacked,
            create_stage_credentials_expanded: false,
            create_stage_file_format_expanded: false,
            multi_insert_into_indent: true,
            multi_insert_when_indent: true,
            multi_insert_values_on_newline: true,
            create_proc_func_params_style: ParamListStyle::Threshold(3),
            create_proc_func_returns_on_newline: true,
            create_proc_func_format_body: false,
            create_proc_func_body_indent: true,
            copy_into_from_on_newline: true,
            pipe_chain_style: PipeChainStyle::Stacked,
            jinja_format_sql_content: true,
            jinja_indent_delimiters: true,
            jinja_content_indent_level: 1,
            jinja_preserve_original: false,
            skip_verification: false,
        }
    }
}

impl FormatterConfig {
    /// Load configuration from TOML file
    pub fn from_toml_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config file '{}': {}", path.display(), e))
    }

    /// Discover .lexega.toml file by walking up from the given path
    ///
    /// Starts at the given path (or its parent if it's a file) and walks up
    /// the directory tree until it finds a .lexega.toml file or reaches the root.
    pub fn discover(start_path: &std::path::Path) -> Option<std::path::PathBuf> {
        // Start from the parent directory if start_path is a file
        let mut current = if start_path.is_file() {
            start_path.parent()?
        } else {
            start_path
        };

        loop {
            let config_path = current.join(".lexega.toml");
            if config_path.exists() && config_path.is_file() {
                return Some(config_path);
            }

            // Move to parent directory
            current = current.parent()?;
        }
    }

    /// Compact style: minimal whitespace, longer lines
    pub fn compact() -> Self {
        Self {
            clauses_on_newlines: false,
            select_items_on_newlines: false,
            where_conditions_on_newlines: false,
            joins_on_newlines: false,
            indent_select_items: false,
            indent_from_tables: false,
            indent_group_by_items: false,
            indent_order_by_items: false,
            compact_simple_select: true,
            case_style_compact: true,
            declare_on_newlines: false,
            blank_line_after_declare: false,
            cursor_query_on_newline: false,
            indent_cursor_query: false,
            loop_body_on_newlines: false,
            if_branches_on_newlines: false,
            create_stage_clause_style: CreateStageClauseStyle::Inline,
            multi_insert_into_indent: false,
            multi_insert_when_indent: false,
            create_proc_func_params_style: ParamListStyle::Inline,
            create_proc_func_returns_on_newline: false,
            copy_into_from_on_newline: false,
            pipe_chain_style: PipeChainStyle::Inline,
            ..Self::default()
        }
    }

    /// Readable style: balanced formatting (same as default)
    pub fn readable() -> Self {
        Self::default()
    }

    /// Ultra readable style: maximum clarity with extra spacing
    pub fn ultra_readable() -> Self {
        Self {
            clauses_on_newlines: true,
            select_items_on_newlines: true,
            where_conditions_on_newlines: true,
            joins_on_newlines: true,
            group_by_items_on_newlines: true,
            order_by_items_on_newlines: true,
            indent_select_items: true,
            indent_from_tables: true,
            indent_group_by_items: true,
            indent_order_by_items: true,
            indent_subqueries: true,
            align_select_aliases: true,
            align_joins: true,
            align_join_conditions: true,
            join_on_clause_on_newline: true,
            indent_join_on_clause: true,
            boolean_operator_position: BooleanOperatorPosition::Start,
            case_when_aligned: true,
            window_function_on_newline: true,
            partition_by_on_newline: true,
            order_by_in_window_on_newline: true,
            declare_on_newlines: true,
            indent_declare_section: true,
            blank_line_after_declare: true,
            loop_body_on_newlines: true,
            indent_loop_body: true,
            if_branches_on_newlines: true,
            indent_if_body: true,
            create_stage_clause_style: CreateStageClauseStyle::Stacked,
            multi_insert_into_indent: true,
            multi_insert_when_indent: true,
            multi_insert_values_on_newline: true,
            create_proc_func_params_style: ParamListStyle::Threshold(3),
            create_proc_func_returns_on_newline: true,
            copy_into_from_on_newline: true,
            pipe_chain_style: PipeChainStyle::Stacked,
            match_recognize_format: MatchRecognizeFormat::Expanded,
            match_recognize_on_newline: true,
            match_recognize_measures_style: MatchRecognizeMeasuresStyle::OnePerLine,
            match_recognize_define_style: MatchRecognizeDefineStyle::OnePerLine,
            parenthesized_expr_style: ParenthesizedExprStyle::Expanded,
            ..Self::default()
        }
    }
}

/// Keyword case style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeywordCase {
    /// UPPERCASE
    Upper,
    /// lowercase
    Lower,
    /// TitleCase
    Title,
    /// Keep original case
    Preserve,
}

/// Identifier case style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentifierCase {
    /// Keep original case
    Preserve,
    /// UPPERCASE
    Upper,
    /// lowercase
    Lower,
}

/// Indentation style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndentStyle {
    /// Use N spaces per indent level
    Spaces(usize),
    /// Use tabs
    Tabs,
}

/// Newline style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NewlineStyle {
    /// Unix-style \n
    Unix,
    /// Windows-style \r\n
    Windows,
}

/// Comma placement style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommaStyle {
    /// Trailing comma (at end of line)
    Trailing,
    /// Leading comma (at start of line)
    Leading,
}

/// Boolean operator position in multiline expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BooleanOperatorPosition {
    /// Operator at end of line: `WHERE a = 1 AND`
    End,
    /// Operator at start of line: `WHERE a = 1\n    AND b = 2`
    Start,
}

/// Parenthesized expression style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParenthesizedExprStyle {
    /// Keep compact
    Compact,
    /// Expand with newlines
    Expanded,
}

/// IN list style
/// Window frame style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowFrameStyle {
    /// Keep compact
    Compact,
    /// Expand with newlines
    Expanded,
}

/// CTE indent style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CteIndentStyle {
    /// Standard indentation
    Standard,
    /// Flush left
    FlushLeft,
    /// Double indent
    DoubleIndent,
}

/// Subquery parenthesis style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubqueryParenStyle {
    /// Opening paren on same line
    SameLine,
    /// Opening paren on new line
    NewLine,
    /// Opening paren on new line, closing too
    NewLineClosing,
}

/// FLATTEN style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlattenStyle {
    /// Keep inline
    Inline,
    /// Stack vertically
    Stacked,
}

/// COPY INTO options style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CopyIntoOptionsStyle {
    /// Keep inline
    Inline,
    /// Stack vertically
    Stacked,
    /// Group related options
    Grouped,
}

/// MATCH_RECOGNIZE format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchRecognizeFormat {
    /// Keep compact
    Compact,
    /// Expand with newlines
    Expanded,
}

/// MATCH_RECOGNIZE MEASURES clause style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchRecognizeMeasuresStyle {
    /// Keep all measures on one line
    Inline,
    /// One measure per line
    OnePerLine,
    /// Break to multiple lines if more than threshold
    Threshold(usize),
}

/// MATCH_RECOGNIZE DEFINE clause style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchRecognizeDefineStyle {
    /// Keep all definitions on one line
    Inline,
    /// One definition per line
    OnePerLine,
    /// Break to multiple lines if more than threshold
    Threshold(usize),
}

/// Array literal style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArrayLiteralStyle {
    /// Keep inline
    Inline,
    /// Multiline
    Multiline,
}

/// Object literal style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectLiteralStyle {
    /// Keep inline
    Inline,
    /// Multiline
    Multiline,
}

/// CREATE STAGE clause style
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CreateStageClauseStyle {
    /// Each clause on new line with indentation
    Stacked,
    /// Keep clauses on same line when possible
    Inline,
    /// Group related clauses together
    Grouped,
}

/// Parameter list style for CREATE PROCEDURE/FUNCTION
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamListStyle {
    /// Keep parameters on one line
    Inline,
    /// Each parameter on new line with indentation
    OnePerLine,
    /// One per line if more than threshold
    Threshold(usize),
}

/// Pipe chain style for experimental |> syntax
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipeChainStyle {
    /// Keep as-is (preserve original formatting)
    Preserve,
    /// Compact all pipes on one line
    Inline,
    /// Each |> on new line with indentation
    Stacked,
}

// Manual Serialize/Deserialize implementations to skip the dialect field
impl Serialize for FormatterConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        // We skip the dialect field during serialization
        // All other fields are serialized normally
        let mut state = serializer.serialize_struct("FormatterConfig", 89)?;

        state.serialize_field("keyword_case", &self.keyword_case)?;
        state.serialize_field("identifier_case", &self.identifier_case)?;
        state.serialize_field("indent_style", &self.indent_style)?;
        state.serialize_field("newline_style", &self.newline_style)?;
        state.serialize_field("max_line_length", &self.max_line_length)?;
        state.serialize_field("dialect", self.dialect.name())?;
        state.serialize_field("align_keywords", &self.align_keywords)?;
        state.serialize_field("trailing_commas", &self.trailing_commas)?;
        state.serialize_field("comma_style", &self.comma_style)?;
        state.serialize_field("clauses_on_newlines", &self.clauses_on_newlines)?;
        state.serialize_field("select_items_on_newlines", &self.select_items_on_newlines)?;
        state.serialize_field(
            "where_conditions_on_newlines",
            &self.where_conditions_on_newlines,
        )?;
        state.serialize_field("joins_on_newlines", &self.joins_on_newlines)?;
        state.serialize_field(
            "group_by_items_on_newlines",
            &self.group_by_items_on_newlines,
        )?;
        state.serialize_field(
            "order_by_items_on_newlines",
            &self.order_by_items_on_newlines,
        )?;
        state.serialize_field("from_tables_on_newlines", &self.from_tables_on_newlines)?;
        state.serialize_field("spaces_around_operators", &self.spaces_around_operators)?;
        state.serialize_field("space_after_comma", &self.space_after_comma)?;
        state.serialize_field("align_select_aliases", &self.align_select_aliases)?;
        state.serialize_field("alias_align_max_width", &self.alias_align_max_width)?;
        state.serialize_field("align_joins", &self.align_joins)?;
        state.serialize_field("align_join_conditions", &self.align_join_conditions)?;
        state.serialize_field("join_on_clause_on_newline", &self.join_on_clause_on_newline)?;
        state.serialize_field("indent_join_on_clause", &self.indent_join_on_clause)?;
        state.serialize_field("boolean_operator_position", &self.boolean_operator_position)?;
        state.serialize_field("align_column_definitions", &self.align_column_definitions)?;
        state.serialize_field("align_update_set", &self.align_update_set)?;
        state.serialize_field("insert_values_on_newlines", &self.insert_values_on_newlines)?;
        state.serialize_field("delete_using_on_newlines", &self.delete_using_on_newlines)?;
        state.serialize_field("align_merge_actions", &self.align_merge_actions)?;
        state.serialize_field("indent_select_items", &self.indent_select_items)?;
        state.serialize_field("indent_from_tables", &self.indent_from_tables)?;
        state.serialize_field("indent_group_by_items", &self.indent_group_by_items)?;
        state.serialize_field("indent_order_by_items", &self.indent_order_by_items)?;
        state.serialize_field("indent_subqueries", &self.indent_subqueries)?;
        state.serialize_field(
            "uppercase_boolean_operators",
            &self.uppercase_boolean_operators,
        )?;
        state.serialize_field("semicolon_on_newline", &self.semicolon_on_newline)?;
        state.serialize_field("indent_case_then", &self.indent_case_then)?;
        state.serialize_field("parenthesized_expr_style", &self.parenthesized_expr_style)?;
        state.serialize_field("normalize_join_keywords", &self.normalize_join_keywords)?;
        state.serialize_field(
            "scripting_statement_spacing",
            &self.scripting_statement_spacing,
        )?;
        state.serialize_field("declare_on_newlines", &self.declare_on_newlines)?;
        state.serialize_field("indent_declare_section", &self.indent_declare_section)?;
        state.serialize_field("blank_line_after_declare", &self.blank_line_after_declare)?;
        state.serialize_field("cursor_query_on_newline", &self.cursor_query_on_newline)?;
        state.serialize_field("indent_cursor_query", &self.indent_cursor_query)?;
        state.serialize_field("loop_body_on_newlines", &self.loop_body_on_newlines)?;
        state.serialize_field("indent_loop_body", &self.indent_loop_body)?;
        state.serialize_field("if_branches_on_newlines", &self.if_branches_on_newlines)?;
        state.serialize_field("indent_if_body", &self.indent_if_body)?;
        state.serialize_field("compact_simple_select", &self.compact_simple_select)?;
        state.serialize_field("case_when_aligned", &self.case_when_aligned)?;
        state.serialize_field("case_style_compact", &self.case_style_compact)?;
        state.serialize_field(
            "case_expression_on_newline",
            &self.case_expression_on_newline,
        )?;
        state.serialize_field("in_list_threshold", &self.in_list_threshold)?;
        state.serialize_field("in_list_items_per_line", &self.in_list_items_per_line)?;
        state.serialize_field(
            "window_function_on_newline",
            &self.window_function_on_newline,
        )?;
        state.serialize_field(
            "indent_window_function_clauses",
            &self.indent_window_function_clauses,
        )?;
        state.serialize_field("partition_by_on_newline", &self.partition_by_on_newline)?;
        state.serialize_field(
            "order_by_in_window_on_newline",
            &self.order_by_in_window_on_newline,
        )?;
        state.serialize_field("window_frame_style", &self.window_frame_style)?;
        state.serialize_field("cte_name_on_newline", &self.cte_name_on_newline)?;
        state.serialize_field("cte_indent_style", &self.cte_indent_style)?;
        state.serialize_field("subquery_paren_style", &self.subquery_paren_style)?;
        state.serialize_field("flatten_style", &self.flatten_style)?;
        state.serialize_field("copy_into_options_style", &self.copy_into_options_style)?;
        state.serialize_field("match_recognize_format", &self.match_recognize_format)?;
        state.serialize_field(
            "match_recognize_on_newline",
            &self.match_recognize_on_newline,
        )?;
        state.serialize_field(
            "match_recognize_measures_style",
            &self.match_recognize_measures_style,
        )?;
        state.serialize_field(
            "match_recognize_define_style",
            &self.match_recognize_define_style,
        )?;
        state.serialize_field("array_literal_style", &self.array_literal_style)?;
        state.serialize_field("array_literal_threshold", &self.array_literal_threshold)?;
        state.serialize_field("object_literal_style", &self.object_literal_style)?;
        state.serialize_field("create_stage_clause_style", &self.create_stage_clause_style)?;
        state.serialize_field(
            "create_stage_credentials_expanded",
            &self.create_stage_credentials_expanded,
        )?;
        state.serialize_field(
            "create_stage_file_format_expanded",
            &self.create_stage_file_format_expanded,
        )?;
        state.serialize_field("multi_insert_into_indent", &self.multi_insert_into_indent)?;
        state.serialize_field("multi_insert_when_indent", &self.multi_insert_when_indent)?;
        state.serialize_field(
            "multi_insert_values_on_newline",
            &self.multi_insert_values_on_newline,
        )?;
        state.serialize_field(
            "create_proc_func_params_style",
            &self.create_proc_func_params_style,
        )?;
        state.serialize_field(
            "create_proc_func_returns_on_newline",
            &self.create_proc_func_returns_on_newline,
        )?;
        state.serialize_field(
            "create_proc_func_format_body",
            &self.create_proc_func_format_body,
        )?;
        state.serialize_field(
            "create_proc_func_body_indent",
            &self.create_proc_func_body_indent,
        )?;
        state.serialize_field("copy_into_from_on_newline", &self.copy_into_from_on_newline)?;
        state.serialize_field("pipe_chain_style", &self.pipe_chain_style)?;
        state.serialize_field("jinja_format_sql_content", &self.jinja_format_sql_content)?;
        state.serialize_field("jinja_indent_delimiters", &self.jinja_indent_delimiters)?;
        state.serialize_field(
            "jinja_content_indent_level",
            &self.jinja_content_indent_level,
        )?;
        state.serialize_field("jinja_preserve_original", &self.jinja_preserve_original)?;
        state.serialize_field("skip_verification", &self.skip_verification)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for FormatterConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into a helper struct, then construct FormatterConfig with dialect
        #[derive(Deserialize)]
        struct FormatterConfigHelper {
            #[serde(default = "default_keyword_case")]
            keyword_case: KeywordCase,
            #[serde(default = "default_identifier_case")]
            identifier_case: IdentifierCase,
            #[serde(default = "default_indent_style")]
            indent_style: IndentStyle,
            #[serde(default = "default_newline_style")]
            newline_style: NewlineStyle,
            #[serde(default)]
            max_line_length: usize,
            #[serde(default)]
            dialect: Option<String>,
            #[serde(default)]
            align_keywords: bool,
            #[serde(default)]
            trailing_commas: bool,
            #[serde(default = "default_comma_style")]
            comma_style: CommaStyle,
            #[serde(default = "default_true")]
            clauses_on_newlines: bool,
            #[serde(default = "default_true")]
            select_items_on_newlines: bool,
            #[serde(default)]
            where_conditions_on_newlines: bool,
            #[serde(default = "default_true")]
            joins_on_newlines: bool,
            #[serde(default)]
            group_by_items_on_newlines: bool,
            #[serde(default)]
            order_by_items_on_newlines: bool,
            #[serde(default)]
            from_tables_on_newlines: bool,
            #[serde(default = "default_true")]
            spaces_around_operators: bool,
            #[serde(default)]
            space_after_comma: bool,
            #[serde(default)]
            align_select_aliases: bool,
            #[serde(default = "default_alias_align_max_width")]
            alias_align_max_width: usize,
            #[serde(default)]
            align_joins: bool,
            #[serde(default)]
            align_join_conditions: bool,
            #[serde(default)]
            join_on_clause_on_newline: bool,
            #[serde(default = "default_true")]
            indent_join_on_clause: bool,
            #[serde(default = "default_boolean_operator_position")]
            boolean_operator_position: BooleanOperatorPosition,
            #[serde(default)]
            align_column_definitions: bool,
            #[serde(default)]
            align_update_set: bool,
            #[serde(default = "default_true")]
            insert_values_on_newlines: bool,
            #[serde(default)]
            delete_using_on_newlines: bool,
            #[serde(default)]
            align_merge_actions: bool,
            #[serde(default)]
            indent_select_items: bool,
            #[serde(default)]
            indent_from_tables: bool,
            #[serde(default = "default_true")]
            indent_group_by_items: bool,
            #[serde(default = "default_true")]
            indent_order_by_items: bool,
            #[serde(default = "default_true")]
            indent_subqueries: bool,
            #[serde(default = "default_true")]
            uppercase_boolean_operators: bool,
            #[serde(default)]
            semicolon_on_newline: bool,
            #[serde(default = "default_true")]
            indent_case_then: bool,
            #[serde(default = "default_parenthesized_expr_style")]
            parenthesized_expr_style: ParenthesizedExprStyle,
            #[serde(default)]
            normalize_join_keywords: bool,
            #[serde(default = "default_true")]
            scripting_statement_spacing: bool,
            #[serde(default = "default_true")]
            declare_on_newlines: bool,
            #[serde(default = "default_true")]
            indent_declare_section: bool,
            #[serde(default = "default_true")]
            blank_line_after_declare: bool,
            #[serde(default = "default_true")]
            cursor_query_on_newline: bool,
            #[serde(default = "default_true")]
            indent_cursor_query: bool,
            #[serde(default = "default_true")]
            loop_body_on_newlines: bool,
            #[serde(default = "default_true")]
            indent_loop_body: bool,
            #[serde(default = "default_true")]
            if_branches_on_newlines: bool,
            #[serde(default = "default_true")]
            indent_if_body: bool,
            #[serde(default)]
            compact_simple_select: bool,
            #[serde(default)]
            case_when_aligned: bool,
            #[serde(default)]
            case_style_compact: bool,
            #[serde(default = "default_true")]
            case_expression_on_newline: bool,
            #[serde(default = "default_in_list_threshold")]
            in_list_threshold: usize,
            #[serde(default)]
            in_list_items_per_line: usize,
            #[serde(default)]
            window_function_on_newline: bool,
            #[serde(default = "default_true")]
            indent_window_function_clauses: bool,
            #[serde(default = "default_true")]
            partition_by_on_newline: bool,
            #[serde(default = "default_true")]
            order_by_in_window_on_newline: bool,
            #[serde(default = "default_window_frame_style")]
            window_frame_style: WindowFrameStyle,
            #[serde(default = "default_true")]
            cte_name_on_newline: bool,
            #[serde(default = "default_cte_indent_style")]
            cte_indent_style: CteIndentStyle,
            #[serde(default = "default_subquery_paren_style")]
            subquery_paren_style: SubqueryParenStyle,
            #[serde(default = "default_flatten_style")]
            flatten_style: FlattenStyle,
            #[serde(default = "default_copy_into_options_style")]
            copy_into_options_style: CopyIntoOptionsStyle,
            #[serde(default = "default_match_recognize_format")]
            match_recognize_format: MatchRecognizeFormat,
            #[serde(default = "default_true")]
            match_recognize_on_newline: bool,
            #[serde(default = "default_match_recognize_measures_style")]
            match_recognize_measures_style: MatchRecognizeMeasuresStyle,
            #[serde(default = "default_match_recognize_define_style")]
            match_recognize_define_style: MatchRecognizeDefineStyle,
            #[serde(default = "default_array_literal_style")]
            array_literal_style: ArrayLiteralStyle,
            #[serde(default = "default_array_literal_threshold")]
            array_literal_threshold: usize,
            #[serde(default = "default_object_literal_style")]
            object_literal_style: ObjectLiteralStyle,
            #[serde(default = "default_create_stage_clause_style")]
            create_stage_clause_style: CreateStageClauseStyle,
            #[serde(default)]
            create_stage_credentials_expanded: bool,
            #[serde(default)]
            create_stage_file_format_expanded: bool,
            #[serde(default = "default_true")]
            multi_insert_into_indent: bool,
            #[serde(default = "default_true")]
            multi_insert_when_indent: bool,
            #[serde(default)]
            multi_insert_values_on_newline: bool,
            #[serde(default = "default_create_proc_func_params_style")]
            create_proc_func_params_style: ParamListStyle,
            #[serde(default = "default_true")]
            create_proc_func_returns_on_newline: bool,
            #[serde(default)]
            create_proc_func_format_body: bool,
            #[serde(default = "default_true")]
            create_proc_func_body_indent: bool,
            #[serde(default = "default_true")]
            copy_into_from_on_newline: bool,
            #[serde(default = "default_pipe_chain_style")]
            pipe_chain_style: PipeChainStyle,
            #[serde(default = "default_true")]
            jinja_format_sql_content: bool,
            #[serde(default = "default_true")]
            jinja_indent_delimiters: bool,
            #[serde(default = "default_jinja_content_indent_level")]
            jinja_content_indent_level: usize,
            #[serde(default)]
            jinja_preserve_original: bool,
            #[serde(default)]
            skip_verification: bool,
        }

        // Default value functions for serde
        fn default_true() -> bool {
            true
        }
        fn default_keyword_case() -> KeywordCase {
            KeywordCase::Upper
        }
        fn default_identifier_case() -> IdentifierCase {
            IdentifierCase::Preserve
        }
        fn default_indent_style() -> IndentStyle {
            IndentStyle::Spaces(4)
        }
        fn default_newline_style() -> NewlineStyle {
            NewlineStyle::Unix
        }
        fn default_comma_style() -> CommaStyle {
            CommaStyle::Trailing
        }
        fn default_boolean_operator_position() -> BooleanOperatorPosition {
            BooleanOperatorPosition::End
        }
        fn default_parenthesized_expr_style() -> ParenthesizedExprStyle {
            ParenthesizedExprStyle::Compact
        }
        fn default_window_frame_style() -> WindowFrameStyle {
            WindowFrameStyle::Compact
        }
        fn default_cte_indent_style() -> CteIndentStyle {
            CteIndentStyle::Standard
        }
        fn default_subquery_paren_style() -> SubqueryParenStyle {
            SubqueryParenStyle::SameLine
        }
        fn default_flatten_style() -> FlattenStyle {
            FlattenStyle::Inline
        }
        fn default_copy_into_options_style() -> CopyIntoOptionsStyle {
            CopyIntoOptionsStyle::Stacked
        }
        fn default_match_recognize_format() -> MatchRecognizeFormat {
            MatchRecognizeFormat::Compact
        }
        fn default_match_recognize_measures_style() -> MatchRecognizeMeasuresStyle {
            MatchRecognizeMeasuresStyle::Threshold(3)
        }
        fn default_match_recognize_define_style() -> MatchRecognizeDefineStyle {
            MatchRecognizeDefineStyle::Threshold(2)
        }
        fn default_array_literal_style() -> ArrayLiteralStyle {
            ArrayLiteralStyle::Inline
        }
        fn default_object_literal_style() -> ObjectLiteralStyle {
            ObjectLiteralStyle::Inline
        }
        fn default_create_stage_clause_style() -> CreateStageClauseStyle {
            CreateStageClauseStyle::Stacked
        }
        fn default_create_proc_func_params_style() -> ParamListStyle {
            ParamListStyle::Inline
        }
        fn default_pipe_chain_style() -> PipeChainStyle {
            PipeChainStyle::Preserve
        }
        fn default_alias_align_max_width() -> usize {
            60
        }
        fn default_in_list_threshold() -> usize {
            5
        }
        fn default_array_literal_threshold() -> usize {
            5
        }
        fn default_jinja_content_indent_level() -> usize {
            1
        }

        let helper = FormatterConfigHelper::deserialize(deserializer)?;

        Ok(FormatterConfig {
            keyword_case: helper.keyword_case,
            identifier_case: helper.identifier_case,
            indent_style: helper.indent_style,
            newline_style: helper.newline_style,
            max_line_length: helper.max_line_length,
            dialect: helper
                .dialect
                .as_deref()
                .and_then(crate::dialect::dialect_from_name)
                .unwrap_or_else(|| Arc::new(SnowflakeDialect)),
            align_keywords: helper.align_keywords,
            trailing_commas: helper.trailing_commas,
            comma_style: helper.comma_style,
            clauses_on_newlines: helper.clauses_on_newlines,
            select_items_on_newlines: helper.select_items_on_newlines,
            where_conditions_on_newlines: helper.where_conditions_on_newlines,
            joins_on_newlines: helper.joins_on_newlines,
            group_by_items_on_newlines: helper.group_by_items_on_newlines,
            order_by_items_on_newlines: helper.order_by_items_on_newlines,
            from_tables_on_newlines: helper.from_tables_on_newlines,
            spaces_around_operators: helper.spaces_around_operators,
            space_after_comma: helper.space_after_comma,
            align_select_aliases: helper.align_select_aliases,
            alias_align_max_width: helper.alias_align_max_width,
            align_joins: helper.align_joins,
            align_join_conditions: helper.align_join_conditions,
            join_on_clause_on_newline: helper.join_on_clause_on_newline,
            indent_join_on_clause: helper.indent_join_on_clause,
            boolean_operator_position: helper.boolean_operator_position,
            align_column_definitions: helper.align_column_definitions,
            align_update_set: helper.align_update_set,
            insert_values_on_newlines: helper.insert_values_on_newlines,
            delete_using_on_newlines: helper.delete_using_on_newlines,
            align_merge_actions: helper.align_merge_actions,
            indent_select_items: helper.indent_select_items,
            indent_from_tables: helper.indent_from_tables,
            indent_group_by_items: helper.indent_group_by_items,
            indent_order_by_items: helper.indent_order_by_items,
            indent_subqueries: helper.indent_subqueries,
            uppercase_boolean_operators: helper.uppercase_boolean_operators,
            semicolon_on_newline: helper.semicolon_on_newline,
            indent_case_then: helper.indent_case_then,
            parenthesized_expr_style: helper.parenthesized_expr_style,
            normalize_join_keywords: helper.normalize_join_keywords,
            scripting_statement_spacing: helper.scripting_statement_spacing,
            declare_on_newlines: helper.declare_on_newlines,
            indent_declare_section: helper.indent_declare_section,
            blank_line_after_declare: helper.blank_line_after_declare,
            cursor_query_on_newline: helper.cursor_query_on_newline,
            indent_cursor_query: helper.indent_cursor_query,
            loop_body_on_newlines: helper.loop_body_on_newlines,
            indent_loop_body: helper.indent_loop_body,
            if_branches_on_newlines: helper.if_branches_on_newlines,
            indent_if_body: helper.indent_if_body,
            compact_simple_select: helper.compact_simple_select,
            case_when_aligned: helper.case_when_aligned,
            case_style_compact: helper.case_style_compact,
            case_expression_on_newline: helper.case_expression_on_newline,
            in_list_threshold: helper.in_list_threshold,
            in_list_items_per_line: helper.in_list_items_per_line,
            window_function_on_newline: helper.window_function_on_newline,
            indent_window_function_clauses: helper.indent_window_function_clauses,
            partition_by_on_newline: helper.partition_by_on_newline,
            order_by_in_window_on_newline: helper.order_by_in_window_on_newline,
            window_frame_style: helper.window_frame_style,
            cte_name_on_newline: helper.cte_name_on_newline,
            cte_indent_style: helper.cte_indent_style,
            subquery_paren_style: helper.subquery_paren_style,
            flatten_style: helper.flatten_style,
            copy_into_options_style: helper.copy_into_options_style,
            match_recognize_format: helper.match_recognize_format,
            match_recognize_on_newline: helper.match_recognize_on_newline,
            match_recognize_measures_style: helper.match_recognize_measures_style,
            match_recognize_define_style: helper.match_recognize_define_style,
            array_literal_style: helper.array_literal_style,
            array_literal_threshold: helper.array_literal_threshold,
            object_literal_style: helper.object_literal_style,
            create_stage_clause_style: helper.create_stage_clause_style,
            create_stage_credentials_expanded: helper.create_stage_credentials_expanded,
            create_stage_file_format_expanded: helper.create_stage_file_format_expanded,
            multi_insert_into_indent: helper.multi_insert_into_indent,
            multi_insert_when_indent: helper.multi_insert_when_indent,
            multi_insert_values_on_newline: helper.multi_insert_values_on_newline,
            create_proc_func_params_style: helper.create_proc_func_params_style,
            create_proc_func_returns_on_newline: helper.create_proc_func_returns_on_newline,
            create_proc_func_format_body: helper.create_proc_func_format_body,
            create_proc_func_body_indent: helper.create_proc_func_body_indent,
            copy_into_from_on_newline: helper.copy_into_from_on_newline,
            pipe_chain_style: helper.pipe_chain_style,
            jinja_format_sql_content: helper.jinja_format_sql_content,
            jinja_indent_delimiters: helper.jinja_indent_delimiters,
            jinja_content_indent_level: helper.jinja_content_indent_level,
            jinja_preserve_original: helper.jinja_preserve_original,
            skip_verification: helper.skip_verification,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FormatterConfig::default();
        assert_eq!(config.keyword_case, KeywordCase::Upper);
        assert_eq!(config.identifier_case, IdentifierCase::Preserve);
        assert_eq!(config.indent_style, IndentStyle::Spaces(4));
        assert_eq!(config.newline_style, NewlineStyle::Unix);
        assert_eq!(config.max_line_length, 0);
        assert!(!config.align_keywords);
        assert!(!config.trailing_commas);
    }

    #[test]
    fn test_keyword_case_variants() {
        assert_eq!(KeywordCase::Upper, KeywordCase::Upper);
        assert_ne!(KeywordCase::Upper, KeywordCase::Lower);
    }

    #[test]
    fn test_indent_style() {
        let spaces = IndentStyle::Spaces(2);
        let tabs = IndentStyle::Tabs;

        match spaces {
            IndentStyle::Spaces(n) => assert_eq!(n, 2),
            _ => panic!("Expected Spaces"),
        }

        assert!(matches!(tabs, IndentStyle::Tabs));
    }
}
