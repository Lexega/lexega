// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Lexing, parsing, AST/CST and formatting for SQL.
//!
//! - **Lexer**: dialect-driven tokenization.
//! - **Parser**: permissive; builds the AST from tokens.
//! - **AST / CST**: AST for structure, CST for text.
//! - **Formatter**: emits from CST tokens, never regenerating text.

pub mod ast;
pub mod context;
pub mod cst;
pub mod dialect;
pub mod error;
pub mod formatter;
pub mod lexer;
pub mod parser;
pub mod span_utils;
pub mod syntax;

pub use ast::{AstExpr, AstScript, AstSelect, AstStmt};
pub use cst::{Cst, TokenId};
pub use dialect::{
    dialect_from_name, BigQueryDialect, DatabricksDialect, Dialect, DialectRef, MsSqlDialect,
    MySqlDialect, PostgresDialect, RedshiftDialect, SnowflakeDialect,
};
pub use error::{ParseError, ParseErrorKind, ParseResult};
pub use formatter::config::{
    ArrayLiteralStyle, BooleanOperatorPosition, CommaStyle, CopyIntoOptionsStyle,
    CreateStageClauseStyle, CteIndentStyle, FlattenStyle, FormatterConfig, IdentifierCase,
    IndentStyle, KeywordCase, MatchRecognizeDefineStyle, MatchRecognizeFormat,
    MatchRecognizeMeasuresStyle, NewlineStyle, ObjectLiteralStyle, ParamListStyle,
    ParenthesizedExprStyle, PipeChainStyle, SubqueryParenStyle, WindowFrameStyle,
};
pub use formatter::Formatter;
pub use lexer::token::{
    IdentifierKind, Keyword, LiteralKind, Operator, Punctuation, Span, Token, TokenKind, Trivia,
    TriviaKind,
};
pub use lexer::tokenize;
pub use lexer::Lexer;
pub use parser::core::MIN_PARSE_STACK_BYTES;
pub use parser::{parse_script, parse_select_from_tokens, parse_stmt, Parser};
pub use span_utils::{offset_to_line_col, span_to_line_col, LineCol};

/// Parse a single statement from a string, returning a Result.
pub fn try_parse_stmt_from_str(src: &str) -> ParseResult<AstStmt> {
    let tokens = tokenize(src).tokens;
    let mut parser = Parser::new(src, &tokens);
    let stmt = parser.parse_statement()?;

    // Check if error-recovery nodes were created during parsing
    // This catches cases like malformed CASE expressions where parsing continued
    // but the expression was replaced with an Error node
    if let Some(err) = parser.get_recovery_errors().first() {
        return Err(err.clone());
    }

    // CRITICAL SAFETY CHECKS:
    // 1. Verify all tokens were consumed
    parser.verify_all_tokens_consumed()?;

    // 2. Verify AST span covers all source content (catches consumed-but-not-in-AST bugs)
    parser.verify_span_coverage(src, stmt.span())?;

    Ok(stmt)
}

pub fn try_parse_script_from_str(src: &str) -> ParseResult<AstScript> {
    let tokens = tokenize(src).tokens;
    parser::try_parse_script(src, &tokens)
}

//
// Primary Parsing API
//

/// Parse SQL source into an AST script.
pub fn parse_sql(src: &str) -> ParseResult<AstScript> {
    let tokens = tokenize(src).tokens;
    let mut parser = Parser::new(src, &tokens);
    parser.parse()
}

/// Parse SQL source into an AST script using a specific dialect.
pub fn parse_sql_with_dialect(src: &str, dialect: &dyn Dialect) -> ParseResult<AstScript> {
    let tokens = lexer::tokenize_with_dialect(src, dialect).tokens;
    parser::try_parse_script_with_dialect(src, &tokens, dialect)
}

/// Parse `src` and return its first statement, or `None` when it does
/// not parse or holds no statement.
pub fn parse_stmt_from_str(src: &str) -> Option<AstStmt> {
    parse_sql(src).ok()?.stmts.into_iter().next()
}

//
// Formatting Functions
//

/// Format SQL with default configuration.
pub fn format_sql(src: &str) -> ParseResult<String> {
    format_sql_with_config(src, &FormatterConfig::default())
}

/// Format SQL with custom configuration.
pub fn format_sql_with_config(src: &str, config: &FormatterConfig) -> ParseResult<String> {
    // Parse the SQL into a script using the dialect from config
    let lex_result = lexer::tokenize_with_dialect(src, config.dialect.as_ref());
    let script =
        parser::try_parse_script_with_dialect(src, &lex_result.tokens, config.dialect.as_ref())?;

    // Create context and format
    let context = context::RenderContext::from_source(src);
    let formatter = Formatter::with_config(config.clone());

    let formatted_context = formatter.format_script(context, &script).map_err(|err| {
        ParseError::new(
            Span {
                start: 0,
                end: src.len() as u32,
            },
            ParseErrorKind::InvalidSyntax {
                message: err.to_string(),
            },
        )
    })?;

    // Extract the formatted output
    let formatted = formatted_context
        .formatted()
        .ok_or_else(|| {
            ParseError::new(
                Span {
                    start: 0,
                    end: src.len() as u32,
                },
                ParseErrorKind::InvalidSyntax {
                    message: "Formatting failed - no output generated".to_string(),
                },
            )
        })?
        .formatted_sql()
        .to_string();

    Ok(formatted)
}

/// Format a pre-parsed SQL script with configuration.
///
/// This is useful when you've already parsed the script (e.g., for error handling)
/// and want to format it without re-parsing.
///
/// # Arguments
///
/// * `src` - Original SQL source code
/// * `script` - Pre-parsed AST script
/// * `config` - Formatter configuration
///
/// # Returns
///
/// * `Ok(String)` - Formatted SQL
/// * `Err(ParseError)` - Formatting error
pub fn format_script_with_config(
    src: &str,
    script: &ast::AstScript,
    config: &FormatterConfig,
) -> ParseResult<String> {
    // Create context and format
    let context = context::RenderContext::from_source(src);
    let formatter = Formatter::with_config(config.clone());

    let formatted_context = formatter.format_script(context, script).map_err(|err| {
        ParseError::new(
            Span {
                start: 0,
                end: src.len() as u32,
            },
            ParseErrorKind::InvalidSyntax {
                message: err.to_string(),
            },
        )
    })?;

    // Extract the formatted output
    let formatted = formatted_context
        .formatted()
        .ok_or_else(|| {
            ParseError::new(
                Span {
                    start: 0,
                    end: src.len() as u32,
                },
                ParseErrorKind::InvalidSyntax {
                    message: "Formatting failed - no output generated".to_string(),
                },
            )
        })?
        .formatted_sql()
        .to_string();

    Ok(formatted)
}

/// Production-safe verification that returns Result instead of panicking.
/// Always available, not just in debug builds.
///
/// Returns Ok(()) if formatting is safe, Err with description if issues found.
pub fn verify_formatting_safe(original: &str, formatted: &str) -> Result<(), String> {
    verify_formatting_impl(original, formatted)
}

/// Dialect-aware formatting safety verification.
///
/// Like [`verify_formatting_safe`], but uses dialect-specific tokenization for both
/// original and formatted SQL. This ensures that dialect-specific tokens (backticks,
/// bracket identifiers, @variables, #temp_tables, etc.) are compared correctly.
pub fn verify_formatting_safe_with_dialect(
    original: &str,
    formatted: &str,
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    verify_formatting_impl_with_dialect(original, formatted, dialect)
}

/// Internal implementation of formatting verification.
fn verify_formatting_impl(original: &str, formatted: &str) -> Result<(), String> {
    let orig_tokens = tokenize(original).tokens;
    let fmt_tokens = tokenize(formatted).tokens;

    // Extract significant tokens (exclude comments and pure whitespace)
    let orig_significant: Vec<&str> = orig_tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .filter(|t| !t.lexeme(original).is_empty()) // Exclude empty tokens (e.g., EOF with empty lexeme)
        .map(|t| t.lexeme(original))
        .collect();

    let fmt_significant: Vec<&str> = fmt_tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .filter(|t| !t.lexeme(formatted).is_empty()) // Exclude empty tokens (e.g., EOF with empty lexeme)
        .map(|t| t.lexeme(formatted))
        .collect();

    // Quick check: if token counts match, likely OK (will catch in tests if normalization issue)
    if orig_significant.len() == fmt_significant.len() {
        // Only check comments and patterns if counts match (most common fast path)
        check_comment_preservation(&orig_tokens, &fmt_tokens, original, formatted)?;
        check_critical_syntax_patterns(original, formatted, &orig_significant, &fmt_significant)?;

        // CRITICAL: Verify tokens are actually equivalent, not just same count
        // This catches semantic changes like value substitution, operator changes, etc.
        for (i, (orig_tok, fmt_tok)) in orig_significant
            .iter()
            .zip(fmt_significant.iter())
            .enumerate()
        {
            if !orig_tok.eq_ignore_ascii_case(fmt_tok) {
                return Err(format!(
                    "Token content mismatch at position {}!\n\
                     Original token: '{}'\n\
                     Formatted token: '{}'\n\
                     \n\
                     Token counts match but content differs - this indicates semantic changes!\n\
                     This could be value substitution, operator change, or function swap.\n\
                     First 10 tokens: {:?}\n\
                     Context around position {}: {:?}",
                    i,
                    orig_tok,
                    fmt_tok,
                    &orig_significant[..orig_significant.len().min(10)],
                    i,
                    &orig_significant[i.saturating_sub(3)..(i + 4).min(orig_significant.len())]
                ));
            }
        }

        return Ok(());
    }

    // Token counts differ - check if it's acceptable normalization
    // Check comments before detailed analysis
    check_comment_preservation(&orig_tokens, &fmt_tokens, original, formatted)?;
    check_critical_syntax_patterns(original, formatted, &orig_significant, &fmt_significant)?;

    // Check for acceptable normalizations
    if is_acceptable_token_difference(&orig_significant, &fmt_significant) {
        return Ok(());
    }

    // Find first divergence
    let mut first_diff_idx = 0;
    for (i, (o, f)) in orig_significant
        .iter()
        .zip(fmt_significant.iter())
        .enumerate()
    {
        if !o.eq_ignore_ascii_case(f) {
            first_diff_idx = i;
            break;
        }
        first_diff_idx = i + 1;
    }

    // Data loss detected!
    Err(format!(
        "Token count mismatch!\n\
         Original tokens: {} significant tokens\n\
         Formatted tokens: {} significant tokens\n\
         \n\
         First divergence at index {}: orig='{}' vs fmt='{}'\n\
         Context (idx-5 to idx+5):\n\
         Original: {:?}\n\
         Formatted: {:?}\n\
         \n\
         First 20 original tokens: {:?}\n\
         First 20 formatted tokens: {:?}",
        orig_significant.len(),
        fmt_significant.len(),
        first_diff_idx,
        orig_significant.get(first_diff_idx).unwrap_or(&"<none>"),
        fmt_significant.get(first_diff_idx).unwrap_or(&"<none>"),
        &orig_significant
            [first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(orig_significant.len())],
        &fmt_significant
            [first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(fmt_significant.len())],
        &orig_significant[..orig_significant.len().min(20)],
        &fmt_significant[..fmt_significant.len().min(20)]
    ))
}

/// Dialect-aware implementation of formatting verification.
///
/// Mirrors [`verify_formatting_impl`] but tokenizes with the given dialect so that
/// dialect-specific constructs (backtick identifiers, bracket identifiers, @variables,
/// #temp tables, etc.) are lexed correctly for comparison.
fn verify_formatting_impl_with_dialect(
    original: &str,
    formatted: &str,
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    let orig_tokens = lexer::tokenize_with_dialect(original, dialect).tokens;
    let fmt_tokens = lexer::tokenize_with_dialect(formatted, dialect).tokens;

    // Extract significant tokens (exclude comments and pure whitespace)
    let orig_significant: Vec<&str> = orig_tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .filter(|t| !t.lexeme(original).is_empty())
        .map(|t| t.lexeme(original))
        .collect();

    let fmt_significant: Vec<&str> = fmt_tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .filter(|t| !t.lexeme(formatted).is_empty())
        .map(|t| t.lexeme(formatted))
        .collect();

    if orig_significant.len() == fmt_significant.len() {
        check_comment_preservation(&orig_tokens, &fmt_tokens, original, formatted)?;
        check_critical_syntax_patterns(original, formatted, &orig_significant, &fmt_significant)?;

        for (i, (orig_tok, fmt_tok)) in orig_significant
            .iter()
            .zip(fmt_significant.iter())
            .enumerate()
        {
            if !orig_tok.eq_ignore_ascii_case(fmt_tok) {
                return Err(format!(
                    "Token content mismatch at position {}!\n\
                     Original token: '{}'\n\
                     Formatted token: '{}'\n\
                     \n\
                     Token counts match but content differs - this indicates semantic changes!\n\
                     First 10 tokens: {:?}\n\
                     Context around position {}: {:?}",
                    i,
                    orig_tok,
                    fmt_tok,
                    &orig_significant[..orig_significant.len().min(10)],
                    i,
                    &orig_significant[i.saturating_sub(3)..(i + 4).min(orig_significant.len())]
                ));
            }
        }

        return Ok(());
    }

    // Token counts differ
    check_comment_preservation(&orig_tokens, &fmt_tokens, original, formatted)?;
    check_critical_syntax_patterns(original, formatted, &orig_significant, &fmt_significant)?;

    if is_acceptable_token_difference(&orig_significant, &fmt_significant) {
        return Ok(());
    }

    // Find first divergence
    let mut first_diff_idx = 0;
    for (i, (o, f)) in orig_significant
        .iter()
        .zip(fmt_significant.iter())
        .enumerate()
    {
        if !o.eq_ignore_ascii_case(f) {
            first_diff_idx = i;
            break;
        }
        first_diff_idx = i + 1;
    }

    Err(format!(
        "Token count mismatch!\n\
         Original tokens: {} significant tokens\n\
         Formatted tokens: {} significant tokens\n\
         \n\
         First divergence at index {}: orig='{}' vs fmt='{}'\n\
         Context (idx-5 to idx+5):\n\
         Original: {:?}\n\
         Formatted: {:?}\n\
         \n\
         First 20 original tokens: {:?}\n\
         First 20 formatted tokens: {:?}",
        orig_significant.len(),
        fmt_significant.len(),
        first_diff_idx,
        orig_significant.get(first_diff_idx).unwrap_or(&"<none>"),
        fmt_significant.get(first_diff_idx).unwrap_or(&"<none>"),
        &orig_significant
            [first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(orig_significant.len())],
        &fmt_significant
            [first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(fmt_significant.len())],
        &orig_significant[..orig_significant.len().min(20)],
        &fmt_significant[..fmt_significant.len().min(20)]
    ))
}

/// Check that all comments from the original are preserved in the formatted output.
///
/// Comments are critical documentation and must not be lost during formatting.
fn check_comment_preservation(
    orig_tokens: &[Token],
    fmt_tokens: &[Token],
    orig_src: &str,
    fmt_src: &str,
) -> Result<(), String> {
    use std::collections::HashSet;

    // Extract all comments from original (check both token-level and trivia)
    let mut orig_comments: Vec<String> = Vec::new();

    for token in orig_tokens {
        // Check if token itself is a comment
        if matches!(token.kind, TokenKind::LineComment | TokenKind::BlockComment) {
            orig_comments.push(token.lexeme(orig_src).trim().to_string());
        }
        // Check leading trivia
        for trivia in &token.leading_trivia {
            if matches!(
                trivia.kind,
                lexer::TriviaKind::LineComment | lexer::TriviaKind::BlockComment
            ) {
                let start = trivia.span.start as usize;
                let end = trivia.span.end as usize;

                // Bounds checking to prevent panics
                if end > orig_src.len() {
                    return Err(format!(
                        "Invalid trivia span: {}..{} exceeds source length {}",
                        start,
                        end,
                        orig_src.len()
                    ));
                }

                // UTF-8 boundary validation
                if let Some(comment_text) = orig_src.get(start..end) {
                    orig_comments.push(comment_text.trim().to_string());
                } else {
                    return Err(format!(
                        "Invalid UTF-8 boundary in trivia span: {}..{}",
                        start, end
                    ));
                }
            }
        }
        // Check trailing trivia
        for trivia in &token.trailing_trivia {
            if matches!(
                trivia.kind,
                lexer::TriviaKind::LineComment | lexer::TriviaKind::BlockComment
            ) {
                let start = trivia.span.start as usize;
                let end = trivia.span.end as usize;

                // Bounds checking to prevent panics
                if end > orig_src.len() {
                    return Err(format!(
                        "Invalid trivia span: {}..{} exceeds source length {}",
                        start,
                        end,
                        orig_src.len()
                    ));
                }

                // UTF-8 boundary validation
                if let Some(comment_text) = orig_src.get(start..end) {
                    orig_comments.push(comment_text.trim().to_string());
                } else {
                    return Err(format!(
                        "Invalid UTF-8 boundary in trivia span: {}..{}",
                        start, end
                    ));
                }
            }
        }
    }

    // Extract all comments from formatted (check both token-level and trivia)
    let mut fmt_comments: Vec<String> = Vec::new();

    for token in fmt_tokens {
        // Check if token itself is a comment
        if matches!(token.kind, TokenKind::LineComment | TokenKind::BlockComment) {
            fmt_comments.push(token.lexeme(fmt_src).trim().to_string());
        }
        // Check leading trivia
        for trivia in &token.leading_trivia {
            if matches!(
                trivia.kind,
                lexer::TriviaKind::LineComment | lexer::TriviaKind::BlockComment
            ) {
                let start = trivia.span.start as usize;
                let end = trivia.span.end as usize;

                // Bounds checking to prevent panics
                if end > fmt_src.len() {
                    return Err(format!(
                        "Invalid trivia span in formatted output: {}..{} exceeds source length {}",
                        start,
                        end,
                        fmt_src.len()
                    ));
                }

                // UTF-8 boundary validation
                if let Some(comment_text) = fmt_src.get(start..end) {
                    fmt_comments.push(comment_text.trim().to_string());
                } else {
                    return Err(format!(
                        "Invalid UTF-8 boundary in formatted trivia span: {}..{}",
                        start, end
                    ));
                }
            }
        }
        // Check trailing trivia
        for trivia in &token.trailing_trivia {
            if matches!(
                trivia.kind,
                lexer::TriviaKind::LineComment | lexer::TriviaKind::BlockComment
            ) {
                let start = trivia.span.start as usize;
                let end = trivia.span.end as usize;

                // Bounds checking to prevent panics
                if end > fmt_src.len() {
                    return Err(format!(
                        "Invalid trivia span in formatted output: {}..{} exceeds source length {}",
                        start,
                        end,
                        fmt_src.len()
                    ));
                }

                // UTF-8 boundary validation
                if let Some(comment_text) = fmt_src.get(start..end) {
                    fmt_comments.push(comment_text.trim().to_string());
                } else {
                    return Err(format!(
                        "Invalid UTF-8 boundary in formatted trivia span: {}..{}",
                        start, end
                    ));
                }
            }
        }
    }

    // Check if any comments were lost
    // Build HashSet for O(1) lookup
    let fmt_comments_set: HashSet<&str> = fmt_comments.iter().map(|s| s.as_str()).collect();

    // Check if any original comments are missing from formatted output
    let mut missing_comments = Vec::new();
    for orig_comment in &orig_comments {
        if !fmt_comments_set.contains(orig_comment.as_str()) {
            missing_comments.push(orig_comment.clone());
        }
    }

    if !missing_comments.is_empty() {
        return Err(format!(
            "Comment loss detected!\n\
             Original had {} comment(s), formatted has {} comment(s)\n\
             Missing comment(s):\n{}\n\
             \n\
             Comments are important documentation and must be preserved.",
            orig_comments.len(),
            fmt_comments.len(),
            missing_comments
                .iter()
                .map(|c| format!("  - {}", c))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    if orig_comments.len() > fmt_comments.len() {
        return Err(format!(
            "Comment loss detected!\n\
             Original had {} comment(s), formatted has {} comment(s)\n\
             Missing comment(s):\n{}\n\
             \n\
             Comments are important documentation and must be preserved.",
            orig_comments.len(),
            fmt_comments.len(),
            missing_comments
                .iter()
                .map(|c| format!("  - {}", c))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    // Check if any comments were duplicated
    if fmt_comments.len() > orig_comments.len() {
        // Count occurrences of each comment in both lists
        use std::collections::HashMap;

        let mut orig_counts: HashMap<&str, usize> = HashMap::new();
        for c in &orig_comments {
            *orig_counts.entry(c.as_str()).or_insert(0) += 1;
        }

        let mut fmt_counts: HashMap<&str, usize> = HashMap::new();
        for c in &fmt_comments {
            *fmt_counts.entry(c.as_str()).or_insert(0) += 1;
        }

        // Find duplicated comments
        let mut duplicated_comments = Vec::new();
        for (comment, fmt_count) in &fmt_counts {
            let orig_count = orig_counts.get(comment).copied().unwrap_or(0);
            if *fmt_count > orig_count {
                duplicated_comments.push(format!(
                    "'{}' (original: {}, formatted: {})",
                    comment, orig_count, fmt_count
                ));
            }
        }

        return Err(format!(
            "Comment duplication detected!\n\
             Original had {} comment(s), formatted has {} comment(s)\n\
             Duplicated comment(s):\n{}\n\
             \n\
             Comments should appear exactly once in the output.",
            orig_comments.len(),
            fmt_comments.len(),
            duplicated_comments
                .iter()
                .map(|c| format!("  - {}", c))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    Ok(())
}

/// Check for critical syntax patterns that must be preserved.
///
/// This catches issues like missing parentheses in IF statements even when token counts match.
fn check_critical_syntax_patterns(
    _original: &str,
    _formatted: &str,
    orig_tokens: &[&str],
    fmt_tokens: &[&str],
) -> Result<(), String> {
    // Check for IF/ELSEIF/WHILE/REPEAT statements with required parentheses
    let keywords = ["IF", "ELSEIF", "ELSIF", "WHILE"];

    for keyword in &keywords {
        let orig_positions: Vec<usize> = orig_tokens
            .iter()
            .enumerate()
            .filter(|(_, t)| t.eq_ignore_ascii_case(keyword))
            .map(|(i, _)| i)
            .collect();

        let fmt_positions: Vec<usize> = fmt_tokens
            .iter()
            .enumerate()
            .filter(|(_, t)| t.eq_ignore_ascii_case(keyword))
            .map(|(i, _)| i)
            .collect();

        // Check each occurrence
        for (orig_pos, fmt_pos) in orig_positions.iter().zip(fmt_positions.iter()) {
            // Look for pattern: KEYWORD ... THEN (should have parens around condition)
            let orig_has_open_paren =
                orig_pos + 1 < orig_tokens.len() && orig_tokens[*orig_pos + 1] == "(";
            let fmt_has_open_paren =
                fmt_pos + 1 < fmt_tokens.len() && fmt_tokens[*fmt_pos + 1] == "(";

            if orig_has_open_paren && !fmt_has_open_paren {
                return Err(format!(
                    "Critical syntax error: {} statement missing required opening parenthesis\n\
                     Original around position {}: {:?}\n\
                     Formatted around position {}: {:?}\n\
                     This will cause Snowflake syntax errors!",
                    keyword,
                    orig_pos,
                    &orig_tokens[*orig_pos..(*orig_pos + 5).min(orig_tokens.len())],
                    fmt_pos,
                    &fmt_tokens[*fmt_pos..(*fmt_pos + 5).min(fmt_tokens.len())]
                ));
            }
        }
    }

    // Check for REPEAT UNTIL with parentheses
    for (i, token) in orig_tokens.iter().enumerate() {
        if token.eq_ignore_ascii_case("UNTIL")
            && i + 1 < orig_tokens.len()
            && orig_tokens[i + 1] == "("
        {
            // Find corresponding UNTIL in formatted
            if let Some(fmt_pos) = fmt_tokens
                .iter()
                .position(|t| t.eq_ignore_ascii_case("UNTIL"))
            {
                if fmt_pos + 1 >= fmt_tokens.len() || fmt_tokens[fmt_pos + 1] != "(" {
                    return Err("Critical syntax error: REPEAT UNTIL statement missing required opening parenthesis\n\
                         This will cause Snowflake syntax errors!".to_string());
                }
            }
        }
    }

    Ok(())
}

/// Check if token differences are acceptable SQL normalizations.
///
/// Returns true for known safe transformations like:
/// - JOIN -> INNER JOIN
/// - LEFT JOIN -> LEFT OUTER JOIN
/// - Adding optional AS keyword before aliases
/// - Adding trailing semicolon
fn is_acceptable_token_difference(orig: &[&str], fmt: &[&str]) -> bool {
    // Quick check: if formatted has fewer tokens, definitely not acceptable
    if fmt.len() < orig.len() {
        return false;
    }

    let token_diff = fmt.len() - orig.len();

    // Normalization 0: Trailing semicolon addition
    // If the only difference is a trailing semicolon, that's OK
    if token_diff == 1 {
        // Check if formatted ends with semicolon and original doesn't
        let fmt_ends_with_semi = !fmt.is_empty() && fmt[fmt.len() - 1] == ";";
        let orig_ends_with_semi = !orig.is_empty() && orig[orig.len() - 1] == ";";

        if fmt_ends_with_semi && !orig_ends_with_semi {
            // Check that everything before the semicolon matches
            let fmt_without_semi = &fmt[..fmt.len() - 1];
            if orig == fmt_without_semi {
                return true;
            }
        }
    }

    // Normalization 1: Combined check for multiple acceptable transformations
    // (AS additions, TABLE() unwrapping, etc.)
    if is_only_acceptable_normalizations(orig, fmt) {
        return true;
    }

    // Normalization 2: JOIN -> INNER JOIN (avoid string allocation)
    if has_token_sequence(orig, &["JOIN"]) && has_token_sequence(fmt, &["INNER", "JOIN"]) {
        return true;
    }

    // Normalization 3: LEFT/RIGHT/FULL JOIN -> LEFT/RIGHT/FULL OUTER JOIN
    if (has_token_sequence(orig, &["LEFT", "JOIN"])
        && has_token_sequence(fmt, &["LEFT", "OUTER", "JOIN"]))
        || (has_token_sequence(orig, &["RIGHT", "JOIN"])
            && has_token_sequence(fmt, &["RIGHT", "OUTER", "JOIN"]))
        || (has_token_sequence(orig, &["FULL", "JOIN"])
            && has_token_sequence(fmt, &["FULL", "OUTER", "JOIN"]))
    {
        return true;
    }

    // Normalization 4: UNPIVOT -> UNPIVOT EXCLUDE NULLS
    if has_token_sequence(orig, &["UNPIVOT"])
        && has_token_sequence(fmt, &["UNPIVOT", "EXCLUDE", "NULLS"])
    {
        return true;
    }

    false
}

/// Check if token sequence contains a pattern (case-insensitive).
fn has_token_sequence(tokens: &[&str], pattern: &[&str]) -> bool {
    if pattern.is_empty() || tokens.len() < pattern.len() {
        return false;
    }
    tokens.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern)
            .all(|(t, p)| t.eq_ignore_ascii_case(p))
    })
}

/// Check if the formatted token stream differs from original only by acceptable normalizations:
/// - AS keyword insertions before aliases
fn is_only_acceptable_normalizations(orig: &[&str], fmt: &[&str]) -> bool {
    let mut orig_idx = 0;
    let mut fmt_idx = 0;
    let mut normalizations = 0;

    while orig_idx < orig.len() && fmt_idx < fmt.len() {
        // If tokens match, advance both
        if orig[orig_idx].eq_ignore_ascii_case(fmt[fmt_idx]) {
            orig_idx += 1;
            fmt_idx += 1;
            continue;
        }

        // Check for AS keyword insertion
        if fmt[fmt_idx].eq_ignore_ascii_case("AS")
            && fmt_idx + 1 < fmt.len()
            && orig_idx < orig.len()
            && fmt[fmt_idx + 1].eq_ignore_ascii_case(orig[orig_idx])
        {
            normalizations += 1;
            fmt_idx += 1; // Skip the AS keyword in formatted
            continue;
        }

        // Tokens don't match and it's not an acceptable normalization
        return false;
    }

    // Verify we consumed all tokens and found at least one normalization
    orig_idx == orig.len() && fmt_idx == fmt.len() && normalizations > 0
}
