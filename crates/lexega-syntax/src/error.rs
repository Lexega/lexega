// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Error types for parsing and formatting operations.
//!
//! This module defines structured error types that provide detailed information
//! about parse failures, including the location (span) and context of the error.

use crate::lexer::token::Span;
use std::fmt;

// ============================================================================
// ANSI Color Codes for Enhanced Error Display
// ============================================================================

/// Check if ANSI color output should be enabled.
/// Respects NO_COLOR environment variable.
fn should_use_color() -> bool {
    // Respect NO_COLOR standard: https://no-color.org/
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check if FORCE_COLOR is set
    if std::env::var("FORCE_COLOR").is_ok() {
        return true;
    }

    // For now, default to true (can be disabled with NO_COLOR=1)
    // Future enhancement: detect TTY capability
    true
}

/// ANSI color helper struct (uses lazy_static pattern manually)
struct Colors {
    enabled: bool,
}

impl Colors {
    fn new() -> Self {
        Self {
            enabled: should_use_color(),
        }
    }

    fn red(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[31m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn green(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[32m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn blue(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[34m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn cyan(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[36m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }
}

fn colors() -> Colors {
    Colors::new()
}

/// Result type for parsing operations.
pub type ParseResult<T> = Result<T, ParseError>;

// ============================================================================
// Tolerant Parsing Support (for LSP)
// ============================================================================

/// Result of tolerant parsing - contains partial AST even when errors occur.
///
/// This is used by the LSP to provide IDE features (hover, completion, etc.)
/// even when the document contains syntax errors. Instead of failing entirely,
/// the parser returns whatever it could parse along with error information.
///
/// # Design Principles
///
/// 1. **Always return something**: Even with errors, the AST contains valid nodes
/// 2. **Error nodes mark unparseable regions**: `AstStmt::Error` placeholders
/// 3. **Errors are recoverable**: Parser synchronizes at statement boundaries
/// 4. **No data loss**: Error spans show exactly what couldn't be parsed
#[derive(Debug, Clone)]
pub struct TolerantParseResult<T> {
    /// The (partial) parse result - may contain Error nodes
    pub ast: T,

    /// Errors encountered during parsing (syntax errors, unexpected tokens, etc.)
    /// These are non-fatal in tolerant mode - parsing continued past them.
    pub errors: Vec<ParseError>,

    /// Whether the parse completed without any errors
    pub is_complete: bool,
}

impl<T> TolerantParseResult<T> {
    /// Create a successful result with no errors.
    pub fn success(ast: T) -> Self {
        Self {
            ast,
            errors: Vec::new(),
            is_complete: true,
        }
    }

    /// Create a partial result with errors.
    pub fn partial(ast: T, errors: Vec<ParseError>) -> Self {
        let is_complete = errors.is_empty();
        Self {
            ast,
            errors,
            is_complete,
        }
    }

    /// Check if there were any parse errors.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Get the number of errors.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Map the AST while preserving errors.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> TolerantParseResult<U> {
        TolerantParseResult {
            ast: f(self.ast),
            errors: self.errors,
            is_complete: self.is_complete,
        }
    }
}

/// Structured parse error with span and message.
///
/// `ParseError` captures information about where and why parsing failed,
/// enabling rich error reporting in editors and CLIs.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Location in the source where the error occurred
    pub span: Span,

    /// The kind of parse error (boxed to keep ParseError small on the stack)
    pub kind: Box<ParseErrorKind>,
}

impl ParseError {
    /// Create a new parse error with the given span and kind.
    pub fn new(span: Span, kind: ParseErrorKind) -> Self {
        Self {
            span,
            kind: Box::new(kind),
        }
    }

    /// Create an error for an unexpected token.
    pub fn unexpected_token(span: Span, expected: Vec<String>, found: String) -> Self {
        Self::new(span, ParseErrorKind::UnexpectedToken { expected, found })
    }

    /// Create an error for unexpected end of file.
    pub fn unexpected_eof(span: Span, expected: Vec<String>) -> Self {
        Self::new(span, ParseErrorKind::UnexpectedEof { expected })
    }

    /// Create an error for an invalid expression.
    pub fn invalid_expression(span: Span, message: String) -> Self {
        Self::new(span, ParseErrorKind::InvalidExpression { message })
    }

    /// Create an error for an invalid statement.
    pub fn invalid_statement(span: Span, message: String) -> Self {
        Self::new(span, ParseErrorKind::InvalidStatement { message })
    }

    /// Get a human-readable error message.
    pub fn message(&self) -> String {
        match &*self.kind {
            ParseErrorKind::UnexpectedToken { expected, found } => {
                if expected.is_empty() {
                    format!("Unexpected token: {}", found)
                } else if expected.len() == 1 {
                    format!("Expected {}, found {}", expected[0], found)
                } else {
                    format!("Expected one of [{}], found {}", expected.join(", "), found)
                }
            }
            ParseErrorKind::UnexpectedEof { expected } => {
                if expected.is_empty() {
                    "Unexpected end of input".to_string()
                } else if expected.len() == 1 {
                    format!("Unexpected end of input, expected {}", expected[0])
                } else {
                    format!(
                        "Unexpected end of input, expected one of [{}]",
                        expected.join(", ")
                    )
                }
            }
            ParseErrorKind::InvalidExpression { message } => {
                format!("Invalid expression: {}", message)
            }
            ParseErrorKind::InvalidStatement { message } => {
                format!("Invalid statement: {}", message)
            }
            ParseErrorKind::UnmatchedKeyword { keyword } => {
                format!("Unmatched keyword: {}", keyword)
            }
            ParseErrorKind::MissingClause { clause } => {
                format!("Missing required clause: {}", clause)
            }
            ParseErrorKind::InvalidSyntax { message } => {
                format!("Invalid syntax: {}", message)
            }
            ParseErrorKind::Internal { message } => {
                format!("Internal parser error: {}", message)
            }
            ParseErrorKind::UnclosedJinjaBlock { block_type, .. } => {
                format!("Unclosed Jinja block: {}", block_type)
            }
            ParseErrorKind::MismatchedJinjaEndTag {
                expected, found, ..
            } => {
                format!(
                    "Mismatched Jinja end tag: expected {}, found {}",
                    expected, found
                )
            }
            ParseErrorKind::UnexpectedJinjaEndTag { tag_type, .. } => {
                format!("Unexpected Jinja end tag: {}", tag_type)
            }
            ParseErrorKind::InvalidJinjaExpression { message, .. } => {
                format!("Invalid Jinja expression: {}", message)
            }
            ParseErrorKind::UnknownJinjaTag { tag_name, .. } => {
                format!("Unknown Jinja tag: {}", tag_name)
            }
            ParseErrorKind::JinjaInInvalidLocation { message, .. } => {
                format!("Jinja block in invalid location: {}", message)
            }
            ParseErrorKind::RecursionLimitExceeded { limit, context } => {
                format!(
                    "Recursion limit exceeded while parsing {}: maximum depth is {}",
                    context, limit
                )
            }
            ParseErrorKind::StatementTooDeep { context, depth } => {
                format!(
                    "Statement nesting too deep to parse safely: {} at depth {}",
                    context, depth
                )
            }
            ParseErrorKind::UnsupportedDialectFeature { feature, dialect } => {
                format!("{} is not supported in {} dialect", feature, dialect)
            }
        }
    }

    /// Format a rich error message with source context and helpful suggestions.
    ///
    /// This creates a multi-line error message showing:
    /// - File location (if provided)
    /// - Line and column numbers
    /// - Multi-line context (lines before and after)
    /// - The problematic line from source
    /// - A caret (^) pointing to the error location
    /// - Error description with context
    /// - Helpful suggestion with examples (if applicable)
    /// - Optional fix suggestions
    ///
    /// # Arguments
    ///
    /// * `source` - The original SQL source text
    /// * `file_path` - Optional file path for display
    ///
    /// # Returns
    ///
    /// Formatted error string ready for display to users
    pub fn format_rich(&self, source: &str, file_path: Option<&str>) -> String {
        let colors = colors();
        let (start_loc, end_loc) = crate::span_to_line_col(source, self.span);
        let lines: Vec<&str> = source.lines().collect();

        let mut output = String::new();

        // Error header with bold red "error:" label
        if let Some(path) = file_path {
            output.push_str(&format!(
                "{}: {}:{}:{}: {}",
                colors.bold(&colors.red("error")),
                colors.bold(path),
                colors.bold(&start_loc.line.to_string()),
                colors.bold(&start_loc.col.to_string()),
                self.message()
            ));
        } else {
            output.push_str(&format!(
                "{}: line {}, column {}: {}",
                colors.bold(&colors.red("error")),
                colors.bold(&start_loc.line.to_string()),
                colors.bold(&start_loc.col.to_string()),
                self.message()
            ));
        }
        output.push('\n');

        // Show context: lines before, error line, lines after
        if start_loc.line <= lines.len() {
            let context_before = 2; // Show 2 lines before
            let context_after = 1; // Show 1 line after

            let start_line = start_loc.line.saturating_sub(context_before);
            let end_line = (start_loc.line + context_after).min(lines.len());

            // Calculate line number width for alignment
            let line_num_width = end_line.to_string().len();

            output.push('\n');

            for line_num in start_line..=end_line {
                if line_num == 0 {
                    continue;
                }

                let line_text = lines.get(line_num - 1).unwrap_or(&"");
                let is_error_line = line_num == start_loc.line;

                if is_error_line {
                    // Error line with blue line number and highlighted text
                    output.push_str(&format!(
                        " {} {} {}\n",
                        colors.blue(&format!("{:width$} │", line_num, width = line_num_width)),
                        colors.blue(">>"),
                        line_text
                    ));

                    // Caret line pointing to error location
                    let caret_start = start_loc.col.saturating_sub(1);
                    let caret_length = if start_loc.line == end_loc.line {
                        (end_loc.col.saturating_sub(start_loc.col)).max(1)
                    } else {
                        1
                    };

                    output.push_str(&format!(
                        " {} {} {}{}{}\n",
                        colors.blue(&format!("{:width$} │", "", width = line_num_width)),
                        "  ",
                        " ".repeat(caret_start),
                        colors.red(&"^".repeat(caret_length)),
                        colors.red(" error occurs here")
                    ));
                } else {
                    // Context line with dimmed line number
                    output.push_str(&format!(
                        " {} {}\n",
                        colors.dim(&format!("{:width$} │", line_num, width = line_num_width)),
                        colors.dim(line_text)
                    ));
                }
            }
        }

        // Add helpful suggestions based on error kind
        if let Some((suggestion, example)) = self.get_suggestion_with_example() {
            output.push('\n');
            output.push_str(&format!(
                "{} {}\n",
                colors.bold(&colors.cyan("help:")),
                suggestion
            ));

            if let Some(ex) = example {
                output.push_str(&format!(
                    "\n{} {}\n",
                    colors.dim("Example:"),
                    colors.green(&ex)
                ));
            }
        }

        output
    }

    /// Get a helpful suggestion for fixing the error, with optional example.
    /// Returns (suggestion_text, optional_example)
    fn get_suggestion_with_example(&self) -> Option<(String, Option<String>)> {
        match &*self.kind {
            ParseErrorKind::UnexpectedToken { expected, found } => {
                // Provide context-specific suggestions with examples
                if expected.iter().any(|e| e.contains("SELECT") || e.contains("INSERT") || e.contains("UPDATE") || e.contains("DELETE") || e.contains("CREATE")) {
                    Some((
                        "Expected a SQL statement keyword. Statements must start with SELECT, INSERT, UPDATE, DELETE, CREATE, etc.".to_string(),
                        Some("SELECT id, name FROM users;".to_string())
                    ))
                } else if expected.iter().any(|e| e.contains("FROM")) {
                    Some((
                        "SELECT statements require a FROM clause specifying the table or data source.".to_string(),
                        Some("SELECT column1, column2 FROM table_name;".to_string())
                    ))
                } else if expected.iter().any(|e| e.contains("WHERE")) && found.contains("=") {
                    Some((
                        "WHERE clause requires a condition expression. Make sure the left-hand side is a column reference.".to_string(),
                        Some("WHERE status = 'active'".to_string())
                    ))
                } else if expected.iter().any(|e| e.contains(";")) {
                    Some((
                        "SQL statements should end with a semicolon.".to_string(),
                        Some("SELECT * FROM users;".to_string())
                    ))
                } else if expected.len() == 1 {
                    Some((
                        format!("Try using '{}' instead of '{}'.", expected[0], found),
                        None
                    ))
                } else if expected.len() <= 3 {
                    Some((
                        format!("Expected one of: {}", expected.join(", ")),
                        None
                    ))
                } else {
                    None
                }
            }
            ParseErrorKind::UnexpectedEof { expected } => {
                if expected.iter().any(|e| e.contains(")")) {
                    Some((
                        "Statement appears incomplete. Check for missing closing parenthesis.".to_string(),
                        Some("SELECT id FROM (SELECT * FROM users)".to_string())
                    ))
                } else if expected.iter().any(|e| e.contains("END")) {
                    Some((
                        "Block statement requires matching END keyword.".to_string(),
                        Some("BEGIN\n  -- statements\nEND;".to_string())
                    ))
                } else {
                    Some((
                        "Statement appears incomplete. Check syntax and ensure all required clauses are present.".to_string(),
                        None
                    ))
                }
            }
            ParseErrorKind::MissingClause { clause } => {
                // Extract helpful context from the clause description
                if clause.contains("UPDATE") && clause.contains("SET") {
                    Some((
                        "UPDATE statements require SET clause to specify columns and values.".to_string(),
                        Some("UPDATE users SET status = 'active' WHERE id = 123;".to_string())
                    ))
                } else if clause.contains("INSERT") && clause.contains("VALUES") {
                    Some((
                        "INSERT statements require VALUES clause or SELECT subquery.".to_string(),
                        Some("INSERT INTO users (id, name) VALUES (1, 'John');".to_string())
                    ))
                } else if clause.contains("SELECT") {
                    Some((
                        "Check the Snowflake SQL documentation for required SELECT statement clauses.".to_string(),
                        Some("SELECT column FROM table WHERE condition;".to_string())
                    ))
                } else {
                    Some((
                        format!("Add the required {} clause to complete this statement.", clause),
                        None
                    ))
                }
            }
            ParseErrorKind::InvalidStatement { message } if message.contains("not yet fully supported") => {
                Some((
                    "This statement type is recognized but not yet fully implemented. It will be added in a future release.".to_string(),
                    None
                ))
            }
            ParseErrorKind::InvalidStatement { message } if message.contains("requires") => {
                Some((
                    "Check the platform's SQL documentation for the correct syntax of this statement.".to_string(),
                    None
                ))
            }
            ParseErrorKind::UnclosedJinjaBlock { block_type, .. } => {
                let end_tag = format!("end{}", block_type);
                Some((
                    format!("Jinja block '{}' is not closed. Add a matching end tag.", block_type),
                    Some(format!("{{% {} %}}\n  ...\n{{% {} %}}", block_type, end_tag))
                ))
            }
            ParseErrorKind::MismatchedJinjaEndTag { expected, found, .. } => {
                Some((
                    format!("Mismatched Jinja tags: '{}' opened but '{}' was used to close it.", expected, found),
                    Some(format!("{{% {} %}} ... {{% {} %}}", expected.trim_start_matches("end"), expected))
                ))
            }
            ParseErrorKind::UnexpectedJinjaEndTag { tag_type, .. } => {
                Some((
                    format!("Found closing tag '{}' without a matching opening tag.", tag_type),
                    None
                ))
            }
            ParseErrorKind::InvalidJinjaExpression { message, .. } => {
                Some((
                    format!("Invalid Jinja expression: {}", message),
                    Some("{{ variable_name }}".to_string())
                ))
            }
            ParseErrorKind::InvalidSyntax { message } if message.contains("DATA LOSS DETECTED") => {
                Some((
                    "INTERNAL ERROR: Parser safety check failed. This indicates a bug in the parser that could cause data loss.".to_string(),
                    Some("Please report this issue with your SQL sample to the maintainers.".to_string())
                ))
            }
            ParseErrorKind::UnmatchedKeyword { keyword } => {
                Some((
                    format!("Found '{}' keyword without matching context.", keyword),
                    None
                ))
            }
            _ => None,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Parse error at {}..{}: {}",
            self.span.start,
            self.span.end,
            self.message()
        )
    }
}

impl std::error::Error for ParseError {}

/// The kind of parse error that occurred.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseErrorKind {
    /// Expected certain tokens but found something else
    UnexpectedToken {
        /// List of expected token descriptions (e.g., "SELECT", "identifier", ")")
        expected: Vec<String>,
        /// What was actually found
        found: String,
    },

    /// Unexpected end of input while parsing
    UnexpectedEof {
        /// What was expected to continue parsing
        expected: Vec<String>,
    },

    /// Invalid expression syntax
    InvalidExpression {
        /// Description of what's wrong
        message: String,
    },

    /// Invalid statement syntax
    InvalidStatement {
        /// Description of what's wrong
        message: String,
    },

    /// Unmatched keyword (e.g., END without BEGIN)
    UnmatchedKeyword {
        /// The unmatched keyword
        keyword: String,
    },

    /// Missing required clause (e.g., SELECT without FROM when required)
    MissingClause {
        /// The missing clause name
        clause: String,
    },

    /// General syntax error
    InvalidSyntax {
        /// Description of the syntax error
        message: String,
    },

    /// Internal parser error (should not occur in normal operation)
    Internal {
        /// Description of the internal error
        message: String,
    },

    // =========================================================================
    // Jinja/Template-specific errors
    // =========================================================================
    /// Unclosed Jinja control block (e.g., {% if %} without {% endif %})
    UnclosedJinjaBlock {
        /// The opening tag type ("if", "for", "macro", etc.)
        block_type: String,
        /// Span of the opening tag
        opening_span: crate::lexer::Span,
    },

    /// Mismatched Jinja end tag (e.g., {% endif %} for a {% for %} block)
    MismatchedJinjaEndTag {
        /// Expected closing tag (e.g., "endfor")
        expected: String,
        /// Actual closing tag found (e.g., "endif")
        found: String,
    },

    /// Recursion depth limit exceeded during parsing
    RecursionLimitExceeded {
        /// The configured limit
        limit: usize,
        /// Description of what was being parsed
        context: String,
    },

    /// Statement nesting exhausted the parser's stack budget. Unlike
    /// `RecursionLimitExceeded` (a fixed depth count), this trips on measured
    /// stack consumption, so builds with large stack frames are stopped
    /// gracefully before the thread's stack can overflow.
    StatementTooDeep {
        /// Description of what was being parsed
        context: String,
        /// Recursion depth when the budget was exhausted
        depth: usize,
    },

    /// Unexpected Jinja end tag without matching opening
    UnexpectedJinjaEndTag {
        /// The end tag type ("endif", "endfor", etc.)
        tag_type: String,
        /// Span of the unexpected end tag
        span: crate::lexer::Span,
    },

    /// Invalid Jinja expression syntax
    InvalidJinjaExpression {
        /// Description of what's wrong
        message: String,
        /// Span of the invalid expression
        span: crate::lexer::Span,
    },

    /// Unknown Jinja tag
    UnknownJinjaTag {
        /// The unrecognized tag name
        tag_name: String,
        /// Span of the unknown tag
        span: crate::lexer::Span,
    },

    /// Jinja block in invalid SQL location
    JinjaInInvalidLocation {
        /// Description of why this location is invalid
        message: String,
        /// Span of the Jinja block
        span: crate::lexer::Span,
    },

    /// Feature not supported in the current SQL dialect
    UnsupportedDialectFeature {
        /// The feature name (e.g., "QUALIFY", "PIVOT", "time travel")
        feature: String,
        /// The dialect name (e.g., "postgresql", "mysql")
        dialect: String,
    },
}

impl ParseErrorKind {
    /// Resource-exhaustion errors (depth cap or stack budget): never absorbed
    /// by intra-statement recovery, contained only at the statement boundary.
    pub(crate) fn is_resource_exhaustion(&self) -> bool {
        matches!(
            self,
            ParseErrorKind::RecursionLimitExceeded { .. } | ParseErrorKind::StatementTooDeep { .. }
        )
    }

    /// Get a human-readable error message for this error kind.
    pub fn message(&self) -> String {
        match self {
            ParseErrorKind::UnexpectedToken { expected, found } => {
                if expected.is_empty() {
                    format!("Unexpected token: {}", found)
                } else if expected.len() == 1 {
                    format!("Expected {}, found {}", expected[0], found)
                } else {
                    format!("Expected one of [{}], found {}", expected.join(", "), found)
                }
            }
            ParseErrorKind::UnexpectedEof { expected } => {
                if expected.is_empty() {
                    "Unexpected end of input".to_string()
                } else if expected.len() == 1 {
                    format!("Unexpected end of input, expected {}", expected[0])
                } else {
                    format!(
                        "Unexpected end of input, expected one of [{}]",
                        expected.join(", ")
                    )
                }
            }
            ParseErrorKind::InvalidExpression { message } => {
                format!("Invalid expression: {}", message)
            }
            ParseErrorKind::InvalidStatement { message } => {
                format!("Invalid statement: {}", message)
            }
            ParseErrorKind::UnmatchedKeyword { keyword } => {
                format!("Unmatched keyword: {}", keyword)
            }
            ParseErrorKind::MissingClause { clause } => {
                format!("Missing required clause: {}", clause)
            }
            ParseErrorKind::InvalidSyntax { message } => {
                format!("Invalid syntax: {}", message)
            }
            ParseErrorKind::Internal { message } => {
                format!("Internal parser error: {}", message)
            }
            ParseErrorKind::UnclosedJinjaBlock { block_type, .. } => {
                format!("Unclosed Jinja block: {}", block_type)
            }
            ParseErrorKind::MismatchedJinjaEndTag {
                expected, found, ..
            } => {
                format!(
                    "Mismatched Jinja end tag: expected {}, found {}",
                    expected, found
                )
            }
            ParseErrorKind::UnexpectedJinjaEndTag { tag_type, .. } => {
                format!("Unexpected Jinja end tag: {}", tag_type)
            }
            ParseErrorKind::InvalidJinjaExpression { message, .. } => {
                format!("Invalid Jinja expression: {}", message)
            }
            ParseErrorKind::UnknownJinjaTag { tag_name, .. } => {
                format!("Unknown Jinja tag: {}", tag_name)
            }
            ParseErrorKind::JinjaInInvalidLocation { message, .. } => {
                format!("Jinja block in invalid location: {}", message)
            }
            ParseErrorKind::RecursionLimitExceeded { limit, context } => {
                format!(
                    "Recursion limit exceeded while parsing {}: maximum depth is {}",
                    context, limit
                )
            }
            ParseErrorKind::StatementTooDeep { context, depth } => {
                format!(
                    "Statement nesting too deep to parse safely: {} at depth {}",
                    context, depth
                )
            }
            ParseErrorKind::UnsupportedDialectFeature { feature, dialect } => {
                format!("{} is not supported in {} dialect", feature, dialect)
            }
        }
    }
}

/// Helper trait to convert `Option<T>` to `ParseResult<T>` with context.
///
/// This trait makes it easy to convert existing `Option`-returning parser
/// functions into `Result`-returning ones without changing internal logic.
pub trait ParseResultExt<T> {
    /// Convert None to a ParseError with the given span and kind.
    fn ok_or_parse_error(self, span: Span, kind: ParseErrorKind) -> ParseResult<T>;

    /// Convert None to an UnexpectedToken error.
    fn ok_or_unexpected(self, span: Span, expected: Vec<String>, found: String) -> ParseResult<T>;

    /// Convert None to an UnexpectedEof error.
    fn ok_or_eof(self, span: Span, expected: Vec<String>) -> ParseResult<T>;
}

impl<T> ParseResultExt<T> for Option<T> {
    fn ok_or_parse_error(self, span: Span, kind: ParseErrorKind) -> ParseResult<T> {
        self.ok_or_else(|| ParseError::new(span, kind))
    }

    fn ok_or_unexpected(self, span: Span, expected: Vec<String>, found: String) -> ParseResult<T> {
        self.ok_or_else(|| ParseError::unexpected_token(span, expected, found))
    }

    fn ok_or_eof(self, span: Span, expected: Vec<String>) -> ParseResult<T> {
        self.ok_or_else(|| ParseError::unexpected_eof(span, expected))
    }
}

/// Unwraps a value the surrounding code has already shown to be present —
/// a token just peeked, a key just inserted. `msg` states that invariant
/// and is the panic message if it does not hold.
pub trait ExpectInvariant<T> {
    /// Returns the contained value, or panics with `msg` at the caller's
    /// location.
    #[track_caller]
    fn expect_invariant(self, msg: &str) -> T;
}

impl<T> ExpectInvariant<T> for Option<T> {
    #[inline(always)]
    fn expect_invariant(self, msg: &str) -> T {
        self.expect(msg)
    }
}

impl<T, E: std::fmt::Debug> ExpectInvariant<T> for Result<T, E> {
    #[inline(always)]
    fn expect_invariant(self, msg: &str) -> T {
        self.expect(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        let span = Span { start: 0, end: 5 };

        // Test unexpected token with single expected
        let err =
            ParseError::unexpected_token(span, vec!["SELECT".to_string()], "SELEKT".to_string());
        assert_eq!(err.message(), "Expected SELECT, found SELEKT");

        // Test unexpected token with multiple expected
        let err = ParseError::unexpected_token(
            span,
            vec![
                "SELECT".to_string(),
                "WITH".to_string(),
                "INSERT".to_string(),
            ],
            "SELEKT".to_string(),
        );
        assert_eq!(
            err.message(),
            "Expected one of [SELECT, WITH, INSERT], found SELEKT"
        );

        // Test unexpected EOF
        let err = ParseError::unexpected_eof(span, vec!["identifier".to_string()]);
        assert_eq!(
            err.message(),
            "Unexpected end of input, expected identifier"
        );

        // Test invalid expression
        let err = ParseError::invalid_expression(span, "Missing operand".to_string());
        assert_eq!(err.message(), "Invalid expression: Missing operand");
    }

    #[test]
    fn test_parse_result_ext() {
        let span = Span { start: 0, end: 5 };

        // Test ok_or_unexpected
        let result: ParseResult<i32> =
            Some(42).ok_or_unexpected(span, vec!["number".to_string()], "text".to_string());
        assert_eq!(result.unwrap(), 42);

        let result: ParseResult<i32> =
            None.ok_or_unexpected(span, vec!["number".to_string()], "text".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().message(), "Expected number, found text");

        // Test ok_or_eof
        let result: ParseResult<i32> = None.ok_or_eof(span, vec!["identifier".to_string()]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().message(),
            "Unexpected end of input, expected identifier"
        );
    }
}
