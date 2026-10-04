// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Lexical analysis.
//!
//! This module provides tokenization of SQL source text into a stream of
//! tokens. The dialect passed to `tokenize_with_dialect` decides how text is
//! tokenized: quoting, comment forms, dollar-quoted bodies, operators. The
//! lexer handles:
//!
//! - **Keywords**: SQL keywords (SELECT, CREATE, BEGIN, etc.)
//! - **Identifiers**: Regular and quoted identifiers, including Unicode support
//! - **Literals**: Numbers, strings, booleans, NULL
//! - **Operators**: Arithmetic (+, -, *, /), comparison (=, <, >), logical (AND, OR)
//! - **Punctuation**: Parentheses, commas, semicolons, brackets
//! - **Trivia**: Whitespace, line comments (--), block comments (/* */)
//! - **Special tokens**: Positional parameters ($1, $2), scripting variables (:var)
//!
//! ## Token Stream
//!
//! Tokens preserve their original source position via `Span` information, enabling
//! accurate error reporting and source reconstruction.

#[allow(clippy::module_inception)] // the tokenizer itself; `token` holds the types it produces
pub mod lexer;
pub mod token;

pub use lexer::Lexer;
pub use token::*;

/// Result of lexing, including tokens and metadata.
#[derive(Debug, Clone)]
pub struct LexResult {
    /// The tokens produced by lexing.
    pub tokens: Vec<Token>,
}

/// Tokenize a Snowflake SQL source string.
///
/// Main entry point for lexical analysis. Converts source text into a vector
/// of tokens with preserved trivia (whitespace, comments) and source positions.
///
/// # Arguments
///
/// * `source` - The SQL source code to tokenize
///
/// # Returns
///
/// A vector of [`Token`] structs, each containing:
/// - Token kind (keyword, identifier, literal, operator, etc.)
/// - Original lexeme (source text)
/// - Source span (start/end positions)
/// - Leading trivia (whitespace/comments before the token)
///
/// # Note
///
/// This function never fails - invalid characters are tokenized as separate
/// tokens that the parser will reject.
pub fn tokenize(source: &str) -> LexResult {
    tokenize_with_dialect(source, &crate::dialect::SnowflakeDialect)
}

/// Tokenize with an explicit SQL dialect.
///
/// This allows lexing SQL from different dialects (PostgreSQL, MySQL, etc.)
/// with dialect-specific keyword and operator handling.
///
/// # Arguments
///
/// * `source` - The SQL source code to tokenize
/// * `dialect` - The SQL dialect to use for keyword recognition
pub fn tokenize_with_dialect(source: &str, dialect: &dyn crate::dialect::Dialect) -> LexResult {
    let lexer = Lexer::with_dialect(source, dialect);
    let result = lexer.lex_all();

    // SAFETY: Verify lexer consumed entire source
    // This catches unclosed delimiters (strings, comments, Jinja) that could
    // silently consume rest of file into single token, causing data loss
    verify_lexer_completeness(source, &result.tokens);

    result
}

/// Verify lexer consumed all source bytes (minimal hardening, zero allocation).
///
/// Checks:
/// 1. Last token is EOF at source end (catches unclosed delimiters)
/// 2. First token starts at position 0 (catches skipped prefix)
///
/// This minimal check catches the most dangerous lexer bugs (unclosed strings/
/// comments consuming rest of file) with negligible performance impact.
fn verify_lexer_completeness(source: &str, tokens: &[Token]) {
    let source_len = source.len() as u32;

    if tokens.is_empty() {
        // Empty token stream is only valid for empty source
        if !source.is_empty() {
            panic!(
                "LEXER BUG: No tokens produced for {} byte source",
                source_len
            );
        }
        return;
    }

    // Check first token starts at beginning
    if let Some(first) = tokens.first() {
        // Account for leading trivia
        let first_pos = if first.leading_trivia.is_empty() {
            first.span.start
        } else {
            first.leading_trivia[0].span.start
        };

        if first_pos != 0 {
            panic!(
                "LEXER BUG: First token/trivia starts at position {}, expected 0. \
                 Lexer may have skipped source prefix.",
                first_pos
            );
        }
    }

    // Check last token is EOF at source end
    if let Some(last) = tokens.last() {
        if !matches!(last.kind, TokenKind::Eof) {
            panic!(
                "LEXER BUG: Last token is {:?} at position {}, not EOF. \
                 Lexer may have terminated early.",
                last.kind, last.span.start
            );
        }

        if last.span.end != source_len {
            panic!(
                "LEXER BUG: EOF token at position {} but source is {} bytes. \
                 Likely unclosed delimiter (string, comment, Jinja block) consumed rest of file.",
                last.span.end, source_len
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jinja_expression_tokenization() {
        let source = "{{ column_name | upper }}";
        let result = tokenize(source);

        // Should produce: {{, identifier, |, identifier, }}, EOF
        assert!(
            result.tokens.len() >= 4,
            "Expected multiple tokens from Jinja expression, got {}",
            result.tokens.len()
        );

        // First token should be {{ delimiter (now properly tokenized as JinjaExprOpen)
        assert!(
            matches!(result.tokens[0].kind, TokenKind::JinjaExprOpen),
            "First token should be JinjaExprOpen, got {:?}",
            result.tokens[0].kind
        );

        // Should have pipe token somewhere
        let has_pipe = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaPipe));
        assert!(has_pipe, "Expected JinjaPipe token in tokenization");

        println!("Jinja expression tokens:");
        for (i, tok) in result.tokens.iter().enumerate() {
            println!("{}: {:?} '{}'", i, tok.kind, tok.lexeme(source));
        }
    }

    #[test]
    fn test_jinja_operators() {
        let source = "{{ a ** b // c ~ d == e and f or not g }}";
        let result = tokenize(source);

        let has_double_star = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaDoubleStar));
        let has_double_slash = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaDoubleSlash));
        let has_tilde = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaTilde));
        let has_double_eq = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaDoubleEq));
        let has_and = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaAnd));
        let has_or = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaOr));
        let has_not = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaNot));

        assert!(has_double_star, "Expected ** (power) operator");
        assert!(has_double_slash, "Expected // (floor division) operator");
        assert!(has_tilde, "Expected ~ (string concat) operator");
        assert!(has_double_eq, "Expected == (equality) operator");
        assert!(has_and, "Expected 'and' keyword");
        assert!(has_or, "Expected 'or' keyword");
        assert!(has_not, "Expected 'not' keyword");

        println!("Jinja operators tokens:");
        for (i, tok) in result.tokens.iter().enumerate() {
            println!("{}: {:?} '{}'", i, tok.kind, tok.lexeme(source));
        }
    }

    #[test]
    fn test_jinja_keywords() {
        let source = "{{ true and false or null in items is not none }}";
        let result = tokenize(source);

        let has_true = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaTrue));
        let has_false = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaFalse));
        let has_null = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaNull));
        let has_in = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaIn));
        let has_is = result
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::JinjaIs));

        assert!(has_true, "Expected 'true' literal");
        assert!(has_false, "Expected 'false' literal");
        assert!(has_null, "Expected 'null' literal");
        assert!(has_in, "Expected 'in' keyword");
        assert!(has_is, "Expected 'is' keyword");
    }
}
