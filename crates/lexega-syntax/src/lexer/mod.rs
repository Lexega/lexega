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
    /// Each dollar-quoted string (`$$…$$`, `$tag$…$tag$`) the lexer read,
    /// opener and closer paired as the lexer pairs them, in source order of
    /// their openers: a string nested in another follows it.
    pub dollar_quotes: Vec<DollarQuote>,
}

/// A dollar-quoted string of the source ([`LexResult::dollar_quotes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DollarQuote {
    /// From its opener's first byte to its closer's last; to the end of the
    /// source where nothing closes it.
    pub span: Span,
    /// The text between its delimiters.
    pub content: Span,
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

/// The spans of the comments the lexer attached to `tokens` as trivia, in
/// source order, each once.
pub fn comment_spans(tokens: &[Token]) -> Vec<Span> {
    let mut spans: Vec<Span> = tokens
        .iter()
        .flat_map(|tok| tok.leading_trivia.iter().chain(&tok.trailing_trivia))
        .filter(|trivia| match trivia.kind {
            TriviaKind::LineComment
            | TriviaKind::BlockComment
            | TriviaKind::JinjaComment
            | TriviaKind::MysqlVersionComment => true,
            TriviaKind::Whitespace
            | TriviaKind::Newline
            | TriviaKind::PsqlMetaCommand(_)
            | TriviaKind::ClientDelimiter
            | TriviaKind::CopyData => false,
        })
        .map(|trivia| trivia.span)
        .collect();
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    spans.dedup();
    spans
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

/// The words written against a string that make it a literal of another
/// kind: national (`N`), hexadecimal (`X`), bit or byte (`B`), escape (`E`),
/// raw (`R`) and raw bytes (`RB`, `BR`).
pub(crate) const LITERAL_PREFIXES: [&str; 7] = ["N", "X", "B", "E", "R", "RB", "BR"];

/// MySQL's character sets, each of which `_name` introduces a literal in.
const MYSQL_CHARACTER_SETS: [&str; 42] = [
    "armscii8", "ascii", "big5", "binary", "cp1250", "cp1251", "cp1256", "cp1257", "cp850",
    "cp852", "cp866", "cp932", "dec8", "eucjpms", "euckr", "gb18030", "gb2312", "gbk", "geostd8",
    "greek", "hebrew", "hp8", "keybcs2", "koi8r", "koi8u", "latin1", "latin2", "latin5", "latin7",
    "macce", "macroman", "sjis", "swe7", "tis620", "ucs2", "ujis", "utf16", "utf16le", "utf32",
    "utf8", "utf8mb3", "utf8mb4",
];

/// Whether `word` is a MySQL charset introducer (`_utf8mb4`, `_binary`).
pub(crate) fn is_charset_introducer(word: &str) -> bool {
    word.strip_prefix('_').is_some_and(|name| {
        MYSQL_CHARACTER_SETS
            .iter()
            .any(|c| name.eq_ignore_ascii_case(c))
    })
}

/// A string literal's value, decoded by [`decode_string_literal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedString {
    /// The value.
    pub value: String,
    /// For each character of `value`, in order, the span of the text that
    /// writes it (a doubled quote or a backslash escape is one span).
    pub sources: Vec<Span>,
    /// The span of the text between the opening and the closing delimiter,
    /// or to the end of the text when the closer is not written.
    pub content: Span,
    /// Whether the closing delimiter is written.
    pub closed: bool,
}

/// Decodes the string literal written as `text`, read as `dialect` reads
/// it; spans are offsets into `text`.
///
/// - A dollar-quoted string (`$$…$$`, `$tag$…$tag$`): its content as
///   written.
/// - A quoted string (`'…'`, `"…"`), alone or after a prefix written
///   against it: `E` (backslash escapes), `N` or a MySQL charset introducer
///   (`_utf8mb4'…'`) as a plain string, `R` (raw) or PostgreSQL's `U&` with
///   no backslash escape decoded. The literal is the whole text, closed
///   where the text ends with its quote; within it a doubled quote is one
///   quote, and a quote alone is itself. A backslash
///   escape is decoded in an `E` string, and in a plain one where the
///   dialect reads them: `\b`, `\f`, `\n`, `\r`, `\t`, octal `\o`–`\ooo`,
///   `\xh`–`\xhh`, `\uXXXX`, `\UXXXXXXXX`; any other is the character after
///   the backslash.
///
/// Returns `None` for text that is not one string literal: a binary
/// literal (`X'…'`, `B'…'`, `RB'…'`), a word that is no prefix, or text
/// after a dollar-quoted string's closer.
pub fn decode_string_literal(
    text: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<DecodedString> {
    let span = |start: usize, end: usize| Span {
        start: start as u32,
        end: end as u32,
    };
    if let Some(rest) = text.strip_prefix('$') {
        let tag_len = rest.find('$')? + 2;
        let tag = &text[..tag_len];
        if !tag[1..tag_len - 1]
            .chars()
            .all(lexer::is_identifier_continue)
        {
            return None;
        }
        let (end, closed) = match text[tag_len..].find(tag) {
            Some(at) if tag_len + at + tag_len == text.len() => (tag_len + at, true),
            Some(_) => return None,
            None => (text.len(), false),
        };
        let content = &text[tag_len..end];
        return Some(DecodedString {
            value: content.to_string(),
            sources: content
                .char_indices()
                .map(|(at, c)| span(tag_len + at, tag_len + at + c.len_utf8()))
                .collect(),
            content: span(tag_len, end),
            closed,
        });
    }
    let open = text.find(['\'', '"'])?;
    let prefix = &text[..open];
    let plain = dialect.backslash_escapes_in_single_quoted_strings();
    let escapes =
        if prefix.is_empty() || prefix.eq_ignore_ascii_case("N") || is_charset_introducer(prefix) {
            plain
        } else if prefix.eq_ignore_ascii_case("E") {
            true
        } else if prefix.eq_ignore_ascii_case("R") || prefix.eq_ignore_ascii_case("U&") {
            false
        } else {
            return None;
        };
    let quote = if text[open..].starts_with('"') {
        '"'
    } else {
        '\''
    };
    let body = open + 1;
    // The literal ends at the text's end: closed where its last character
    // is the quote.
    let closed = text.len() > body && text.ends_with(quote);
    let body_end = if closed { text.len() - 1 } else { text.len() };
    let mut value = String::with_capacity(body_end - body);
    let mut sources = Vec::with_capacity(body_end - body);
    let mut rest = text[body..body_end]
        .char_indices()
        .map(|(at, c)| (body + at, c))
        .peekable();
    while let Some((at, c)) = rest.next() {
        let mut end = at + c.len_utf8();
        let decoded = if c == quote {
            if rest.peek().is_some_and(|&(_, n)| n == quote) {
                rest.next();
                end += quote.len_utf8();
            }
            quote
        } else if c == '\\' && escapes {
            match rest.next() {
                Some((escaped_at, escaped)) => {
                    end = escaped_at + escaped.len_utf8();
                    let (radix, most_digits, first) = match escaped {
                        '0'..='7' => (8, 3, escaped.to_digit(8)),
                        'x' => (16, 2, None),
                        'u' => (16, 4, None),
                        'U' => (16, 8, None),
                        'b' => (0, 0, Some(0x08)),
                        'f' => (0, 0, Some(0x0C)),
                        'n' => (0, 0, Some(u32::from('\n'))),
                        'r' => (0, 0, Some(u32::from('\r'))),
                        't' => (0, 0, Some(u32::from('\t'))),
                        other => (0, 0, Some(u32::from(other))),
                    };
                    let mut code = first.unwrap_or(0);
                    let mut digits = usize::from(radix == 8);
                    while digits < most_digits {
                        let Some(&(digit_at, digit)) = rest.peek() else {
                            break;
                        };
                        let Some(value) = digit.to_digit(radix) else {
                            break;
                        };
                        code = code * radix + value;
                        end = digit_at + 1;
                        digits += 1;
                        rest.next();
                    }
                    if radix == 16 && digits == 0 {
                        // `\x`, `\u` with no digits stand for the letter.
                        escaped
                    } else {
                        char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER)
                    }
                }
                None => c,
            }
        } else {
            c
        };
        value.push(decoded);
        sources.push(span(at, end));
    }
    Some(DecodedString {
        value,
        sources,
        content: span(body, body_end),
        closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_literal_decodes_to_its_value_with_the_span_of_each_character() {
        use crate::dialect::{MySqlDialect, PostgresDialect};
        let pg = PostgresDialect;
        let decoded = |text: &str, dialect: &dyn crate::dialect::Dialect| {
            decode_string_literal(text, dialect).map(|d| {
                let sources: Vec<(u32, u32)> = d.sources.iter().map(|s| (s.start, s.end)).collect();
                (d.value, sources, (d.content.start, d.content.end), d.closed)
            })
        };
        // A doubled quote and an escape are one character with one span.
        assert_eq!(
            decoded("E'a''\\tb'", &pg),
            Some((
                "a'\tb".to_string(),
                vec![(2, 3), (3, 5), (5, 7), (7, 8)],
                (2, 8),
                true
            ))
        );
        // A plain string's backslash follows the dialect.
        assert_eq!(
            decoded("'a\\nb'", &pg).map(|d| d.0),
            Some("a\\nb".to_string())
        );
        assert_eq!(
            decoded("'a\\nb'", &MySqlDialect).map(|d| d.0),
            Some("a\nb".to_string())
        );
        assert_eq!(
            decoded("_utf8mb4'\\x41'", &MySqlDialect).map(|d| d.0),
            Some("A".to_string())
        );
        assert_eq!(
            decoded("U&'\\0041'", &pg).map(|d| d.0),
            Some("\\0041".to_string())
        );
        assert_eq!(
            decoded("\"a\"\"b\"", &pg).map(|d| d.0),
            Some("a\"b".to_string())
        );
        assert_eq!(
            decoded("$t$a 'b$t$", &pg),
            Some((
                "a 'b".to_string(),
                vec![(3, 4), (4, 5), (5, 6), (6, 7)],
                (3, 7),
                true
            ))
        );
        // Not closed: the value runs to the end of the text.
        assert_eq!(
            decoded("'ab", &pg),
            Some(("ab".to_string(), vec![(1, 2), (2, 3)], (1, 3), false))
        );
        assert_eq!(
            decoded("$$ab", &pg).map(|d| (d.0, d.3)),
            Some(("ab".to_string(), false))
        );
        // Not one string literal.
        assert_eq!(decoded("X'41'", &pg), None);
        assert_eq!(decoded("abc'x'", &pg), None);
        assert_eq!(decoded("$$a$$ b", &pg), None);
    }

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
