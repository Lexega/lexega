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
pub mod secrets;
pub mod span_utils;
pub mod syntax;

pub use ast::{AstExpr, AstScript, AstSelect, AstStmt};
pub use context::CopiedSpan;
pub use cst::{Cst, TokenId};
pub use dialect::{
    dialect_from_name, BigQueryDialect, CaretOperator, DatabricksDialect, Dialect, DialectRef,
    DollarNumber, DoubleAmpersand, MsSqlDialect, MySqlDialect, NumberLiteralGrammar,
    PostgresDialect, RadixPrefix, RedshiftDialect, SnowflakeDialect, WordOperator,
};
pub use error::{ParseError, ParseErrorKind, ParseResult};
pub use formatter::config::{
    ArrayLiteralStyle, BooleanOperatorPosition, CommaStyle, CopyIntoOptionsStyle,
    CreateStageClauseStyle, CteIndentStyle, FlattenStyle, FormatterConfig, IdentifierCase,
    IndentStyle, KeywordCase, LineBreak, MatchRecognizeDefineStyle, MatchRecognizeFormat,
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

/// Verification over the plain lexer, the Snowflake one.
fn verify_formatting_impl(original: &str, formatted: &str) -> Result<(), String> {
    verify_formatting_impl_with_dialect(original, formatted, &dialect::SnowflakeDialect)
}

/// Dialect-aware implementation of formatting verification: tokenizes with
/// the given dialect so that dialect-specific constructs (backtick
/// identifiers, bracket identifiers, @variables, #temp tables, etc.) are
/// lexed correctly for comparison.
fn verify_formatting_impl_with_dialect(
    original: &str,
    formatted: &str,
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    let orig_tokens = lexer::tokenize_with_dialect(original, dialect).tokens;
    let fmt_tokens = lexer::tokenize_with_dialect(formatted, dialect).tokens;
    verify_token_streams(original, formatted, &orig_tokens, &fmt_tokens, dialect)
}

/// Rejects `formatted` where a span the formatter copied from `original` as
/// written (`copied`, the formatter's own record,
/// [`context::FormattedContext::copied_spans`]: a routine body in another
/// language, a function body, a type written as read) does not read byte for
/// byte where it was written, at whatever depth the span lies. `formatted` is
/// the text as it will be written, so a change made to it after formatting is
/// seen too; a line break appended at its end moves no span.
pub fn verify_copied_spans(
    original: &str,
    formatted: &str,
    copied: &[CopiedSpan],
) -> Result<(), String> {
    let describe = |text: Option<&str>| {
        text.map_or_else(
            || "outside the text".to_string(),
            |text| format!("{text:?}"),
        )
    };
    for span in copied {
        let source = original.get(span.source.start as usize..span.source.end as usize);
        let output = formatted.get(span.output.start as usize..span.output.end as usize);
        if source.is_some() && source == output {
            continue;
        }
        return Err(format!(
            "Copied text changed: text the formatter copies as written reads differently in the output.\n\
             Original: {}\n\
             Formatted: {}",
            describe(source),
            describe(output)
        ));
    }
    Ok(())
}

/// The tokens a reader of `source` sees: not comments, not empty (EOF).
fn significant_tokens<'t>(tokens: &'t [Token], source: &str) -> Vec<&'t Token> {
    tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .filter(|t| !t.lexeme(source).is_empty())
        .collect()
}

/// Whether `formatted` reads as `original`: every comment kept, the
/// significant tokens the same and in order (only the insertions
/// [`inserted_token_count`] names added), and no two tokens written against
/// each other set apart where that changes how they read
/// ([`reads_as_one_with`]), and every batch separator where it was
/// ([`check_batch_separators`]).
fn verify_token_streams(
    original: &str,
    formatted: &str,
    orig_tokens: &[Token],
    fmt_tokens: &[Token],
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    let orig = significant_tokens(orig_tokens, original);
    let fmt = significant_tokens(fmt_tokens, formatted);
    let orig_lexemes: Vec<&str> = orig.iter().map(|t| t.lexeme(original)).collect();
    let fmt_lexemes: Vec<&str> = fmt.iter().map(|t| t.lexeme(formatted)).collect();

    check_comment_preservation(orig_tokens, fmt_tokens, original, formatted)?;
    check_critical_syntax_patterns(original, formatted, &orig_lexemes, &fmt_lexemes)?;

    let matched = align_significant_tokens(&orig, &fmt, original, formatted)
        .map_err(|at| token_mismatch_message(&orig_lexemes, &fmt_lexemes, at))?;
    let streams = TokenStreams {
        original,
        formatted,
        orig_tokens,
        fmt_tokens,
    };
    check_batch_separators(&streams, &orig, &fmt, &matched, dialect)?;
    check_sqlcmd_lines(&streams, dialect)?;
    check_tokens_kept_together(&orig, &fmt, &matched, original, formatted)
}

/// Rejects `formatted` where the sqlcmd command lines
/// ([`parser::sqlcmd_command_line`]) differ from the original's: sqlcmd
/// reads a command only from its own line, as written.
fn check_sqlcmd_lines(
    streams: &TokenStreams<'_>,
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    let lines = |source: &'_ str, tokens: &[Token]| -> Vec<String> {
        tokens
            .iter()
            .filter_map(|tok| {
                let line = parser::sqlcmd_command_line(source, tokens, tok, dialect)?;
                source
                    .get(tok.span.start as usize..line.end as usize)
                    .map(str::to_string)
            })
            .collect()
    };
    let kept = lines(streams.original, streams.orig_tokens);
    let written = lines(streams.formatted, streams.fmt_tokens);
    match kept.iter().zip(&written).find(|(k, w)| k != w) {
        Some((k, w)) => Err(format!(
            "sqlcmd command line changed: `{k}` is written `{w}`."
        )),
        None if kept.len() != written.len() => Err(format!(
            "sqlcmd command lines changed: {} in the original, {} formatted.",
            kept.len(),
            written.len()
        )),
        None => Ok(()),
    }
}

/// The original and formatted text with every token the lexer read in each.
struct TokenStreams<'s> {
    original: &'s str,
    formatted: &'s str,
    orig_tokens: &'s [Token],
    fmt_tokens: &'s [Token],
}

/// Rejects `formatted` where a batch separator is not the original's own
/// ([`parser::is_batch_separator`]): a `go` name set alone on its line ends
/// the batch there for `sqlcmd` and SSMS, and a separator moved off its line
/// joins two batches. A line the original starts with `GO`, separator or
/// not ([`parser::go_line_start`]), must start a line in the output too.
fn check_batch_separators(
    streams: &TokenStreams<'_>,
    orig: &[&Token],
    fmt: &[&Token],
    matched: &[usize],
    dialect: &dyn dialect::Dialect,
) -> Result<(), String> {
    let TokenStreams {
        original,
        formatted,
        orig_tokens,
        fmt_tokens,
    } = *streams;
    let line_of = |tok: &Token| formatted[..tok.span.start as usize].matches('\n').count() + 1;
    let kept: Vec<usize> = orig
        .iter()
        .zip(matched)
        .filter(|(tok, _)| parser::is_batch_separator(original, orig_tokens, tok, dialect))
        .map(|(_, at)| *at)
        .collect();
    let written: Vec<usize> = fmt
        .iter()
        .enumerate()
        .filter(|(_, tok)| parser::is_batch_separator(formatted, fmt_tokens, tok, dialect))
        .map(|(at, _)| at)
        .collect();
    if kept != written {
        let message = match written.iter().find(|at| !kept.contains(at)) {
            Some(at) => format!(
                "Batch separator added: `{}` stands alone on formatted line {}, where sqlcmd and SSMS end the batch.",
                fmt[*at].lexeme(formatted),
                line_of(fmt[*at]),
            ),
            None => "Batch separator lost: a GO that stood alone on its line no longer does."
                .to_string(),
        };
        return Err(message);
    }
    let joined = orig.iter().zip(matched).find(|(tok, at)| {
        parser::go_line_start(original, orig_tokens, tok, dialect).is_some()
            && parser::go_line_start(formatted, fmt_tokens, fmt[**at], dialect).is_none()
    });
    match joined {
        Some((_, at)) => Err(format!(
            "GO line joined: the `{}` that starts its line in the original does not start formatted line {}.",
            fmt[*at].lexeme(formatted),
            line_of(fmt[*at]),
        )),
        None => Ok(()),
    }
}

/// Whether two tokens are the same token: words compare without regard to
/// case (keyword and identifier casing are formatter options), a string or
/// a quoted name byte for byte.
fn same_token(orig: &Token, orig_lexeme: &str, fmt_lexeme: &str) -> bool {
    let exact = matches!(
        orig.kind,
        TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
            | TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            }
    );
    if exact {
        orig_lexeme == fmt_lexeme
    } else {
        orig_lexeme.eq_ignore_ascii_case(fmt_lexeme)
    }
}

/// How many tokens at `fmt[j]` the formatter inserted before the original's
/// token `orig[i]`, by the normalizations it makes: an `AS` before an alias,
/// `INNER` before a bare `JOIN`, `OUTER` after `LEFT` / `RIGHT` / `FULL`.
/// Zero if none.
fn inserted_token_count(orig: &[&str], fmt: &[&str], i: usize, j: usize) -> usize {
    let is = |s: Option<&&str>, w: &str| s.is_some_and(|s| s.eq_ignore_ascii_case(w));
    let before_orig = |k: usize| {
        fmt.get(k)
            .zip(orig.get(i))
            .is_some_and(|(f, o)| f.eq_ignore_ascii_case(o))
    };
    let previous = i.checked_sub(1).and_then(|p| orig.get(p));
    if is(fmt.get(j), "AS") && before_orig(j + 1) {
        return 1;
    }
    if is(fmt.get(j), "INNER") && is(orig.get(i), "JOIN") && before_orig(j + 1) {
        return 1;
    }
    let outer_join_side = ["LEFT", "RIGHT", "FULL"].iter().any(|w| is(previous, w));
    if is(fmt.get(j), "OUTER") && outer_join_side && is(orig.get(i), "JOIN") && before_orig(j + 1) {
        return 1;
    }
    0
}

/// Pairs each significant token of the original with the formatted token
/// that is the same ([`same_token`]), allowing only the formatter's
/// insertions ([`inserted_token_count`]) and a `;` added at the end. Returns
/// the formatted index of each original token, or the original index at
/// which the two diverge.
fn align_significant_tokens(
    orig: &[&Token],
    fmt: &[&Token],
    orig_src: &str,
    fmt_src: &str,
) -> Result<Vec<usize>, usize> {
    let orig_lexemes: Vec<&str> = orig.iter().map(|t| t.lexeme(orig_src)).collect();
    let fmt_lexemes: Vec<&str> = fmt.iter().map(|t| t.lexeme(fmt_src)).collect();
    let mut matched = Vec::with_capacity(orig.len());
    let mut j = 0;
    for (i, tok) in orig.iter().enumerate() {
        loop {
            let Some(fmt_lexeme) = fmt_lexemes.get(j) else {
                return Err(i);
            };
            if same_token(tok, orig_lexemes[i], fmt_lexeme) {
                break;
            }
            match inserted_token_count(&orig_lexemes, &fmt_lexemes, i, j) {
                0 => return Err(i),
                n => j += n,
            }
        }
        matched.push(j);
        j += 1;
    }
    let rest = &fmt_lexemes[j.min(fmt_lexemes.len())..];
    let semicolon_added = rest == [";"] && orig_lexemes.last() != Some(&";");
    if rest.is_empty() || semicolon_added {
        Ok(matched)
    } else {
        Err(orig.len())
    }
}

/// The error for token streams that diverge at original index `at`.
fn token_mismatch_message(orig: &[&str], fmt: &[&str], at: usize) -> String {
    if orig.len() == fmt.len() {
        let i = at.min(orig.len().saturating_sub(1));
        return format!(
            "Token content mismatch at position {}!\n\
             Original token: '{}'\n\
             Formatted token: '{}'\n\
             \n\
             Token counts match but content differs - this indicates semantic changes!\n\
             This could be value substitution, operator change, or function swap.\n\
             First 10 tokens: {:?}\n\
             Context around position {}: {:?}",
            i,
            orig.get(i).unwrap_or(&"<none>"),
            fmt.get(i).unwrap_or(&"<none>"),
            &orig[..orig.len().min(10)],
            i,
            &orig[i.saturating_sub(3)..(i + 4).min(orig.len())]
        );
    }

    let mut first_diff_idx = 0;
    for (i, (o, f)) in orig.iter().zip(fmt.iter()).enumerate() {
        if !o.eq_ignore_ascii_case(f) {
            first_diff_idx = i;
            break;
        }
        first_diff_idx = i + 1;
    }
    format!(
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
        orig.len(),
        fmt.len(),
        first_diff_idx,
        orig.get(first_diff_idx).unwrap_or(&"<none>"),
        fmt.get(first_diff_idx).unwrap_or(&"<none>"),
        &orig[first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(orig.len())],
        &fmt[first_diff_idx.saturating_sub(5)..(first_diff_idx + 5).min(fmt.len())],
        &orig[..orig.len().min(20)],
        &fmt[..fmt.len().min(20)]
    )
}

/// Whether a token of this kind ends in a character that runs on into a
/// word written against it: a keyword, a name, a number, a boolean, `NULL`,
/// `$1`, the close of a template expression or statement.
fn ends_in_word_character(kind: &TokenKind) -> bool {
    match kind {
        TokenKind::Keyword(_) | TokenKind::JinjaExprClose | TokenKind::JinjaStmtClose => true,
        TokenKind::Identifier { kind, .. } => match kind {
            IdentifierKind::Unquoted
            | IdentifierKind::AtVariable
            | IdentifierKind::TempTable
            | IdentifierKind::DollarQuoteDelimiter => true,
            IdentifierKind::Quoted => false,
        },
        TokenKind::Literal(literal) => match literal {
            LiteralKind::Number
            | LiteralKind::Position
            | LiteralKind::Parameter
            | LiteralKind::Money
            | LiteralKind::Boolean
            | LiteralKind::Null => true,
            LiteralKind::String | LiteralKind::StringFragment => false,
        },
        TokenKind::Operator(_)
        | TokenKind::Punctuation(_)
        | TokenKind::LineComment
        | TokenKind::BlockComment
        | TokenKind::JinjaComment
        | TokenKind::JinjaExprOpen
        | TokenKind::JinjaStmtOpen
        | TokenKind::JinjaPipe
        | TokenKind::JinjaTilde
        | TokenKind::JinjaDoubleStar
        | TokenKind::JinjaDoubleSlash
        | TokenKind::JinjaDoubleEq
        | TokenKind::JinjaAnd
        | TokenKind::JinjaOr
        | TokenKind::JinjaNot
        | TokenKind::JinjaIn
        | TokenKind::JinjaIs
        | TokenKind::JinjaTrue
        | TokenKind::JinjaFalse
        | TokenKind::JinjaNull
        | TokenKind::JinjaIf
        | TokenKind::JinjaElif
        | TokenKind::JinjaElse
        | TokenKind::JinjaEndIf
        | TokenKind::JinjaFor
        | TokenKind::JinjaEndFor
        | TokenKind::JinjaSet
        | TokenKind::JinjaEndSet
        | TokenKind::JinjaDocs
        | TokenKind::JinjaEndDocs
        | TokenKind::JinjaFilter
        | TokenKind::JinjaEndFilter
        | TokenKind::JinjaCall
        | TokenKind::JinjaEndCall
        | TokenKind::Placeholder
        | TokenKind::Eof
        | TokenKind::Unknown => false,
    }
}

/// Whether a token of this kind starts with a character a word written
/// against it runs on into: a keyword, an unquoted name, a number, a
/// boolean, `NULL`, the open of a template expression or statement.
fn starts_with_word_character(kind: &TokenKind) -> bool {
    match kind {
        TokenKind::Keyword(_) | TokenKind::JinjaExprOpen | TokenKind::JinjaStmtOpen => true,
        TokenKind::Identifier { kind, .. } => match kind {
            IdentifierKind::Unquoted | IdentifierKind::DollarQuoteDelimiter => true,
            IdentifierKind::Quoted | IdentifierKind::AtVariable | IdentifierKind::TempTable => {
                false
            }
        },
        TokenKind::Literal(literal) => match literal {
            LiteralKind::Number | LiteralKind::Boolean | LiteralKind::Null => true,
            LiteralKind::Position
            | LiteralKind::Parameter
            | LiteralKind::Money
            | LiteralKind::String
            | LiteralKind::StringFragment => false,
        },
        TokenKind::Operator(_)
        | TokenKind::Punctuation(_)
        | TokenKind::LineComment
        | TokenKind::BlockComment
        | TokenKind::JinjaComment
        | TokenKind::JinjaExprClose
        | TokenKind::JinjaStmtClose
        | TokenKind::JinjaPipe
        | TokenKind::JinjaTilde
        | TokenKind::JinjaDoubleStar
        | TokenKind::JinjaDoubleSlash
        | TokenKind::JinjaDoubleEq
        | TokenKind::JinjaAnd
        | TokenKind::JinjaOr
        | TokenKind::JinjaNot
        | TokenKind::JinjaIn
        | TokenKind::JinjaIs
        | TokenKind::JinjaTrue
        | TokenKind::JinjaFalse
        | TokenKind::JinjaNull
        | TokenKind::JinjaIf
        | TokenKind::JinjaElif
        | TokenKind::JinjaElse
        | TokenKind::JinjaEndIf
        | TokenKind::JinjaFor
        | TokenKind::JinjaEndFor
        | TokenKind::JinjaSet
        | TokenKind::JinjaEndSet
        | TokenKind::JinjaDocs
        | TokenKind::JinjaEndDocs
        | TokenKind::JinjaFilter
        | TokenKind::JinjaEndFilter
        | TokenKind::JinjaCall
        | TokenKind::JinjaEndCall
        | TokenKind::Placeholder
        | TokenKind::Eof
        | TokenKind::Unknown => false,
    }
}

/// Whether two tokens written against each other read as one piece of text,
/// so that setting them apart changes what the text says: word characters
/// on both sides (`0x41` lexed as `0` and `x41`, a template expression and
/// the name written against it), or an unquoted word and the string it
/// prefixes (`X'41'`, `N'…'`, `_utf8mb4'…'`), or a dollar-quote delimiter
/// and a string written against it.
fn reads_as_one_with(left: &TokenKind, right: &TokenKind) -> bool {
    let prefixes_string = matches!(
        left,
        TokenKind::Identifier {
            kind: IdentifierKind::Unquoted | IdentifierKind::DollarQuoteDelimiter,
            ..
        }
    ) && matches!(
        right,
        TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
    );
    prefixes_string || (ends_in_word_character(left) && starts_with_word_character(right))
}

/// Rejects formatted text that sets apart two tokens the original writes
/// against each other where they read as one ([`reads_as_one_with`]).
/// `matched[i]` is the formatted index of original token `i`.
fn check_tokens_kept_together(
    orig: &[&Token],
    fmt: &[&Token],
    matched: &[usize],
    orig_src: &str,
    fmt_src: &str,
) -> Result<(), String> {
    let touches = |a: &Token, b: &Token| a.span.end == b.span.start;
    for (i, pair) in orig.windows(2).enumerate() {
        let (left, right) = (pair[0], pair[1]);
        if !touches(left, right) || !reads_as_one_with(&left.kind, &right.kind) {
            continue;
        }
        // A template statement (`{% … %}`) renders nothing: the word after
        // it reads against the word before it only if both touch the tag.
        if matches!(left.kind, TokenKind::JinjaStmtClose) {
            let open = orig[..i]
                .iter()
                .rposition(|t| matches!(t.kind, TokenKind::JinjaStmtOpen));
            let word_before = open.and_then(|k| k.checked_sub(1)).is_some_and(|k| {
                touches(orig[k], orig[k + 1]) && ends_in_word_character(&orig[k].kind)
            });
            if !word_before {
                continue;
            }
        }
        if matches!(right.kind, TokenKind::JinjaStmtOpen) {
            let close = orig[i + 1..]
                .iter()
                .position(|t| matches!(t.kind, TokenKind::JinjaStmtClose))
                .map(|k| i + 1 + k);
            let word_after = close.is_some_and(|k| {
                orig.get(k + 1).is_some_and(|next| {
                    touches(orig[k], next) && starts_with_word_character(&next.kind)
                })
            });
            if !word_after {
                continue;
            }
        }
        let (fl, fr) = (matched[i], matched[i + 1]);
        if fr == fl + 1 && fmt[fl].span.end == fmt[fr].span.start {
            continue;
        }
        let written = orig_src
            .get(left.span.start as usize..right.span.end as usize)
            .unwrap_or("");
        let printed = fmt_src
            .get(fmt[fl].span.start as usize..fmt[fr].span.end as usize)
            .unwrap_or("");
        return Err(format!(
            "Token separation detected!\n\
             Original: {:?}\n\
             Formatted: {:?}\n\
             \n\
             The original writes these tokens against each other; set apart, they read differently.",
            written, printed
        ));
    }
    Ok(())
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
