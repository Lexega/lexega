// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! COPY INTO statement parsing.
//!
//! Handles both forms of COPY INTO:
//! - Load: `COPY INTO <table> FROM <stage> ...`
//! - Unload: `COPY INTO <stage> FROM <table/query> ...`
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/sql/copy-into-table>

use crate::ast::{AstCopyOption, AstStageCredentialOption};
use crate::lexer::{decode_string_literal, Keyword, LiteralKind, Operator, Punctuation, TokenKind};
use crate::parser::core::{NamePosition, Parser};
use crate::parser::create_stage::try_parse_credential_option;
use crate::parser::set_operations::star_over_table;
use crate::parser::sql_stmt::{build_copy_into_span, build_select, build_table_ref};

/// Parse COPY INTO statement.
///
/// COPY INTO can take two forms:
/// 1. COPY INTO <table> FROM <stage/location> ...  (load data)
/// 2. COPY INTO <stage/location> FROM <table/query> ... (unload data)
///
/// This function determines which variant based on what follows the INTO keyword.
pub(crate) fn try_parse_copy_into_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<crate::ast::AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseResultExt};

    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["COPY".to_string()])?; // COPY
    let keyword_span = kw.span;

    // Expect INTO keyword
    let into_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY statement requires INTO keyword".to_string(),
            },
        )
    })?;

    if !into_tok.lexeme(p.source).eq_ignore_ascii_case("INTO") {
        return Err(ParseError::new(
            into_tok.span,
            crate::error::ParseErrorKind::InvalidSyntax {
                message: format!(
                    "Expected INTO after COPY, found '{}'",
                    into_tok.lexeme(p.source)
                ),
            },
        ));
    }

    p.advance()
        .expect_invariant("INTO keyword confirmed by prior validation");

    // Peek at the next token to determine variant
    // If it starts with @ it's a stage (location variant)
    // Otherwise, try to parse as table name (table variant)
    let next_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO requires a target (table or location)".to_string(),
            },
        )
    })?;

    let is_location =
        next_tok.lexeme(p.source).starts_with('@') || next_tok.lexeme(p.source).starts_with('\'');

    if is_location {
        // COPY INTO <location> FROM <table/query>
        parse_copy_into_location(p, keyword_span)
    } else {
        // COPY INTO <table> FROM <stage/location>
        parse_copy_into_table(p, keyword_span)
    }
}

/// Parse COPY INTO <table> FROM <stage> variant
fn parse_copy_into_table(
    p: &mut Parser<'_>,
    _keyword_span: crate::lexer::Span,
) -> crate::error::ParseResult<crate::ast::AstStmt> {
    use crate::error::{ExpectInvariant, ParseError};

    // Parse table name
    let table_start_idx = p.idx;
    while let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("FROM") {
            break;
        }
        match tok.kind {
            crate::lexer::TokenKind::Eof
            | crate::lexer::TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | crate::lexer::TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            _ => {
                let _ = p.advance();
            }
        }
    }
    let table_end_idx = p.idx;

    let table_name = if table_end_idx > table_start_idx {
        let node_id = p.id_gen.next();
        // `name [(column, …)]`: the name, then the column list after it.
        let name_end = p
            .object_name_end(table_start_idx)
            .filter(|&end| end == table_end_idx || p.parens_end(end) == Some(table_end_idx))
            .unwrap_or(table_end_idx);
        p.object_ref_of_range(table_start_idx, name_end, node_id)
    } else {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO requires a table name".to_string(),
            },
        ));
    };

    // Expect FROM keyword
    let from_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO <table> requires FROM clause".to_string(),
            },
        )
    })?;

    if !from_tok.lexeme(p.source).eq_ignore_ascii_case("FROM") {
        return Err(ParseError::new(
            from_tok.span,
            crate::error::ParseErrorKind::InvalidSyntax {
                message: format!(
                    "Expected FROM after table name, found '{}'",
                    from_tok.lexeme(p.source)
                ),
            },
        ));
    }

    let from_tok = p
        .advance()
        .expect_invariant("FROM keyword confirmed by prior validation");
    let from_start = from_tok.span.start;

    // Capture the load source URL if the first non-trivia token after FROM
    // is a string literal (COPY INTO t FROM 's3://…' — external location).
    let (from_location_url, from_location_url_span) = match p.peek_non_trivia() {
        Some(tok) if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) => (
            decode_string_literal(tok.lexeme(p.source), p.dialect).map(|d| d.value),
            Some(tok.span),
        ),
        _ => (None, None),
    };

    // Parse FROM clause (stage/location and all options)
    // This includes: stage/location, FILES, PATTERN, FILE_FORMAT, copy options, VALIDATION_MODE
    let from_start_idx = p.idx;
    let from_stage = p.stage_ref_at(from_start_idx);
    let mut file_format_name = None;
    let mut credentials: Vec<AstStageCredentialOption> = Vec::new();
    let mut copy_options: Vec<AstCopyOption> = Vec::new();
    let mut depth: i32 = 0;
    while let Some(tok) = p.peek_non_trivia() {
        if depth == 0 && file_format_name.is_none() {
            file_format_name = file_format_name_at(p, p.idx);
        }
        // Databricks' `CREDENTIAL (…)`, `FORMAT_OPTIONS (…)`, `COPY_OPTIONS (…)`.
        if ["CREDENTIAL", "FORMAT_OPTIONS", "COPY_OPTIONS"]
            .iter()
            .any(|w| tok.lexeme(p.source).eq_ignore_ascii_case(w))
        {
            p.record_option_list_secrets(p.idx + 1);
        }
        match tok.kind {
            TokenKind::Eof
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Operator(Operator::Pipe) => break,
            // Loading straight from an external location embeds credentials
            // on the statement — same typed extraction (and redaction-span
            // recording) as the unload direction.
            TokenKind::Keyword(Keyword::Credentials) => {
                extract_inline_credentials(p, &mut credentials);
            }
            // Track nesting so a `NAME = VALUE` inside a parenthesized value
            // (FILE_FORMAT = (...)) or subquery isn't read as a top-level option.
            TokenKind::Punctuation(Punctuation::LParen) => {
                depth += 1;
                let _ = p.advance();
            }
            TokenKind::Punctuation(Punctuation::RParen) => {
                depth = depth.saturating_sub(1);
                let _ = p.advance();
            }
            _ if depth == 0 => match try_parse_copy_option(p) {
                Some(opt) => copy_options.push(opt),
                None => {
                    let _ = p.advance();
                }
            },
            _ => {
                let _ = p.advance();
            }
        }
    }
    let from_end_idx = p.idx;

    let (from_span, span) = if from_end_idx > from_start_idx {
        let last = &p.tokens[from_end_idx - 1];
        let last_span_end = last.span.end;
        (
            crate::lexer::Span {
                start: from_start,
                end: last_span_end,
            },
            build_copy_into_span(_keyword_span, last_span_end),
        )
    } else {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO <table> FROM requires a stage or location".to_string(),
            },
        ));
    };

    // The opaque `from_span` preserves the full FROM clause byte-for-byte;
    // `copy_options` carries the typed `NAME = VALUE` settings extracted above.
    let options_span = None;

    Ok(crate::ast::AstStmt::CopyIntoTable {
        node_id: p.id_gen.next(),
        span,
        table_name,
        from_span,
        options_span,
        copy_options,
        from_location_url,
        from_location_url_span,
        from_stage: from_stage.map(Box::new),
        file_format_name: file_format_name.map(Box::new),
        credentials,
    })
}

/// The file format named by `FILE_FORMAT = (FORMAT_NAME = name)` written at
/// token `at`.
fn file_format_name_at(p: &Parser<'_>, at: usize) -> Option<crate::ast::AstObjectRef> {
    let assigns = p
        .tokens
        .get(at + 1)
        .is_some_and(|t| t.kind == TokenKind::Operator(Operator::Eq))
        && p.tokens
            .get(at + 2)
            .is_some_and(|t| t.kind == TokenKind::Punctuation(Punctuation::LParen));
    if !(assigns && p.word_at(at, "FILE_FORMAT")) {
        return None;
    }
    p.format_name_in(at + 2)
}

/// Parse COPY INTO <location> FROM <table/query> variant.
///
/// Captures the location URL (when it's a quoted string literal) and any
/// inline `CREDENTIALS=(...)` clause within the statement body as typed
/// fields on the AST, so nothing downstream re-tokenizes.
fn parse_copy_into_location(
    p: &mut Parser<'_>,
    _keyword_span: crate::lexer::Span,
) -> crate::error::ParseResult<crate::ast::AstStmt> {
    use crate::error::{ExpectInvariant, ParseError};

    // Capture the location URL if the first non-trivia token after INTO
    // is a string literal (e.g. COPY INTO 's3://bucket/...').
    let (location_url, location_url_span) = match p.peek_non_trivia() {
        Some(tok) if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) => (
            decode_string_literal(tok.lexeme(p.source), p.dialect).map(|d| d.value),
            Some(tok.span),
        ),
        _ => (None, None),
    };

    // Parse location (stage or external location)
    let into_start_idx = p.idx;
    let into_stage = p.stage_ref_at(into_start_idx);
    while let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("FROM") {
            break;
        }
        match tok.kind {
            TokenKind::Eof
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Operator(Operator::Pipe) => break,
            _ => {
                let _ = p.advance();
            }
        }
    }
    let into_end_idx = p.idx;

    let into_span = if into_end_idx > into_start_idx {
        let first = &p.tokens[into_start_idx];
        let last = &p.tokens[into_end_idx - 1];
        crate::lexer::Span {
            start: first.span.start,
            end: last.span.end,
        }
    } else {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO requires a location (stage or external location)".to_string(),
            },
        ));
    };

    // Expect FROM keyword
    let from_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO <location> requires FROM clause".to_string(),
            },
        )
    })?;

    if !from_tok.lexeme(p.source).eq_ignore_ascii_case("FROM") {
        return Err(ParseError::new(
            from_tok.span,
            crate::error::ParseErrorKind::InvalidSyntax {
                message: format!(
                    "Expected FROM after location, found '{}'",
                    from_tok.lexeme(p.source)
                ),
            },
        ));
    }

    let from_tok = p
        .advance()
        .expect_invariant("FROM keyword confirmed by prior validation");
    let from_start = from_tok.span.start;

    // Parse FROM clause (table/query and all options). This includes:
    // table/query, PARTITION BY, FILE_FORMAT, copy options, VALIDATION_MODE,
    // HEADER, and (for external locations) CREDENTIALS / STORAGE_INTEGRATION.
    //
    // We hook the token walk to detect `CREDENTIALS = ( … )` and decompose
    // the body into typed `AstStageCredentialOption` entries; everything
    // else is consumed opaquely (preserved as `from_span` bytes).
    let from_start_idx = p.idx;

    // Capture the unload SOURCE (table or parenthesized subquery) structurally
    // before the opaque option walk below — so the egress point can analyze the
    // classification of the columns leaving the warehouse. The walk still spans
    // the whole FROM clause into `from_span`; on any shape we don't recognize,
    // `source` is None and behavior is unchanged (bytes remain in `from_span`).
    let source = parse_unload_source(p);

    let mut file_format_name = None;
    let mut credentials: Vec<AstStageCredentialOption> = Vec::new();
    let mut copy_options: Vec<AstCopyOption> = Vec::new();
    let mut depth: i32 = 0;
    while let Some(tok) = p.peek_non_trivia() {
        if depth == 0 && file_format_name.is_none() {
            file_format_name = file_format_name_at(p, p.idx);
        }
        match tok.kind {
            TokenKind::Eof
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Operator(Operator::Pipe) => break,
            // CREDENTIALS gets typed extraction; everything else that is a
            // `NAME = VALUE` at top level becomes a copy option.
            TokenKind::Keyword(Keyword::Credentials) => {
                extract_inline_credentials(p, &mut credentials);
            }
            TokenKind::Punctuation(Punctuation::LParen) => {
                depth += 1;
                let _ = p.advance();
            }
            TokenKind::Punctuation(Punctuation::RParen) => {
                depth = depth.saturating_sub(1);
                let _ = p.advance();
            }
            _ if depth == 0 => match try_parse_copy_option(p) {
                Some(opt) => copy_options.push(opt),
                None => {
                    let _ = p.advance();
                }
            },
            _ => {
                let _ = p.advance();
            }
        }
    }
    let from_end_idx = p.idx;

    let (from_span, span) = if from_end_idx > from_start_idx {
        let last = &p.tokens[from_end_idx - 1];
        let last_span_end = last.span.end;
        (
            crate::lexer::Span {
                start: from_start,
                end: last_span_end,
            },
            build_copy_into_span(_keyword_span, last_span_end),
        )
    } else {
        return Err(ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "COPY INTO <location> FROM requires a table or query".to_string(),
            },
        ));
    };

    // The opaque `from_span` preserves the full FROM clause byte-for-byte;
    // `credentials` and `copy_options` carry the typed settings extracted above.
    let options_span = None;

    Ok(crate::ast::AstStmt::CopyIntoLocation {
        node_id: p.id_gen.next(),
        span,
        into_span,
        into_stage: into_stage.map(Box::new),
        file_format_name: file_format_name.map(Box::new),
        from_span,
        options_span,
        location_url,
        location_url_span,
        credentials,
        copy_options,
        source,
    })
}

/// Capture the unload source of `COPY INTO <location> FROM <source>`: a
/// parenthesized subquery `(<query>)` or a (qualified) table name. Returns
/// `None` for any shape we don't capture — the FROM bytes still flow into
/// `from_span`, so behavior is unchanged. The consumed tokens are part of
/// the FROM clause the caller's option walk continues over.
fn parse_unload_source(p: &mut Parser<'_>) -> Option<crate::ast::AstUnloadSource> {
    let tok = p.peek_non_trivia()?;
    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
        let _ = p.advance(); // consume (
        let stmt = p.parse_statement().ok()?;
        // Consume the matching ) when present; tolerate absence (the option
        // walk resumes either way).
        if let Some(t) = p.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                let _ = p.advance();
            }
        }
        Some(crate::ast::AstUnloadSource::Subquery(Box::new(stmt)))
    } else {
        let name = p.parse_object_ref_with_argument(NamePosition::Object)?;
        let name_span = name.span;
        let table = Box::new(build_table_ref(
            p.id_gen.next(),
            name_span,
            name,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ));
        let (star, from) = star_over_table(p, table);
        let query = build_select(
            p.id_gen.next(),
            name_span,
            name_span,
            None,
            None,
            None,
            None,
            star,
            from,
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        Some(crate::ast::AstUnloadSource::Table {
            name_span,
            query: Box::new(crate::ast::AstStmt::Select(Box::new(query))),
        })
    }
}

/// Walk a `CREDENTIALS = ( KEY = VALUE … )` block at the current token
/// position. The caller has already verified the current token is the
/// `CREDENTIALS` keyword; this consumes through the matching `)`.
///
/// On shape divergence (missing `=`, missing `(`, unexpected tokens
/// inside the block), advances one token and returns — the outer loop
/// will resume scanning. This keeps zero-loss byte-preservation
/// intact: anything not matched as a typed option flows through as
/// opaque from-clause content.
fn extract_inline_credentials(p: &mut Parser<'_>, out: &mut Vec<AstStageCredentialOption>) {
    let _ = p.advance(); // consume CREDENTIALS keyword

    // Expect =
    match p.peek_non_trivia() {
        Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq)) => {
            let _ = p.advance();
        }
        _ => return,
    }

    // Expect (
    match p.peek_non_trivia() {
        Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) => {
            let _ = p.advance();
        }
        _ => return,
    }

    // Walk options until matching ).
    loop {
        let next = match p.peek_non_trivia() {
            Some(t) => t,
            None => return,
        };
        if matches!(next.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            let _ = p.advance();
            return;
        }
        if matches!(next.kind, TokenKind::Punctuation(Punctuation::Comma)) {
            let _ = p.advance();
            continue;
        }
        match try_parse_credential_option(p) {
            Some(opt) => out.push(opt),
            None => {
                // Shape divergence inside the block — depth-walk to the
                // matching close paren and return.
                let mut depth = 1;
                while depth > 0 {
                    let t = match p.peek_non_trivia() {
                        Some(t) => t,
                        None => return,
                    };
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        depth += 1;
                    } else if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        depth -= 1;
                        let _ = p.advance();
                        if depth == 0 {
                            return;
                        }
                        continue;
                    }
                    let _ = p.advance();
                }
                return;
            }
        }
    }
}

/// Try to parse a `NAME = VALUE` copy option at the current position.
///
/// On success, consumes through the value (a scalar token, or a full
/// `( … )` block for parenthesized values like `FILE_FORMAT = (...)`) and
/// returns the typed option. On shape divergence — the name isn't a word,
/// or no `=` follows — restores the position and returns `None`, so the
/// caller advances one token and the bytes flow through as opaque
/// from-clause content (zero-loss, mirroring `extract_inline_credentials`).
fn try_parse_copy_option(p: &mut Parser<'_>) -> Option<AstCopyOption> {
    let saved = p.idx;

    // Option name: an identifier or keyword token.
    let name_tok = p.peek_non_trivia()?;
    if !matches!(
        name_tok.kind,
        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
    ) {
        return None;
    }
    let name_span = name_tok.span;
    let _ = p.advance();

    // Require `=`.
    match p.peek_non_trivia() {
        Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq)) => {
            let _ = p.advance();
        }
        _ => {
            p.idx = saved;
            return None;
        }
    }

    // Value: a parenthesized block or a single scalar token.
    let (value_start, first_end, is_lparen) = match p.peek_non_trivia() {
        Some(t) => (
            t.span.start,
            t.span.end,
            matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
        ),
        None => {
            p.idx = saved;
            return None;
        }
    };

    let value_end = if is_lparen {
        let _ = p.advance(); // consume '('
        let mut depth = 1i32;
        let mut end = first_end;
        while depth > 0 {
            let (tok_end, is_l, is_r) = match p.peek_non_trivia() {
                Some(t) => (
                    t.span.end,
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                ),
                None => break,
            };
            end = tok_end;
            let _ = p.advance();
            if is_l {
                depth += 1;
            } else if is_r {
                depth -= 1;
            }
        }
        end
    } else {
        let _ = p.advance();
        first_end
    };

    Some(AstCopyOption {
        node_id: p.id_gen.next(),
        span: crate::lexer::Span {
            start: name_span.start,
            end: value_end,
        },
        name_span,
        value_span: crate::lexer::Span {
            start: value_start,
            end: value_end,
        },
    })
}
