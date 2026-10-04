// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE STAGE statement parsing
//!
//! Implements comprehensive parsing for Snowflake CREATE STAGE statements,
//! supporting both internal and external stages with all Snowflake-documented
//! parameters:
//!
//! - Internal stages: ENCRYPTION parameters
//! - External stages: URL, STORAGE_INTEGRATION, CREDENTIALS, ENCRYPTION
//! - Directory tables: DIRECTORY clause with ENABLE, AUTO_REFRESH, etc.
//! - File formats: FILE_FORMAT with FORMAT_NAME or TYPE specifications
//! - Metadata: COMMENT, TAG clauses
//! - Variants: OR REPLACE, TEMPORARY, IF NOT EXISTS, CLONE
//!
//! ## Grammar (from Snowflake docs)
//!
//! ```text
//! CREATE [ OR REPLACE ] [ { TEMP | TEMPORARY } ] STAGE [ IF NOT EXISTS ] <stage_name>
//!   [ URL = 'protocol://bucket/path' ]
//!   [ { STORAGE_INTEGRATION = <integration_name> } | { CREDENTIALS = ( ... ) } ]
//!   [ ENCRYPTION = ( ... ) ]
//!   [ DIRECTORY = ( ... ) ]
//!   [ FILE_FORMAT = ( ... ) ]
//!   [ COMMENT = '<string_literal>' ]
//!   [ [ WITH ] TAG ( <tag_name> = '<tag_value>' [ , ... ] ) ]
//! ```

use crate::ast::{
    AstCreateStage, AstStageCredentialOption, AstStageCredentialOptionValue,
    AstStageCredentialsClause, AstStageCredentialsKind, AstStageFileFormatClause,
    AstStageFileFormatSpec, AstStageType, AstStageUrlClause, AstStmt,
};
use crate::ast::{AstUnknownClause, UnknownKind};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Parse CREATE STAGE statement with comprehensive support for all Snowflake options.
///
/// This parser handles:
/// - Internal stages (no URL) with ENCRYPTION
/// - External stages (with URL) supporting S3, GCS, Azure, S3-compatible storage
/// - STORAGE_INTEGRATION for secure cloud access
/// - CREDENTIALS for direct authentication
/// - ENCRYPTION settings (different per cloud provider)
/// - DIRECTORY tables for metadata management
/// - FILE_FORMAT specifications
/// - COMMENT and TAG metadata
/// - CREATE OR REPLACE, TEMPORARY, IF NOT EXISTS modifiers
/// - CLONE variant
///
/// Returns Result with detailed error information on parse failure.
pub(crate) fn try_parse_create_stage_stmt_with_parser(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume CREATE keyword
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let mut span = create_span;

    // Optional OR REPLACE
    let mut or_replace_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p
                .advance()
                .expect_invariant("OR keyword should be available after peek");
            if let Some(replace_tok) = p.peek_non_trivia() {
                if matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE keyword should be available after peek");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                }
            }
        }
    }

    // Optional TEMPORARY / TEMP
    let mut temporary_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Temp) | TokenKind::Keyword(Keyword::Temporary)
        ) {
            let temp = p
                .advance()
                .expect_invariant("TEMP/TEMPORARY keyword should be available after peek");
            temporary_span = Some(temp.span);
            span.end = temp.span.end;
        }
    }

    // Expect STAGE keyword
    let stage_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["STAGE".to_string()])?;
    if !matches!(stage_tok.kind, TokenKind::Keyword(Keyword::Stage)) {
        return Err(ParseError::new(
            stage_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected STAGE keyword, found '{}'",
                    stage_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let stage_keyword = p
        .advance()
        .expect_invariant("STAGE keyword should be available after peek");
    let stage_keyword_span = stage_keyword.span;
    span.end = stage_keyword_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword should be available after peek");
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    let _not = p
                        .advance()
                        .expect_invariant("NOT keyword should be available after peek");
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS keyword should be available after peek");
                            if_not_exists_span = Some(Span {
                                start: if_tok.span.start,
                                end: exists.span.end,
                            });
                            span.end = exists.span.end;
                        }
                    }
                }
            }
        }
    }

    // Stage name (required)
    let name_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["stage_name".to_string()])?;
    let name_span = parse_stage_name(p, name_tok.span)?;
    span.end = name_span.end;

    // Now parse optional clauses in any order (Snowflake allows flexible ordering)
    let mut url_clause: Option<AstStageUrlClause> = None;
    let mut credentials_clause: Option<AstStageCredentialsClause> = None;
    let mut encryption_clause: Option<Span> = None;
    let mut endpoint_clause: Option<Span> = None;
    let mut directory_clause: Option<Span> = None;
    let mut file_format_clause: Option<AstStageFileFormatClause> = None;
    let mut comment_span: Option<Span> = None;
    let mut tag_clause: Option<Span> = None;
    let mut clone_clause: Option<Span> = None;
    let mut extras: Vec<AstUnknownClause> = Vec::new();

    // Parse clauses until we hit semicolon or EOF
    while let Some(tok) = p.peek_non_trivia() {
        // Check for statement terminator
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            // DON'T consume semicolon or include it in span
            // The main formatter loop will handle semicolons as gap content
            break;
        }

        // Check for next statement keyword (end of this statement)
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Create)
                | TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Insert)
                | TokenKind::Keyword(Keyword::Update)
                | TokenKind::Keyword(Keyword::Delete)
                | TokenKind::Keyword(Keyword::Drop)
        ) {
            break;
        }

        // Parse clause based on keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Url)) {
            let clause = parse_url_clause(p)?;
            span.end = clause.span.end;
            url_clause = Some(clause);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::StorageIntegration)) {
            // STORAGE_INTEGRATION = ...
            let clause = parse_storage_integration_clause(p)?;
            span.end = clause.span.end;
            credentials_clause = Some(clause);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Credentials)) {
            let clause = parse_credentials_clause(p)?;
            span.end = clause.span.end;
            credentials_clause = Some(clause);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Encryption)) {
            let clause_span = parse_encryption_clause(p)?;
            span.end = clause_span.end;
            encryption_clause = Some(clause_span);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Endpoint)) {
            // ENDPOINT = 'url' for S3-compatible storage
            let clause_span = parse_endpoint_clause(p)?;
            span.end = clause_span.end;
            endpoint_clause = Some(clause_span);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Directory)) {
            let clause_span = parse_directory_clause(p)?;
            span.end = clause_span.end;
            directory_clause = Some(clause_span);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::File))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::FileFormat))
        {
            let clause = parse_file_format_clause(p)?;
            span.end = clause.span.end;
            file_format_clause = Some(clause);
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            let clause_span = parse_comment_clause(p)?;
            span.end = clause_span.end;
            comment_span = Some(clause_span);
        } else if tok.lexeme(p.source).eq_ignore_ascii_case("WITH")
            || tok.lexeme(p.source).eq_ignore_ascii_case("TAG")
        {
            let clause_span = parse_tag_clause(p)?;
            span.end = clause_span.end;
            tag_clause = Some(clause_span);
        } else if tok.lexeme(p.source).eq_ignore_ascii_case("CLONE") {
            let clause_span = parse_clone_clause(p)?;
            span.end = clause_span.end;
            clone_clause = Some(clause_span);
        } else {
            // Unknown clause - capture it instead of failing (defensive design)
            let unknown_start = tok.span.start;
            let introducer_span = tok.span;

            // Consume the unknown keyword
            let _ = p.advance();

            // Try to consume until we hit a known keyword, semicolon, or EOF
            let mut unknown_end = introducer_span.end;
            while let Some(next_tok) = p.peek_non_trivia() {
                // Stop at known keywords or terminators
                if matches!(
                    next_tok.kind,
                    TokenKind::Keyword(Keyword::Url)
                        | TokenKind::Keyword(Keyword::StorageIntegration)
                        | TokenKind::Keyword(Keyword::Credentials)
                        | TokenKind::Keyword(Keyword::Encryption)
                        | TokenKind::Keyword(Keyword::Endpoint)
                        | TokenKind::Keyword(Keyword::Directory)
                        | TokenKind::Keyword(Keyword::File)
                        | TokenKind::Keyword(Keyword::FileFormat)
                        | TokenKind::Keyword(Keyword::Comment)
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) || next_tok.lexeme(p.source).eq_ignore_ascii_case("WITH")
                    || next_tok.lexeme(p.source).eq_ignore_ascii_case("TAG")
                    || next_tok.lexeme(p.source).eq_ignore_ascii_case("CLONE")
                {
                    break;
                }

                // Consume token as part of unknown clause
                let consumed = p
                    .advance()
                    .expect_invariant("unknown clause token after peek");
                unknown_end = consumed.span.end;
            }

            let unknown_span = Span {
                start: unknown_start,
                end: unknown_end,
            };
            span.end = unknown_end;

            extras.push(AstUnknownClause {
                introducer: Some(introducer_span),
                span: unknown_span,
                kind: UnknownKind::Property,
                node_id: p.id_gen.next(),
            });
        }
    }

    // Determine stage type based on URL presence
    let stage_type = if url_clause.is_some() {
        AstStageType::External
    } else {
        AstStageType::Internal
    };

    Ok(AstStmt::CreateStage(Box::new(AstCreateStage {
        node_id: p.id_gen.next(),
        span,
        create_span,
        or_replace_span,
        temporary_span,
        stage_keyword_span,
        if_not_exists_span,
        name_span,
        stage_type,
        url_clause,
        credentials_clause,
        encryption_clause,
        endpoint_clause,
        directory_clause,
        file_format_clause,
        comment_span,
        tag_clause,
        clone_clause,
        extras, // Unknown properties captured here
    })))
}

/// Parse stage name (may be qualified: schema.stage_name or db.schema.stage_name)
fn parse_stage_name(p: &mut Parser<'_>, start: Span) -> ParseResult<Span> {
    let name_tok = p
        .advance()
        .ok_or_eof(start, vec!["stage_name".to_string()])?;
    let mut span = name_tok.span;

    // Check for dot (qualified name)
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
        ) {
            let dot = p
                .advance()
                .expect_invariant("DOT punctuation should be available after peek");
            span.end = dot.span.end;

            // Expect identifier after dot
            let part = p
                .advance()
                .ok_or_eof(span, vec!["identifier".to_string()])?;
            span.end = part.span.end;
        } else {
            break;
        }
    }

    Ok(span)
}

/// Parse URL clause: URL = 'protocol://bucket/path'
fn parse_url_clause(p: &mut Parser<'_>) -> ParseResult<AstStageUrlClause> {
    let url_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["URL".to_string()])?;
    let url_keyword_span = url_kw.span;
    let mut span = url_keyword_span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after URL, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect string literal
    let url_val = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["string_literal".to_string()])?;
    if !matches!(
        url_val.kind,
        TokenKind::Literal(crate::lexer::LiteralKind::String)
    ) {
        return Err(ParseError::new(
            url_val.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected string literal for URL value, found '{}'",
                    url_val.lexeme(p.source)
                ),
            },
        ));
    }
    let url_value = p
        .advance()
        .expect_invariant("URL string literal should be available after peek");
    let url_value_span = url_value.span;
    span.end = url_value_span.end;
    let url_text = unquote_sql_string(url_value.lexeme(p.source));

    Ok(AstStageUrlClause {
        node_id: p.id_gen.next(),
        span,
        url_keyword_span,
        url_value_span,
        url_text,
    })
}

/// Parse STORAGE_INTEGRATION clause: STORAGE_INTEGRATION = integration_name
fn parse_storage_integration_clause(p: &mut Parser<'_>) -> ParseResult<AstStageCredentialsClause> {
    let storage_integration_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["STORAGE_INTEGRATION".to_string()])?;
    let mut span = storage_integration_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after STORAGE_INTEGRATION, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect integration name
    let _name_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["integration_name".to_string()])?;
    let name = p
        .advance()
        .expect_invariant("integration name identifier should be available after peek");
    let integration_name_span = name.span;
    span.end = integration_name_span.end;

    Ok(AstStageCredentialsClause {
        node_id: p.id_gen.next(),
        span,
        kind: AstStageCredentialsKind::StorageIntegration,
        options: Vec::new(),
        integration_name_span: Some(integration_name_span),
    })
}

/// Parse CREDENTIALS clause: CREDENTIALS = ( KEY = VALUE [KEY = VALUE]* )
///
/// Decomposes the parenthesized body into a typed `Vec<AstStageCredentialOption>`
/// so consumers can inspect the extracted literal values without
/// re-tokenizing.
///
/// Falls back to opaque span-only consumption if the body shape diverges
/// from `KEY = VALUE` (preserves zero-token-loss).
fn parse_credentials_clause(p: &mut Parser<'_>) -> ParseResult<AstStageCredentialsClause> {
    let cred_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREDENTIALS".to_string()])?;
    let mut span = cred_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after CREDENTIALS, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect (
    let lparen_tok = p.peek_non_trivia().ok_or_eof(span, vec!["(".to_string()])?;
    if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '(' after CREDENTIALS =, found '{}'",
                    lparen_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Walk KEY = VALUE triples until the matching ')'. The body is
    // permissive: nested parens and unrecognized tokens are tolerated by
    // falling through to depth-tracked consumption that records nothing
    // typed for that span (zero-loss byte-preservation maintained by the
    // formatter, which reads `clause.span` not `options`).
    let mut options: Vec<AstStageCredentialOption> = Vec::new();
    let close_paren_end;
    loop {
        let tok = p.peek_non_trivia().ok_or_eof(span, vec![")".to_string()])?;
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            let close = p
                .advance()
                .expect_invariant("RParen should be available after peek");
            close_paren_end = close.span.end;
            break;
        }

        // Snowflake separates credential options with whitespace; some
        // dialects/customer SQL inserts commas. Skip leading commas.
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
            let _ = p.advance();
            continue;
        }

        // Try to parse `KEY = VALUE`. If the shape doesn't fit, depth-walk
        // through the remainder of the clause and stop emitting typed
        // options; the formatter's span-based emission still preserves
        // bytes.
        match try_parse_credential_option(p) {
            Some(opt) => options.push(opt),
            None => {
                let close = parse_parenthesized_content(p, span)?;
                close_paren_end = close.end;
                break;
            }
        }
    }
    span.end = close_paren_end;

    Ok(AstStageCredentialsClause {
        node_id: p.id_gen.next(),
        span,
        kind: AstStageCredentialsKind::Credentials,
        options,
        integration_name_span: None,
    })
}

/// Attempt to parse one `KEY = VALUE` triple inside a `CREDENTIALS=(...)`
/// body. Returns `None` when the shape diverges (e.g. nested paren,
/// unexpected token) — the caller then falls back to opaque consumption
/// of the rest of the body.
///
/// Shared with [`crate::parser::alter_stage`] so `ALTER STAGE SET
/// CREDENTIALS=(...)` decomposes the same way.
pub(crate) fn try_parse_credential_option(p: &mut Parser<'_>) -> Option<AstStageCredentialOption> {
    let key_tok = p.peek_non_trivia()?;
    let key_text_starts_clause = matches!(
        key_tok.kind,
        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
    );
    if !key_text_starts_clause {
        return None;
    }
    let name = p.advance()?;
    let name_span = name.span;
    let mut span = name_span;

    let eq = p.peek_non_trivia()?;
    if !matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
        return None;
    }
    let _ = p.advance();

    let val_tok = p.peek_non_trivia()?;
    match val_tok.kind {
        TokenKind::Literal(LiteralKind::String) => {
            let v = p.advance()?;
            let value_span = v.span;
            span.end = value_span.end;
            // Every value inside CREDENTIALS=(...) is a credential — mask it
            // out of output surfaces.
            p.redaction_spans.push(value_span);
            // A rendered placeholder is not a statically-known value — the
            // real credential is injected later. Capture as non-literal so
            // consumers do not mistake it for a hard-coded value (still
            // masked above).
            if p.span_overlaps_placeholder(value_span) {
                return Some(AstStageCredentialOption {
                    node_id: p.id_gen.next(),
                    span,
                    name_span,
                    value: AstStageCredentialOptionValue::Other { span: value_span },
                });
            }
            let text = unquote_sql_string(v.lexeme(p.source));
            Some(AstStageCredentialOption {
                node_id: p.id_gen.next(),
                span,
                name_span,
                value: AstStageCredentialOptionValue::StringLiteral {
                    span: value_span,
                    text,
                },
            })
        }
        TokenKind::Punctuation(Punctuation::LParen) => {
            // Compound value (e.g. nested options) — abort typed parse.
            None
        }
        _ => {
            let v = p.advance()?;
            let value_span = v.span;
            span.end = value_span.end;
            p.redaction_spans.push(value_span);
            Some(AstStageCredentialOption {
                node_id: p.id_gen.next(),
                span,
                name_span,
                value: AstStageCredentialOptionValue::Other { span: value_span },
            })
        }
    }
}

/// Strip surrounding `'…'` or `"…"` quotes and fold `''` escapes. Returns
/// the original input if it isn't recognizable as a quoted literal —
/// downstream content predicates simply see no match in that case.
///
/// Shared with [`crate::parser::alter_stage`] for symmetric URL / credential
/// literal extraction across CREATE STAGE and ALTER STAGE.
pub(crate) fn unquote_sql_string(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        return trimmed[1..trimmed.len() - 1].replace("''", "'");
    }
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    trimmed.to_string()
}

/// Parse ENCRYPTION clause: ENCRYPTION = ( ... )
fn parse_encryption_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let enc_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ENCRYPTION".to_string()])?;
    let mut span = enc_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after ENCRYPTION, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect (
    let lparen_tok = p.peek_non_trivia().ok_or_eof(span, vec!["(".to_string()])?;
    if !matches!(
        lparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '(' after ENCRYPTION =, found '{}'",
                    lparen_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Parse encryption content until closing paren
    let close_paren = parse_parenthesized_content(p, span)?;
    span.end = close_paren.end;

    Ok(span)
}

/// Parse ENDPOINT clause: ENDPOINT = 'url' (for S3-compatible storage)
fn parse_endpoint_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let endpoint_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ENDPOINT".to_string()])?;
    let mut span = endpoint_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after ENDPOINT, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect string literal
    let val_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["string_literal".to_string()])?;
    if !matches!(
        val_tok.kind,
        TokenKind::Literal(crate::lexer::LiteralKind::String)
    ) {
        return Err(ParseError::new(
            val_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected string literal for ENDPOINT value, found '{}'",
                    val_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let val = p
        .advance()
        .expect_invariant("ENDPOINT string literal should be available after peek");
    span.end = val.span.end;

    Ok(span)
}

/// Parse DIRECTORY clause: DIRECTORY = ( ... )
fn parse_directory_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let dir_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DIRECTORY".to_string()])?;
    let mut span = dir_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after DIRECTORY, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect (
    let lparen_tok = p.peek_non_trivia().ok_or_eof(span, vec!["(".to_string()])?;
    if !matches!(
        lparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '(' after DIRECTORY =, found '{}'",
                    lparen_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Parse directory content until closing paren
    let close_paren = parse_parenthesized_content(p, span)?;
    span.end = close_paren.end;

    Ok(span)
}

/// Parse FILE_FORMAT clause: FILE_FORMAT = ( FORMAT_NAME = '...' | TYPE = ... )
fn parse_file_format_clause(p: &mut Parser<'_>) -> ParseResult<AstStageFileFormatClause> {
    let file_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FILE".to_string()])?;
    let mut span = file_kw.span;

    // Check if this is FILE_FORMAT (single token) or FILE FORMAT (two tokens)
    let keyword_span = if matches!(file_kw.kind, TokenKind::Keyword(Keyword::FileFormat)) {
        // FILE_FORMAT as single token - already consumed
        file_kw.span
    } else {
        // FILE as separate token - expect FORMAT next
        let fmt_tok = p
            .peek_non_trivia()
            .ok_or_eof(span, vec!["FORMAT".to_string()])?;
        if !matches!(fmt_tok.kind, TokenKind::Keyword(Keyword::Format)) {
            return Err(ParseError::new(
                fmt_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected FORMAT keyword after FILE, found '{}'",
                        fmt_tok.lexeme(p.source)
                    ),
                },
            ));
        }
        let fmt = p
            .advance()
            .expect_invariant("FORMAT keyword should be available after peek");
        Span {
            start: span.start,
            end: fmt.span.end,
        }
    };

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after FILE_FORMAT, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect (
    let lparen_tok = p.peek_non_trivia().ok_or_eof(span, vec!["(".to_string()])?;
    if !matches!(
        lparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '(' after FILE_FORMAT =, found '{}'",
                    lparen_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Peek inside to determine FORMAT_NAME vs TYPE
    let format_spec = if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("FORMAT_NAME") {
            AstStageFileFormatSpec::FormatName
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
            AstStageFileFormatSpec::Type
        } else {
            // Default to Type if unclear
            AstStageFileFormatSpec::Type
        }
    } else {
        AstStageFileFormatSpec::Type
    };

    // Parse file format content until closing paren
    let close_paren = parse_parenthesized_content(p, span)?;
    span.end = close_paren.end;

    Ok(AstStageFileFormatClause {
        node_id: p.id_gen.next(),
        span,
        keyword_span,
        format_spec,
    })
}

/// Parse COMMENT clause: COMMENT = 'string'
fn parse_comment_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let comment_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["COMMENT".to_string()])?;
    let mut span = comment_kw.span;

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_eof(span, vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' after COMMENT, found '{}'",
                    eq_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Expect string literal
    let val_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["string_literal".to_string()])?;
    if !matches!(
        val_tok.kind,
        TokenKind::Literal(crate::lexer::LiteralKind::String)
    ) {
        return Err(ParseError::new(
            val_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected string literal for COMMENT value, found '{}'",
                    val_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let val = p
        .advance()
        .expect_invariant("COMMENT string literal should be available after peek");
    span.end = val.span.end;

    Ok(span)
}

/// Parse TAG clause: [ WITH ] TAG ( tag_name = 'tag_value' [ , ... ] )
fn parse_tag_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let first_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TAG".to_string()])?;
    let mut span = first_tok.span;

    // If WITH, expect TAG next
    if first_tok.lexeme(p.source).eq_ignore_ascii_case("WITH") {
        let tag_tok = p
            .peek_non_trivia()
            .ok_or_eof(span, vec!["TAG".to_string()])?;
        if !tag_tok.lexeme(p.source).eq_ignore_ascii_case("TAG") {
            return Err(ParseError::new(
                tag_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TAG keyword after WITH, found '{}'",
                        tag_tok.lexeme(p.source)
                    ),
                },
            ));
        }
        let tag = p
            .advance()
            .expect_invariant("TAG keyword should be available after peek");
        span.end = tag.span.end;
    }

    // Expect (
    let lparen_tok = p.peek_non_trivia().ok_or_eof(span, vec!["(".to_string()])?;
    if !matches!(
        lparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '(' after TAG, found '{}'",
                    lparen_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let _ = p.advance();

    // Parse tag content until closing paren
    let close_paren = parse_parenthesized_content(p, span)?;
    span.end = close_paren.end;

    Ok(span)
}

/// Parse CLONE clause: CLONE source_stage
fn parse_clone_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let clone_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CLONE".to_string()])?;
    let mut span = clone_kw.span;

    // Expect source stage name
    let source_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["source_stage_name".to_string()])?;
    let source_span = parse_stage_name(p, source_tok.span)?;
    span.end = source_span.end;

    Ok(span)
}

/// Helper: Parse content within parentheses until closing paren.
/// Returns the span of the closing paren.
fn parse_parenthesized_content(p: &mut Parser<'_>, start_span: Span) -> ParseResult<Span> {
    let mut depth = 1;
    let mut last_span = start_span;

    while depth > 0 {
        let tok = p
            .peek_non_trivia()
            .ok_or_eof(start_span, vec![")".to_string()])?;
        last_span = tok.span;

        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            depth += 1;
        } else if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            depth -= 1;
        }

        let _ = p.advance();
    }

    Ok(last_span)
}

// =============================================================================
// Parser methods - CREATE STAGE parsing
// =============================================================================

impl Parser<'_> {
    // Wrapper method that delegates to the standalone function above.

    pub(crate) fn try_parse_create_stage_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_create_stage_stmt_with_parser(self)
    }
}
