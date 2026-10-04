// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! BigQuery `GRANT` typed parser.
//!
//! Parses `AstStmt::Grant` into typed [`AstGrant`] for the BigQuery IAM-role
//! grammar:
//!
//! ```text
//! GRANT `<role>` [, `<role>` ...]
//!   ON <resource_type> <resource_name>
//!   TO "<principal>" [, "<principal>" ...]
//! ```
//!
//! `<role>` is a backtick-quoted IAM role (`\`roles/bigquery.dataViewer\``)
//! preserved verbatim on [`AstPrivilegeKind::Other`].
//!
//! `<resource_type>` is one of `SCHEMA` / `TABLE` / `VIEW` / etc. —
//! mapped to the corresponding [`AstObjectKind`] when recognized,
//! `Other { lexemes: [<class>] }` otherwise.
//!
//! `<principal>` is a string literal: `"user:..."`, `"group:..."`,
//! `"serviceAccount:..."`, `"allUsers"`, `"allAuthenticatedUsers"`,
//! `"domain:..."`. Each becomes one [`AstGrantee::Role`] with
//! `name_span` covering the string literal. Consumers that normalize
//! grantee names can treat `allUsers` and `allAuthenticatedUsers` as the
//! everyone-principal (`PUBLIC` in other dialects).
//!
//! No `WITH GRANT OPTION` clause exists in BigQuery IAM; the parser
//! does not look for it.

use crate::ast::{
    AstGrant, AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind, AstPrivilege,
    AstPrivilegeGrantBody, AstPrivilegeKind, AstPrivilegeList, AstStmt,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult};
use crate::lexer::token::{LiteralKind, Span, TokenKind};
use crate::lexer::{Keyword, Punctuation};
use crate::parser::core::Parser;
use crate::parser::grant::{
    body_start_pos_after, consume_to_terminator, current_position, expect_keyword,
};

/// Parse a BigQuery `GRANT ...` statement. Always succeeds: typed-parse
/// failure degrades the body to `AstGrantShape::Unparsed`.
pub(crate) fn parse_grant_bq(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("bq_grant")?;

    let grant_kw = expect_keyword(p, Keyword::Grant, "GRANT")?;
    let stmt_start = grant_kw.span.start;
    let keyword_span = grant_kw.span;
    let body_start_idx = p.idx;
    let body_start_pos = body_start_pos_after(grant_kw);

    let shape = match try_parse_privilege_body(p) {
        Ok(body) => AstGrantShape::Privilege(body),
        Err(_) => {
            p.idx = body_start_idx;
            let body_end = consume_to_terminator(p);
            AstGrantShape::Unparsed {
                body_span: Span {
                    start: body_start_pos,
                    end: body_end,
                },
            }
        }
    };

    let span_end = current_position(p);

    Ok(AstStmt::Grant(Box::new(AstGrant {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: span_end,
        },
        keyword_span,
        shape,
        semicolon_token: None,
    })))
}

fn try_parse_privilege_body(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeGrantBody> {
    let privileges = parse_bq_role_list(p)?;
    expect_keyword(p, Keyword::On, "ON")?;
    let object = parse_bq_grant_object(p)?;
    expect_keyword(p, Keyword::To, "TO")?;

    let mut grantees: Vec<AstGrantee> = Vec::new();
    grantees.push(parse_bq_grantee(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        grantees.push(parse_bq_grantee(p)?);
    }

    Ok(AstPrivilegeGrantBody {
        privileges,
        objects: vec![object],
        grantees,
        // BigQuery IAM has no WITH GRANT OPTION equivalent.
        with_grant_option: None,
    })
}

// ---------------------------------------------------------------------------
// IAM role list — `roles/X`, comma-separated.
// ---------------------------------------------------------------------------

fn parse_bq_role_list(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeList> {
    let first_span = p.current_span();
    let mut privileges: Vec<AstPrivilege> = Vec::new();
    privileges.push(parse_bq_role(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        privileges.push(parse_bq_role(p)?);
    }
    let end = privileges
        .last()
        .expect_invariant("at least one role parsed")
        .span
        .end;
    Ok(AstPrivilegeList {
        all: None,
        privileges,
        span: Span {
            start: first_span.start,
            end,
        },
    })
}

fn parse_bq_role(p: &mut Parser<'_>) -> ParseResult<AstPrivilege> {
    let first = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    if !p.can_be_identifier_token(first) {
        return Err(ParseError::new(
            first.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected backticked IAM role, found '{}'",
                    first.lexeme(p.source)
                ),
            },
        ));
    }
    let consumed = p.advance().expect_invariant("role identifier");
    let lex = consumed.lexeme(p.source).to_string();
    Ok(AstPrivilege {
        kind: AstPrivilegeKind::Other { lexemes: vec![lex] },
        span: consumed.span,
    })
}

// ---------------------------------------------------------------------------
// Resource object — `<class> <name>`.
// ---------------------------------------------------------------------------

fn parse_bq_grant_object(p: &mut Parser<'_>) -> ParseResult<AstGrantObject> {
    let class_tok = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    let class_lex = class_tok.lexeme(p.source).to_uppercase();
    let class_span = class_tok.span;
    let _ = p.advance();

    let object_kind = bq_class_to_object_kind(&class_lex);
    let name_span = p.parse_qualified_name_span()?;

    Ok(AstGrantObject::Single {
        object_kind,
        kind_span: class_span,
        name_span,
        function_signature: None,
    })
}

fn bq_class_to_object_kind(class_lex: &str) -> AstObjectKind {
    match class_lex {
        "SCHEMA" => AstObjectKind::Schema,
        "TABLE" => AstObjectKind::Table,
        "VIEW" => AstObjectKind::View,
        "EXTERNAL TABLE" => AstObjectKind::ExternalTable,
        other => AstObjectKind::Other {
            lexemes: vec![other.to_string()],
        },
    }
}

// ---------------------------------------------------------------------------
// Grantee — string-literal IAM principal.
// ---------------------------------------------------------------------------

fn parse_bq_grantee(p: &mut Parser<'_>) -> ParseResult<AstGrantee> {
    let tok = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    // BigQuery principals are string literals: "user:...", "group:...",
    // "serviceAccount:...", "domain:...", "allUsers", "allAuthenticatedUsers".
    let is_string = matches!(tok.kind, TokenKind::Literal(LiteralKind::String));
    if !is_string && !p.can_be_identifier_token(tok) {
        return Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected BigQuery principal string, found '{}'",
                    tok.lexeme(p.source)
                ),
            },
        ));
    }
    let consumed = p.advance().expect_invariant("principal");
    // For string-literal principals, point `name_span` at the inner
    // content (between the quote delimiters). This keeps the downstream
    // `IdentName` clean (`"allUsers"` → normalized `"ALLUSERS"`, not
    // `"\"ALLUSERS\""`), so consumers can match the principal name without
    // escaping the outer quotes. Non-string identifiers
    // (the bare-name fallback) keep the full span.
    let name_span = if is_string && consumed.span.end > consumed.span.start + 1 {
        Span {
            start: consumed.span.start + 1,
            end: consumed.span.end - 1,
        }
    } else {
        consumed.span
    };
    Ok(AstGrantee::Role {
        role_keyword_span: None,
        name_span,
    })
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

#[inline]
fn peek_token_kind(p: &mut Parser<'_>, want: TokenKind) -> bool {
    p.peek_non_trivia()
        .map(|t| std::mem::discriminant(&t.kind) == std::mem::discriminant(&want) && t.kind == want)
        .unwrap_or(false)
}

fn eof_err(p: &Parser<'_>) -> ParseError {
    ParseError::new(
        p.tokens
            .last()
            .map(|t| t.span)
            .unwrap_or(Span { start: 0, end: 0 }),
        ParseErrorKind::InvalidStatement {
            message: "Unexpected end of input in BigQuery GRANT".to_string(),
        },
    )
}
