// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL T-SQL `GRANT` typed parser.
//!
//! Parses `AstStmt::Grant` into the typed [`AstGrant`] for the MSSQL grammar:
//!
//! ```text
//! GRANT { ALL [ PRIVILEGES ] | <permission> [ ,...n ] }
//!   [ ON [ <class>:: ] securable ]
//!   TO <principal> [ ,...n ]
//!   [ WITH GRANT OPTION ]
//!   [ AS <principal> ]
//! ```
//!
//! Three shape differences from Snowflake drive the dialect split:
//! - **Optional `ON` clause** — server-tier permissions (`CONTROL SERVER`,
//!   `ALTER ANY LOGIN`, `VIEW ANY DATABASE`, …) omit `ON` entirely. The
//!   resulting [`AstPrivilegeGrantBody`] carries an empty `objects` vec.
//! - **Class qualifier** — `LOGIN::sa`, `SCHEMA::dbo`, `OBJECT::dbo.t`,
//!   `USER::etl_user`, `DATABASE::db1`. The class lexeme is preserved on
//!   the produced `AstObjectKind` (typed for `SCHEMA` / `DATABASE`,
//!   `Other { lexemes: ["LOGIN"] }` / etc. for MSSQL-specific securables).
//! - **Multi-principal** — `TO p1, p2, p3`. Each principal becomes one
//!   entry in `body.grantees`.
//!
//! The `AS <principal>` ownership-delegation clause is consumed and
//! discarded. Promote to a typed field on `AstPrivilegeGrantBody` when the
//! first consumer needs it.
//!
//! ## Failure semantics
//!
//! Mirrors `mssql_deny.rs` / `grant.rs`: typed-parse failure rolls back
//! to just past the `GRANT` keyword, consumes to the next semicolon, and
//! emits `AstGrantShape::Unparsed`. Customer SQL never aborts at the
//! statement level due to a malformed GRANT.

use crate::ast::{
    AstGrant, AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind, AstPrivilegeGrantBody,
    AstStmt,
};
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::token::{Span, TokenKind};
use crate::lexer::{Keyword, Operator, Punctuation};
use crate::parser::core::Parser;
use crate::parser::grant::{
    body_start_pos_after, consume_to_terminator, consume_with_grant_option, current_position,
    expect_keyword, parse_grantee, parse_privilege_list,
};

/// Parse a T-SQL `GRANT ...` statement. Always succeeds: typed-parse
/// failure degrades the body to `AstGrantShape::Unparsed`.
pub(crate) fn parse_grant_mssql(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mssql_grant")?;

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

/// Body parser: privileges → optional ON → required TO with multi-grantee
/// → optional WITH GRANT OPTION → optional AS principal.
fn try_parse_privilege_body(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeGrantBody> {
    let privileges = parse_privilege_list(p)?;

    // Server/account-tier permissions (CONTROL SERVER, ALTER ANY LOGIN,
    // VIEW ANY DATABASE, ...) omit the ON clause. Detect by peeking for
    // TO immediately after the privilege list.
    let objects: Vec<AstGrantObject> = if peek_token_kind(p, TokenKind::Keyword(Keyword::On)) {
        let _on = p.advance().expect_invariant("ON token");
        let object = parse_mssql_grant_object(p)?;
        vec![object]
    } else {
        Vec::new()
    };

    expect_keyword(p, Keyword::To, "TO")?;

    let mut grantees: Vec<AstGrantee> = Vec::new();
    grantees.push(parse_grantee(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        grantees.push(parse_grantee(p)?);
    }

    let with_grant_option = consume_with_grant_option(p);

    // Optional trailing `AS <principal>`, consumed and discarded.
    if peek_token_kind(p, TokenKind::Keyword(Keyword::As)) {
        let _ = p.advance(); // AS
        let _ = p.parse_qualified_name_span()?;
    }

    Ok(AstPrivilegeGrantBody {
        privileges,
        objects,
        grantees,
        with_grant_option,
    })
}

/// Parse the MSSQL `[ <class>:: ] <name>` shape into an `AstGrantObject`.
///
/// Recognized classes:
/// - `SCHEMA::<name>` → [`AstObjectKind::Schema`]
/// - `DATABASE::<name>` → [`AstObjectKind::Database`]
/// - `USER::<name>` → [`AstObjectKind::User`]
/// - `ROLE::<name>` → [`AstObjectKind::Role`]
/// - any other class → [`AstObjectKind::Other`] with the class lexeme
///   preserved (e.g. `LOGIN::`, `OBJECT::`, `SERVER ROLE::`)
/// - no class → [`AstObjectKind::Other`] with implicit `OBJECT`
pub(crate) fn parse_mssql_grant_object(p: &mut Parser<'_>) -> ParseResult<AstGrantObject> {
    let (object_kind, kind_span) = if peek_two_lexemes_form_class_qualifier(p) {
        let class_tok = p.advance().expect_invariant("class lexeme");
        let class_span = class_tok.span;
        let class_lex = class_tok.lexeme(p.source).to_uppercase();
        let _colon_colon = p.advance().expect_invariant("::");
        let kind = mssql_class_to_object_kind(&class_lex);
        (kind, class_span)
    } else {
        // No class qualifier — MSSQL defaults to OBJECT class.
        let here = current_position(p);
        (
            AstObjectKind::Other {
                lexemes: vec!["OBJECT".to_string()],
            },
            Span {
                start: here,
                end: here,
            },
        )
    };

    let name_span = p.parse_qualified_name_span()?;

    Ok(AstGrantObject::Single {
        object_kind,
        kind_span,
        name_span,
        function_signature: None,
    })
}

/// Peek for the `<identifier>::` pattern that marks an MSSQL class
/// qualifier. Distinguishes `SCHEMA::dbo` (class-qualified) from `dbo.t`
/// (bare 2-part name).
fn peek_two_lexemes_form_class_qualifier(p: &mut Parser<'_>) -> bool {
    // First token must be identifier-like (keyword or identifier — MSSQL
    // class names like SCHEMA, DATABASE, OBJECT lex as keywords; LOGIN,
    // USER, ROLE may lex as identifiers).
    let first_ok = match p.peek_non_trivia() {
        Some(t) => matches!(t.kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_)),
        None => return false,
    };
    if !first_ok {
        return false;
    }
    // Second token must be `::`.
    let mut i = p.idx;
    let mut skipped_first = false;
    while i < p.tokens.len() {
        let t = &p.tokens[i];
        i += 1;
        if matches!(
            t.kind,
            TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
        ) {
            continue;
        }
        if !skipped_first {
            skipped_first = true;
            continue;
        }
        return matches!(t.kind, TokenKind::Operator(Operator::ColonColon));
    }
    false
}

/// Map an MSSQL securable-class lexeme to an `AstObjectKind`. Unknown
/// classes preserve the original spelling in `Other`.
fn mssql_class_to_object_kind(class_lex: &str) -> AstObjectKind {
    match class_lex {
        "SCHEMA" => AstObjectKind::Schema,
        "DATABASE" => AstObjectKind::Database,
        "USER" => AstObjectKind::User,
        "ROLE" => AstObjectKind::Role,
        other => AstObjectKind::Other {
            lexemes: vec![other.to_string()],
        },
    }
}

#[inline]
fn peek_token_kind(p: &mut Parser<'_>, want: TokenKind) -> bool {
    p.peek_non_trivia()
        .map(|t| std::mem::discriminant(&t.kind) == std::mem::discriminant(&want) && t.kind == want)
        .unwrap_or(false)
}
