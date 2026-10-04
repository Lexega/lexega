// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL `DENY` typed parser.
//!
//! Parses `AstStmt::Deny` into a typed [`AstDeny`] carrying the structural
//! inputs a DENY analysis needs:
//!
//! - `privileges: AstPrivilegeList` — what is denied, with an `all`
//!   marker. Reused verbatim from the Snowflake GRANT/REVOKE parser.
//! - `grantees: Vec<AstGrantee>` — who is denied (consumers normalize
//!   the names, e.g. to recognize `public`).
//! - `cascade: Option<Span>` — the `CASCADE` option.
//! - `as_principal: Option<AstDenyAs>` — the `AS <principal>` clause.
//!
//! The `ON [class::]securable` clause is captured span-only. Promote it
//! to typed fields when the first consumer needs the class or name.
//!
//! Grammar (MSSQL T-SQL):
//! ```text
//! DENY { ALL [ PRIVILEGES ] | <permission> [ ,...n ] }
//!   [ ON [ <class>:: ] securable ]
//!   TO <principal> [ ,...n ]
//!   [ CASCADE ] [ AS <principal> ]
//! ```
//!
//! ## Failure semantics
//!
//! On a typed-parse error the parser rolls back to just past the
//! `DENY` keyword, consumes to the next semicolon/EOF, and emits an
//! [`AstDeny`] with `privileges.all = None`, `privileges.privileges`
//! empty, no grantees, and `object_span = None`. This keeps parsing
//! permissive: malformed DENY never aborts the script.

use crate::ast::{AstDeny, AstDenyAs, AstDenyObject, AstGrantee, AstPrivilegeList, AstStmt};
use crate::error::ParseResult;
use crate::lexer::token::{Span, TokenKind};
use crate::lexer::{Keyword, Punctuation};
use crate::parser::core::Parser;
use crate::parser::grant::{
    body_start_pos_after, consume_to_terminator, current_position, expect_keyword, parse_grantee,
    parse_privilege_list, peek_lexeme_eq,
};

/// Parse a `DENY ...` statement. Always succeeds: typed-parse failure
/// degrades to an [`AstDeny`] with empty `privileges` / `grantees`, so
/// consumers see a DENY with nothing to report rather than a parse error.
pub(crate) fn parse_deny(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("deny")?;

    let deny_kw = expect_keyword(p, Keyword::Deny, "DENY")?;
    let stmt_start = deny_kw.span.start;
    let keyword_span = deny_kw.span;
    let body_start_idx = p.idx;
    let body_start_pos = body_start_pos_after(deny_kw);

    let (privileges, object_span, grantees, cascade, as_principal) = match try_parse_deny_body(p) {
        Ok(parts) => parts,
        Err(_) => {
            // Roll back and consume to semicolon. The unparsed
            // body becomes a synthetic `privileges` list with no
            // entries.
            p.idx = body_start_idx;
            let body_end = consume_to_terminator(p);
            let synthetic_span = Span {
                start: body_start_pos,
                end: body_end,
            };
            (
                AstPrivilegeList {
                    all: None,
                    privileges: Vec::new(),
                    span: synthetic_span,
                },
                None,
                Vec::new(),
                None,
                None,
            )
        }
    };

    let span_end = current_position(p);

    Ok(AstStmt::Deny(Box::new(AstDeny {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: span_end,
        },
        keyword_span,
        privileges,
        object_span,
        grantees,
        cascade,
        as_principal,
        semicolon_token: None,
    })))
}

#[allow(clippy::type_complexity)]
fn try_parse_deny_body(
    p: &mut Parser<'_>,
) -> ParseResult<(
    AstPrivilegeList,
    Option<AstDenyObject>,
    Vec<AstGrantee>,
    Option<Span>,
    Option<AstDenyAs>,
)> {
    // 1) Privilege list (or `ALL [PRIVILEGES]`).
    let privileges = parse_privilege_list(p)?;

    // 2) Optional `ON [class::]securable`. MSSQL uses `::` as a scope
    //    qualifier; we capture everything between `ON` and `TO` (the
    //    next mandatory keyword) into `target_span`.
    let object_span = if peek_token_kind(p, TokenKind::Keyword(Keyword::On)) {
        let on_kw = p.advance().expect("peek confirmed");
        let on_span = on_kw.span;
        let target_start = on_span.end;
        let mut target_end = target_start;
        while let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::To)) {
                break;
            }
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let consumed = p.advance().expect("peek confirmed");
            target_end = consumed.span.end;
        }
        Some(AstDenyObject {
            keyword_span: on_span,
            target_span: Span {
                start: target_start,
                end: target_end,
            },
        })
    } else {
        None
    };

    // 3) `TO <principal> [, <principal>]*`.
    expect_keyword(p, Keyword::To, "TO")?;
    let mut grantees: Vec<AstGrantee> = Vec::new();
    grantees.push(parse_grantee(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        grantees.push(parse_grantee(p)?);
    }

    // 4) Trailing `CASCADE` (optional) — note this is a *keyword*-cased
    //    identifier in the MSSQL grammar but the lexer maps it to
    //    `Keyword::Cascade` for some dialects and an unquoted
    //    identifier for others. Match by uppercased lexeme for safety.
    let cascade = if peek_lexeme_eq(p, "CASCADE") {
        let tok = p.advance().expect("peek confirmed");
        Some(tok.span)
    } else {
        None
    };

    // 5) Trailing `AS <principal>` (optional).
    let as_principal = if peek_token_kind(p, TokenKind::Keyword(Keyword::As)) {
        let as_tok = p.advance().expect("peek confirmed");
        let principal_name_span = p.parse_qualified_name_span()?;
        Some(AstDenyAs {
            keyword_span: as_tok.span,
            principal_name_span,
        })
    } else {
        None
    };

    Ok((privileges, object_span, grantees, cascade, as_principal))
}

#[inline]
fn peek_token_kind(p: &mut Parser<'_>, want: TokenKind) -> bool {
    p.peek_non_trivia()
        .map(|t| std::mem::discriminant(&t.kind) == std::mem::discriminant(&want) && t.kind == want)
        .unwrap_or(false)
}
