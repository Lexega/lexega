// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MSSQL T-SQL `REVOKE` typed parser.
//!
//! Parses `AstStmt::Revoke` into the typed [`AstRevoke`] for the MSSQL
//! grammar:
//!
//! ```text
//! REVOKE [ GRANT OPTION FOR ]
//!   { ALL [ PRIVILEGES ] | <permission> [ ,...n ] }
//!   [ ON [ <class>:: ] securable ]
//!   { TO | FROM } <principal> [ ,...n ]
//!   [ CASCADE ] [ AS <principal> ]
//! ```
//!
//! Mirrors `mssql_grant.rs`: optional `ON` clause (server-tier permissions
//! yield an empty `objects` vec), `<class>::securable` qualifiers, and
//! multi-principal lists. T-SQL admits both `TO` and `FROM` before the
//! principal list. The trailing `AS <principal>` delegation clause is
//! consumed-and-discarded (parity with `mssql_grant.rs`).
//!
//! ## Failure semantics
//!
//! Typed-parse failure rolls back to just past `REVOKE [GRANT OPTION FOR]`,
//! consumes to the next semicolon, and emits `AstRevokeShape::Unparsed`.

use crate::ast::{AstCascadeMode, AstPrivilegeRevokeBody, AstRevoke, AstRevokeShape, AstStmt};
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::token::{Span, TokenKind};
use crate::lexer::{Keyword, Punctuation};
use crate::parser::core::Parser;
use crate::parser::grant::{
    body_start_pos_after, consume_cascade_mode, consume_grant_option_for, consume_to_terminator,
    current_position, expect_keyword, parse_grantee, parse_privilege_list,
};
use crate::parser::mssql_grant::parse_mssql_grant_object;

/// Parse a T-SQL `REVOKE ...` statement. Always succeeds: typed-parse
/// failure degrades the body to `AstRevokeShape::Unparsed`.
pub(crate) fn parse_revoke_mssql(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mssql_revoke")?;

    let revoke_kw = expect_keyword(p, Keyword::Revoke, "REVOKE")?;
    let stmt_start = revoke_kw.span.start;
    let keyword_span = revoke_kw.span;

    // Optional `GRANT OPTION FOR` prefix (revokes only the grant-option).
    let grant_option_for = consume_grant_option_for(p);

    let body_start_idx = p.idx;
    let body_start_pos = if grant_option_for.is_some() {
        current_position(p)
    } else {
        body_start_pos_after(revoke_kw)
    };

    let (shape, cascade_mode) = match try_parse_privilege_body(p) {
        Ok((body, cascade)) => (AstRevokeShape::Privilege(body), cascade),
        Err(_) => {
            p.idx = body_start_idx;
            let body_end = consume_to_terminator(p);
            (
                AstRevokeShape::Unparsed {
                    body_span: Span {
                        start: body_start_pos,
                        end: body_end,
                    },
                },
                None,
            )
        }
    };

    let span_end = current_position(p);

    Ok(AstStmt::Revoke(Box::new(AstRevoke {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: span_end,
        },
        keyword_span,
        grant_option_for,
        shape,
        cascade_mode,
        semicolon_token: None,
    })))
}

/// Body parser: privileges → optional ON → `TO`/`FROM` with multi-grantee
/// → optional CASCADE → optional AS principal. CASCADE/AS are parsed here
/// (not at top level) so a malformed trailer degrades the whole body to
/// `Unparsed` instead of aborting the statement.
fn try_parse_privilege_body(
    p: &mut Parser<'_>,
) -> ParseResult<(AstPrivilegeRevokeBody, Option<AstCascadeMode>)> {
    let privileges = parse_privilege_list(p)?;

    // Server/account-tier permissions omit the ON clause (mirrors
    // `mssql_grant.rs`).
    let objects = if peek_token_kind(p, TokenKind::Keyword(Keyword::On)) {
        let _on = p.advance().expect_invariant("ON token");
        vec![parse_mssql_grant_object(p)?]
    } else {
        Vec::new()
    };

    // T-SQL REVOKE accepts both `TO` and `FROM` before the principals.
    if peek_token_kind(p, TokenKind::Keyword(Keyword::To)) {
        let _ = p.advance();
    } else {
        expect_keyword(p, Keyword::From, "FROM")?;
    }

    let mut grantees = Vec::new();
    grantees.push(parse_grantee(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        grantees.push(parse_grantee(p)?);
    }

    let cascade_mode = consume_cascade_mode(p);

    // Optional trailing `AS <principal>`. Consumed-and-discarded —
    // parity with `mssql_grant.rs`.
    if peek_token_kind(p, TokenKind::Keyword(Keyword::As)) {
        let _ = p.advance(); // AS
        let _ = p.parse_qualified_name_span()?;
    }

    Ok((
        AstPrivilegeRevokeBody {
            privileges,
            objects,
            grantees,
        },
        cascade_mode,
    ))
}

#[inline]
fn peek_token_kind(p: &mut Parser<'_>, want: TokenKind) -> bool {
    p.peek_non_trivia().map(|t| t.kind == want).unwrap_or(false)
}
