// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `GRANT` typed parser.
//!
//! Parses `AstStmt::Grant` into typed [`AstGrant`] for the MySQL grammar:
//!
//! ```text
//! GRANT { ALL [ PRIVILEGES ] | <permission> [ ,...n ] }
//!   ON [<object_type>] <priv_level>
//!   TO <user_or_role> [ ,...n ]
//!   [ WITH GRANT OPTION ]
//! ```
//!
//! `priv_level` cardinalities:
//! - `*.*` — server-wide. Projected to [`AstGrantObject::Account`].
//! - `db.*` — all objects in a database. Projected to
//!   [`AstGrantObject::AllInScope`] with `plural = Tables` (MySQL's
//!   default object type for the wildcard form).
//! - `db.tbl` or `tbl` — single named object. Projected to
//!   [`AstGrantObject::Single`] with an `Other { lexemes: ["TABLE"] }`
//!   kind (no `ON TABLE` keyword is required in MySQL grammar).
//!
//! Grantees:
//! - `'user'@'host'` — captured as a single [`AstGrantee::Role`]
//!   `name_span` covering both parts plus the `@` separator. Consumers
//!   that normalize grantee names can recognize the `'%'@'%'` wildcard
//!   form as the everyone-principal (`PUBLIC` in other dialects).
//! - bare identifier (`role_name`) — same shape, `name_span` covers the
//!   identifier only.
//!
//! Per-column privileges (`SELECT (col1, col2)`) and the resource-limit
//! / role-default trailers (`MAX_QUERIES_PER_HOUR`, `AS user WITH ROLE ...`)
//! are not lifted into typed fields. The parser degrades to `Unparsed`
//! if it encounters those tokens.

use crate::ast::{
    AstAllPrivileges, AstGrant, AstGrantObject, AstGrantShape, AstGrantee, AstObjectKind,
    AstObjectScope, AstPluralObjectKind, AstPrivilege, AstPrivilegeGrantBody, AstPrivilegeKind,
    AstPrivilegeList, AstStmt,
};
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::token::{LiteralKind, Span, TokenKind};
use crate::lexer::{Keyword, Operator, Punctuation};
use crate::parser::core::Parser;
use crate::parser::grant::{
    body_start_pos_after, consume_to_terminator, consume_with_grant_option, current_position,
    expect_keyword,
};

/// Parse a MySQL `GRANT ...` statement. Always succeeds: typed-parse
/// failure degrades the body to `AstGrantShape::Unparsed`.
pub(crate) fn parse_grant_mysql(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mysql_grant")?;

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
    let privileges = parse_mysql_privilege_list(p)?;
    expect_keyword(p, Keyword::On, "ON")?;
    let object = parse_mysql_grant_object(p)?;
    expect_keyword(p, Keyword::To, "TO")?;

    let mut grantees: Vec<AstGrantee> = Vec::new();
    grantees.push(parse_mysql_grantee(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        grantees.push(parse_mysql_grantee(p)?);
    }

    let with_grant_option = consume_with_grant_option(p);

    Ok(AstPrivilegeGrantBody {
        privileges,
        objects: vec![object],
        grantees,
        with_grant_option,
    })
}

// ---------------------------------------------------------------------------
// Privilege list — handles `ALL [PRIVILEGES]` and named comma-list.
// ---------------------------------------------------------------------------

fn parse_mysql_privilege_list(p: &mut Parser<'_>) -> ParseResult<AstPrivilegeList> {
    let start_span = p.current_span();

    if peek_token_kind(p, TokenKind::Keyword(Keyword::All)) {
        let all_tok = p.advance().expect_invariant("ALL keyword");
        let mut end = all_tok.span.end;
        let privileges_keyword = if peek_lexeme_eq(p, "PRIVILEGES") {
            let priv_tok = p.advance().expect_invariant("PRIVILEGES");
            end = priv_tok.span.end;
            true
        } else {
            false
        };
        let span = Span {
            start: all_tok.span.start,
            end,
        };
        return Ok(AstPrivilegeList {
            all: Some(AstAllPrivileges {
                privileges_keyword,
                span,
            }),
            privileges: Vec::new(),
            span,
        });
    }

    let mut privileges: Vec<AstPrivilege> = Vec::new();
    privileges.push(parse_one_mysql_privilege(p)?);
    while peek_token_kind(p, TokenKind::Punctuation(Punctuation::Comma)) {
        let _ = p.advance();
        privileges.push(parse_one_mysql_privilege(p)?);
    }
    let end = privileges
        .last()
        .expect_invariant("at least one privilege")
        .span
        .end;
    Ok(AstPrivilegeList {
        all: None,
        privileges,
        span: Span {
            start: start_span.start,
            end,
        },
    })
}

/// One privilege name; consumes contiguous identifier/keyword lexemes
/// until ON, comma, or end-of-list. Mirrors the Snowflake parser's
/// `parse_one_privilege` minus the privilege-name classification table.
fn parse_one_mysql_privilege(p: &mut Parser<'_>) -> ParseResult<AstPrivilege> {
    let first = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    let start = first.span.start;
    let mut end = first.span.end;
    let mut lexemes: Vec<String> = Vec::new();

    while let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Keyword(Keyword::On)
            | TokenKind::Punctuation(Punctuation::Comma)
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Eof => break,
            TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                let consumed = p.advance().expect_invariant("identifier-like");
                lexemes.push(consumed.lexeme(p.source).to_uppercase());
                end = consumed.span.end;
            }
            _ => break,
        }
    }
    Ok(AstPrivilege {
        kind: classify_mysql_privilege(&lexemes),
        span: Span { start, end },
    })
}

fn classify_mysql_privilege(lexemes: &[String]) -> AstPrivilegeKind {
    use AstPrivilegeKind::*;
    match lexemes.join(" ").as_str() {
        "SELECT" => Select,
        "INSERT" => Insert,
        "UPDATE" => Update,
        "DELETE" => Delete,
        "EXECUTE" => Execute,
        "REFERENCES" => References,
        "CREATE" => Create,
        "CREATE USER" => CreateUser,
        "CREATE ROLE" => CreateRole,
        "USAGE" => Usage,
        // Other MySQL-specific privileges (SUPER, RELOAD, REPLICATION SLAVE,
        // FILE, PROCESS, SHUTDOWN, GRANT OPTION, ...) preserve their
        // spelling in Other.
        _ => Other {
            lexemes: lexemes.to_vec(),
        },
    }
}

// ---------------------------------------------------------------------------
// Object (priv_level) — *.*  / db.*  / db.tbl / tbl
// ---------------------------------------------------------------------------

fn parse_mysql_grant_object(p: &mut Parser<'_>) -> ParseResult<AstGrantObject> {
    let first = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    let first_span = first.span;
    let first_kind = first.kind.clone();

    // `*.*` (server-wide) or `*` (any-table).
    if matches!(first_kind, TokenKind::Operator(Operator::Star)) {
        let star_tok = p.advance().expect_invariant("star");
        let mut span_end = star_tok.span.end;

        // Optional `.*` suffix for `*.*`.
        if peek_token_kind(p, TokenKind::Punctuation(Punctuation::Dot)) {
            let _ = p.advance(); // .
            if peek_token_kind(p, TokenKind::Operator(Operator::Star)) {
                let star2 = p.advance().expect_invariant("trailing star");
                span_end = star2.span.end;
            }
        }
        // Server-wide grant → Account tier.
        return Ok(AstGrantObject::Account {
            keyword_span: Span {
                start: first_span.start,
                end: span_end,
            },
        });
    }

    // <name> [.<name>|.*]
    let name_start = first_span.start;
    let mut name_end = first_span.end;
    // Consume first name token.
    let _first = p.advance().expect_invariant("name token");

    // Look for `.*` (all-in-db) or `.<name>` (qualified table).
    let mut saw_wildcard = false;
    if peek_token_kind(p, TokenKind::Punctuation(Punctuation::Dot)) {
        let _ = p.advance(); // .
        if peek_token_kind(p, TokenKind::Operator(Operator::Star)) {
            let star = p.advance().expect_invariant("star after dot");
            name_end = star.span.end;
            saw_wildcard = true;
        } else if let Some(t) = p.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_)) {
                let next = p.advance().expect_invariant("qualified name segment");
                name_end = next.span.end;
            }
        }
    }

    let name_span = Span {
        start: name_start,
        end: name_end,
    };

    if saw_wildcard {
        // `db.*` — project to AllInScope { Tables, Database }. Tables is
        // the conventional reading of `*` at this granularity.
        return Ok(AstGrantObject::AllInScope {
            plural_kind: AstPluralObjectKind::Tables,
            plural_kind_span: name_span,
            scope: AstObjectScope::Database {
                keyword_span: name_span,
                name_span,
            },
        });
    }

    // `db.tbl` or bare `tbl`.
    Ok(AstGrantObject::Single {
        object_kind: AstObjectKind::Other {
            lexemes: vec!["TABLE".to_string()],
        },
        kind_span: Span {
            start: name_span.start,
            end: name_span.start,
        },
        name_span,
        function_signature: None,
    })
}

// ---------------------------------------------------------------------------
// Grantee — 'user'@'host' or bare identifier.
// ---------------------------------------------------------------------------

fn parse_mysql_grantee(p: &mut Parser<'_>) -> ParseResult<AstGrantee> {
    let first = p.peek_non_trivia().ok_or_else(|| eof_err(p))?;
    let start = first.span.start;
    let mut end = first.span.end;

    let first_is_string = matches!(first.kind, TokenKind::Literal(LiteralKind::String));
    if !first_is_string && !p.can_be_identifier_token(first) {
        return Err(crate::error::ParseError::new(
            first.span,
            crate::error::ParseErrorKind::InvalidStatement {
                message: format!("Expected MySQL grantee, found '{}'", first.lexeme(p.source)),
            },
        ));
    }
    let _user = p.advance().expect_invariant("user");

    // Optional `@<host>` (MySQL `'user'@'host'`).
    if peek_token_kind(p, TokenKind::Operator(Operator::At)) {
        let _at = p.advance().expect_invariant("@");
        if let Some(host) = p.peek_non_trivia() {
            let host_is_str = matches!(host.kind, TokenKind::Literal(LiteralKind::String));
            if host_is_str || p.can_be_identifier_token(host) {
                let host_tok = p.advance().expect_invariant("host");
                end = host_tok.span.end;
            }
        }
    }

    // Project to Role grantee with role_keyword_span = None. MySQL users
    // and roles share one grammar here; telling them apart needs the
    // catalog, which the parser does not have.
    Ok(AstGrantee::Role {
        role_keyword_span: None,
        name_span: Span { start, end },
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

#[inline]
fn peek_lexeme_eq(p: &mut Parser<'_>, expected: &str) -> bool {
    p.peek_non_trivia()
        .map(|t| t.lexeme(p.source).eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn eof_err(p: &Parser<'_>) -> crate::error::ParseError {
    crate::error::ParseError::new(
        p.tokens
            .last()
            .map(|t| t.span)
            .unwrap_or(Span { start: 0, end: 0 }),
        crate::error::ParseErrorKind::InvalidStatement {
            message: "Unexpected end of input in MySQL GRANT".to_string(),
        },
    )
}
