// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE/ALTER/DROP WAREHOUSE statement parsing (Snowflake)
//!
//! Warehouse statements are property-based DDL with an open-ended set of
//! KEY = VALUE properties. Known properties are captured as individual spans;
//! unrecognized properties are preserved via the `extras` pattern.
//!
//! ## Token Reference
//!
//! | SQL Text | Token Kind | Notes |
//! |----------|------------|-------|
//! | WAREHOUSE | Identifier | NOT a keyword |
//! | WAREHOUSE_SIZE | Identifier | Property |
//! | AUTO_SUSPEND | Identifier | Property |
//! | AUTO_RESUME | Identifier | Property |
//! | INITIALLY_SUSPENDED | Identifier | Property |
//! | RESOURCE_MONITOR | Identifier | Property |
//! | ENABLE_QUERY_ACCELERATION | Identifier | Property |
//! | QUERY_ACCELERATION_MAX_SCALE_FACTOR | Identifier | Property |
//! | MAX_CONCURRENCY_LEVEL | Identifier | Property |
//! | STATEMENT_QUEUED_TIMEOUT_IN_SECONDS | Identifier | Property |
//! | STATEMENT_TIMEOUT_IN_SECONDS | Identifier | Property |
//! | WAREHOUSE_TYPE | Identifier | Property |
//! | MIN_CLUSTER_COUNT | Identifier | Property |
//! | MAX_CLUSTER_COUNT | Identifier | Property |
//! | SCALING_POLICY | Identifier | Property |
//! | SUSPEND | Identifier | ALTER action |
//! | RESUME | Identifier | ALTER action |
//! | ABORT_ALL_QUERIES | Identifier | ALTER action (or ABORT + ALL + QUERIES) |
//! | ABORT | Identifier | ALTER action part |
//! | COMMENT | Keyword | Property |
//! | SET/UNSET | Keyword | ALTER action |
//! | TAG | Keyword | Clause modifier |
//! | RENAME | Keyword | ALTER action |
//! | TO | Keyword | ALTER action part |
//! | WITH | Keyword | Optional before TAG |

use crate::ast::{
    AstAlterWarehouse, AstAlterWarehouseAction, AstAlterWarehouseActionKind, AstCreateWarehouse,
    AstDropWarehouse, AstStmt, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

// ============================================================================
// Shared helpers
// ============================================================================

/// Parse KEY = VALUE property clause, return span covering the full clause.
/// Handles parenthesized values like RESOURCE_MONITOR = (...).
fn parse_property_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let key_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;
    let start = key_tok.span.start;
    let mut end = key_tok.span.end;

    // Expect =
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
            let eq = p.advance().expect_invariant("= consumed after match");
            end = eq.span.end;

            // Value: string, identifier, number, boolean, or parenthesized
            if let Some(val) = p.peek_non_trivia() {
                if matches!(val.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance(); // consume LParen
                    end = skip_to_matching_paren(p)?;
                } else {
                    let v = p
                        .advance()
                        .expect_invariant("value consumed after = in property");
                    end = v.span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse TAG (key = 'value', ...) clause including the TAG keyword.
/// Returns span covering the full TAG (...) construct.
fn parse_tag_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let tag_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TAG".to_string()])?;
    let start = tag_tok.span.start;
    let mut end = tag_tok.span.end;

    // Expect parenthesized list
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            p.advance(); // LParen
            end = skip_to_matching_paren(p)?;
        }
    }

    Ok(Span { start, end })
}

/// Skip to matching closing paren, return end position of RParen.
fn skip_to_matching_paren(p: &mut Parser<'_>) -> ParseResult<u32> {
    let mut depth = 1;
    while let Some(tok) = p.advance() {
        match tok.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(tok.span.end);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::new(
        p.current_span(),
        ParseErrorKind::InvalidStatement {
            message: "Unmatched parenthesis in WAREHOUSE statement".to_string(),
        },
    ))
}

/// Skip to statement end (semicolon or EOF), return end position.
fn skip_to_statement_end(p: &mut Parser<'_>) -> u32 {
    let mut end = p.current_span().end;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed during skip_to_statement_end");
        end = t.span.end;
        // Handle nested parens
        if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            if let Ok(paren_end) = skip_to_matching_paren(p) {
                end = paren_end;
            }
        }
    }
    end
}

/// Skip to statement end, return span from current position.
fn skip_to_statement_end_span(p: &mut Parser<'_>) -> Span {
    let start = p.current_span().start;
    let end = skip_to_statement_end(p);
    Span { start, end }
}

// ============================================================================
// CREATE WAREHOUSE
// ============================================================================

/// Parse CREATE [OR REPLACE] WAREHOUSE [IF NOT EXISTS] name [properties...]
///
/// Entry: parser positioned at CREATE token.
pub(crate) fn try_parse_create_warehouse(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("create_warehouse")?;

    // Consume CREATE
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let mut span = create_span;

    // Optional OR REPLACE
    let mut or_replace_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR consumed after match");
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p.advance().expect_invariant("REPLACE consumed after match");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                }
            }
        }
    }

    // WAREHOUSE identifier
    let wh_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["WAREHOUSE".to_string()])?;
    if !wh_tok.lexeme(p.source).eq_ignore_ascii_case("WAREHOUSE") {
        return Err(ParseError::new(
            wh_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected WAREHOUSE, found '{}'", wh_tok.lexeme(p.source)),
            },
        ));
    }
    let warehouse_kw = p
        .advance()
        .expect_invariant("WAREHOUSE consumed after lexeme check");
    let warehouse_span = warehouse_kw.span;
    span.end = warehouse_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF consumed after match");
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    p.advance(); // NOT
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists =
                                p.advance().expect_invariant("EXISTS consumed after match");
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

    // Warehouse name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;
    span.end = name_span.end;

    // Optional WITH keyword (skip it — syntactic sugar)
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
            let with = p.advance().expect_invariant("WITH consumed after match");
            span.end = with.span.end;
        }
    }

    // Parse properties
    let mut warehouse_size_span: Option<Span> = None;
    let mut auto_suspend_span: Option<Span> = None;
    let mut auto_resume_span: Option<Span> = None;
    let mut initially_suspended_span: Option<Span> = None;
    let mut resource_monitor_span: Option<Span> = None;
    let mut comment_span: Option<Span> = None;
    let mut enable_query_acceleration_span: Option<Span> = None;
    let mut query_acceleration_max_scale_factor_span: Option<Span> = None;
    let mut max_concurrency_level_span: Option<Span> = None;
    let mut statement_queued_timeout_span: Option<Span> = None;
    let mut statement_timeout_span: Option<Span> = None;
    let mut warehouse_type_span: Option<Span> = None;
    let mut min_cluster_count_span: Option<Span> = None;
    let mut max_cluster_count_span: Option<Span> = None;
    let mut scaling_policy_span: Option<Span> = None;
    let mut tag_span: Option<Span> = None;
    let mut extras: Vec<AstUnknownClause> = Vec::new();

    while let Some(tok) = p.peek_non_trivia() {
        // Stop at semicolon
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        let lexeme = tok.lexeme(p.source);

        // TAG keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            tag_span = Some(parse_tag_clause(p)?);
            span.end = tag_span.as_ref().unwrap().end;
            continue;
        }

        // COMMENT keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            comment_span = Some(parse_property_clause(p)?);
            span.end = comment_span.as_ref().unwrap().end;
            continue;
        }

        // All warehouse properties are Identifier tokens — dispatch by lexeme
        if lexeme.eq_ignore_ascii_case("WAREHOUSE_SIZE") {
            warehouse_size_span = Some(parse_property_clause(p)?);
            span.end = warehouse_size_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("AUTO_SUSPEND") {
            auto_suspend_span = Some(parse_property_clause(p)?);
            span.end = auto_suspend_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("AUTO_RESUME") {
            auto_resume_span = Some(parse_property_clause(p)?);
            span.end = auto_resume_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("INITIALLY_SUSPENDED") {
            initially_suspended_span = Some(parse_property_clause(p)?);
            span.end = initially_suspended_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("RESOURCE_MONITOR") {
            resource_monitor_span = Some(parse_property_clause(p)?);
            span.end = resource_monitor_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("ENABLE_QUERY_ACCELERATION") {
            enable_query_acceleration_span = Some(parse_property_clause(p)?);
            span.end = enable_query_acceleration_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("QUERY_ACCELERATION_MAX_SCALE_FACTOR") {
            query_acceleration_max_scale_factor_span = Some(parse_property_clause(p)?);
            span.end = query_acceleration_max_scale_factor_span
                .as_ref()
                .unwrap()
                .end;
        } else if lexeme.eq_ignore_ascii_case("MAX_CONCURRENCY_LEVEL") {
            max_concurrency_level_span = Some(parse_property_clause(p)?);
            span.end = max_concurrency_level_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("STATEMENT_QUEUED_TIMEOUT_IN_SECONDS") {
            statement_queued_timeout_span = Some(parse_property_clause(p)?);
            span.end = statement_queued_timeout_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("STATEMENT_TIMEOUT_IN_SECONDS") {
            statement_timeout_span = Some(parse_property_clause(p)?);
            span.end = statement_timeout_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("WAREHOUSE_TYPE") {
            warehouse_type_span = Some(parse_property_clause(p)?);
            span.end = warehouse_type_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("MIN_CLUSTER_COUNT") {
            min_cluster_count_span = Some(parse_property_clause(p)?);
            span.end = min_cluster_count_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("MAX_CLUSTER_COUNT") {
            max_cluster_count_span = Some(parse_property_clause(p)?);
            span.end = max_cluster_count_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SCALING_POLICY") {
            scaling_policy_span = Some(parse_property_clause(p)?);
            span.end = scaling_policy_span.as_ref().unwrap().end;
        } else {
            // Unknown property — preserve via extras (defensive design)
            let introducer_span = tok.span;
            let prop_span = parse_property_clause(p)?;
            extras.push(AstUnknownClause {
                node_id: p.id_gen.next(),
                introducer: Some(introducer_span),
                span: prop_span,
                kind: UnknownKind::Property,
            });
            span.end = prop_span.end;
        }
    }
    Ok(AstStmt::CreateWarehouse(Box::new(AstCreateWarehouse {
        node_id: p.id_gen.next(),
        span,
        create_span,
        warehouse_span,
        or_replace_span,
        if_not_exists_span,
        name_span,
        warehouse_size_span,
        auto_suspend_span,
        auto_resume_span,
        initially_suspended_span,
        resource_monitor_span,
        comment_span,
        enable_query_acceleration_span,
        query_acceleration_max_scale_factor_span,
        max_concurrency_level_span,
        statement_queued_timeout_span,
        statement_timeout_span,
        warehouse_type_span,
        min_cluster_count_span,
        max_cluster_count_span,
        scaling_policy_span,
        tag_span,
        extras,
    })))
}

// ============================================================================
// ALTER WAREHOUSE
// ============================================================================

/// Parse ALTER WAREHOUSE [IF EXISTS] name { action }
///
/// Entry: parser positioned at ALTER token.
pub(crate) fn try_parse_alter_warehouse(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("alter_warehouse")?;

    // Consume ALTER
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;

    // WAREHOUSE identifier
    let wh_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["WAREHOUSE".to_string()])?;
    if !wh_tok.lexeme(p.source).eq_ignore_ascii_case("WAREHOUSE") {
        return Err(ParseError::new(
            wh_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected WAREHOUSE, found '{}'", wh_tok.lexeme(p.source)),
            },
        ));
    }
    let warehouse_kw = p
        .advance()
        .expect_invariant("WAREHOUSE consumed after lexeme check");
    let warehouse_span = warehouse_kw.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let saved_idx = p.idx;
            let if_tok = p.advance().expect_invariant("IF consumed after match");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant("EXISTS consumed after match");
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                } else {
                    p.idx = saved_idx;
                }
            } else {
                p.idx = saved_idx;
            }
        }
    }

    // Warehouse name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Parse action
    let mut extras: Vec<AstUnknownClause> = Vec::new();
    let (action, action_span) = parse_alter_warehouse_action(p, &mut extras)?;

    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };
    Ok(AstStmt::AlterWarehouse(Box::new(AstAlterWarehouse {
        node_id: p.id_gen.next(),
        span: stmt_span,
        alter_span,
        warehouse_span,
        if_exists_span,
        name_span,
        action_span,
        action,
        extras,
    })))
}

/// Parse the action portion of ALTER WAREHOUSE.
fn parse_alter_warehouse_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<(AstAlterWarehouseAction, Span)> {
    let tok = p.peek_non_trivia().ok_or_eof(
        p.current_span(),
        vec!["action (SUSPEND, RESUME, SET, ...)".to_string()],
    )?;
    let action_start = tok.span.start;

    let kind = if tok.lexeme(p.source).eq_ignore_ascii_case("SUSPEND") {
        // SUSPEND
        let t = p.advance().expect_invariant("SUSPEND consumed");
        AstAlterWarehouseActionKind::Suspend {
            suspend_span: t.span,
        }
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("RESUME") {
        // RESUME [IF SUSPENDED]
        let t = p.advance().expect_invariant("RESUME consumed");
        let mut end = t.span.end;
        // Optional IF SUSPENDED
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::If)) {
                let saved = p.idx;
                p.advance(); // IF
                if let Some(sus) = p.peek_non_trivia() {
                    if sus.lexeme(p.source).eq_ignore_ascii_case("SUSPENDED") {
                        let s = p.advance().expect_invariant("SUSPENDED consumed");
                        end = s.span.end;
                    } else {
                        p.idx = saved;
                    }
                } else {
                    p.idx = saved;
                }
            }
        }
        AstAlterWarehouseActionKind::Resume {
            resume_span: Span {
                start: t.span.start,
                end,
            },
        }
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("ABORT")
        || tok
            .lexeme(p.source)
            .eq_ignore_ascii_case("ABORT_ALL_QUERIES")
    {
        // ABORT ALL QUERIES (or ABORT_ALL_QUERIES as single token)
        let t = p.advance().expect_invariant("ABORT consumed");
        let mut end = t.span.end;
        if t.lexeme(p.source).eq_ignore_ascii_case("ABORT") {
            // Multi-token form: consume ALL, QUERIES
            if let Some(all) = p.peek_non_trivia() {
                if matches!(all.kind, TokenKind::Keyword(Keyword::All)) {
                    let a = p.advance().expect_invariant("ALL consumed");
                    end = a.span.end;
                    if let Some(q) = p.peek_non_trivia() {
                        if q.lexeme(p.source).eq_ignore_ascii_case("QUERIES") {
                            let qu = p.advance().expect_invariant("QUERIES consumed");
                            end = qu.span.end;
                        }
                    }
                }
            }
        }
        AstAlterWarehouseActionKind::AbortAllQueries {
            abort_span: Span {
                start: t.span.start,
                end,
            },
        }
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Rename)) {
        // RENAME TO <new_name>
        let rename_tok = p.advance().expect_invariant("RENAME consumed");
        let to_tok = p
            .peek_non_trivia()
            .ok_or_eof(p.current_span(), vec!["TO".to_string()])?;
        if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
            return Err(ParseError::new(
                to_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TO after RENAME, found '{}'",
                        to_tok.lexeme(p.source)
                    ),
                },
            ));
        }
        let to = p.advance().expect_invariant("TO consumed");
        let new_name_span = p.parse_qualified_name_span()?;
        AstAlterWarehouseActionKind::RenameTo {
            rename_span: rename_tok.span,
            to_span: to.span,
            new_name_span,
        }
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
        // SET: could be SET TAG or SET properties
        let set_tok = p.advance().expect_invariant("SET consumed");
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                // SET TAG <tag_name> = '<value>' [, ...]
                let tag_tok = p.advance().expect_invariant("TAG consumed");
                let mut end = tag_tok.span.end;
                if let Some(lparen) = p.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        p.advance(); // LParen
                        end = skip_to_matching_paren(p)?;
                    } else {
                        // No parens — consume tag assignments until semicolon
                        while let Some(tok) = p.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            let t = p.advance().unwrap();
                            end = t.span.end;
                        }
                    }
                }
                AstAlterWarehouseActionKind::SetTag {
                    set_span: set_tok.span,
                    tag_span: tag_tok.span,
                    assignments_span: Span {
                        start: tag_tok.span.start,
                        end,
                    },
                }
            } else {
                // SET property = value [property = value ...]
                let props_start = next.span.start;
                let mut end = props_start;
                // Consume all properties until semicolon
                while let Some(tok) = p.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    let t = p.advance().unwrap();
                    end = t.span.end;
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        if let Ok(pend) = skip_to_matching_paren(p) {
                            end = pend;
                        }
                    }
                }
                AstAlterWarehouseActionKind::Set {
                    set_span: set_tok.span,
                    properties_span: Span {
                        start: props_start,
                        end,
                    },
                }
            }
        } else {
            AstAlterWarehouseActionKind::Set {
                set_span: set_tok.span,
                properties_span: set_tok.span,
            }
        }
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset)) {
        // UNSET: could be UNSET TAG or UNSET properties
        let unset_tok = p.advance().expect_invariant("UNSET consumed");
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                // UNSET TAG <tag_name> [, <tag_name> ...]
                let tag_tok = p.advance().expect_invariant("TAG consumed");
                let mut end = tag_tok.span.end;
                if let Some(lparen) = p.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        p.advance(); // LParen
                        end = skip_to_matching_paren(p)?;
                    } else {
                        // No parens — consume tag names until semicolon
                        while let Some(tok) = p.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            let t = p.advance().unwrap();
                            end = t.span.end;
                        }
                    }
                }
                AstAlterWarehouseActionKind::UnsetTag {
                    unset_span: unset_tok.span,
                    tag_span: tag_tok.span,
                    names_span: Span {
                        start: tag_tok.span.start,
                        end,
                    },
                }
            } else {
                // UNSET property [, property ...]
                let props_start = next.span.start;
                let mut end = props_start;
                while let Some(tok) = p.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    let t = p.advance().unwrap();
                    end = t.span.end;
                }
                AstAlterWarehouseActionKind::Unset {
                    unset_span: unset_tok.span,
                    properties_span: Span {
                        start: props_start,
                        end,
                    },
                }
            }
        } else {
            AstAlterWarehouseActionKind::Unset {
                unset_span: unset_tok.span,
                properties_span: unset_tok.span,
            }
        }
    } else {
        // Unknown action — preserve as extra
        let unknown_span = skip_to_statement_end_span(p);
        extras.push(AstUnknownClause {
            node_id: p.id_gen.next(),
            introducer: Some(tok.span),
            span: unknown_span,
            kind: UnknownKind::Clause,
        });
        // Return a dummy suspend so the AST node is valid
        AstAlterWarehouseActionKind::Suspend {
            suspend_span: unknown_span,
        }
    };

    let action_end = match &kind {
        AstAlterWarehouseActionKind::Suspend { suspend_span } => suspend_span.end,
        AstAlterWarehouseActionKind::Resume { resume_span } => resume_span.end,
        AstAlterWarehouseActionKind::AbortAllQueries { abort_span } => abort_span.end,
        AstAlterWarehouseActionKind::RenameTo { new_name_span, .. } => new_name_span.end,
        AstAlterWarehouseActionKind::Set {
            properties_span, ..
        } => properties_span.end,
        AstAlterWarehouseActionKind::Unset {
            properties_span, ..
        } => properties_span.end,
        AstAlterWarehouseActionKind::SetTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterWarehouseActionKind::UnsetTag { names_span, .. } => names_span.end,
    };

    let action_span = Span {
        start: action_start,
        end: action_end,
    };

    Ok((
        AstAlterWarehouseAction {
            span: action_span,
            kind,
        },
        action_span,
    ))
}

// ============================================================================
// DROP WAREHOUSE
// ============================================================================

/// Parse DROP WAREHOUSE [IF EXISTS] name
///
/// Entry: parser positioned at DROP token.
pub(crate) fn try_parse_drop_warehouse(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("drop_warehouse")?;

    // Consume DROP
    let drop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let drop_span = drop_tok.span;

    // WAREHOUSE identifier
    let wh_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["WAREHOUSE".to_string()])?;
    if !wh_tok.lexeme(p.source).eq_ignore_ascii_case("WAREHOUSE") {
        return Err(ParseError::new(
            wh_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected WAREHOUSE, found '{}'", wh_tok.lexeme(p.source)),
            },
        ));
    }
    let warehouse_kw = p
        .advance()
        .expect_invariant("WAREHOUSE consumed after lexeme check");
    let warehouse_span = warehouse_kw.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let saved_idx = p.idx;
            let if_tok = p.advance().expect_invariant("IF consumed after match");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant("EXISTS consumed after match");
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                } else {
                    p.idx = saved_idx;
                }
            } else {
                p.idx = saved_idx;
            }
        }
    }

    // Warehouse name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    let stmt_span = Span {
        start: drop_span.start,
        end: name_span.end,
    };
    Ok(AstStmt::DropWarehouse(Box::new(AstDropWarehouse {
        node_id: p.id_gen.next(),
        span: stmt_span,
        drop_span,
        warehouse_span,
        if_exists_span,
        name_span,
    })))
}
