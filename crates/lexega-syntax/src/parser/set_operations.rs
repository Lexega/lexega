// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Set operation parsing (UNION, INTERSECT, EXCEPT, MINUS).
//!
//! Handles compound SELECT statements with set operators:
//! - `SELECT ... UNION [ALL] SELECT ...`
//! - `SELECT ... INTERSECT SELECT ...`
//! - `SELECT ... EXCEPT SELECT ...`
//! - `SELECT ... MINUS SELECT ...` (Snowflake alias for EXCEPT)
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/operators-query>

use crate::ast::*;
use crate::lexer::{Keyword, TokenKind};
use crate::parser::core::Parser;
use crate::parser::cte::try_parse_with_clause;

/// Parse a single operand for a set operation with Result-based error handling.
/// This can be:
/// - A plain SELECT statement
/// - A parenthesized set operation: (SELECT ... UNION SELECT ...)
///
/// Per Snowflake grammar: [ ( ] <query> [ ) ]
pub(crate) fn try_parse_set_operand(p: &mut Parser<'_>) -> crate::error::ParseResult<AstStmt> {
    use crate::error::ParseError;

    // Check for leading parenthesis
    if let Some(tok) = p.peek() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            // Capture opening paren token ID
            let lparen_start = tok.span.start;
            let lparen_token_id = p.current_token_id();

            // Consume the opening paren
            let _ = p.advance();

            // Recursively parse the parenthesized statement (which could itself be a set operation)
            let mut inner_stmt = try_parse_set_or_select_stmt(p)?;

            // Consume the closing paren
            let closing = p.peek().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message: "Expected ')' to close parenthesized query".to_string(),
                    },
                )
            })?;
            if !matches!(
                closing.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                return Err(ParseError::unexpected_token(
                    closing.span,
                    vec![")".to_string()],
                    Parser::token_description(closing, p.source),
                ));
            }

            let rparen_end = closing.span.end;
            let _ = p.advance(); // Consume rparen first
            let rparen_token_id = p.last_token_id(); // Then get its token ID

            // Create syntax node for the parentheses
            let paren_span = crate::lexer::Span {
                start: lparen_start,
                end: rparen_end,
            };

            let select_span = inner_stmt.span();

            let syntax_subquery = crate::syntax::SyntaxSubquery {
                l_paren: lparen_token_id,
                select_span,
                r_paren: rparen_token_id,
                span: paren_span,
            };

            let syntax_id = p.syntax_arena.alloc_subquery(syntax_subquery);

            // Attach syntax ID to the inner statement
            match &mut inner_stmt {
                AstStmt::Select(ref mut select) => {
                    select.paren_syntax_id = Some(syntax_id);
                }
                AstStmt::SetSelect(ref mut set_select) => {
                    // SetSelect also needs paren tracking when wrapped in parentheses
                    // Example: ((SELECT a) UNION (SELECT b)) - outer parens wrap SetSelect
                    set_select.paren_syntax_id = Some(syntax_id);
                }
                AstStmt::ValuesQuery(ref mut vq) => {
                    vq.paren_syntax_id = Some(syntax_id);
                }
                _ => {}
            }

            return Ok(inner_stmt);
        }
    }

    // Check for VALUES keyword — parse as standalone values query operand.
    // IMPORTANT: Delegate to a separate #[inline(never)] function so that its locals
    // don't bloat try_parse_set_operand's stack frame. This function is called recursively
    // per nesting level in deeply nested subqueries (e.g., 40-deep CTEs), so every byte
    // in its stack frame is multiplied by the nesting depth.
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Values)) {
            return parse_values_operand(p);
        }
    }

    // MySQL `TABLE tbl [ORDER BY ...] [LIMIT ...]` — query-bearing sugar for
    // `SELECT * FROM tbl ...`. Recognized here so it composes as a set-op
    // operand and (via the leading-paren branch above) as a subquery.
    if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Table))
            && p.dialect.supports_table_query_statement()
        {
            return parse_table_query_operand(p);
        }
    }

    // No parenthesis and not VALUES, parse a plain SELECT
    let select = p.try_parse_select_in_mode_boxed()?;
    Ok(AstStmt::Select(select))
}

/// Parse a MySQL `TABLE tbl [ORDER BY col] [LIMIT n [OFFSET m]]` statement
/// into the equivalent `AstSelect` (synthetic `*` projection over the single
/// table), tagged with `table_syntax_span`. Returning an `AstStmt::Select`
/// means everything that understands a SELECT applies unchanged, and every
/// query context (set-op, subquery, INSERT source, CTAS body) composes with
/// no extra plumbing.
#[inline(never)]
fn parse_table_query_operand(p: &mut Parser<'_>) -> crate::error::ParseResult<AstStmt> {
    use crate::ast::{AstProjection, AstProjectionKind, AstStarProjection, FromItem, FromItemKind};
    use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

    let table_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TABLE".to_string()])?;
    let table_kw_span = table_tok.span;
    let start = table_kw_span.start;

    let table = p.parse_table_factor(table_kw_span)?.ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "TABLE statement requires a table name".to_string(),
            },
        )
    })?;
    let table_span = table.span;

    // Optional ORDER BY ... and LIMIT n [OFFSET m] tail (reused SELECT parsers).
    let order_by = p.parse_select_order_by()?;
    let limit_offset = p.parse_select_limit_offset()?;

    // Synthetic `*` projection — never emitted (the TABLE form is re-emitted
    // verbatim by the formatter); consumers read it as `SELECT *`.
    let star = AstProjection {
        node_id: p.id_gen.next(),
        kind: AstProjectionKind::Star(Box::new(AstStarProjection {
            node_id: p.id_gen.next(),
            star_span: table_span,
            qualifier: None,
            ilike: None,
            exclude: None,
            replace: None,
            rename: None,
        })),
        exclude: None,
        span: table_span,
    };

    let from = vec![FromItem {
        node_id: p.id_gen.next(),
        kind: FromItemKind::TableRef(table),
    }];

    let mut end = table_span.end;
    if let Some(ob) = &order_by {
        end = end.max(ob.span.end);
    }
    if let Some(le) = &limit_offset.limit_expr {
        end = end.max(crate::parser::scripting::expr_span_end(le));
    }
    if let Some(oe) = &limit_offset.offset_expr {
        end = end.max(crate::parser::scripting::expr_span_end(oe));
    }
    let span = crate::lexer::Span { start, end };

    let mut select = crate::parser::sql_stmt::build_select(
        p.id_gen.next(),
        span,
        table_kw_span, // select_span
        None,          // select_as_qualifier
        None,          // set_quantifier
        None,          // set_quantifier_span
        None,          // top
        star,
        from,
        Vec::new(), // statement_fragments
        None,       // where_clause
        None,       // group_by
        None,       // having
        None,       // connect_by
        order_by,
        None, // qualify
        None, // into_target
        limit_offset.limit_expr.map(Box::new),
        limit_offset.offset_expr.map(Box::new),
        limit_offset.limit_keyword_span,
        limit_offset.fetch_clause_span,
        limit_offset.offset_keyword_span,
        None, // for_update
        None, // semicolon_token
        None, // window_clause
    );
    select.table_syntax_span = Some(table_kw_span);
    select.limit_offset_comma_span = limit_offset.limit_comma_span;
    Ok(AstStmt::Select(Box::new(select)))
}

/// Parse a VALUES query as a set operand.
///
/// Extracted from `try_parse_set_operand` with `#[inline(never)]` to prevent its locals
/// (values, order_by, limit_offset, span_end, vq) from bloating the caller's stack frame.
/// `try_parse_set_operand` is called recursively per nesting level in deeply nested
/// subqueries, so its frame size is critical — every extra byte is multiplied by depth.
#[inline(never)]
fn parse_values_operand(p: &mut Parser<'_>) -> crate::error::ParseResult<AstStmt> {
    use crate::error::ParseError;

    let values = p.parse_values().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidStatement {
                message: "Expected VALUES clause with at least one row".to_string(),
            },
        )
    })?;

    let order_by = if let Some(t) = p.peek() {
        if matches!(t.kind, TokenKind::Keyword(Keyword::Order)) {
            p.parse_select_order_by()?
        } else {
            None
        }
    } else {
        None
    };

    let limit_offset = p.parse_select_limit_offset()?;

    let mut span_end = values.span.end;
    if let Some(ref ob) = order_by {
        span_end = ob.span.end;
    }
    if let Some(ref off_kw) = limit_offset.offset_keyword_span {
        span_end = span_end.max(off_kw.end);
    }
    if let Some(ref off) = limit_offset.offset_expr {
        span_end = span_end.max(off.span().end);
    }
    if let Some(ref lim) = limit_offset.limit_expr {
        span_end = span_end.max(lim.span().end);
    }
    if let Some(ref fetch) = limit_offset.fetch_clause_span {
        span_end = span_end.max(fetch.end);
    }

    let vq = crate::ast::AstValuesQuery {
        node_id: p.id_gen.next(),
        span: crate::lexer::Span {
            start: values.span.start,
            end: span_end,
        },
        values,
        order_by: order_by.map(Box::new),
        limit: limit_offset.limit_expr.map(Box::new),
        offset: limit_offset.offset_expr.map(Box::new),
        limit_keyword_span: limit_offset.limit_keyword_span,
        fetch_clause_span: limit_offset.fetch_clause_span,
        offset_keyword_span: limit_offset.offset_keyword_span,
        paren_syntax_id: None,
    };

    Ok(AstStmt::ValuesQuery(Box::new(vq)))
}

/// Parse a SELECT statement with Result-based error handling and specified expression mode.
/// This is a wrapper that calls the parser method and wraps the result in AstStmt.
pub(crate) fn try_parse_select_stmt_with_parser(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    let select = p.try_parse_select_in_mode_boxed()?;
    Ok(AstStmt::Select(select))
}

/// Parse a SELECT statement or set operation (UNION/INTERSECT/EXCEPT) with Result-based error handling.
pub(crate) fn try_parse_set_or_select_stmt(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError};

    // Optional: Parse WITH clause first (CTEs)
    // WITH [RECURSIVE] cte_name1 [(col_list)] AS (SELECT ...) [, cte_name2 ...] SELECT ...
    let with_clause = if let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
            Some(try_parse_with_clause(p)?)
        } else {
            None
        }
    } else {
        None
    };

    // If we just parsed a WITH clause, check if it's followed by DML (writable CTEs)
    // PostgreSQL supports: WITH ... INSERT/UPDATE/DELETE/MERGE
    if let Some(ref with) = with_clause {
        if let Some(tok) = p.peek_non_trivia() {
            match &tok.kind {
                TokenKind::Keyword(Keyword::Insert) => {
                    let mut stmt = super::sql_stmt::try_parse_insert_stmt_with_parser(p)?;
                    if let AstStmt::Insert(ref mut insert) = &mut stmt {
                        let with_start = with.span.start;
                        insert.with_clause = Some(with.clone());
                        insert.span = crate::lexer::Span {
                            start: with_start,
                            end: insert.span.end,
                        };
                    }
                    return Ok(stmt);
                }
                TokenKind::Keyword(Keyword::Update) => {
                    let mut stmt = super::sql_stmt::try_parse_update_stmt_with_parser(p)?;
                    if let AstStmt::Update(ref mut update) = &mut stmt {
                        let with_start = with.span.start;
                        update.with_clause = Some(with.clone());
                        update.span = crate::lexer::Span {
                            start: with_start,
                            end: update.span.end,
                        };
                    }
                    return Ok(stmt);
                }
                TokenKind::Keyword(Keyword::Delete) => {
                    let mut stmt = super::sql_stmt::try_parse_delete_stmt_with_parser(p)?;
                    if let AstStmt::Delete(ref mut delete) = &mut stmt {
                        let with_start = with.span.start;
                        delete.with_clause = Some(with.clone());
                        delete.span = crate::lexer::Span {
                            start: with_start,
                            end: delete.span.end,
                        };
                    }
                    return Ok(stmt);
                }
                TokenKind::Keyword(Keyword::Merge) => {
                    // MERGE with CTEs: dispatch to MERGE parser and attach WITH clause.
                    let mut stmt = super::sql_stmt::try_parse_merge_stmt_with_parser(p)?;
                    if let AstStmt::Merge(ref mut merge) = &mut stmt {
                        let with_start = with.span.start;
                        merge.with_clause = Some(with.clone());
                        merge.span = crate::lexer::Span {
                            start: with_start,
                            end: merge.span.end,
                        };
                    }
                    return Ok(stmt);
                }
                TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Values)
                | TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                    // Valid SELECT/VALUES — continue to normal path below
                }
                _ => {
                    // Allow parsing to continue and fail naturally with a more specific error
                }
            }
        }
    }

    // Parse the first operand (could be SELECT or parenthesized statement)
    let mut left_stmt = try_parse_set_operand(p)?;

    // Attach WITH clause to the SELECT if present
    if let Some(with) = with_clause {
        if let AstStmt::Select(ref mut select) = &mut left_stmt {
            select.with_clause = Some(Box::new(with.clone()));
            // Update SELECT span to include WITH clause
            select.span = crate::lexer::Span {
                start: with.span.start,
                end: select.span.end,
            };
        }
    }

    let mut last_set: Option<crate::ast::AstSetSelect> = None;

    while let Some(op_tok) = p.peek() {
        // Look for a set operator (UNION/INTERSECT/EXCEPT).
        let op_kind = match crate::parser::sql_stmt::is_set_op_keyword(&op_tok.kind) {
            Some(k) => k,
            None => break,
        };
        // Consume the set operator keyword and capture its token ID.
        let op_keyword_tok = p
            .advance()
            .expect_invariant("set operator keyword confirmed by peek");
        let op_keyword_token_id = p.last_token_id();
        let mut op_span = op_keyword_tok.span;

        // Optional ALL or DISTINCT modifier
        // ALL: returns all rows including duplicates
        // DISTINCT: deduplicate (default behavior, but BigQuery uses it explicitly)
        let mut modifier = crate::ast::AstSetModifier::None;
        let mut modifier_token_id: Option<crate::cst::TokenId> = None;
        if let Some(next) = p.peek() {
            if crate::parser::sql_stmt::parse_set_all_flag(&next.kind) {
                let mod_tok = p
                    .advance()
                    .expect_invariant("ALL keyword confirmed by peek");
                modifier = crate::ast::AstSetModifier::All;
                modifier_token_id = Some(p.last_token_id());
                op_span.end = mod_tok.span.end;
            } else if matches!(next.kind, TokenKind::Keyword(Keyword::Distinct)) {
                let mod_tok = p
                    .advance()
                    .expect_invariant("DISTINCT keyword confirmed by peek");
                modifier = crate::ast::AstSetModifier::Distinct;
                modifier_token_id = Some(p.last_token_id());
                op_span.end = mod_tok.span.end;
            }
        }

        // Allocate syntax node for the set operator
        let set_op_syntax_id =
            p.syntax_arena
                .alloc_set_operator(crate::syntax::SyntaxSetOperator {
                    op_keyword: op_keyword_token_id,
                    modifier_keyword: modifier_token_id,
                    span: op_span,
                });

        // Parse the right-hand side operand (could be SELECT or parenthesized statement)
        let right_stmt = try_parse_set_operand(p)?;

        // Extract the SELECT from the right operand
        let right_select = match right_stmt {
            AstStmt::Select(sel) => *sel,
            AstStmt::SetSelect(set) => {
                // Right side is a parenthesized set operation
                let new_set = crate::ast::AstSetSelect {
                    node_id: p.id_gen.next(),
                    left: Box::new(left_stmt),
                    op: op_kind,
                    modifier,
                    right: Box::new(AstStmt::SetSelect(set)),
                    set_op_syntax_id: Some(set_op_syntax_id),
                    semicolon_token: None,
                    paren_syntax_id: None,
                    order_by: None,
                    limit: None,
                    offset: None,
                    limit_keyword_span: None,
                    fetch_clause_span: None,
                    offset_keyword_span: None,
                    limit_offset_comma_span: None,
                };
                left_stmt = AstStmt::SetSelect(new_set.clone());
                last_set = Some(new_set);
                continue;
            }
            AstStmt::ValuesQuery(_) => {
                // Right side is a VALUES query — store directly in AstSetSelect
                let new_set = crate::ast::AstSetSelect {
                    node_id: p.id_gen.next(),
                    left: Box::new(left_stmt),
                    op: op_kind,
                    modifier,
                    right: Box::new(right_stmt),
                    set_op_syntax_id: Some(set_op_syntax_id),
                    semicolon_token: None,
                    paren_syntax_id: None,
                    order_by: None,
                    limit: None,
                    offset: None,
                    limit_keyword_span: None,
                    fetch_clause_span: None,
                    offset_keyword_span: None,
                    limit_offset_comma_span: None,
                };
                left_stmt = AstStmt::SetSelect(new_set.clone());
                last_set = Some(new_set);
                continue;
            }
            _ => {
                return Err(ParseError::new(
                    p.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!("Unexpected statement type after {:?} operator", op_kind),
                    },
                ));
            }
        };

        let new_set = crate::parser::sql_stmt::build_set_select(
            p.id_gen.next(),
            left_stmt,
            op_kind,
            modifier,
            Some(set_op_syntax_id),
            right_select,
        );
        left_stmt = AstStmt::SetSelect(new_set.clone());
        last_set = Some(new_set);
    }

    // A trailing ORDER BY / LIMIT after the chain belongs to the whole set
    // operation, not to any operand. (A lone SELECT — `last_set` is None —
    // already carries its own tail and is left untouched.)
    if let Some(set) = last_set.as_mut() {
        attach_set_query_tail(p, set)?;
    }

    Ok(crate::parser::sql_stmt::finalize_set_or_select(
        left_stmt, last_set,
    ))
}

/// Attach the trailing `ORDER BY` / `LIMIT` / `OFFSET` / `FETCH` of a set
/// operation to the set node. The clause belongs to the whole query
/// expression and arrives one of two ways:
///   (a) a parenthesized last operand leaves it in the token stream, so it is
///       consumed here; or
///   (b) a bare last operand's SELECT parser greedily absorbed it (a bare set
///       operand cannot legally own a trailing clause in SQL), so it is
///       hoisted off the inner `AstSelect`.
pub(crate) fn attach_set_query_tail(
    p: &mut Parser<'_>,
    set: &mut AstSetSelect,
) -> crate::error::ParseResult<()> {
    let order_by = if matches!(
        p.peek().map(|t| &t.kind),
        Some(TokenKind::Keyword(Keyword::Order))
    ) {
        p.parse_select_order_by()?
    } else {
        None
    };
    let lim = p.parse_select_limit_offset()?;
    let consumed = order_by.is_some()
        || lim.limit_expr.is_some()
        || lim.offset_expr.is_some()
        || lim.fetch_clause_span.is_some();

    if consumed {
        // (a) consumed directly from the token stream.
        set.order_by = order_by.map(Box::new);
        set.limit = lim.limit_expr.map(Box::new);
        set.offset = lim.offset_expr.map(Box::new);
        set.limit_keyword_span = lim.limit_keyword_span;
        set.fetch_clause_span = lim.fetch_clause_span;
        set.offset_keyword_span = lim.offset_keyword_span;
        set.limit_offset_comma_span = lim.limit_comma_span;
        return Ok(());
    }

    // (b) hoist a tail the bare last operand absorbed.
    if let AstStmt::Select(sel) = set.right.as_mut() {
        // A parenthesized operand legitimately owns its inner tail.
        if sel.paren_syntax_id.is_some() {
            return Ok(());
        }
        let has_tail = sel.order_by.is_some()
            || sel.limit.is_some()
            || sel.offset.is_some()
            || sel.fetch_clause_span.is_some();
        if has_tail {
            set.order_by = sel.order_by.take();
            set.limit = sel.limit.take();
            set.offset = sel.offset.take();
            set.limit_keyword_span = sel.limit_keyword_span.take();
            set.fetch_clause_span = sel.fetch_clause_span.take();
            set.offset_keyword_span = sel.offset_keyword_span.take();
            set.limit_offset_comma_span = sel.limit_offset_comma_span.take();
        }
    }
    Ok(())
}
