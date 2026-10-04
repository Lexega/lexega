// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE DYNAMIC TABLE statement parsing
//!
//! Implements parsing for Snowflake CREATE DYNAMIC TABLE statements,
//! which define incrementally refreshed materialized views:
//!
//! ## Grammar (from Snowflake docs)
//!
//! ```text
//! CREATE [ OR REPLACE ] [ TRANSIENT ] DYNAMIC [ ICEBERG ] TABLE [ IF NOT EXISTS ] <name>
//!   [ ( <col_name> <col_type> [ , ... ] ) ]
//!   TARGET_LAG = { '<time>' | DOWNSTREAM }
//!   WAREHOUSE = <warehouse_name>
//!   [ INITIALIZATION_WAREHOUSE = <warehouse_name> ]
//!   [ REFRESH_MODE = { AUTO | FULL | INCREMENTAL } ]
//!   [ INITIALIZE = { ON_CREATE | ON_SCHEDULE } ]
//!   [ CLUSTER BY ( <expr> [ , ... ] ) ]
//!   [ DATA_RETENTION_TIME_IN_DAYS = <num> ]
//!   [ MAX_DATA_EXTENSION_TIME_IN_DAYS = <num> ]
//!   [ COMMENT = '<string>' ]
//!   [ COPY GRANTS ]
//!   [ ROW ACCESS POLICY <policy> ON ( <col> [ , ... ] ) ]
//!   [ AGGREGATION POLICY <policy> ]
//!   [ [ WITH ] TAG ( <tag_name> = '<value>' [ , ... ] ) ]
//!   AS <select_statement>
//! ```
//!
//! ## Token Reference
//!
//! | SQL Text | Token Kind | Notes |
//! |----------|------------|-------|
//! | DYNAMIC | Identifier | NOT a keyword - check lexeme |
//! | TARGET_LAG | Identifier | Single token with underscore |
//! | DOWNSTREAM | Identifier | Value for TARGET_LAG |
//! | WAREHOUSE | Identifier | Property name |
//! | REFRESH_MODE | Identifier | Property name |
//! | INITIALIZE | Identifier | Property name |
//! | ICEBERG | Identifier | Optional modifier |

use crate::ast::{
    AstAlterDynamicTable, AstAlterDynamicTableAction, AstAlterDynamicTableActionKind,
    AstCreateDynamicTable, AstStmt, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxAlterDynamicTableStmt;

/// Parse CREATE DYNAMIC TABLE statement.
///
/// Entry point expects parser positioned at CREATE token.
/// Returns parsed AstStmt::CreateDynamicTable on success.
pub(crate) fn try_parse_create_dynamic_table(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume CREATE keyword
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let mut span = create_span;

    // Optional OR REPLACE or OR ALTER
    let mut or_replace_span: Option<Span> = None;
    let mut or_alter_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p
                .advance()
                .expect_invariant("OR keyword consumed after match");
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE keyword consumed after match");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                } else if next.lexeme(p.source).eq_ignore_ascii_case("ALTER") {
                    let alter = p
                        .advance()
                        .expect_invariant("ALTER identifier consumed after lexeme check");
                    or_alter_span = Some(Span {
                        start: or_tok.span.start,
                        end: alter.span.end,
                    });
                    span.end = alter.span.end;
                }
            }
        }
    }

    // Optional TRANSIENT
    let mut transient_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("TRANSIENT") {
            let t = p
                .advance()
                .expect_invariant("TRANSIENT identifier consumed after lexeme check");
            transient_span = Some(t.span);
            span.end = t.span.end;
        }
    }

    // DYNAMIC keyword (identifier, not keyword)
    let dynamic_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["DYNAMIC".to_string()])?;
    if !dynamic_tok.lexeme(p.source).eq_ignore_ascii_case("DYNAMIC") {
        return Err(ParseError::new(
            dynamic_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected DYNAMIC keyword, found '{}'",
                    dynamic_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let dynamic = p
        .advance()
        .expect_invariant("DYNAMIC identifier consumed after lexeme check");
    let dynamic_span = dynamic.span;
    span.end = dynamic_span.end;

    // Optional ICEBERG
    let mut iceberg_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("ICEBERG") {
            let t = p
                .advance()
                .expect_invariant("ICEBERG identifier consumed after lexeme check");
            iceberg_span = Some(t.span);
            span.end = t.span.end;
        }
    }

    // TABLE keyword
    let table_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["TABLE".to_string()])?;
    if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
        return Err(ParseError::new(
            table_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TABLE keyword, found '{}'",
                    table_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let table = p
        .advance()
        .expect_invariant("TABLE keyword consumed after match");
    let table_span = table.span;
    span.end = table_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match");
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    let _not = p
                        .advance()
                        .expect_invariant("NOT keyword consumed after match");
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS keyword consumed after match");
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

    // Table name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;
    span.end = name_span.end;

    // Optional column definitions ( col1 TYPE, col2 TYPE, ... )
    let mut columns_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            let lparen = p
                .advance()
                .expect_invariant("LParen consumed after match for column definitions");
            let start = lparen.span.start;
            // Find matching rparen
            let end = skip_to_matching_paren(p)?;
            columns_span = Some(Span { start, end });
            span.end = end;
        }
    }

    // Parse options until AS keyword
    let mut target_lag_span: Option<Span> = None;
    let mut warehouse_span: Option<Span> = None;
    let mut init_warehouse_span: Option<Span> = None;
    let mut refresh_mode_span: Option<Span> = None;
    let mut initialize_span: Option<Span> = None;
    let mut cluster_by_span: Option<Span> = None;
    let mut data_retention_span: Option<Span> = None;
    let mut max_data_extension_span: Option<Span> = None;
    let mut comment_span: Option<Span> = None;
    let mut copy_grants_span: Option<Span> = None;
    let mut row_access_policy_span: Option<Span> = None;
    let mut aggregation_policy_span: Option<Span> = None;
    let mut tag_span: Option<Span> = None;
    let mut require_user_span: Option<Span> = None;
    let mut immutable_where_span: Option<Span> = None;
    let mut backfill_from_span: Option<Span> = None;

    // Track options span start (for defensive parsing)
    let options_start = p.peek_non_trivia().map(|t| t.span.start);

    while let Some(tok) = p.peek_non_trivia() {
        // Stop at AS keyword (start of query)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            break;
        }

        // Stop at semicolon
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        let lexeme = &tok.lexeme(p.source);

        if lexeme.eq_ignore_ascii_case("TARGET_LAG") {
            target_lag_span = Some(parse_property_clause(p)?);
            span.end = target_lag_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("WAREHOUSE") {
            warehouse_span = Some(parse_property_clause(p)?);
            span.end = warehouse_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("INITIALIZATION_WAREHOUSE") {
            init_warehouse_span = Some(parse_property_clause(p)?);
            span.end = init_warehouse_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("REFRESH_MODE") {
            refresh_mode_span = Some(parse_property_clause(p)?);
            span.end = refresh_mode_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("INITIALIZE") {
            initialize_span = Some(parse_property_clause(p)?);
            span.end = initialize_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("CLUSTER") {
            // CLUSTER BY (...)
            cluster_by_span = Some(parse_cluster_by_clause(p)?);
            span.end = cluster_by_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("DATA_RETENTION_TIME_IN_DAYS") {
            data_retention_span = Some(parse_property_clause(p)?);
            span.end = data_retention_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("MAX_DATA_EXTENSION_TIME_IN_DAYS") {
            max_data_extension_span = Some(parse_property_clause(p)?);
            span.end = max_data_extension_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("COMMENT") {
            comment_span = Some(parse_property_clause(p)?);
            span.end = comment_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("COPY") {
            // COPY GRANTS
            copy_grants_span = Some(parse_copy_grants(p)?);
            span.end = copy_grants_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("ROW") {
            // ROW ACCESS POLICY
            row_access_policy_span = Some(parse_row_access_policy_clause(p)?);
            span.end = row_access_policy_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("AGGREGATION") {
            // AGGREGATION POLICY
            aggregation_policy_span = Some(parse_aggregation_policy_clause(p)?);
            span.end = aggregation_policy_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("WITH") || lexeme.eq_ignore_ascii_case("TAG") {
            // [WITH] TAG (...)
            tag_span = Some(parse_tag_clause(p)?);
            span.end = tag_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("REQUIRE") {
            // REQUIRE USER
            require_user_span = Some(parse_require_user(p)?);
            span.end = require_user_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("IMMUTABLE") {
            // IMMUTABLE WHERE (...)
            immutable_where_span = Some(parse_immutable_where(p)?);
            span.end = immutable_where_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("BACKFILL") {
            // BACKFILL FROM ...
            backfill_from_span = Some(parse_backfill_from(p)?);
            span.end = backfill_from_span.as_ref().unwrap().end;
        } else {
            // Unknown option - skip to next recognizable token
            // This provides defensive parsing for future Snowflake additions
            p.advance();
        }
    }

    // Build options_span if any options were parsed
    let options_span = options_start.and_then(|start| {
        let end = p
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(span.end);
        if end > start {
            Some(Span { start, end })
        } else {
            None
        }
    });

    // AS keyword and query
    let as_span: Option<Span>;
    let query: Result<Box<AstStmt>, Span>;

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_tok = p
                .advance()
                .expect_invariant("AS keyword consumed after match");
            as_span = Some(as_tok.span);
            span.end = as_tok.span.end;

            // Parse the SELECT statement
            match p.parse_statement() {
                Ok(stmt) => {
                    span.end = stmt.span().end;
                    query = Ok(Box::new(stmt));
                }
                Err(_) => {
                    // Capture unparseable query as span
                    let query_start = p.current_span().start;
                    let query_end = skip_to_statement_end(p);
                    query = Err(Span {
                        start: query_start,
                        end: query_end,
                    });
                    span.end = query_end;
                }
            }
        } else {
            // No AS keyword - error or incomplete statement
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "CREATE DYNAMIC TABLE requires AS <query>".to_string(),
                },
            ));
        }
    } else {
        return Err(ParseError::new(
            span,
            ParseErrorKind::InvalidStatement {
                message: "CREATE DYNAMIC TABLE requires AS <query>".to_string(),
            },
        ));
    }

    let node = AstCreateDynamicTable {
        node_id: p.id_gen.next(),
        span,
        create_span,
        or_replace_span,
        or_alter_span,
        transient_span,
        dynamic_span,
        iceberg_span,
        table_span,
        if_not_exists_span,
        name_span,
        columns_span,
        target_lag_span,
        warehouse_span,
        init_warehouse_span,
        refresh_mode_span,
        initialize_span,
        cluster_by_span,
        data_retention_span,
        max_data_extension_span,
        comment_span,
        copy_grants_span,
        row_access_policy_span,
        aggregation_policy_span,
        tag_span,
        require_user_span,
        immutable_where_span,
        backfill_from_span,
        as_span,
        query,
        options_span,
    };

    Ok(AstStmt::CreateDynamicTable(Box::new(node)))
}

/// Skip to matching closing paren, return end position
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
            message: "Unmatched parenthesis".to_string(),
        },
    ))
}

/// Parse KEY = VALUE clause, return span covering entire clause
fn parse_property_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let key_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;
    let start = key_tok.span.start;
    let mut end = key_tok.span.end;

    // Expect =
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            let eq = p
                .advance()
                .expect_invariant("Eq operator consumed after match in property clause");
            end = eq.span.end;

            // Value (could be string, identifier, number, or DOWNSTREAM)
            if let Some(val) = p.peek_non_trivia() {
                // Handle parenthesized values like CLUSTER BY (...)
                if matches!(val.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                } else {
                    let v = p
                        .advance()
                        .expect_invariant("property value consumed after peek in property clause");
                    end = v.span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse CLUSTER BY (...) clause
fn parse_cluster_by_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let cluster_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CLUSTER".to_string()])?;
    let start = cluster_tok.span.start;
    let mut end = cluster_tok.span.end;

    // Expect BY
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::By)) {
            let by = p
                .advance()
                .expect_invariant("BY keyword consumed after match in CLUSTER BY");
            end = by.span.end;

            // Expect (...)
            if let Some(lparen) = p.peek_non_trivia() {
                if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse COPY GRANTS clause
fn parse_copy_grants(p: &mut Parser<'_>) -> ParseResult<Span> {
    let copy_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["COPY".to_string()])?;
    let start = copy_tok.span.start;
    let mut end = copy_tok.span.end;

    // Expect GRANTS
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("GRANTS") {
            let grants = p
                .advance()
                .expect_invariant("GRANTS identifier consumed after lexeme check");
            end = grants.span.end;
        }
    }

    Ok(Span { start, end })
}

/// Parse ROW ACCESS POLICY clause
fn parse_row_access_policy_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let row_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ROW".to_string()])?;
    let start = row_tok.span.start;
    let mut end = row_tok.span.end;

    // Expect ACCESS
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("ACCESS") {
            let access = p
                .advance()
                .expect_invariant("ACCESS identifier consumed after lexeme check");
            end = access.span.end;

            // Expect POLICY
            if let Some(tok) = p.peek_non_trivia() {
                if tok.lexeme(p.source).eq_ignore_ascii_case("POLICY") {
                    let policy = p.advance().expect_invariant(
                        "POLICY identifier consumed after lexeme check in ROW ACCESS POLICY",
                    );
                    end = policy.span.end;

                    // Policy name
                    if let Some(name) = p.peek_non_trivia() {
                        if !matches!(name.kind, TokenKind::Keyword(Keyword::On)) {
                            let name_span = p.parse_qualified_name_span().expect_invariant(
                                "policy name consumed after peek in ROW ACCESS POLICY",
                            );
                            end = name_span.end;
                        }
                    }

                    // Optional ON (col, ...)
                    if let Some(tok) = p.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                            let on = p.advance().expect_invariant(
                                "ON keyword consumed after match in ROW ACCESS POLICY",
                            );
                            end = on.span.end;

                            if let Some(lparen) = p.peek_non_trivia() {
                                if matches!(
                                    lparen.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    p.advance();
                                    end = skip_to_matching_paren(p)?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse AGGREGATION POLICY clause
fn parse_aggregation_policy_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let agg_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AGGREGATION".to_string()])?;
    let start = agg_tok.span.start;
    let mut end = agg_tok.span.end;

    // Expect POLICY
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("POLICY") {
            let policy = p.advance().expect_invariant(
                "POLICY identifier consumed after lexeme check in AGGREGATION POLICY",
            );
            end = policy.span.end;

            // Policy name (identifier or qualified)
            if let Some(name) = p.peek_non_trivia() {
                if !is_dynamic_table_boundary(name.lexeme(p.source))
                    && !matches!(name.kind, TokenKind::Punctuation(Punctuation::Semi))
                    && !matches!(name.kind, TokenKind::Keyword(Keyword::As))
                {
                    let name_span = p
                        .parse_qualified_name_span()
                        .expect_invariant("policy name consumed after peek in AGGREGATION POLICY");
                    end = name_span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse [WITH] TAG (...) clause
fn parse_tag_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let first = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["TAG".to_string()])?;
    let start = first.span.start;
    let mut end = first.span.end;

    // Optional WITH
    if first.lexeme(p.source).eq_ignore_ascii_case("WITH") {
        p.advance();
        end = first.span.end;
    }

    // TAG keyword
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("TAG") {
            let tag = p
                .advance()
                .expect_invariant("TAG identifier consumed after lexeme check");
            end = tag.span.end;

            // Expect (...)
            if let Some(lparen) = p.peek_non_trivia() {
                if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse REQUIRE USER clause
fn parse_require_user(p: &mut Parser<'_>) -> ParseResult<Span> {
    let require = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["REQUIRE".to_string()])?;
    let start = require.span.start;
    let mut end = require.span.end;

    // Expect USER
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("USER") {
            let user = p
                .advance()
                .expect_invariant("USER identifier consumed after lexeme check");
            end = user.span.end;
        }
    }

    Ok(Span { start, end })
}

/// Parse IMMUTABLE WHERE (...) clause
fn parse_immutable_where(p: &mut Parser<'_>) -> ParseResult<Span> {
    let immutable = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["IMMUTABLE".to_string()])?;
    let start = immutable.span.start;
    let mut end = immutable.span.end;

    // Expect WHERE
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
            let where_tok = p
                .advance()
                .expect_invariant("WHERE keyword consumed after match in IMMUTABLE WHERE");
            end = where_tok.span.end;

            // Expect (...)
            if let Some(lparen) = p.peek_non_trivia() {
                if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse BACKFILL FROM ... clause
fn parse_backfill_from(p: &mut Parser<'_>) -> ParseResult<Span> {
    let backfill = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BACKFILL".to_string()])?;
    let start = backfill.span.start;
    let mut end = backfill.span.end;

    // Expect FROM
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
            let from = p
                .advance()
                .expect_invariant("FROM keyword consumed after match in BACKFILL FROM");
            end = from.span.end;

            // Value (could be timestamp, expression, etc.)
            // Consume until next known boundary
            while let Some(tok) = p.peek_non_trivia() {
                if is_dynamic_table_boundary(tok.lexeme(p.source)) {
                    break;
                }
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    break;
                }
                if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                    break;
                }
                let t = p
                    .advance()
                    .expect_invariant("BACKFILL value token consumed after peek");
                end = t.span.end;
            }
        }
    }

    Ok(Span { start, end })
}

/// Check if lexeme is a dynamic table option boundary
fn is_dynamic_table_boundary(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("TARGET_LAG")
        || lexeme.eq_ignore_ascii_case("WAREHOUSE")
        || lexeme.eq_ignore_ascii_case("INITIALIZATION_WAREHOUSE")
        || lexeme.eq_ignore_ascii_case("REFRESH_MODE")
        || lexeme.eq_ignore_ascii_case("INITIALIZE")
        || lexeme.eq_ignore_ascii_case("CLUSTER")
        || lexeme.eq_ignore_ascii_case("DATA_RETENTION_TIME_IN_DAYS")
        || lexeme.eq_ignore_ascii_case("MAX_DATA_EXTENSION_TIME_IN_DAYS")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("ROW")
        || lexeme.eq_ignore_ascii_case("AGGREGATION")
        || lexeme.eq_ignore_ascii_case("WITH")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("REQUIRE")
        || lexeme.eq_ignore_ascii_case("IMMUTABLE")
        || lexeme.eq_ignore_ascii_case("BACKFILL")
}

/// Skip to end of statement (semicolon or EOF)
fn skip_to_statement_end(p: &mut Parser<'_>) -> u32 {
    let mut end = p.current_span().end;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed after peek in skip_to_statement_end");
        end = t.span.end;
    }
    end
}

// ============================================================================
// ALTER DYNAMIC TABLE
// ============================================================================
//
// Implements full parsing for ALTER DYNAMIC TABLE statements.
//
// ## Grammar (from Snowflake docs)
//
// ```text
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> { SUSPEND | RESUME }
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> RENAME TO <new_name>
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> SWAP WITH <other_table>
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> REFRESH [COPY SESSION]
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> SET <properties...>
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> UNSET <properties...>
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> { clusteringAction }
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> { dataGovnPolicyTagAction }
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> { searchOptimizationAction }
// ALTER DYNAMIC TABLE [ IF EXISTS ] <name> { tableColumnCommentAction }
// ```
//
// ## Token Reference
//
// | SQL Text | Token Kind | Notes |
// |----------|------------|-------|
// | DYNAMIC | Identifier | NOT a keyword - check lexeme |
// | SUSPEND | Identifier | Action keyword |
// | RESUME | Identifier | Action keyword |
// | DOWNSTREAM | Identifier | Property value |
// | TARGET_LAG | Identifier | Property name (underscore) |
// | RECLUSTER | Identifier | Clustering action |
// | SEARCH | Identifier | Search optimization |
// | OPTIMIZATION | Identifier | Search optimization |

/// Parse ALTER DYNAMIC TABLE statement.
///
/// Entry point expects parser positioned at ALTER token.
/// Returns parsed AstStmt::AlterDynamicTable on success.
pub(crate) fn try_parse_alter_dynamic_table(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("alter_dynamic_table")?;

    // ALTER
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;
    let alter_keyword = p.last_token_id();

    // DYNAMIC (actually an Identifier)
    let dynamic_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DYNAMIC".to_string()])?;
    if !dynamic_tok.lexeme(p.source).eq_ignore_ascii_case("DYNAMIC") {
        return Err(ParseError::new(
            dynamic_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected DYNAMIC after ALTER, found '{}'",
                    dynamic_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let dynamic_span = dynamic_tok.span;
    let dynamic_token = p.last_token_id();

    // TABLE
    let table_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TABLE".to_string()])?;
    if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table))
        && !table_tok.lexeme(p.source).eq_ignore_ascii_case("TABLE")
    {
        return Err(ParseError::new(
            table_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TABLE after DYNAMIC, found '{}'",
                    table_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let table_span = table_tok.span;
    let table_keyword = p.last_token_id();

    // Optional IF EXISTS
    let (if_exists_span, if_keyword, exists_keyword) = parse_if_exists_adt(p)?;

    // Table name (qualified name) - use standard parser method
    let name_span = p.parse_qualified_name_span()?;

    // Parse action with defensive unknown handling
    let mut extras: Vec<AstUnknownClause> = Vec::new();
    let _action_start = p.current_span().start;
    let action = parse_alter_dynamic_table_action(p, &mut extras)?;
    let action_span = action.span;

    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };

    // Build CST node
    let syntax_stmt = SyntaxAlterDynamicTableStmt {
        alter_keyword,
        dynamic_token,
        table_keyword,
        if_keyword,
        exists_keyword,
        name_span,
        action_span,
        span: stmt_span,
    };
    let syntax_stmt_id = p.syntax_arena.alloc_alter_dynamic_table_stmt(syntax_stmt);

    Ok(AstStmt::AlterDynamicTable(Box::new(AstAlterDynamicTable {
        node_id: p.id_gen.next(),
        span: stmt_span,
        syntax_id: Some(syntax_stmt_id),
        alter_span,
        dynamic_span,
        table_span,
        if_exists_span,
        name_span,
        action_span,
        action,
        extras,
    })))
}

/// Parse optional IF EXISTS clause for ALTER DYNAMIC TABLE.
fn parse_if_exists_adt(
    p: &mut Parser<'_>,
) -> ParseResult<(
    Option<Span>,
    Option<crate::cst::TokenId>,
    Option<crate::cst::TokenId>,
)> {
    if let Some(tok) = p.peek_non_trivia() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("IF") {
            let if_tok = p
                .advance()
                .expect_invariant("IF consumed after lexeme check");
            let if_keyword = Some(p.last_token_id());

            if let Some(exists_tok) = p.peek_non_trivia() {
                if exists_tok.lexeme(p.source).eq_ignore_ascii_case("EXISTS") {
                    let e = p
                        .advance()
                        .expect_invariant("EXISTS consumed after lexeme check");
                    let exists_keyword = Some(p.last_token_id());
                    let if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: e.span.end,
                    });
                    return Ok((if_exists_span, if_keyword, exists_keyword));
                }
            }

            return Err(ParseError::new(
                if_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "ALTER DYNAMIC TABLE IF requires EXISTS".to_string(),
                },
            ));
        }
    }
    Ok((None, None, None))
}

/// Parse the action part of ALTER DYNAMIC TABLE.
/// Captures unknown actions in `extras` for defensive parsing.
fn parse_alter_dynamic_table_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<AstAlterDynamicTableAction> {
    let start = p.current_span().start;

    let Some(tok) = p.peek_non_trivia() else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::UnexpectedEof {
                expected: vec!["ALTER DYNAMIC TABLE action".to_string()],
            },
        ));
    };

    let lexeme = tok.lexeme(p.source);
    let kind = if lexeme.eq_ignore_ascii_case("SUSPEND") {
        parse_action_suspend_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("RESUME") {
        parse_action_resume_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("RENAME") {
        parse_action_rename_to_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("SWAP") {
        parse_action_swap_with_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("REFRESH") {
        parse_action_refresh_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("SET") {
        parse_action_set_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("UNSET") {
        parse_action_unset_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("CLUSTER") {
        parse_action_cluster_by_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("DROP") {
        parse_action_drop_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("ADD") {
        parse_action_add_adt(p)?
    } else if lexeme.eq_ignore_ascii_case("ALTER") || lexeme.eq_ignore_ascii_case("MODIFY") {
        parse_action_alter_column_adt(p)?
    } else {
        // Unknown action - consume as span and add to extras for defensive parsing
        let span = consume_until_semi_adt(p)?;
        extras.push(AstUnknownClause {
            introducer: Some(tok.span),
            span,
            kind: UnknownKind::Clause,
            node_id: p.id_gen.next(),
        });
        AstAlterDynamicTableActionKind::Unknown { span }
    };

    let end = get_action_end(&kind, start);
    Ok(AstAlterDynamicTableAction {
        node_id: p.id_gen.next(),
        span: Span { start, end },
        kind,
    })
}

/// SUSPEND
fn parse_action_suspend_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let tok = p
        .advance()
        .expect_invariant("SUSPEND consumed after lexeme check");

    // Check for SUSPEND RECLUSTER
    if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("RECLUSTER") {
            let recluster = p.advance().expect_invariant("RECLUSTER consumed");
            return Ok(AstAlterDynamicTableActionKind::SuspendRecluster {
                suspend_span: tok.span,
                recluster_span: recluster.span,
            });
        }
        // Check for SUSPEND SEARCH OPTIMIZATION
        if next.lexeme(p.source).eq_ignore_ascii_case("SEARCH") {
            return parse_search_optimization_after_keyword(p, tok.span, "suspend");
        }
    }

    Ok(AstAlterDynamicTableActionKind::Suspend {
        suspend_span: tok.span,
    })
}

/// RESUME
fn parse_action_resume_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let tok = p
        .advance()
        .expect_invariant("RESUME consumed after lexeme check");

    // Check for RESUME RECLUSTER
    if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("RECLUSTER") {
            let recluster = p.advance().expect_invariant("RECLUSTER consumed");
            return Ok(AstAlterDynamicTableActionKind::ResumeRecluster {
                resume_span: tok.span,
                recluster_span: recluster.span,
            });
        }
        // Check for RESUME SEARCH OPTIMIZATION
        if next.lexeme(p.source).eq_ignore_ascii_case("SEARCH") {
            return parse_search_optimization_after_keyword(p, tok.span, "resume");
        }
    }

    Ok(AstAlterDynamicTableActionKind::Resume {
        resume_span: tok.span,
    })
}

/// RENAME TO <new_name>
fn parse_action_rename_to_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let rename_tok = p.advance().expect_invariant("RENAME consumed");

    // TO
    let to_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TO".to_string()])?;
    if !to_tok.lexeme(p.source).eq_ignore_ascii_case("TO") {
        return Err(ParseError::new(
            to_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected TO after RENAME".to_string(),
            },
        ));
    }

    // New name
    let new_name_span = p.parse_qualified_name_span()?;

    Ok(AstAlterDynamicTableActionKind::RenameTo {
        rename_span: rename_tok.span,
        to_span: to_tok.span,
        new_name_span,
    })
}

/// SWAP WITH <other_table>
fn parse_action_swap_with_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let swap_tok = p.advance().expect_invariant("SWAP consumed");

    // WITH
    let with_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WITH".to_string()])?;
    if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With))
        && !with_tok.lexeme(p.source).eq_ignore_ascii_case("WITH")
    {
        return Err(ParseError::new(
            with_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected WITH after SWAP".to_string(),
            },
        ));
    }

    // Other table name
    let other_table_span = p.parse_qualified_name_span()?;

    Ok(AstAlterDynamicTableActionKind::SwapWith {
        swap_span: swap_tok.span,
        with_span: with_tok.span,
        other_table_span,
    })
}

/// REFRESH [COPY SESSION]
fn parse_action_refresh_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let refresh_tok = p.advance().expect_invariant("REFRESH consumed");

    // Check for COPY SESSION
    let copy_session_span = if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("COPY") {
            let copy = p.advance().expect_invariant("COPY consumed");
            if let Some(session) = p.peek_non_trivia() {
                if session.lexeme(p.source).eq_ignore_ascii_case("SESSION") {
                    let s = p.advance().expect_invariant("SESSION consumed");
                    Some(Span {
                        start: copy.span.start,
                        end: s.span.end,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstAlterDynamicTableActionKind::Refresh {
        refresh_span: refresh_tok.span,
        copy_session_span,
    })
}

/// SET <properties...>
fn parse_action_set_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let set_tok = p.advance().expect_invariant("SET consumed");

    // Peek to determine property type
    if let Some(next) = p.peek_non_trivia() {
        let lexeme = next.lexeme(p.source);

        // SET TAG
        if lexeme.eq_ignore_ascii_case("TAG") {
            let tag_tok = p.advance().expect_invariant("TAG consumed");
            let assignments_span = consume_tag_assignments_adt(p)?;
            return Ok(AstAlterDynamicTableActionKind::SetTag {
                set_span: set_tok.span,
                tag_span: tag_tok.span,
                assignments_span,
            });
        }

        // SET COMMENT
        if lexeme.eq_ignore_ascii_case("COMMENT") {
            let comment_tok = p.advance().expect_invariant("COMMENT consumed");
            // Expect =
            let _eq = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
            // Consume value
            let value_span = if let Some(_v) = p.peek_non_trivia() {
                let t = p.advance().expect_invariant("comment value consumed");
                t.span
            } else {
                comment_tok.span
            };
            return Ok(AstAlterDynamicTableActionKind::SetComment {
                set_span: set_tok.span,
                comment_span: comment_tok.span,
                value_span,
            });
        }

        // SET AGGREGATION POLICY
        if lexeme.eq_ignore_ascii_case("AGGREGATION") {
            return parse_set_aggregation_policy_adt(p, set_tok.span);
        }
    }

    // Generic SET properties
    let properties_span = consume_until_semi_adt(p)?;
    Ok(AstAlterDynamicTableActionKind::Set {
        set_span: set_tok.span,
        properties_span,
    })
}

/// SET AGGREGATION POLICY
fn parse_set_aggregation_policy_adt(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterDynamicTableActionKind> {
    let aggregation_tok = p.advance().expect_invariant("AGGREGATION consumed");

    // POLICY
    let policy_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
    if !policy_tok.lexeme(p.source).eq_ignore_ascii_case("POLICY") {
        return Err(ParseError::new(
            policy_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected POLICY after AGGREGATION".to_string(),
            },
        ));
    }

    // Policy name
    let policy_name_span = p.parse_qualified_name_span()?;

    // Optional ENTITY KEY (...)
    let entity_key_span = if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("ENTITY") {
            let start = p.current_span().start;
            p.advance(); // ENTITY
            if let Some(key) = p.peek_non_trivia() {
                if key.lexeme(p.source).eq_ignore_ascii_case("KEY") {
                    p.advance(); // KEY
                                 // Consume parenthesized list
                    if let Some(lparen) = p.peek_non_trivia() {
                        if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            let paren_span = consume_balanced_parens_adt(p)?;
                            Some(Span {
                                start,
                                end: paren_span.end,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Optional FORCE
    let force_span = if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("FORCE") {
            let t = p.advance().expect_invariant("FORCE consumed");
            Some(t.span)
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstAlterDynamicTableActionKind::SetAggregationPolicy {
        set_span,
        aggregation_span: aggregation_tok.span,
        policy_span: policy_tok.span,
        policy_name_span,
        entity_key_span,
        force_span,
    })
}

/// UNSET <properties...>
fn parse_action_unset_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let unset_tok = p.advance().expect_invariant("UNSET consumed");

    // Peek to determine property type
    if let Some(next) = p.peek_non_trivia() {
        let lexeme = next.lexeme(p.source);

        // UNSET TAG
        if lexeme.eq_ignore_ascii_case("TAG") {
            let tag_tok = p.advance().expect_invariant("TAG consumed");
            let tags_span = consume_tag_names_adt(p)?;
            return Ok(AstAlterDynamicTableActionKind::UnsetTag {
                unset_span: unset_tok.span,
                tag_span: tag_tok.span,
                tags_span,
            });
        }

        // UNSET COMMENT
        if lexeme.eq_ignore_ascii_case("COMMENT") {
            let comment_tok = p.advance().expect_invariant("COMMENT consumed");
            return Ok(AstAlterDynamicTableActionKind::UnsetComment {
                unset_span: unset_tok.span,
                comment_span: comment_tok.span,
            });
        }

        // UNSET AGGREGATION POLICY
        if lexeme.eq_ignore_ascii_case("AGGREGATION") {
            let agg_tok = p.advance().expect_invariant("AGGREGATION consumed");
            let policy_tok = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
            return Ok(AstAlterDynamicTableActionKind::UnsetAggregationPolicy {
                unset_span: unset_tok.span,
                aggregation_span: agg_tok.span,
                policy_span: policy_tok.span,
            });
        }
    }

    // Generic UNSET properties
    let properties_span = consume_until_semi_adt(p)?;
    Ok(AstAlterDynamicTableActionKind::Unset {
        unset_span: unset_tok.span,
        properties_span,
    })
}

/// CLUSTER BY (<exprs>)
fn parse_action_cluster_by_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let cluster_tok = p.advance().expect_invariant("CLUSTER consumed");

    // BY
    let by_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BY".to_string()])?;
    if !by_tok.lexeme(p.source).eq_ignore_ascii_case("BY") {
        return Err(ParseError::new(
            by_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected BY after CLUSTER".to_string(),
            },
        ));
    }

    // Parenthesized expressions
    let exprs_span = consume_balanced_parens_adt(p)?;

    Ok(AstAlterDynamicTableActionKind::ClusterBy {
        cluster_span: cluster_tok.span,
        by_span: by_tok.span,
        exprs_span,
    })
}

/// DROP ... (clustering key, row access policy, search optimization)
fn parse_action_drop_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let drop_tok = p.advance().expect_invariant("DROP consumed");

    let Some(next) = p.peek_non_trivia() else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::UnexpectedEof {
                expected: vec!["DROP action target".to_string()],
            },
        ));
    };

    let lexeme = next.lexeme(p.source);

    // DROP CLUSTERING KEY
    if lexeme.eq_ignore_ascii_case("CLUSTERING") {
        let clustering = p.advance().expect_invariant("CLUSTERING consumed");
        let key_span = if let Some(k) = p.peek_non_trivia() {
            if k.lexeme(p.source).eq_ignore_ascii_case("KEY") {
                Some(p.advance().expect_invariant("KEY consumed").span)
            } else {
                None
            }
        } else {
            None
        };
        return Ok(AstAlterDynamicTableActionKind::DropClusteringKey {
            drop_span: drop_tok.span,
            clustering_span: clustering.span,
            key_span,
        });
    }

    // DROP ROW ACCESS POLICY
    if lexeme.eq_ignore_ascii_case("ROW") {
        let row = p.advance().expect_invariant("ROW consumed");
        let access = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ACCESS".to_string()])?;
        let policy = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
        let policy_name_span = p.parse_qualified_name_span()?;
        return Ok(AstAlterDynamicTableActionKind::DropRowAccessPolicy {
            drop_span: drop_tok.span,
            row_span: row.span,
            access_span: access.span,
            policy_span: policy.span,
            policy_name_span,
        });
    }

    // DROP ALL ROW ACCESS POLICIES
    if lexeme.eq_ignore_ascii_case("ALL") {
        let all = p.advance().expect_invariant("ALL consumed");
        let row = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ROW".to_string()])?;
        let access = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ACCESS".to_string()])?;
        let policies = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["POLICIES".to_string()])?;
        return Ok(AstAlterDynamicTableActionKind::DropAllRowAccessPolicies {
            drop_span: drop_tok.span,
            all_span: all.span,
            row_span: row.span,
            access_span: access.span,
            policies_span: policies.span,
        });
    }

    // DROP SEARCH OPTIMIZATION
    if lexeme.eq_ignore_ascii_case("SEARCH") {
        return parse_search_optimization_after_keyword(p, drop_tok.span, "drop");
    }

    // Unknown DROP action
    let span = consume_until_semi_adt(p)?;
    Ok(AstAlterDynamicTableActionKind::Unknown {
        span: Span {
            start: drop_tok.span.start,
            end: span.end,
        },
    })
}

/// ADD ... (row access policy, search optimization)
fn parse_action_add_adt(p: &mut Parser<'_>) -> ParseResult<AstAlterDynamicTableActionKind> {
    let add_tok = p.advance().expect_invariant("ADD consumed");

    let Some(next) = p.peek_non_trivia() else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::UnexpectedEof {
                expected: vec!["ADD action target".to_string()],
            },
        ));
    };

    let lexeme = next.lexeme(p.source);

    // ADD ROW ACCESS POLICY
    if lexeme.eq_ignore_ascii_case("ROW") {
        let row = p.advance().expect_invariant("ROW consumed");
        let access = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ACCESS".to_string()])?;
        let policy = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
        let policy_name_span = p.parse_qualified_name_span()?;

        // ON (columns)
        let on_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ON".to_string()])?;
        let columns_span = consume_balanced_parens_adt(p)?;

        return Ok(AstAlterDynamicTableActionKind::AddRowAccessPolicy {
            add_span: add_tok.span,
            row_span: row.span,
            access_span: access.span,
            policy_span: policy.span,
            policy_name_span,
            on_span: on_tok.span,
            columns_span,
        });
    }

    // ADD SEARCH OPTIMIZATION
    if lexeme.eq_ignore_ascii_case("SEARCH") {
        return parse_search_optimization_after_keyword(p, add_tok.span, "add");
    }

    // Unknown ADD action
    let span = consume_until_semi_adt(p)?;
    Ok(AstAlterDynamicTableActionKind::Unknown {
        span: Span {
            start: add_tok.span.start,
            end: span.end,
        },
    })
}

/// ALTER | MODIFY [COLUMN] <col> ... (column operations)
fn parse_action_alter_column_adt(
    p: &mut Parser<'_>,
) -> ParseResult<AstAlterDynamicTableActionKind> {
    let alter_tok = p.advance().expect_invariant("ALTER/MODIFY consumed");
    let alter_span = alter_tok.span;

    // Optional COLUMN keyword
    let (column_keyword_span, column_name_span) = if let Some(next) = p.peek_non_trivia() {
        if next.lexeme(p.source).eq_ignore_ascii_case("COLUMN") {
            let col_kw = p.advance().expect_invariant("COLUMN consumed");
            let name = p.parse_qualified_name_span()?;
            (Some(col_kw.span), name)
        } else {
            // No COLUMN keyword, next is the column name
            let name = p.parse_qualified_name_span()?;
            (None, name)
        }
    } else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::UnexpectedEof {
                expected: vec!["column name".to_string()],
            },
        ));
    };

    // Now determine what operation on the column
    let Some(action_tok) = p.peek_non_trivia() else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::UnexpectedEof {
                expected: vec!["column action".to_string()],
            },
        ));
    };

    let action_lexeme = action_tok.lexeme(p.source);

    // SET ...
    if action_lexeme.eq_ignore_ascii_case("SET") {
        let set_tok = p.advance().expect_invariant("SET consumed");

        if let Some(what) = p.peek_non_trivia() {
            let what_lexeme = what.lexeme(p.source);

            // SET MASKING POLICY
            if what_lexeme.eq_ignore_ascii_case("MASKING") {
                let masking = p.advance().expect_invariant("MASKING consumed");
                let policy = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
                let policy_name_span = p.parse_qualified_name_span()?;

                // Optional USING (...)
                let using_span = if let Some(u) = p.peek_non_trivia() {
                    if u.lexeme(p.source).eq_ignore_ascii_case("USING") {
                        let using = p.advance().expect_invariant("USING consumed");
                        let parens = consume_balanced_parens_adt(p)?;
                        Some(Span {
                            start: using.span.start,
                            end: parens.end,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Optional FORCE
                let force_span = if let Some(f) = p.peek_non_trivia() {
                    if f.lexeme(p.source).eq_ignore_ascii_case("FORCE") {
                        Some(p.advance().expect_invariant("FORCE consumed").span)
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(AstAlterDynamicTableActionKind::SetColumnMaskingPolicy {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    set_span: set_tok.span,
                    masking_span: masking.span,
                    policy_span: policy.span,
                    policy_name_span,
                    using_span,
                    force_span,
                });
            }

            // SET PROJECTION POLICY
            if what_lexeme.eq_ignore_ascii_case("PROJECTION") {
                let projection = p.advance().expect_invariant("PROJECTION consumed");
                let policy = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
                let policy_name_span = p.parse_qualified_name_span()?;

                // Optional FORCE
                let force_span = if let Some(f) = p.peek_non_trivia() {
                    if f.lexeme(p.source).eq_ignore_ascii_case("FORCE") {
                        Some(p.advance().expect_invariant("FORCE consumed").span)
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(AstAlterDynamicTableActionKind::SetColumnProjectionPolicy {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    set_span: set_tok.span,
                    projection_span: projection.span,
                    policy_span: policy.span,
                    policy_name_span,
                    force_span,
                });
            }

            // SET TAG
            if what_lexeme.eq_ignore_ascii_case("TAG") {
                let tag = p.advance().expect_invariant("TAG consumed");
                let assignments_span = consume_tag_assignments_adt(p)?;
                return Ok(AstAlterDynamicTableActionKind::SetColumnTag {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    set_span: set_tok.span,
                    tag_span: tag.span,
                    assignments_span,
                });
            }
        }
    }

    // UNSET ...
    if action_lexeme.eq_ignore_ascii_case("UNSET") {
        let unset_tok = p.advance().expect_invariant("UNSET consumed");

        if let Some(what) = p.peek_non_trivia() {
            let what_lexeme = what.lexeme(p.source);

            // UNSET MASKING POLICY
            if what_lexeme.eq_ignore_ascii_case("MASKING") {
                let masking = p.advance().expect_invariant("MASKING consumed");
                let policy = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
                return Ok(AstAlterDynamicTableActionKind::UnsetColumnMaskingPolicy {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    unset_span: unset_tok.span,
                    masking_span: masking.span,
                    policy_span: policy.span,
                });
            }

            // UNSET PROJECTION POLICY
            if what_lexeme.eq_ignore_ascii_case("PROJECTION") {
                let projection = p.advance().expect_invariant("PROJECTION consumed");
                let policy = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["POLICY".to_string()])?;
                return Ok(
                    AstAlterDynamicTableActionKind::UnsetColumnProjectionPolicy {
                        alter_span,
                        column_keyword_span,
                        column_name_span,
                        unset_span: unset_tok.span,
                        projection_span: projection.span,
                        policy_span: policy.span,
                    },
                );
            }

            // UNSET TAG
            if what_lexeme.eq_ignore_ascii_case("TAG") {
                let tag = p.advance().expect_invariant("TAG consumed");
                let tags_span = consume_tag_names_adt(p)?;
                return Ok(AstAlterDynamicTableActionKind::UnsetColumnTag {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    unset_span: unset_tok.span,
                    tag_span: tag.span,
                    tags_span,
                });
            }

            // UNSET COMMENT
            if what_lexeme.eq_ignore_ascii_case("COMMENT") {
                let comment = p.advance().expect_invariant("COMMENT consumed");
                return Ok(AstAlterDynamicTableActionKind::UnsetColumnComment {
                    alter_span,
                    column_keyword_span,
                    column_name_span,
                    unset_span: unset_tok.span,
                    comment_span: comment.span,
                });
            }
        }
    }

    // COMMENT '<string>'
    if action_lexeme.eq_ignore_ascii_case("COMMENT") {
        let comment = p.advance().expect_invariant("COMMENT consumed");
        let value = if let Some(_v) = p.peek_non_trivia() {
            p.advance().expect_invariant("comment value consumed").span
        } else {
            comment.span
        };
        return Ok(AstAlterDynamicTableActionKind::SetColumnComment {
            alter_span,
            column_keyword_span,
            column_name_span,
            comment_span: comment.span,
            value_span: value,
        });
    }

    // Unknown column action
    let span = consume_until_semi_adt(p)?;
    Ok(AstAlterDynamicTableActionKind::Unknown {
        span: Span {
            start: alter_span.start,
            end: span.end,
        },
    })
}

/// Parse SEARCH OPTIMIZATION after a keyword (ADD, DROP, SUSPEND, RESUME)
fn parse_search_optimization_after_keyword(
    p: &mut Parser<'_>,
    keyword_span: Span,
    keyword_type: &str,
) -> ParseResult<AstAlterDynamicTableActionKind> {
    let search = p.advance().expect_invariant("SEARCH consumed");

    let optimization_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["OPTIMIZATION".to_string()])?;
    if !optimization_tok
        .lexeme(p.source)
        .eq_ignore_ascii_case("OPTIMIZATION")
    {
        return Err(ParseError::new(
            optimization_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected OPTIMIZATION after SEARCH".to_string(),
            },
        ));
    }

    // Optional ON clause
    let on_clause_span = if let Some(on) = p.peek_non_trivia() {
        if on.lexeme(p.source).eq_ignore_ascii_case("ON") {
            let on_tok = p.advance().expect_invariant("ON consumed");
            // Consume until semicolon or EOF
            let end_span = consume_until_semi_adt(p)?;
            Some(Span {
                start: on_tok.span.start,
                end: end_span.end,
            })
        } else {
            None
        }
    } else {
        None
    };

    match keyword_type {
        "add" => Ok(AstAlterDynamicTableActionKind::AddSearchOptimization {
            add_span: keyword_span,
            search_span: search.span,
            optimization_span: optimization_tok.span,
            on_clause_span,
        }),
        "drop" => Ok(AstAlterDynamicTableActionKind::DropSearchOptimization {
            drop_span: keyword_span,
            search_span: search.span,
            optimization_span: optimization_tok.span,
            on_clause_span,
        }),
        "suspend" => Ok(AstAlterDynamicTableActionKind::SuspendSearchOptimization {
            suspend_span: keyword_span,
            search_span: search.span,
            optimization_span: optimization_tok.span,
            on_clause_span,
        }),
        "resume" => Ok(AstAlterDynamicTableActionKind::ResumeSearchOptimization {
            resume_span: keyword_span,
            search_span: search.span,
            optimization_span: optimization_tok.span,
            on_clause_span,
        }),
        _ => unreachable!("Invalid keyword type"),
    }
}

/// Consume until semicolon or EOF, return span
fn consume_until_semi_adt(p: &mut Parser<'_>) -> ParseResult<Span> {
    let start = p.current_span().start;
    let mut end = start;

    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed in consume_until_semi_adt");
        end = t.span.end;
    }

    Ok(Span { start, end })
}

/// Consume balanced parentheses, return span including parens
fn consume_balanced_parens_adt(p: &mut Parser<'_>) -> ParseResult<Span> {
    let lparen = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
    if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
        return Err(ParseError::new(
            lparen.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["(".to_string()],
                found: lparen.lexeme(p.source).to_string(),
            },
        ));
    }

    let start = lparen.span.start;
    let mut depth = 1;
    let mut end = lparen.span.end;

    while depth > 0 {
        let Some(tok) = p.advance() else {
            return Err(ParseError::new(
                p.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec![")".to_string()],
                },
            ));
        };

        match tok.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
            _ => {}
        }
        end = tok.span.end;
    }

    Ok(Span { start, end })
}

/// Consume tag assignments (TAG name = 'value', ...)
fn consume_tag_assignments_adt(p: &mut Parser<'_>) -> ParseResult<Span> {
    let start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let tag_name_span = p.parse_qualified_name_span()?;
        end = tag_name_span.end;

        // =
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                let t = p.advance().expect_invariant("= consumed");
                end = t.span.end;
            }
        }

        // value
        if let Some(_tok) = p.peek_non_trivia() {
            let t = p.advance().expect_invariant("tag value consumed");
            end = t.span.end;
        }

        // Check for comma (more assignments)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance(); // comma
                continue;
            }
        }
        break;
    }

    Ok(Span { start, end })
}

/// Consume tag names (TAG name, name, ...)
fn consume_tag_names_adt(p: &mut Parser<'_>) -> ParseResult<Span> {
    let start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let tag_name_span = p.parse_qualified_name_span()?;
        end = tag_name_span.end;

        // Check for comma (more names)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance(); // comma
                continue;
            }
        }
        break;
    }

    Ok(Span { start, end })
}

/// Get end position for action kind
fn get_action_end(kind: &AstAlterDynamicTableActionKind, _fallback: u32) -> u32 {
    match kind {
        AstAlterDynamicTableActionKind::Suspend { suspend_span } => suspend_span.end,
        AstAlterDynamicTableActionKind::Resume { resume_span } => resume_span.end,
        AstAlterDynamicTableActionKind::RenameTo { new_name_span, .. } => new_name_span.end,
        AstAlterDynamicTableActionKind::SwapWith {
            other_table_span, ..
        } => other_table_span.end,
        AstAlterDynamicTableActionKind::Refresh {
            refresh_span,
            copy_session_span,
        } => copy_session_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(refresh_span.end),
        AstAlterDynamicTableActionKind::Set {
            properties_span, ..
        } => properties_span.end,
        AstAlterDynamicTableActionKind::Unset {
            properties_span, ..
        } => properties_span.end,
        AstAlterDynamicTableActionKind::SetComment { value_span, .. } => value_span.end,
        AstAlterDynamicTableActionKind::UnsetComment { comment_span, .. } => comment_span.end,
        AstAlterDynamicTableActionKind::ClusterBy { exprs_span, .. } => exprs_span.end,
        AstAlterDynamicTableActionKind::DropClusteringKey {
            key_span,
            clustering_span,
            ..
        } => key_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(clustering_span.end),
        AstAlterDynamicTableActionKind::SuspendRecluster { recluster_span, .. } => {
            recluster_span.end
        }
        AstAlterDynamicTableActionKind::ResumeRecluster { recluster_span, .. } => {
            recluster_span.end
        }
        AstAlterDynamicTableActionKind::SetColumnComment { value_span, .. } => value_span.end,
        AstAlterDynamicTableActionKind::UnsetColumnComment { comment_span, .. } => comment_span.end,
        AstAlterDynamicTableActionKind::AddRowAccessPolicy { columns_span, .. } => columns_span.end,
        AstAlterDynamicTableActionKind::DropRowAccessPolicy {
            policy_name_span, ..
        } => policy_name_span.end,
        AstAlterDynamicTableActionKind::DropAllRowAccessPolicies { policies_span, .. } => {
            policies_span.end
        }
        AstAlterDynamicTableActionKind::SetAggregationPolicy {
            force_span,
            policy_name_span,
            entity_key_span,
            ..
        } => force_span
            .as_ref()
            .or(entity_key_span.as_ref())
            .map(|s| s.end)
            .unwrap_or(policy_name_span.end),
        AstAlterDynamicTableActionKind::UnsetAggregationPolicy { policy_span, .. } => {
            policy_span.end
        }
        AstAlterDynamicTableActionKind::SetColumnMaskingPolicy {
            force_span,
            using_span,
            policy_name_span,
            ..
        } => force_span
            .as_ref()
            .or(using_span.as_ref())
            .map(|s| s.end)
            .unwrap_or(policy_name_span.end),
        AstAlterDynamicTableActionKind::UnsetColumnMaskingPolicy { policy_span, .. } => {
            policy_span.end
        }
        AstAlterDynamicTableActionKind::SetColumnProjectionPolicy {
            force_span,
            policy_name_span,
            ..
        } => force_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(policy_name_span.end),
        AstAlterDynamicTableActionKind::UnsetColumnProjectionPolicy { policy_span, .. } => {
            policy_span.end
        }
        AstAlterDynamicTableActionKind::SetTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterDynamicTableActionKind::UnsetTag { tags_span, .. } => tags_span.end,
        AstAlterDynamicTableActionKind::SetColumnTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterDynamicTableActionKind::UnsetColumnTag { tags_span, .. } => tags_span.end,
        AstAlterDynamicTableActionKind::AddSearchOptimization {
            on_clause_span,
            optimization_span,
            ..
        } => on_clause_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(optimization_span.end),
        AstAlterDynamicTableActionKind::DropSearchOptimization {
            on_clause_span,
            optimization_span,
            ..
        } => on_clause_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(optimization_span.end),
        AstAlterDynamicTableActionKind::SuspendSearchOptimization {
            on_clause_span,
            optimization_span,
            ..
        } => on_clause_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(optimization_span.end),
        AstAlterDynamicTableActionKind::ResumeSearchOptimization {
            on_clause_span,
            optimization_span,
            ..
        } => on_clause_span
            .as_ref()
            .map(|s| s.end)
            .unwrap_or(optimization_span.end),
        AstAlterDynamicTableActionKind::Unknown { span } => span.end,
    }
}
