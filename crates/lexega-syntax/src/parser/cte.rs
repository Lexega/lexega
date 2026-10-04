// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Common Table Expression (CTE) parsing.
//!
//! Handles WITH clause parsing including:
//! - Named CTEs: `WITH cte_name AS (SELECT ...)`
//! - Recursive CTEs: `WITH RECURSIVE cte_name AS (...)`
//! - Multiple CTEs: `WITH cte1 AS (...), cte2 AS (...)`
//! - Jinja-wrapped CTEs for dbt models
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/constructs/with>

use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::set_operations::try_parse_set_or_select_stmt;

/// Parse WITH clause (CTEs) with Result-based error handling.
pub(crate) fn try_parse_with_clause(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<crate::ast::AstWithClause> {
    use crate::error::{ParseError, ParseResultExt};

    // WITH keyword
    let with_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WITH".to_string()])?;
    if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
        return Err(ParseError::unexpected_token(
            with_tok.span,
            vec!["WITH".to_string()],
            Parser::token_description(with_tok, p.source),
        ));
    }
    let with_span = with_tok.span;

    // Optional RECURSIVE keyword
    let recursive_span = if let Some(tok) = p.peek() {
        if tok.lexeme(p.source).eq_ignore_ascii_case("RECURSIVE") {
            let rec_tok = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["RECURSIVE".to_string()])?;
            Some(rec_tok.span)
        } else {
            None
        }
    } else {
        None
    };

    // Parse comma-separated list of CTEs
    let mut ctes: Vec<crate::ast::CteItem> = Vec::new();

    loop {
        // Parse regular CTE: name [(col1, col2, ...)] AS (SELECT ...)
        let cte = try_parse_single_cte(p)?;
        ctes.push(crate::ast::CteItem::Cte(cte));

        // Check for comma (more CTEs) or end
        if let Some(tok) = p.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                let _ = p.advance(); // consume comma
                continue;
            }
        }
        break;
    }

    // Calculate span: from WITH keyword to end of last CTE
    let last_cte_end = ctes
        .last()
        .map(|item| item.span().end)
        .unwrap_or(with_span.end);
    let span = Span {
        start: with_span.start,
        end: last_cte_end,
    };

    Ok(crate::ast::AstWithClause {
        node_id: p.id_gen.next(),
        with_span,
        recursive_span,
        ctes,
        span,
    })
}

/// Parse a single CTE with Result-based error handling: cte_name [(col_list)] AS (SELECT ...)
pub(crate) fn try_parse_single_cte(
    p: &mut Parser<'_>,
) -> crate::error::ParseResult<crate::ast::AstCte> {
    use crate::error::{ParseError, ParseErrorKind};

    // Skip any Jinja comments before CTE name: {# comment #}
    while let Some(tok) = p.peek() {
        if matches!(tok.kind, TokenKind::JinjaComment) {
            p.advance();
        } else {
            break;
        }
    }

    // CTE name (identifier)
    let name_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "WITH clause requires CTE name".to_string(),
            },
        )
    })?;
    // Use parser helper `can_be_identifier_token` to allow all keywords that
    // Snowflake permits as identifiers
    // This includes contextual keywords like GROUPING, FINAL, FIRST, LAST, etc.
    let name = if p.can_be_identifier_token(name_tok) {
        crate::ast::AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
        }
    } else {
        return Err(ParseError::unexpected_token(
            name_tok.span,
            vec!["CTE name (identifier)".to_string()],
            Parser::token_description(name_tok, p.source),
        ));
    };

    // Optional column list: (col1, col2, ...)
    let mut column_list = Vec::new();
    if let Some(tok) = p.peek() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            let _ = p.advance(); // consume (

            // Check if this is the column list or the AS (SELECT ...) part
            let saved_idx = p.idx;
            let mut is_column_list = false;

            // Try to parse as column list
            if let Some(first_tok) = p.peek() {
                if p.can_be_identifier_token(first_tok) {
                    is_column_list = true;
                }
            }

            if is_column_list {
                // Parse column list
                loop {
                    let col_tok = p.advance().ok_or_else(|| {
                        ParseError::new(
                            p.current_span(),
                            crate::error::ParseErrorKind::InvalidSyntax {
                                message: "Expected column name in CTE column list".to_string(),
                            },
                        )
                    })?;
                    if p.can_be_identifier_token(col_tok) {
                        column_list.push(crate::ast::AstIdentifier {
                            node_id: p.id_gen.next(),
                            span: col_tok.span,
                        });
                    } else {
                        return Err(ParseError::unexpected_token(
                            col_tok.span,
                            vec!["column name".to_string()],
                            Parser::token_description(col_tok, p.source),
                        ));
                    }

                    // Check for comma or closing paren
                    if let Some(tok) = p.peek() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            let _ = p.advance(); // consume comma
                            continue;
                        } else if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            let _ = p.advance(); // consume )
                            break;
                        }
                    }
                    return Err(ParseError::new(
                        p.current_span(),
                        crate::error::ParseErrorKind::InvalidSyntax {
                            message: "Expected ',' or ')' in CTE column list".to_string(),
                        },
                    ));
                }
            } else {
                // This is the AS (SELECT ...) part, restore position
                p.idx = saved_idx;
            }
        }
    }

    // AS keyword
    let as_token_id = p.current_token_id();
    let as_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::MissingClause {
                clause: "AS".to_string(),
            },
        )
    })?;
    if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
        return Err(ParseError::unexpected_token(
            as_tok.span,
            vec!["AS".to_string()],
            Parser::token_description(as_tok, p.source),
        ));
    }

    // Opening paren for subquery
    let lparen_token_id = p.current_token_id();
    let lparen_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            crate::error::ParseErrorKind::InvalidSyntax {
                message: "CTE requires '(' before subquery".to_string(),
            },
        )
    })?;
    if !matches!(
        lparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::unexpected_token(
            lparen_tok.span,
            vec!["(".to_string()],
            Parser::token_description(lparen_tok, p.source),
        ));
    }

    // Parse the subquery inside the CTE body.
    // Standard SQL: only SELECT/set operations.
    // PostgreSQL writable CTEs: INSERT/UPDATE/DELETE with RETURNING are also allowed.
    let query = if let Some(tok) = p.peek_non_trivia() {
        match &tok.kind {
            TokenKind::Keyword(Keyword::Insert) => Box::new(
                crate::parser::sql_stmt::try_parse_insert_stmt_with_parser(p)?,
            ),
            TokenKind::Keyword(Keyword::Update) => Box::new(
                crate::parser::sql_stmt::try_parse_update_stmt_with_parser(p)?,
            ),
            TokenKind::Keyword(Keyword::Delete) => Box::new(
                crate::parser::sql_stmt::try_parse_delete_stmt_with_parser(p)?,
            ),
            _ => {
                // SELECT or set operation (UNION/INTERSECT/EXCEPT) — the normal path
                Box::new(try_parse_set_or_select_stmt(p)?)
            }
        }
    } else {
        Box::new(try_parse_set_or_select_stmt(p)?)
    };

    // Expect closing paren
    let rparen_token_id = p.current_token_id();
    let rparen_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            Span {
                start: lparen_tok.span.end,
                end: lparen_tok.span.end,
            },
            ParseErrorKind::UnexpectedEof {
                expected: vec![")".to_string()],
            },
        )
    })?;
    if !matches!(
        rparen_tok.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
    ) {
        return Err(ParseError::unexpected_token(
            rparen_tok.span,
            vec![")".to_string()],
            Parser::token_description(rparen_tok, p.source),
        ));
    }

    let span = Span {
        start: name.span.start,
        end: rparen_tok.span.end,
    };

    // Allocate syntax node
    let syntax_id = p.syntax_arena.alloc_cte(crate::syntax::SyntaxCte {
        as_keyword: as_token_id,
        l_paren: lparen_token_id,
        r_paren: rparen_token_id,
        span,
    });

    Ok(crate::ast::AstCte {
        node_id: p.id_gen.next(),
        name,
        column_list,
        syntax_id,
        query,
        span,
    })
}
