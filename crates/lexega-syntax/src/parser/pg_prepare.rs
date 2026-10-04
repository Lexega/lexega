// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for PostgreSQL prepared statement commands.
//!
//! - `PREPARE name [ ( data_type [, ...] ) ] AS statement`
//! - `EXECUTE name [ ( parameter [, ...] ) ]`
//! - `DEALLOCATE [ PREPARE ] { name | ALL }`
//!
//! Token shapes:
//! - PREPARE → Identifier (not a keyword!)
//! - EXECUTE → Keyword(Execute) (conflicts with Snowflake EXECUTE IMMEDIATE)
//! - DEALLOCATE → Identifier (not a keyword!)
//! - AS → Keyword(As)
//! - ALL → Keyword(All)
//! - Parameter types (int, text, etc.) → Identifiers
//! - $1, $2 → Literal(Position)

use crate::ast::types::{AstPgDeallocate, AstPgExecute, AstPgPrepare, AstStmt, PgDeallocateTarget};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxPgDeallocateStmt, SyntaxPgExecuteStmt, SyntaxPgPrepareStmt};

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // PREPARE name [ ( data_type [, ...] ) ] AS statement
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_pg_prepare_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_prepare")?;
        let start_span = self.current_span();

        // PREPARE keyword (Identifier in our lexer)
        let prepare_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["PREPARE".to_string()])?;
        let prepare_keyword = self.last_token_id();
        let start = prepare_tok.span.start;

        // Statement name (required) — always an identifier
        let name_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["prepared statement name".to_string()],
        )?;
        let name = name_tok.span;

        // Optional: ( data_type [, ...] )
        let mut param_types_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lparen_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                let paren_start = lparen_tok.span.start;
                // Consume balanced parens — type list can contain commas, qualified names, etc.
                let mut depth: u32 = 1;
                let mut paren_end = lparen_tok.span.end;
                while depth > 0 {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    match t.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => {
                            depth -= 1;
                            if depth == 0 {
                                paren_end = t.span.end;
                            }
                        }
                        _ => {}
                    }
                }
                param_types_span = Some(Span {
                    start: paren_start,
                    end: paren_end,
                });
            }
        }

        // Two dialect spellings:
        //   - PostgreSQL: `PREPARE name [(types)] AS <stmt>`
        //   - MySQL/MariaDB: `PREPARE name FROM <expr>` (where `<expr>`
        //     is a string literal, session variable like `@sql`, or
        //     a `CONCAT(...)` expression yielding the SQL string).
        let (as_span, body, from_expr) = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) => {
                let from_kw = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
                // Enter scripting mode so MySQL session variables (`@sql`)
                // and Snowflake bind variables (`:var`) are recognized as
                // identifiers rather than failing the expression parse.
                let expr = crate::parser::scripting::try_parse_expr_scripting(self)?;
                let placeholder = AstStmt::Null {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: expr.span().start,
                        end: expr.span().end,
                    },
                    null_span: Span {
                        start: expr.span().start,
                        end: expr.span().start,
                    },
                    null_token: None,
                    semicolon_token: None,
                };
                (from_kw.span, placeholder, Some(Box::new(expr)))
            }
            _ => {
                let as_span = self.expect_keyword(Keyword::As)?;
                let body = self.parse_statement()?;
                (as_span, body, None)
            }
        };
        let end = from_expr
            .as_ref()
            .map(|e| e.span().end)
            .unwrap_or_else(|| body.span().end);

        // Build CST node
        let syntax_id = {
            let syntax_node = SyntaxPgPrepareStmt {
                prepare_keyword,
                span: Span { start, end },
            };
            self.syntax_arena.alloc_pg_prepare_stmt(syntax_node)
        };

        let ast = AstPgPrepare {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            syntax_id: Some(syntax_id),
            name,
            param_types_span,
            as_span,
            body: Box::new(body),
            from_expr,
        };
        Ok(AstStmt::PgPrepare(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // EXECUTE name [ ( parameter [, ...] ) ]
    //
    // Dialect-gated: only called when dialect is "postgresql".
    // Snowflake's EXECUTE IMMEDIATE is handled by scripting.rs.
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_pg_execute_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_execute")?;
        let start_span = self.current_span();

        // EXECUTE keyword (Keyword::Execute in our lexer)
        let execute_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["EXECUTE".to_string()])?;
        let execute_keyword = self.last_token_id();
        let start = execute_tok.span.start;

        // Statement name (required)
        let name_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["prepared statement name".to_string()],
        )?;
        let name = name_tok.span;

        // Optional: ( parameter [, ...] )
        let mut args_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lparen_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                let paren_start = lparen_tok.span.start;
                let mut depth: u32 = 1;
                let mut paren_end = lparen_tok.span.end;
                while depth > 0 {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    match t.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => {
                            depth -= 1;
                            if depth == 0 {
                                paren_end = t.span.end;
                            }
                        }
                        _ => {}
                    }
                }
                args_span = Some(Span {
                    start: paren_start,
                    end: paren_end,
                });
            }
        }

        // Optional: MySQL `USING @v1, @v2, ...` bind-parameter tail. PG's
        // form has no USING here, so recognizing it is purely additive.
        let mut using_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let using_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["USING".to_string()])?;
                let using_start = using_tok.span.start;
                let mut using_end;
                loop {
                    let expr = self.parse_expr()?;
                    using_end = crate::parser::scripting::expr_span_end(&expr);
                    if let Some(comma) = self.peek_non_trivia() {
                        if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            self.advance(); // consume comma, continue param list
                            continue;
                        }
                    }
                    break;
                }
                using_span = Some(Span {
                    start: using_start,
                    end: using_end,
                });
            }
        }

        let end = using_span.or(args_span).map(|s| s.end).unwrap_or(name.end);

        // Build CST node
        let syntax_id = {
            let syntax_node = SyntaxPgExecuteStmt {
                execute_keyword,
                span: Span { start, end },
            };
            self.syntax_arena.alloc_pg_execute_stmt(syntax_node)
        };

        let ast = AstPgExecute {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            syntax_id: Some(syntax_id),
            name,
            args_span,
            using_span,
        };
        Ok(AstStmt::PgExecute(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DROP PREPARE name — MySQL synonym for DEALLOCATE PREPARE name.
    //
    // The DROP keyword is already consumed by the DROP dispatcher; the
    // cursor is at PREPARE. Reuses the `PgDeallocate` node so MySQL
    // prepared-statement teardown is typed correctly (not a generic DROP).
    // `drop_keyword_id` lets the formatter re-emit the original `DROP`.
    // -----------------------------------------------------------------------
    pub(crate) fn try_parse_drop_prepare_stmt(
        &mut self,
        drop_keyword_span: Span,
        drop_keyword_id: crate::cst::TokenId,
    ) -> ParseResult<AstStmt> {
        let prepare_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PREPARE".to_string()])?;
        let prepare_span = Some(prepare_tok.span);

        let name_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["prepared statement name".to_string()],
        )?;
        let target = PgDeallocateTarget::Name(name_tok.span);

        let span = Span {
            start: drop_keyword_span.start,
            end: name_tok.span.end,
        };

        let syntax_id = {
            let syntax_node = SyntaxPgDeallocateStmt {
                deallocate_keyword: drop_keyword_id,
                span,
            };
            self.syntax_arena.alloc_pg_deallocate_stmt(syntax_node)
        };

        let ast = AstPgDeallocate {
            node_id: self.id_gen.next(),
            span,
            syntax_id: Some(syntax_id),
            prepare_span,
            target,
        };

        Ok(AstStmt::PgDeallocate(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DEALLOCATE [ PREPARE ] { name | ALL }
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_pg_deallocate_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_deallocate")?;
        let start_span = self.current_span();

        // DEALLOCATE keyword (Identifier in our lexer)
        let deallocate_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DEALLOCATE".to_string()])?;
        let deallocate_keyword = self.last_token_id();
        let start = deallocate_tok.span.start;

        // Optional: PREPARE keyword
        let mut prepare_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("PREPARE") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["PREPARE".to_string()])?;
                prepare_span = Some(t.span);
            }
        }

        // Target: name | ALL (required)
        let target = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::All)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ALL".to_string()])?;
                PgDeallocateTarget::All(t.span)
            } else {
                // Must be a name
                let t = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["prepared statement name or ALL".to_string()],
                )?;
                PgDeallocateTarget::Name(t.span)
            }
        } else {
            return Err(crate::error::ParseError::unexpected_eof(
                self.current_span(),
                vec!["prepared statement name or ALL".to_string()],
            ));
        };

        let end = match target {
            PgDeallocateTarget::All(span) | PgDeallocateTarget::Name(span) => span.end,
        };

        // Build CST node
        let syntax_id = {
            let syntax_node = SyntaxPgDeallocateStmt {
                deallocate_keyword,
                span: Span { start, end },
            };
            self.syntax_arena.alloc_pg_deallocate_stmt(syntax_node)
        };

        let ast = AstPgDeallocate {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            syntax_id: Some(syntax_id),
            prepare_span,
            target,
        };
        Ok(AstStmt::PgDeallocate(Box::new(ast)))
    }
}
