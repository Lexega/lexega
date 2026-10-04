// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// This file contains the parser implementation for RETURNING clause
// (Common in PostgreSQL, also supported by some other databases)

use crate::ast::{AstReturning, AstReturningItem};
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxReturning;

impl<'a> Parser<'a> {
    /// Parse RETURNING clause: RETURNING expr [AS alias], ...
    ///
    /// Called after VALUES/SET/WHERE clauses in INSERT/UPDATE/DELETE.
    /// Parsed permissively regardless of target dialect - let the database
    /// reject unsupported syntax at execution time.
    ///
    /// Returns None if no RETURNING keyword found.
    /// Returns Some(AstReturning) with parsed expression list.
    pub(crate) fn try_parse_returning(&mut self) -> ParseResult<Option<AstReturning>> {
        // Check for RETURNING keyword
        let _returning_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Returning)) => tok,
            _ => return Ok(None),
        };

        // Consume RETURNING keyword
        let returning_tok = self
            .advance()
            .expect_invariant("RETURNING keyword after peek");
        let returning_token_id = self.last_token_id();
        let returning_span = returning_tok.span;

        // Parse expression list (at least one expression required)
        // Each item can have an optional AS alias: expr [AS alias]
        let mut items = Vec::new();

        loop {
            let expr = self.parse_expr()?;
            let expr_start = expr.span().start;
            let mut item_end = expr.span().end;

            // Check for optional alias: [AS] identifier
            let alias = self.parse_optional_alias();
            if let Some(ref a) = alias {
                item_end = a.ident.span.end;
            }

            let item = AstReturningItem {
                node_id: self.id_gen.next(),
                expr: Box::new(expr),
                alias,
                span: Span {
                    start: expr_start,
                    end: item_end,
                },
            };
            items.push(item);

            // Check for comma (more expressions) or end
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma
                    continue;
                }
            }

            // No more commas - done with expression list
            break;
        }

        // Calculate span covering RETURNING + all items
        let last_item_end = items
            .last()
            .map(|i| i.span.end)
            .unwrap_or(returning_span.end);
        let span = Span {
            start: returning_span.start,
            end: last_item_end,
        };

        // Build CST node
        let syntax_node = SyntaxReturning {
            returning_token: returning_token_id,
            span,
        };
        let syntax_id = self.syntax_arena.alloc_returning(syntax_node);

        // Build AST node
        Ok(Some(AstReturning {
            syntax_id: Some(syntax_id),
            returning_span,
            items,
            span,
            node_id: self.id_gen.next(),
        }))
    }
}
