// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// This file contains the parser implementation for RETURNING clause
// (Common in PostgreSQL, also supported by some other databases)

use crate::ast::{
    AstIdentifier, AstIdentifierKind, AstReturning, AstReturningAliases, AstReturningItem,
};
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
        let with_aliases = self.parse_returning_aliases();

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
            with_aliases,
            items,
            span,
            node_id: self.id_gen.next(),
        }))
    }

    /// `WITH ( { OLD | NEW } AS name [, …] )` after `RETURNING`: the names
    /// the list reads the row's versions under. `None`, consuming nothing,
    /// where that is not written.
    fn parse_returning_aliases(&mut self) -> Option<AstReturningAliases> {
        let from = self.idx;
        let read = self.read_returning_aliases();
        if read.is_none() {
            self.idx = from;
        }
        read
    }

    fn read_returning_aliases(&mut self) -> Option<AstReturningAliases> {
        let with = self
            .peek()
            .filter(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))?;
        self.advance();
        self.peek()
            .filter(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)))?;
        self.advance();
        let (mut old, mut new) = (None, None);
        loop {
            let is_old = self.is_word(self.peek(), "OLD");
            if !is_old && !self.is_word(self.peek(), "NEW") {
                return None;
            }
            self.advance();
            self.peek()
                .filter(|t| matches!(t.kind, TokenKind::Keyword(Keyword::As)))?;
            self.advance();
            let name = self
                .peek()
                .filter(|t| matches!(t.kind, TokenKind::Identifier { .. }))?;
            self.advance();
            let ident = AstIdentifier {
                node_id: self.id_gen.next(),
                span: name.span,
                kind: AstIdentifierKind::of(&name.kind),
                templated: None,
            };
            match is_old {
                true => old = Some(ident),
                false => new = Some(ident),
            }
            let next = self.advance()?;
            match next.kind {
                TokenKind::Punctuation(Punctuation::Comma) => {}
                TokenKind::Punctuation(Punctuation::RParen) => {
                    return Some(AstReturningAliases {
                        span: Span {
                            start: with.span.start,
                            end: next.span.end,
                        },
                        old,
                        new,
                    });
                }
                _ => return None,
            }
        }
    }
}
