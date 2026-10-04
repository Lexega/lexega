// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::ast::AstOutputClause;
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse optional OUTPUT clause used by MSSQL DML statements.
    ///
    /// The parser is permissive and span-based: it consumes OUTPUT and all tokens
    /// until one of the provided boundary keywords is found at paren depth 0,
    /// or statement terminators (; / EOF).
    pub(crate) fn try_parse_output_clause(
        &mut self,
        boundary_keywords: &[Keyword],
    ) -> ParseResult<Option<AstOutputClause>> {
        let output_tok = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Output)) => tok,
            _ => return Ok(None),
        };

        let output_start = output_tok.span.start;
        let mut end = output_tok.span.end;
        self.advance();

        let mut paren_depth: i32 = 0;
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::LParen) => {
                    paren_depth += 1;
                }
                TokenKind::Punctuation(Punctuation::RParen) => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                }
                TokenKind::Keyword(keyword)
                    if paren_depth == 0 && boundary_keywords.contains(&keyword) =>
                {
                    break;
                }
                _ => {}
            }

            let consumed = self
                .advance()
                .expect_invariant("OUTPUT: token available after peek_non_trivia");
            end = consumed.span.end;
        }

        Ok(Some(AstOutputClause {
            node_id: self.id_gen.next(),
            output_span: output_tok.span,
            span: Span {
                start: output_start,
                end,
            },
        }))
    }
}
