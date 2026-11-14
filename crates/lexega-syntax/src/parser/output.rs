// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::ast::AstOutputClause;
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse optional OUTPUT clause used by MSSQL DML statements: `OUTPUT …
    /// [INTO target [(cols)]]`, and after an `INTO` a second `OUTPUT …`
    /// whose rows go to the client.
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
        // Whether the list read so far is `… INTO target`, which a second
        // `OUTPUT` may follow.
        let mut second_output_may_follow = false;
        while let Some(tok) = self.peek_non_trivia() {
            if paren_depth == 0 && matches!(tok.kind, TokenKind::Keyword(Keyword::Into)) {
                second_output_may_follow = true;
            } else if paren_depth == 0
                && second_output_may_follow
                && matches!(tok.kind, TokenKind::Keyword(Keyword::Output))
            {
                second_output_may_follow = false;
                let consumed = self
                    .advance()
                    .expect_invariant("OUTPUT: token available after peek_non_trivia");
                end = consumed.span.end;
                continue;
            }
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
            // What starts a statement ends the list: T-SQL `INSERT … OUTPUT
            // inserted.id EXEC p`, whose rows the procedure gives.
            if paren_depth == 0 && self.should_stop_scan_at_statement_start(tok) {
                break;
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
