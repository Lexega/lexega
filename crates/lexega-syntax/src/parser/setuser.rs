// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `SETUSER ['username'] [WITH { NORESET | RESET }]`
//! statement.
//!
//! `SETUSER` is the legacy, deprecated equivalent of `EXECUTE AS USER`: it
//! switches the database security context to another user (or, with no
//! argument, reverts to the original dbo context). It is a privilege-escalation
//! / audit-evasion surface. Recognition captures the single governance-bearing
//! element — the impersonated principal, when present. The trailing `WITH`
//! options carry no governance signal and are scanned past.
//!
//! `SETUSER` is an Identifier in our lexer.

use crate::ast::types::{AstMssqlSetuser, AstStmt};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::{LiteralKind, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_setuser_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_setuser")?;
        let start_span = self.current_span();

        // 1. SETUSER keyword (Identifier in our lexer).
        let setuser_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["SETUSER".to_string()])?;
        let start = setuser_tok.span.start;
        let mut end = setuser_tok.span.end;

        // 2. Optional principal — a string literal `'username'`. Its absence is
        //    the revert form. A `;`/EOF terminator means no principal.
        let principal_span = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) => {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["principal".to_string()])?;
                end = t.span.end;
                Some(t.span)
            }
            _ => None,
        };

        // 3. Consume any trailing `WITH { NORESET | RESET }` to the depth-0
        //    terminator. These carry no governance signal.
        let mut depth: u32 = 0;
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                _ => {}
            }
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = t.span.end;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlSetuser {
            node_id: self.id_gen.next(),
            span: stmt_span,
            principal_span,
        };
        Ok(AstStmt::MssqlSetuser(Box::new(ast)))
    }
}
