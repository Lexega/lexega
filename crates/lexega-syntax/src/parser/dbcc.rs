// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `DBCC <command> [ ( args ) ] [WITH options]` statement.
//!
//! `DBCC` (database console command) is a maintenance / admin utility, not DDL.
//! Recognition captures the single governance-bearing element — the command
//! verb (`CHECKDB`, `TRACEON`, `WRITEPAGE`, …). Which command is dangerous is
//! the consumer's verdict. Arguments and `WITH` options
//! are consumed to the depth-0 statement terminator but not surfaced.
//!
//! Token reference (mssql dialect): `DBCC` lexes to an Identifier (not a
//! Keyword), as do the command names; `WITH` is a Keyword.

use crate::ast::types::{AstMssqlDbcc, AstStmt};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `DBCC` identifier introduces a
/// T-SQL DBCC statement only when a command-name token follows. Keeps a stray
/// `DBCC` identifier (e.g. used as a column reference) from being hijacked,
/// without a dialect branch in the dispatcher.
pub(crate) fn is_mssql_dbcc_at(tokens: &[Token], idx: usize, _source: &str) -> bool {
    let mut i = idx + 1;
    while i < tokens.len() {
        let kind = &tokens[i].kind;
        if matches!(kind, TokenKind::LineComment | TokenKind::BlockComment) {
            i += 1;
            continue;
        }
        // A command verb must follow: any identifier/keyword token. A bare
        // terminator (`;` / EOF) or punctuation means this isn't a DBCC command.
        return matches!(kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_));
    }
    false
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_dbcc_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("dbcc")?;
        let start_span = self.current_span();

        // 1. DBCC keyword (Identifier in our lexer).
        let dbcc_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DBCC".to_string()])?;
        let dbcc_keyword_span = dbcc_tok.span;
        let start = dbcc_tok.span.start;

        // 2. Command name (e.g. CHECKDB / TRACEON) — the governance primitive.
        let command_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["<dbcc command>".to_string()])?;
        let command_span = command_tok.span;
        let mut end = command_span.end;

        // 3. Consume the remainder (`( args )`, `WITH <options>`) up to a
        //    depth-0 semicolon or EOF. Operands carry no governance signal.
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
        let ast = AstMssqlDbcc {
            node_id: self.id_gen.next(),
            span: stmt_span,
            dbcc_keyword_span,
            command_span,
        };
        Ok(AstStmt::MssqlDbcc(Box::new(ast)))
    }
}
