// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL CLR assembly statements:
//! `CREATE ASSEMBLY name [AUTHORIZATION owner] FROM { '<path>' | <binary> }
//! [WITH PERMISSION_SET = { SAFE | EXTERNAL_ACCESS | UNSAFE }]` and
//! `ALTER ASSEMBLY name { FROM … | ADD FILE … | WITH PERMISSION_SET = … | … }`.
//!
//! A CLR assembly registers .NET code that runs inside the SQL Server process.
//! `PERMISSION_SET = UNSAFE` grants it full trust (native calls, P/Invoke,
//! arbitrary I/O) — an arbitrary-code-execution surface; `EXTERNAL_ACCESS`
//! grants filesystem / network / registry access. The governance-bearing
//! primitives are the verb, the permission set, and whether the assembly is
//! loaded from a filesystem path. Which permission is dangerous is the
//! consumer's verdict. The `AUTHORIZATION` owner and the binary / path operands carry no
//! governance signal for this verdict and are scanned past.
//!
//! `ASSEMBLY` / `PERMISSION_SET` / `EXTERNAL_ACCESS` / `UNSAFE` are Identifiers
//! in our lexer; `FROM` is a Keyword.

use crate::ast::types::{AssemblyAction, AssemblyPermissionSet, AstMssqlAssembly, AstStmt};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Index of the next significant (non-comment) token at or after `from`.
fn next_sig_idx(tokens: &[Token], mut from: usize) -> Option<usize> {
    while from < tokens.len() {
        if matches!(
            tokens[from].kind,
            TokenKind::LineComment | TokenKind::BlockComment
        ) {
            from += 1;
            continue;
        }
        return Some(from);
    }
    None
}

impl<'a> Parser<'a> {
    /// `CREATE ASSEMBLY …` — dispatched on `create_type_lexeme == ASSEMBLY`.
    pub(crate) fn try_parse_create_mssql_assembly(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_assembly")?;
        let start_span = self.current_span();
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        self.parse_assembly_tail(AssemblyAction::Create, start)
    }

    /// `ALTER ASSEMBLY …` — dispatched on `tok == ASSEMBLY`.
    pub(crate) fn try_parse_alter_mssql_assembly(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_assembly")?;
        let start_span = self.current_span();
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.parse_assembly_tail(AssemblyAction::Alter, start)
    }

    /// Shared tail: consume `ASSEMBLY`, then scan the remainder to the depth-0
    /// terminator capturing the governance-bearing primitives — the
    /// `PERMISSION_SET`, and whether a `FROM '<path>'` loads from the filesystem.
    fn parse_assembly_tail(&mut self, action: AssemblyAction, start: u32) -> ParseResult<AstStmt> {
        // ASSEMBLY (identifier) — guaranteed by the dispatcher.
        let asm_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ASSEMBLY".to_string()])?;
        let mut end = asm_tok.span.end;

        let mut permission_set = AssemblyPermissionSet::Unset;
        let mut from_file = false;
        let mut depth: u32 = 0;
        while self.idx < self.tokens.len() {
            let tok = &self.tokens[self.idx];
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                _ => {}
            }
            let lx = tok.lexeme(self.source);
            if lx.eq_ignore_ascii_case("PERMISSION_SET") {
                // PERMISSION_SET = { SAFE | EXTERNAL_ACCESS | UNSAFE }
                if let Some(eq) = next_sig_idx(self.tokens, self.idx + 1) {
                    if matches!(self.tokens[eq].kind, TokenKind::Operator(Operator::Eq)) {
                        if let Some(v) = next_sig_idx(self.tokens, eq + 1) {
                            let vl = self.tokens[v].lexeme(self.source);
                            if vl.eq_ignore_ascii_case("UNSAFE") {
                                permission_set = AssemblyPermissionSet::Unsafe;
                            } else if vl.eq_ignore_ascii_case("EXTERNAL_ACCESS") {
                                permission_set = AssemblyPermissionSet::ExternalAccess;
                            } else if vl.eq_ignore_ascii_case("SAFE") {
                                permission_set = AssemblyPermissionSet::Safe;
                            }
                        }
                    }
                }
            } else if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::From)) {
                // FROM '<path>' — a filesystem source (vs an inline 0x binary).
                if let Some(v) = next_sig_idx(self.tokens, self.idx + 1) {
                    if matches!(
                        self.tokens[v].kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::String)
                    ) {
                        from_file = true;
                    }
                }
            }
            end = tok.span.end;
            self.idx += 1;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlAssembly {
            node_id: self.id_gen.next(),
            span: stmt_span,
            action,
            permission_set,
            from_file,
        };
        Ok(AstStmt::MssqlAssembly(Box::new(ast)))
    }
}
