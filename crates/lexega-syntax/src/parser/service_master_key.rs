// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `ALTER SERVICE MASTER KEY` statement:
//! `ALTER SERVICE MASTER KEY { [FORCE] REGENERATE | WITH { OLD_ACCOUNT = '…'
//! OLD_PASSWORD = '…' | NEW_ACCOUNT = '…' NEW_PASSWORD = '…' } }`.
//!
//! The Service Master Key (SMK) is the root of the SQL Server encryption
//! hierarchy. `REGENERATE` re-keys it (and re-encrypts everything below);
//! `FORCE REGENERATE` does so even when some material can no longer be
//! decrypted — discarding it irreversibly. The `WITH … _ACCOUNT / _PASSWORD`
//! form rotates the Windows service-account credentials that protect the SMK.
//!
//! Recognition captures the operation, whether it is forced, and whether an
//! inline password is present. The account-name operands
//! carry no governance signal and are scanned past; the password value is
//! recorded as a redaction span.
//!
//! `SERVICE` / `MASTER` / `REGENERATE` / `FORCE` / `OLD_PASSWORD` /
//! `NEW_PASSWORD` are Identifiers in our lexer.

use crate::ast::types::{AstMssqlAlterServiceMasterKey, AstStmt, ServiceMasterKeyOperation};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::principal::peek_string_literal_after;

impl<'a> Parser<'a> {
    /// `ALTER SERVICE MASTER KEY …` — dispatched on `ALTER SERVICE` + next ==
    /// `MASTER`.
    pub(crate) fn try_parse_alter_service_master_key(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_service_master_key")?;
        let start_span = self.current_span();
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        let mut end = alter_tok.span.end;

        // Scan from SERVICE to the depth-0 terminator. The `SERVICE MASTER KEY`
        // prefix, the account names, and other operands are scanned uniformly;
        // we capture only the governance-bearing primitives.
        let mut regenerate = false;
        let mut force = false;
        let mut account_change = false;
        let mut password_spans = Vec::new();
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
            if lx.eq_ignore_ascii_case("REGENERATE") {
                regenerate = true;
            } else if lx.eq_ignore_ascii_case("FORCE") {
                force = true;
            } else if lx.eq_ignore_ascii_case("OLD_ACCOUNT")
                || lx.eq_ignore_ascii_case("NEW_ACCOUNT")
            {
                account_change = true;
            } else if lx.eq_ignore_ascii_case("OLD_PASSWORD")
                || lx.eq_ignore_ascii_case("NEW_PASSWORD")
            {
                account_change = true;
                if let Some(sp) = peek_string_literal_after(self.tokens, self.idx, self.source) {
                    password_spans.push(sp);
                }
            }
            end = tok.span.end;
            self.idx += 1;
        }

        let password_present = !password_spans.is_empty();
        for sp in password_spans {
            self.redaction_spans.push(sp);
        }

        // REGENERATE (forced or not) is the rotation form; otherwise the
        // `WITH … _ACCOUNT/_PASSWORD` credential-rotation form.
        let operation = if regenerate {
            ServiceMasterKeyOperation::Regenerate
        } else if account_change {
            ServiceMasterKeyOperation::AccountChange
        } else {
            ServiceMasterKeyOperation::Regenerate
        };

        let stmt_span = Span { start, end };
        let ast = AstMssqlAlterServiceMasterKey {
            node_id: self.id_gen.next(),
            span: stmt_span,
            operation,
            force,
            password_present,
        };
        Ok(AstStmt::MssqlAlterServiceMasterKey(Box::new(ast)))
    }
}
