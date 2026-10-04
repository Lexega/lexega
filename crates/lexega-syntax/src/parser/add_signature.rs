// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL module-signing statement:
//! `ADD [COUNTER] SIGNATURE TO <module> BY { CERTIFICATE name | ASYMMETRIC KEY
//! name } [WITH PASSWORD = '…' | WITH SIGNATURE = 0x…]`.
//!
//! Adding a signature to a module (proc / function / trigger / assembly) is the
//! privilege-delegation mechanism: the signed module then executes with the
//! permissions granted to a login/user derived from the signing certificate or
//! asymmetric key, regardless of who calls it. The governance-bearing
//! primitives are whether it is a counter-signature, the signer kind, and
//! whether an inline password unlocks the signer's private key. Which
//! combination is dangerous is the consumer's verdict. The signed module name and the
//! precomputed-signature operand carry no governance signal and are scanned
//! past.
//!
//! `ADD` / `SIGNATURE` / `COUNTER` / `CERTIFICATE` / `ASYMMETRIC` are
//! Identifiers in our lexer; `BY` / `TO` are Keywords.

use crate::ast::types::{AstMssqlAddSignature, AstStmt, SignerKind};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::principal::peek_string_literal_after;

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

/// Disambiguation guard: a statement-leading `ADD` identifier introduces a
/// module-signing statement when followed by `SIGNATURE` or `COUNTER`. `idx`
/// points at the `ADD` token. Keeps a stray `ADD` identifier from being
/// hijacked, without a dialect branch.
pub(crate) fn is_mssql_add_signature_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    next_sig_idx(tokens, idx + 1)
        .map(|i| {
            let l = tokens[i].lexeme(source);
            l.eq_ignore_ascii_case("SIGNATURE") || l.eq_ignore_ascii_case("COUNTER")
        })
        .unwrap_or(false)
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_add_signature_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_add_signature")?;
        let start_span = self.current_span();

        // 1. ADD (Identifier in our lexer).
        let add_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ADD".to_string()])?;
        let start = add_tok.span.start;

        // 2. Optional COUNTER, then SIGNATURE (the guard guarantees one).
        let counter = next_sig_idx(self.tokens, self.idx)
            .map(|i| {
                self.tokens[i]
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("COUNTER")
            })
            .unwrap_or(false);

        // 3. Scan the remainder to the depth-0 terminator, classifying the
        //    signer kind (CERTIFICATE / ASYMMETRIC KEY) and recording an inline
        //    `WITH PASSWORD = '…'` literal (a credential). The value is redacted.
        let mut signer_kind = SignerKind::Certificate;
        let mut signer_seen = false;
        let mut password_spans = Vec::new();
        let mut depth: u32 = 0;
        let mut end = add_tok.span.end;
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
            if !signer_seen && lx.eq_ignore_ascii_case("CERTIFICATE") {
                signer_kind = SignerKind::Certificate;
                signer_seen = true;
            } else if !signer_seen && lx.eq_ignore_ascii_case("ASYMMETRIC") {
                signer_kind = SignerKind::AsymmetricKey;
                signer_seen = true;
            } else if lx.eq_ignore_ascii_case("PASSWORD") {
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

        let stmt_span = Span { start, end };
        let ast = AstMssqlAddSignature {
            node_id: self.id_gen.next(),
            span: stmt_span,
            counter,
            signer_kind,
            password_present,
        };
        Ok(AstStmt::MssqlAddSignature(Box::new(ast)))
    }
}
