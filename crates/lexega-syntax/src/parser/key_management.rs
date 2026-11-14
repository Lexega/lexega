// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL encryption-key activation statements:
//! `OPEN / CLOSE { MASTER KEY | SYMMETRIC KEY <name> | ALL SYMMETRIC KEYS }`.
//!
//! These are session-scoped key-context switches (distinct from the
//! `{CREATE|ALTER|DROP}` key *object* DDL handled by `mssql_security_object`).
//! `OPEN` / `CLOSE` lex as `Keyword`s and otherwise route to the cursor
//! statement parsers; this family is disambiguated structurally — a
//! `MASTER`/`SYMMETRIC` token followed by `KEY`, or a leading `ALL` — with no
//! dialect branch.
//!
//! Recognition captures three governance-bearing primitives: the verb
//! (open/close), the key kind, and each inline `PASSWORD = '…'` literal that
//! decrypts the key. Which combination is dangerous is the consumer's verdict.
//! Each password's content is recorded as a redaction span at parse time so it
//! is masked from every output surface; operands (certificate / asymmetric-key
//! names) carry nothing a rule reads and are scanned past.

use crate::ast::types::{AstMssqlKeyManagement, AstStmt, KeyMgmtAction, KeyMgmtKind};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
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

/// Disambiguation guard: a statement-leading `OPEN`/`CLOSE` introduces an
/// encryption-key statement (rather than a cursor op) only when it is followed
/// by `ALL`, or by `MASTER`/`SYMMETRIC` + `KEY`. `idx` points at the
/// `OPEN`/`CLOSE` token. Dialect-neutral (lexeme match, like the security-object
/// parser).
pub(crate) fn is_mssql_key_stmt_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    let i1 = match next_sig_idx(tokens, idx + 1) {
        Some(i) => i,
        None => return false,
    };
    let l1 = tokens[i1].lexeme(source);
    // `CLOSE ALL SYMMETRIC KEYS` — `ALL` never leads a cursor op.
    if l1.eq_ignore_ascii_case("ALL") {
        return true;
    }
    if l1.eq_ignore_ascii_case("MASTER") || l1.eq_ignore_ascii_case("SYMMETRIC") {
        if let Some(i2) = next_sig_idx(tokens, i1 + 1) {
            return tokens[i2].lexeme(source).eq_ignore_ascii_case("KEY");
        }
    }
    false
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_key_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_key")?;
        let start_span = self.current_span();

        // 1. OPEN | CLOSE verb (Keyword in our lexer).
        let verb_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["OPEN".to_string(), "CLOSE".to_string()])?;
        let action = if matches!(verb_tok.kind, TokenKind::Keyword(Keyword::Open)) {
            KeyMgmtAction::Open
        } else {
            KeyMgmtAction::Close
        };
        let start = verb_tok.span.start;

        // 2. Key kind — the guard guarantees the next token is ALL / MASTER /
        //    SYMMETRIC. The trailing `KEY` / name / `KEYS` carry nothing a
        //    rule reads beyond the kind and are scanned past below.
        let kind_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MASTER".to_string()])?;
        let kl = kind_tok.lexeme(self.source);
        let key_kind = if kl.eq_ignore_ascii_case("ALL") {
            KeyMgmtKind::AllSymmetric
        } else if kl.eq_ignore_ascii_case("MASTER") {
            KeyMgmtKind::Master
        } else {
            KeyMgmtKind::Symmetric
        };
        let mut end = kind_tok.span.end;

        // 3. Scan the remainder to the depth-0 terminator, recording EVERY
        //    inline `PASSWORD = '…'` literal (DECRYPTION BY PASSWORD / WITH
        //    PASSWORD). Each content is redacted; one a placeholder overlaps
        //    is no literal the author wrote and is not recorded.
        // `KEY`, `KEY name` or `SYMMETRIC KEYS`, then `DECRYPTION BY …`.
        let head_end = match key_kind {
            KeyMgmtKind::Master => self.words_end(self.idx, &["KEY"]),
            KeyMgmtKind::Symmetric => self
                .words_end(self.idx, &["KEY"])
                .and_then(|k| self.option_value_end(k)),
            KeyMgmtKind::AllSymmetric => self.words_end(self.idx, &["SYMMETRIC", "KEYS"]),
        }
        .unwrap_or(self.idx);
        let bound = self.clauses_bound(self.key_clauses_end(head_end));
        let mut password_literal_spans = Vec::new();
        let mut depth: u32 = 0;
        while self.idx < self.tokens.len() && self.idx < bound {
            let tok = &self.tokens[self.idx];
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                _ => {}
            }
            if tok.lexeme(self.source).eq_ignore_ascii_case("PASSWORD") {
                password_literal_spans.extend(self.password_literal_after(self.idx));
            }
            end = tok.span.end;
            self.idx += 1;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlKeyManagement {
            node_id: self.id_gen.next(),
            span: stmt_span,
            action,
            key_kind,
            password_literal_spans,
        };
        Ok(AstStmt::MssqlKeyManagement(Box::new(ast)))
    }
}
