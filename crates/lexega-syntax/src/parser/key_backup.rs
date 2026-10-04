// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL encryption key-material protection statements:
//! `BACKUP { SERVICE MASTER KEY | MASTER KEY | CERTIFICATE name | ASYMMETRIC
//! KEY name } TO FILE = '…' [ENCRYPTION BY PASSWORD = '…']` and
//! `RESTORE { SERVICE MASTER KEY | MASTER KEY } FROM FILE = '…' DECRYPTION BY
//! PASSWORD = '…' [ENCRYPTION BY PASSWORD = '…']`.
//!
//! These move root key material across the filesystem boundary — backing up the
//! service / database master key exports the root of the entire encryption
//! hierarchy, and restoring re-keys the instance from an external file. They are
//! distinct verbs from the `{CREATE|ALTER|DROP}` key *object* DDL.
//!
//! `BACKUP` / `RESTORE` are Identifiers in our lexer. Disambiguation from the
//! data-protection `BACKUP/RESTORE { DATABASE | LOG }` forms is structural (the
//! object token is `SERVICE` / `MASTER` / `CERTIFICATE` / `ASYMMETRIC`, never
//! `DATABASE` / `LOG`) — no dialect branch.
//!
//! Recognition captures the verb, the key object, and whether an inline
//! `PASSWORD` protects/unlocks the material; which combination is dangerous is
//! the consumer's verdict. The password VALUE is recorded as a redaction span at parse
//! time. The file path is not surfaced (it can embed a credential).

use crate::ast::types::{AstMssqlKeyBackup, AstStmt, BackupKeyObject, KeyBackupAction};
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

/// Disambiguation guard: a statement-leading `BACKUP`/`RESTORE` identifier
/// introduces a key-material statement when the object token is `SERVICE`,
/// `MASTER`, `CERTIFICATE`, or `ASYMMETRIC` (disjoint from the `DATABASE` / `LOG`
/// data-protection forms). `idx` points at the `BACKUP`/`RESTORE` token.
pub(crate) fn is_mssql_key_backup_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    let Some(i1) = next_sig_idx(tokens, idx + 1) else {
        return false;
    };
    let l = tokens[i1].lexeme(source);
    l.eq_ignore_ascii_case("SERVICE")
        || l.eq_ignore_ascii_case("MASTER")
        || l.eq_ignore_ascii_case("CERTIFICATE")
        || l.eq_ignore_ascii_case("ASYMMETRIC")
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_key_backup_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_key_backup")?;
        let start_span = self.current_span();

        // 1. BACKUP | RESTORE verb (Identifier in our lexer).
        let verb_tok = self.advance().ok_or_eof(
            start_span,
            vec!["BACKUP".to_string(), "RESTORE".to_string()],
        )?;
        let action = if verb_tok.lexeme(self.source).eq_ignore_ascii_case("RESTORE") {
            KeyBackupAction::Restore
        } else {
            KeyBackupAction::Backup
        };
        let start = verb_tok.span.start;

        // 2. Classify the key object from the next significant token (the guard
        //    guarantees one of these). Tokens are not consumed here — the scan
        //    below passes over the object name / `KEY` keyword uniformly.
        let key_object = match next_sig_idx(self.tokens, self.idx) {
            Some(i) => {
                let l = self.tokens[i].lexeme(self.source);
                if l.eq_ignore_ascii_case("SERVICE") {
                    BackupKeyObject::ServiceMasterKey
                } else if l.eq_ignore_ascii_case("MASTER") {
                    BackupKeyObject::MasterKey
                } else if l.eq_ignore_ascii_case("ASYMMETRIC") {
                    BackupKeyObject::AsymmetricKey
                } else {
                    BackupKeyObject::Certificate
                }
            }
            None => BackupKeyObject::Certificate,
        };

        // 3. Scan the remainder to the depth-0 terminator, recording EVERY
        //    inline `{ENCRYPTION|DECRYPTION} BY PASSWORD = '…'` literal (a
        //    credential) wherever it appears — including nested inside `WITH
        //    PRIVATE KEY (…)`, and both passwords of a `RESTORE … DECRYPTION BY
        //    PASSWORD … ENCRYPTION BY PASSWORD …`. Each value is redacted.
        let mut password_spans = Vec::new();
        let mut depth: u32 = 0;
        let mut end = verb_tok.span.end;
        while self.idx < self.tokens.len() {
            let tok = &self.tokens[self.idx];
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                _ => {}
            }
            if tok.lexeme(self.source).eq_ignore_ascii_case("PASSWORD") {
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
        let ast = AstMssqlKeyBackup {
            node_id: self.id_gen.next(),
            span: stmt_span,
            action,
            key_object,
            password_present,
        };
        Ok(AstStmt::MssqlKeyBackup(Box::new(ast)))
    }
}
