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
//! each inline password literal that unlocks the signer's private key. Which
//! combination is dangerous is the consumer's verdict. The signed module and
//! each signer are kept as object references; the precomputed-signature
//! operand is scanned past.
//!
//! `ADD` / `SIGNATURE` / `COUNTER` / `CERTIFICATE` / `ASYMMETRIC` are
//! Identifiers in our lexer; `BY` / `TO` are Keywords.

use crate::ast::types::{AstMssqlAddSignature, AstObjectRef, AstSigner, AstStmt, SignerKind};
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
        //    signer kind (CERTIFICATE / ASYMMETRIC KEY) and recording each
        //    inline `WITH PASSWORD = '…'` literal (a credential). Each content
        //    is redacted; one a placeholder overlaps is not recorded.
        let mut signer_kind = SignerKind::Certificate;
        let mut signer_seen = false;
        let mut password_literal_spans = Vec::new();
        let mut depth: u32 = 0;
        let mut end = add_tok.span.end;
        let shape = self.add_signature_shape(self.idx);
        let bound = self.clauses_bound(shape.end.unwrap_or(self.tokens.len()));
        while self.idx < self.tokens.len().min(bound) {
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
                password_literal_spans.extend(self.password_literal_after(self.idx));
            }
            end = tok.span.end;
            self.idx += 1;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlAddSignature {
            node_id: self.id_gen.next(),
            span: stmt_span,
            counter,
            signer_kind,
            password_literal_spans,
            module: shape.module,
            module_class: shape.module_class,
            signers: shape.signers,
        };
        Ok(AstStmt::MssqlAddSignature(Box::new(ast)))
    }

    /// `[COUNTER] SIGNATURE TO [class ::] module BY signer [, signer]*` at
    /// `i`, read without consuming, a signer being `{CERTIFICATE name | ASYMMETRIC KEY
    /// name} [WITH {PASSWORD | SIGNATURE} = value]`.
    ///
    /// `end` is `None` unless the whole form is written; the module and the
    /// signers are those read before it stops.
    fn add_signature_shape(&self, i: usize) -> AddSignatureShape {
        let mut shape = AddSignatureShape {
            end: None,
            module_class: None,
            module: None,
            signers: Vec::new(),
        };
        let k = self.words_end(i, &["COUNTER"]).unwrap_or(i);
        let Some(k) = self.words_end(k, &["SIGNATURE", "TO"]) else {
            return shape;
        };
        let class_qualified = self.is_word_at(k)
            && self
                .tokens
                .get(k + 1)
                .is_some_and(|t| matches!(t.kind, TokenKind::Operator(Operator::ColonColon)));
        let module = if class_qualified { k + 2 } else { k };
        if class_qualified {
            shape.module_class = Some(self.tokens[k].span);
        }
        let Some((k, module)) = self.object_ref_at(module, self.id_gen.next()) else {
            return shape;
        };
        shape.module = Some(module);
        let Some(mut at) = self.words_end(k, &["BY"]) else {
            return shape;
        };
        while let Some((kind, name_at)) = self
            .words_end(at, &["CERTIFICATE"])
            .map(|n| (SignerKind::Certificate, n))
            .or_else(|| {
                self.words_end(at, &["ASYMMETRIC", "KEY"])
                    .map(|n| (SignerKind::AsymmetricKey, n))
            })
        {
            let Some((end, name)) = self.object_ref_at(name_at, self.id_gen.next()) else {
                break;
            };
            shape.signers.push(AstSigner { kind, name });
            let end = self
                .words_end(end, &["WITH"])
                .and_then(|w| self.any_words_end(w, &[&["PASSWORD"], &["SIGNATURE"]]))
                .and_then(|v| self.eq_value_end(v))
                .unwrap_or(end);
            shape.end = Some(end);
            let more = self
                .tokens
                .get(end)
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)));
            if !more {
                break;
            }
            at = end + 1;
        }
        shape
    }
}

/// What [`Parser::add_signature_shape`] reads.
struct AddSignatureShape {
    end: Option<usize>,
    module_class: Option<Span>,
    module: Option<AstObjectRef>,
    signers: Vec<AstSigner>,
}
