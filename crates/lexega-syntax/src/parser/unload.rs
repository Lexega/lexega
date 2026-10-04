// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the Amazon Redshift `UNLOAD` statement.
//!
//! ```text
//! UNLOAD ('select-statement')
//!   TO 's3://bucket/prefix/'
//!   [ IAM_ROLE 'arn:aws:iam::…:role/…'
//!   | ACCESS_KEY_ID '…' SECRET_ACCESS_KEY '…' [ SESSION_TOKEN '…' ]
//!   | CREDENTIALS 'aws_access_key_id=…;aws_secret_access_key=…' ]
//!   [ <other options: FORMAT AS PARQUET, PARALLEL OFF, GZIP, ALLOWOVERWRITE, … > ]
//! ```
//!
//! Inline credentials are decomposed at parse time into typed
//! [`AstStageCredentialOption`] entries (mirroring `COPY INTO <location>`) so
//! secrets are never swallowed as an opaque span. The single-quoted
//! `CREDENTIALS '…'` blob is split on `;`/`=`
//! into per-key options whose name spans point into the literal body.

use crate::ast::{AstStageCredentialOption, AstStageCredentialOptionValue, AstStmt};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::token::LiteralKind;
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_stage::unquote_sql_string;

/// Credential-bearing `KEYWORD 'value'` option names in Redshift COPY/UNLOAD
/// authorization clauses. `CREDENTIALS` is handled separately (it carries a
/// `;`-delimited blob rather than a single value).
fn is_redshift_credential_keyword(lexeme: &str) -> bool {
    matches!(
        lexeme.to_ascii_uppercase().as_str(),
        "IAM_ROLE"
            | "ACCESS_KEY_ID"
            | "SECRET_ACCESS_KEY"
            | "SESSION_TOKEN"
            | "MASTER_SYMMETRIC_KEY"
    )
}

impl<'a> Parser<'a> {
    /// Parse a Redshift `UNLOAD ('query') TO 'location' [auth] [options]`.
    ///
    /// Dispatched on the `UNLOAD` lexeme at statement start (Redshift does not
    /// reserve `UNLOAD`, so it lexes as an identifier).
    pub(crate) fn try_parse_unload_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("unload")?;
        let start_span = self.current_span();

        // UNLOAD keyword (identifier lexeme).
        let unload_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["UNLOAD".to_string()])?;
        let start = unload_tok.span.start;

        // ('select-statement') — a parenthesized, single-quoted source query.
        let paren_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(paren_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::unexpected_token(
                paren_tok.span,
                vec!["(".to_string()],
                Parser::token_description(paren_tok, self.source),
            ));
        }
        let query_span = self.consume_balanced_parens()?;

        // TO 'location'
        let to_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
        if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
            return Err(ParseError::unexpected_token(
                to_tok.span,
                vec!["TO".to_string()],
                Parser::token_description(to_tok, self.source),
            ));
        }
        let to_start = to_tok.span.start;
        self.advance(); // TO
        let loc_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["destination location string".to_string()],
        )?;
        let location_url = if matches!(loc_tok.kind, TokenKind::Literal(LiteralKind::String)) {
            Some(unquote_sql_string(loc_tok.lexeme(self.source)))
        } else {
            None
        };
        let to_span = Span {
            start: to_start,
            end: loc_tok.span.end,
        };
        let mut end = loc_tok.span.end;

        // Authorization / option trailer (shared with Redshift COPY).
        let mut credentials: Vec<AstStageCredentialOption> = Vec::new();
        end = self.parse_redshift_credential_trailer(end, &mut credentials)?;
        Ok(AstStmt::Unload {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            query_span,
            to_span,
            location_url,
            credentials,
        })
    }

    /// Parse the authorization / option trailer common to Redshift `COPY` and
    /// `UNLOAD`: `IAM_ROLE '…'`, `ACCESS_KEY_ID '…' SECRET_ACCESS_KEY '…'`, the
    /// `CREDENTIALS '…'` blob, and any other option tokens. Inline secrets are
    /// decomposed into typed [`AstStageCredentialOption`]s; every other option
    /// token is consumed opaquely so the statement span covers it (byte-exact
    /// formatter round-trip). Stops at `;` or EOF. `end` is the running span
    /// end before the trailer; the returned value is the span end after it.
    pub(crate) fn parse_redshift_credential_trailer(
        &mut self,
        mut end: u32,
        credentials: &mut Vec<AstStageCredentialOption>,
    ) -> ParseResult<u32> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let lexeme = tok.lexeme(self.source);

            if lexeme.eq_ignore_ascii_case("CREDENTIALS") {
                let cred_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CREDENTIALS".to_string()])?;
                end = cred_tok.span.end;
                // Optional `=` between CREDENTIALS and the blob.
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance();
                    }
                }
                if let Some(blob) = self.peek_non_trivia() {
                    if matches!(blob.kind, TokenKind::Literal(LiteralKind::String)) {
                        let blob_span = blob.span;
                        self.advance();
                        end = blob_span.end;
                        self.decompose_credential_blob(blob_span, credentials);
                    }
                }
                continue;
            }

            if is_redshift_credential_keyword(lexeme) {
                let key_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["credential keyword".to_string()])?;
                let name_span = key_tok.span;
                end = key_tok.span.end;
                // Some Redshift variants accept an `=` before the value; tolerate it.
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance();
                    }
                }
                if let Some(val) = self.peek_non_trivia() {
                    if matches!(val.kind, TokenKind::Literal(LiteralKind::String)) {
                        let val_span = val.span;
                        let text = unquote_sql_string(val.lexeme(self.source));
                        self.advance();
                        end = val_span.end;
                        credentials.push(AstStageCredentialOption {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: name_span.start,
                                end: val_span.end,
                            },
                            name_span,
                            value: AstStageCredentialOptionValue::StringLiteral {
                                span: val_span,
                                text,
                            },
                        });
                    }
                }
                continue;
            }

            // Any other option token — consume opaquely so the whole statement
            // is captured in the span (byte-exact formatter round-trip).
            let other = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["COPY/UNLOAD option".to_string()])?;
            end = other.span.end;
        }
        Ok(end)
    }

    /// Decompose a single-quoted Redshift `CREDENTIALS` blob
    /// (`aws_access_key_id=…;aws_secret_access_key=…`) into typed credential
    /// options whose name/value spans point into the literal body.
    fn decompose_credential_blob(
        &mut self,
        literal_span: Span,
        out: &mut Vec<AstStageCredentialOption>,
    ) {
        let Some(raw) = self
            .source
            .get(literal_span.start as usize..literal_span.end as usize)
        else {
            return;
        };
        // Strip a single surrounding quote (Redshift credential blobs are plain
        // single-quoted strings without embedded escapes).
        let (content_start, inner) = if raw.len() >= 2
            && ((raw.starts_with('\'') && raw.ends_with('\''))
                || (raw.starts_with('"') && raw.ends_with('"')))
        {
            (literal_span.start + 1, &raw[1..raw.len() - 1])
        } else {
            (literal_span.start, raw)
        };

        let mut seg_start: usize = 0; // byte offset of the current segment within `inner`
        for segment in inner.split(';') {
            let seg_off = seg_start;
            seg_start += segment.len() + 1; // +1 for the ';' separator
            let Some(eq_idx) = segment.find('=') else {
                continue;
            };
            let key_raw = &segment[..eq_idx];
            let val_raw = &segment[eq_idx + 1..];

            let key_trimmed = key_raw.trim();
            if key_trimmed.is_empty() {
                continue;
            }
            let key_lead = key_raw.len() - key_raw.trim_start().len();
            let key_abs = content_start as usize + seg_off + key_lead;
            let name_span = Span {
                start: key_abs as u32,
                end: (key_abs + key_trimmed.len()) as u32,
            };

            let val_trimmed = val_raw.trim();
            let val_lead = val_raw.len() - val_raw.trim_start().len();
            let val_abs = content_start as usize + seg_off + eq_idx + 1 + val_lead;
            let val_span = Span {
                start: val_abs as u32,
                end: (val_abs + val_trimmed.len()) as u32,
            };

            out.push(AstStageCredentialOption {
                node_id: self.id_gen.next(),
                span: Span {
                    start: name_span.start,
                    end: val_span.end,
                },
                name_span,
                value: AstStageCredentialOptionValue::StringLiteral {
                    span: val_span,
                    text: val_trimmed.to_string(),
                },
            });
        }
    }
}
