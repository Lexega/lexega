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

use std::rc::Rc;

use crate::ast::{
    AstStageCredentialOption, AstStageCredentialOptionValue, AstStmt, AstUnloadSource,
};
use crate::dialect::Dialect;
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::token::LiteralKind;
use crate::lexer::{
    decode_string_literal, tokenize_with_dialect, DecodedString, Keyword, Operator, Punctuation,
    Span, Token, TokenKind, Trivia,
};
use crate::parser::core::Parser;

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
        let query_literal = self.unload_query_literal();
        let query_span = self.consume_balanced_parens()?;
        let source = query_literal.and_then(|literal| self.unload_query(literal));

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
        let (location_url, location_url_span) =
            if matches!(loc_tok.kind, TokenKind::Literal(LiteralKind::String)) {
                (
                    decode_string_literal(loc_tok.lexeme(self.source), self.dialect)
                        .map(|d| d.value),
                    Some(loc_tok.span),
                )
            } else {
                (None, None)
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
            source,
            to_span,
            location_url,
            location_url_span,
            credentials,
        })
    }

    /// The span of the string literal alone between the `(` at the current
    /// token and its `)`: one literal token, or a string written with
    /// Jinja in it. Reads ahead only: the position is kept.
    fn unload_query_literal(&mut self) -> Option<Span> {
        let at = self.idx;
        self.advance();
        let first = self.peek_non_trivia();
        let literal =
            if first.is_some_and(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::String))) {
                self.advance().map(|t| t.span)
            } else if first
                .is_some_and(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::StringFragment)))
            {
                self.parse_string_with_jinja().ok().map(|e| e.span())
            } else {
                None
            };
        let closed = self
            .peek_non_trivia()
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)));
        self.idx = at;
        literal.filter(|_| closed)
    }

    /// The query the string literal at `literal` holds, read as SQL in this
    /// parser's dialect from tokens placed where their text is written in
    /// the source ([`tokens_at_source`]). `None` where the text is not one
    /// statement read whole: a statement not parsed, more or fewer than
    /// one, or one read only by recovering past what it could not parse.
    /// The query is written out from the `UNLOAD`'s own span, so the syntax
    /// nodes of its read are not kept. The secrets of a text not read are
    /// recorded as unparsed text's are.
    fn unload_query(&mut self, literal: Span) -> Option<AstUnloadSource> {
        let decoded = self
            .source
            .get(literal.start as usize..literal.end as usize)
            .and_then(|raw| decode_string_literal(raw, self.dialect))
            .filter(|decoded| decoded.closed)?;
        let (tokens, as_written) = tokens_at_source(self.source, literal, &decoded, self.dialect)?;
        let mut reader = Parser::with_dialect(self.source, &tokens, self.dialect);
        reader.id_gen = Rc::clone(&self.id_gen);
        reader.placeholder_spans = self.placeholder_spans.clone();
        let query = as_written.then(|| reader.read_whole_statement()).flatten();
        if query.is_none() {
            reader.record_unparsed_secrets(0, tokens.len());
        }
        self.redaction_spans.append(&mut reader.redaction_spans);
        query.map(|query| AstUnloadSource::Subquery(Box::new(query)))
    }

    /// The one statement this parser's tokens read as, parsed whole: not
    /// opaque, with no recovery and no cut. The secrets it records stay
    /// this parser's.
    fn read_whole_statement(&mut self) -> Option<AstStmt> {
        let script = self.try_parse_script().ok()?;
        self.redaction_spans = script.redaction_spans;
        self.verify_all_tokens_consumed().ok()?;
        if !self.recovery_errors.is_empty() || !script.cut_statements.is_empty() {
            return None;
        }
        let [query] = <[AstStmt; 1]>::try_from(script.stmts).ok()?;
        (!matches!(query, AstStmt::OpaqueContent { .. } | AstStmt::Error { .. })).then_some(query)
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
                    } else {
                        // A blob a template writes into is masked whole.
                        self.redaction_spans.extend(self.secret_value_at(self.idx));
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
                // Every key and token is masked; a role ARN is no secret.
                if !lexeme.eq_ignore_ascii_case("IAM_ROLE") {
                    self.redaction_spans.extend(self.secret_value_at(self.idx));
                }
                if let Some(val) = self.peek_non_trivia() {
                    if matches!(val.kind, TokenKind::Literal(LiteralKind::String)) {
                        let val_span = val.span;
                        let written = val.lexeme(self.source);
                        let text = decode_string_literal(written, self.dialect)
                            .map_or_else(|| written.to_string(), |d| d.value);
                        self.advance();
                        end = val_span.end;
                        let value = self.credential_value(val_span, text);
                        credentials.push(AstStageCredentialOption {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: name_span.start,
                                end: val_span.end,
                            },
                            name_span,
                            value,
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
        let Some(decoded) = self
            .source
            .get(literal_span.start as usize..literal_span.end as usize)
            .and_then(|raw| crate::lexer::decode_string_literal(raw, self.dialect))
        else {
            // Not read into its keys: masked whole.
            self.redaction_spans
                .push(crate::parser::principal::inner_literal_span(
                    literal_span,
                    self.source,
                    self.dialect,
                ));
            return;
        };
        // Each character of the value with the span of the text that writes
        // it, in the source.
        let chars: Vec<(char, Span)> = decoded
            .value
            .chars()
            .zip(&decoded.sources)
            .map(|(c, at)| {
                (
                    c,
                    Span {
                        start: literal_span.start + at.start,
                        end: literal_span.start + at.end,
                    },
                )
            })
            .collect();
        // The characters of `part` without white space around them, and
        // the source span they cover.
        let trimmed = |part: &[(char, Span)]| -> Option<(String, Span)> {
            let first = part.iter().position(|(c, _)| !c.is_whitespace())?;
            let last = part.iter().rposition(|(c, _)| !c.is_whitespace())?;
            let part = &part[first..=last];
            let span = Span {
                start: part[0].1.start,
                end: part[part.len() - 1].1.end,
            };
            Some((part.iter().map(|(c, _)| c).collect(), span))
        };

        for segment in chars.split(|(c, _)| *c == ';') {
            let Some(eq_idx) = segment.iter().position(|(c, _)| *c == '=') else {
                continue;
            };
            let Some((name, name_span)) = trimmed(&segment[..eq_idx]) else {
                continue;
            };
            let value = &segment[eq_idx + 1..];
            let (text, val_span) = trimmed(value).unwrap_or_else(|| {
                // An empty value sits past the `=` and any white space.
                let at = value.last().unwrap_or(&segment[eq_idx]).1.end;
                (String::new(), Span { start: at, end: at })
            });
            // Every key and token is masked; a role ARN is no secret.
            if val_span.start < val_span.end && !name.eq_ignore_ascii_case("aws_iam_role") {
                self.redaction_spans.push(val_span);
            }

            let value = self.credential_value(val_span, text);
            out.push(AstStageCredentialOption {
                node_id: self.id_gen.next(),
                span: Span {
                    start: name_span.start,
                    end: val_span.end,
                },
                name_span,
                value,
            });
        }
    }

    /// The credential written at `span` as `text`: no literal where a
    /// rendered placeholder overlaps it, the value being injected later.
    fn credential_value(&self, span: Span, text: String) -> AstStageCredentialOptionValue {
        if self.span_overlaps_placeholder(span) {
            AstStageCredentialOptionValue::Other { span }
        } else {
            AstStageCredentialOptionValue::StringLiteral { span, text }
        }
    }
}

/// The tokens `dialect` lexes `decoded` to (the value of the string literal
/// at `literal` in `source`), each placed where its text is written in
/// `source`, its trivia over the source text that writes it.
///
/// A token's span holds exactly its text, so a reader of the source at the
/// span reads the token: it runs from its first character's last byte to
/// its last character's first byte as written, which keeps the one quote
/// next to the content of a doubled quote that opens or closes an inner
/// literal (`''NV''` is the token `'NV'`). A token whose text is written
/// nowhere as it reads (a quote or escape inside it) spans the whole text
/// that writes it, where a reader would read the escaped text: the second
/// value says whether every token holds its own text, so the tokens can be
/// read as SQL.
pub(crate) fn tokens_at_source(
    source: &str,
    literal: Span,
    decoded: &DecodedString,
    dialect: &dyn Dialect,
) -> Option<(Vec<Token>, bool)> {
    // The source text writing the character of each byte of the value.
    let mut written: Vec<Span> = Vec::with_capacity(decoded.value.len());
    for (c, at) in decoded.value.chars().zip(&decoded.sources) {
        let at = Span {
            start: literal.start + at.start,
            end: literal.start + at.end,
        };
        written.extend(std::iter::repeat_n(at, c.len_utf8()));
    }
    let content_end = literal.start + decoded.content.end;
    let point = |at: u32| {
        let at = written.get(at as usize).map_or(content_end, |w| w.start);
        Span { start: at, end: at }
    };
    let cover = |span: Span| {
        if span.start == span.end {
            return Some(point(span.start));
        }
        Some(Span {
            start: written.get(span.start as usize)?.start,
            end: written.get(span.end as usize - 1)?.end,
        })
    };
    let token_at = |span: Span| {
        let text = decoded.value.get(span.start as usize..span.end as usize)?;
        let (Some(first), Some(last)) = (text.chars().next(), text.chars().next_back()) else {
            return Some(point(span.start));
        };
        let start = written
            .get(span.start as usize)?
            .end
            .checked_sub(first.len_utf8() as u32)?;
        let end = written.get(span.end as usize - 1)?.start + last.len_utf8() as u32;
        (start <= end && source.get(start as usize..end as usize) == Some(text))
            .then_some(Span { start, end })
    };
    let trivia_at = |trivia: Vec<Trivia>| {
        trivia
            .into_iter()
            .map(|t| {
                Some(Trivia {
                    kind: t.kind,
                    span: cover(t.span)?,
                })
            })
            .collect::<Option<Vec<_>>>()
    };
    let mut as_written = true;
    let mut tokens = Vec::new();
    for token in tokenize_with_dialect(&decoded.value, dialect).tokens {
        let span = match token_at(token.span) {
            Some(span) => span,
            None => {
                as_written = false;
                cover(token.span)?
            }
        };
        tokens.push(Token {
            span,
            leading_trivia: trivia_at(token.leading_trivia)?,
            trailing_trivia: trivia_at(token.trailing_trivia)?,
            kind: token.kind,
        });
    }
    Some((tokens, as_written))
}
