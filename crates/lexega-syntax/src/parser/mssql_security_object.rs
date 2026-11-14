// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL security-object DDL:
//! `{ CREATE | ALTER | DROP } MASTER KEY …`
//! `DROP DATABASE ENCRYPTION KEY`
//! `{ CREATE | ALTER | DROP } { SYMMETRIC | ASYMMETRIC } KEY <name> …`
//! `{ CREATE | ALTER | DROP } CERTIFICATE <name> …`
//! `{ CREATE | ALTER | DROP } [DATABASE SCOPED] CREDENTIAL <name> …`
//!
//! The encryption-mechanism body is consumed span-only; the
//! `ENCRYPTION/DECRYPTION BY PASSWORD = '<lit>'` and `SECRET = '<lit>'`
//! literals are lifted typed so hard-coded secrets are visible as such.

use crate::ast::types::{
    AstMssqlAuditAction, AstMssqlSecurityObjectDdl, AstMssqlSecurityObjectKind, AstStmt,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{LiteralKind, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Cursor sits on the verb (`CREATE` / `ALTER` / `DROP`); the
    /// dispatcher has verified a security-object keyword follows.
    pub(crate) fn try_parse_mssql_security_object_stmt(
        &mut self,
        action: AstMssqlAuditAction,
    ) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_security_object")?;

        let verb_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE/ALTER/DROP".to_string()])?;
        let start = verb_tok.span.start;

        let first_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["security object".to_string()])?;
        let first_lex = first_tok.lexeme(self.source);
        let mut kw_end = first_tok.span.end;
        let mut database_scoped = false;

        let object = if first_lex.eq_ignore_ascii_case("MASTER")
            || first_lex.eq_ignore_ascii_case("SYMMETRIC")
            || first_lex.eq_ignore_ascii_case("ASYMMETRIC")
        {
            // <prefix> KEY
            let key_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["KEY".to_string()])?;
            if !key_tok.lexeme(self.source).eq_ignore_ascii_case("KEY") {
                return Err(ParseError::invalid_statement(
                    key_tok.span,
                    format!("expected KEY, found {}", key_tok.lexeme(self.source)),
                ));
            }
            kw_end = key_tok.span.end;
            if first_lex.eq_ignore_ascii_case("MASTER") {
                AstMssqlSecurityObjectKind::MasterKey
            } else if first_lex.eq_ignore_ascii_case("SYMMETRIC") {
                AstMssqlSecurityObjectKind::SymmetricKey
            } else {
                AstMssqlSecurityObjectKind::AsymmetricKey
            }
        } else if first_lex.eq_ignore_ascii_case("CERTIFICATE") {
            AstMssqlSecurityObjectKind::Certificate
        } else if first_lex.eq_ignore_ascii_case("CREDENTIAL") {
            AstMssqlSecurityObjectKind::Credential
        } else if first_lex.eq_ignore_ascii_case("DATABASE")
            && self.words_end(self.idx, &["ENCRYPTION", "KEY"]).is_some()
        {
            // DATABASE ENCRYPTION KEY — the database's transparent data
            // encryption key.
            self.advance();
            let key_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["KEY".to_string()])?;
            kw_end = key_tok.span.end;
            AstMssqlSecurityObjectKind::DatabaseEncryptionKey
        } else if first_lex.eq_ignore_ascii_case("DATABASE") {
            // DATABASE SCOPED CREDENTIAL
            let scoped_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["SCOPED".to_string()])?;
            let cred_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
            if !scoped_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SCOPED")
                || !cred_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("CREDENTIAL")
            {
                return Err(ParseError::invalid_statement(
                    scoped_tok.span,
                    "expected SCOPED CREDENTIAL after DATABASE".to_string(),
                ));
            }
            kw_end = cred_tok.span.end;
            database_scoped = true;
            AstMssqlSecurityObjectKind::Credential
        } else {
            return Err(ParseError::invalid_statement(
                first_tok.span,
                format!("expected a security-object keyword, found {first_lex}"),
            ));
        };
        let keyword_span = Span { start, end: kw_end };

        // Name — every object except MASTER KEY carries one.
        let mut end = kw_end;
        let name_span = if matches!(
            object,
            AstMssqlSecurityObjectKind::MasterKey
                | AstMssqlSecurityObjectKind::DatabaseEncryptionKey
        ) {
            None
        } else {
            let name_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["object name".to_string()])?;
            end = name_tok.span.end;
            Some(name_tok.span)
        };

        // Body: consume to semicolon/EOF; lift PASSWORD / SECRET string
        // literals (`… BY PASSWORD = '<lit>'`, `SECRET = '<lit>'`). One
        // overlapping a rendered placeholder is no literal.
        let body_start = end;
        let body_idx = self.idx;
        let bound = self.clauses_bound(self.key_clauses_end(self.idx));
        let mut password_literal = None;
        let mut secret_literal = None;
        let mut pending: Option<&str> = None;
        let mut saw_eq = false;
        let mut consumed_any = false;
        while let Some(t) = self.peek_non_trivia().filter(|_| self.idx < bound) {
            if matches!(
                t.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let lex = t.lexeme(self.source);
            match pending {
                Some(kind) if saw_eq => {
                    if matches!(t.kind, TokenKind::Literal(LiteralKind::String))
                        && !self.span_overlaps_placeholder(t.span)
                    {
                        let inner = crate::parser::principal::inner_literal_span(
                            t.span,
                            self.source,
                            self.dialect,
                        );
                        if kind == "PASSWORD" && password_literal.is_none() {
                            password_literal = Some(inner);
                        } else if kind == "SECRET" && secret_literal.is_none() {
                            secret_literal = Some(inner);
                        }
                    }
                    pending = None;
                    saw_eq = false;
                }
                Some(_) => {
                    saw_eq = matches!(t.kind, TokenKind::Operator(Operator::Eq));
                    if !saw_eq {
                        pending = None;
                    }
                }
                None => {
                    if lex.eq_ignore_ascii_case("PASSWORD") {
                        pending = Some("PASSWORD");
                        saw_eq = false;
                    } else if lex.eq_ignore_ascii_case("SECRET") {
                        pending = Some("SECRET");
                        saw_eq = false;
                    }
                }
            }
            end = t.span.end;
            consumed_any = true;
            self.advance();
        }
        // Every password and secret the body writes is masked out of output
        // surfaces.
        self.record_secret_literals(body_idx, self.idx);
        let trailing_span = consumed_any.then_some(Span {
            start: body_start,
            end,
        });

        let ast = AstMssqlSecurityObjectDdl {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            keyword_span,
            action,
            object,
            name_span,
            database_scoped,
            password_literal,
            secret_literal,
            trailing_span,
        };
        Ok(AstStmt::MssqlSecurityObjectDdl(Box::new(ast)))
    }
}

impl<'a> Parser<'a> {
    /// The index past the clauses of a T-SQL master key, symmetric or
    /// asymmetric key, certificate or credential statement at `i`, in any
    /// order: `AUTHORIZATION name`, `FROM {PROVIDER name | ASSEMBLY name |
    /// [EXECUTABLE] FILE = value | URL = value | BINARY = value}`, `TO
    /// {FILE | URL} = value`, `[FORCE] REGENERATE`, `FORCE`,
    /// `[ADD | DROP] ENCRYPTION BY mechanism [, mechanism]*`, `DECRYPTION BY
    /// mechanism`, `REMOVE {PROVIDER KEY | PRIVATE KEY | ATTESTED OPTION}`,
    /// `FOR CRYPTOGRAPHIC PROVIDER name`, `ACTIVE FOR BEGIN_DIALOG = value`
    /// and `WITH option [, option]*`.
    pub(crate) fn key_clauses_end(&self, mut i: usize) -> usize {
        while let Some(next) = self.key_clause_end(i).filter(|&next| next > i) {
            i = next;
        }
        i
    }

    fn key_clause_end(&self, i: usize) -> Option<usize> {
        if let Some(k) = self.any_words_end(
            i,
            &[
                &["AUTHORIZATION"],
                &["FROM", "PROVIDER"],
                &["FROM", "ASSEMBLY"],
                &["FOR", "CRYPTOGRAPHIC", "PROVIDER"],
            ],
        ) {
            return self.option_value_end(k);
        }
        if let Some(k) = self.any_words_end(
            i,
            &[
                &["FROM", "FILE"],
                &["FROM", "URL"],
                &["FROM", "EXECUTABLE", "FILE"],
                &["FROM", "BINARY"],
                &["TO", "FILE"],
                &["TO", "URL"],
                &["ACTIVE", "FOR", "BEGIN_DIALOG"],
            ],
        ) {
            return self.eq_value_end(k);
        }
        if let Some(k) = self.any_words_end(
            i,
            &[
                &["ENCRYPTION", "BY"],
                &["ADD", "ENCRYPTION", "BY"],
                &["DROP", "ENCRYPTION", "BY"],
                &["DECRYPTION", "BY"],
            ],
        ) {
            return self.comma_list_end(k, |j| self.key_mechanism_end(j));
        }
        if let Some(k) = self.any_words_end(
            i,
            &[
                &["FORCE", "REGENERATE"],
                &["REGENERATE"],
                &["FORCE"],
                &["REMOVE", "PROVIDER", "KEY"],
                &["REMOVE", "PRIVATE", "KEY"],
                &["REMOVE", "ATTESTED", "OPTION"],
            ],
        ) {
            return Some(k);
        }
        self.with_list_end(i, |k| {
            self.words_end(k, &["PRIVATE", "KEY"])
                .and_then(|p| self.parens_end(p))
                .or_else(|| {
                    self.words_end(k, &["ENCRYPTION", "BY"])
                        .and_then(|e| self.comma_list_end(e, |j| self.key_mechanism_end(j)))
                })
                .or_else(|| {
                    self.words_end(k, &["ACTIVE", "FOR", "BEGIN_DIALOG"])
                        .and_then(|a| self.eq_value_end(a))
                })
                .or_else(|| {
                    self.is_word_at(k)
                        .then(|| self.eq_value_end(k + 1))
                        .flatten()
                })
        })
    }

    /// The index past an encryption or decryption mechanism at `i`:
    /// `CERTIFICATE name [WITH PASSWORD = value]`, `ASYMMETRIC KEY name
    /// [WITH PASSWORD = value]`, `SYMMETRIC KEY name`, `PASSWORD = value`
    /// or `SERVICE MASTER KEY`.
    fn key_mechanism_end(&self, i: usize) -> Option<usize> {
        if let Some(k) = self.words_end(i, &["PASSWORD"]) {
            return self.eq_value_end(k);
        }
        if let Some(k) = self.words_end(i, &["SERVICE", "MASTER", "KEY"]) {
            return Some(k);
        }
        let name = self.any_words_end(
            i,
            &[
                &["CERTIFICATE"],
                &["ASYMMETRIC", "KEY"],
                &["SYMMETRIC", "KEY"],
            ],
        )?;
        let end = self.option_value_end(name)?;
        Some(
            self.words_end(end, &["WITH", "PASSWORD"])
                .and_then(|k| self.eq_value_end(k))
                .unwrap_or(end),
        )
    }

    /// Lookahead for the ALTER dispatcher: does `tok` (the token after
    /// ALTER, cursor positioned on it) start a security-object keyword
    /// sequence? (Token stream is significant-only, so idx+1 is the
    /// next meaningful token.)
    pub(crate) fn peek_mssql_security_object_at(&self, tok: &crate::lexer::Token) -> bool {
        let next = self.tokens.get(self.idx + 1).map(|t| t.lexeme(self.source));
        is_mssql_security_object_pair(
            Some(tok.lexeme(self.source)),
            next,
            self.dialect.bare_credential_is_identity_secret(),
        )
    }
}

/// Shared first/second-lexeme classifier for the CREATE / ALTER / DROP
/// dispatchers.
pub(crate) fn is_mssql_security_object_pair(
    first: Option<&str>,
    second: Option<&str>,
    bare_credential: bool,
) -> bool {
    let Some(first) = first else {
        return false;
    };
    let second_is = |w: &str| second.map(|s| s.eq_ignore_ascii_case(w)).unwrap_or(false);
    if (first.eq_ignore_ascii_case("MASTER")
        || first.eq_ignore_ascii_case("SYMMETRIC")
        || first.eq_ignore_ascii_case("ASYMMETRIC"))
        && second_is("KEY")
    {
        return true;
    }
    if first.eq_ignore_ascii_case("CERTIFICATE") {
        return true;
    }
    // Bare CREDENTIAL is contested: T-SQL identity/secret credential
    // vs Databricks storage credential — the dialect grammar decides.
    if first.eq_ignore_ascii_case("CREDENTIAL") {
        return bare_credential;
    }
    // DATABASE SCOPED CREDENTIAL
    first.eq_ignore_ascii_case("DATABASE") && second_is("SCOPED")
}
