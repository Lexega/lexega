// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL security-object DDL:
//! `{ CREATE | ALTER | DROP } MASTER KEY …`
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
        let name_span = if matches!(object, AstMssqlSecurityObjectKind::MasterKey) {
            None
        } else {
            let name_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["object name".to_string()])?;
            end = name_tok.span.end;
            Some(name_tok.span)
        };

        // Body: consume to semicolon/EOF; lift PASSWORD / SECRET string
        // literals (`… BY PASSWORD = '<lit>'`, `SECRET = '<lit>'`).
        let body_start = end;
        let mut password_literal = None;
        let mut secret_literal = None;
        let mut pending: Option<&str> = None;
        let mut saw_eq = false;
        let mut consumed_any = false;
        while let Some(t) = self.peek_non_trivia() {
            if matches!(
                t.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let lex = t.lexeme(self.source);
            match pending {
                Some(kind) if saw_eq => {
                    if matches!(t.kind, TokenKind::Literal(LiteralKind::String)) {
                        let inner = inner_string_span(t.span);
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

/// Strip the surrounding quotes from a string-literal token span.
fn inner_string_span(span: Span) -> Span {
    if span.end > span.start + 1 {
        Span {
            start: span.start + 1,
            end: span.end - 1,
        }
    } else {
        span
    }
}

impl<'a> Parser<'a> {
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
