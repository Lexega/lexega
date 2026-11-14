// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL audit DDL:
//! `{ CREATE | ALTER | DROP } SERVER AUDIT [SPECIFICATION] <name> …`
//! `{ CREATE | ALTER | DROP } DATABASE AUDIT SPECIFICATION <name> …`
//!
//! The destination / action-group body (`TO FILE …`, `ADD (…)`,
//! `WHERE …`) is consumed span-only; `STATE = { ON | OFF }` is lifted
//! typed because enabling or disabling an audit is the governance event.

use crate::ast::types::{
    AstMssqlAuditAction, AstMssqlAuditDdl, AstMssqlAuditScope, AstMssqlAuditState, AstObjectRef,
    AstStmt,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Cursor sits on the verb (`CREATE` / `ALTER` / `DROP`); the
    /// dispatcher has verified `SERVER AUDIT` / `DATABASE AUDIT`
    /// follows.
    pub(crate) fn try_parse_mssql_audit_ddl_stmt(
        &mut self,
        action: AstMssqlAuditAction,
    ) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_audit_ddl")?;

        let verb_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE/ALTER/DROP".to_string()])?;
        let start = verb_tok.span.start;

        // SERVER | DATABASE
        let scope_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SERVER or DATABASE".to_string()])?;
        let scope_lex = scope_tok.lexeme(self.source);
        let server_scope = scope_lex.eq_ignore_ascii_case("SERVER");

        // AUDIT
        let audit_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AUDIT".to_string()])?;
        if !audit_tok.lexeme(self.source).eq_ignore_ascii_case("AUDIT") {
            return Err(ParseError::invalid_statement(
                audit_tok.span,
                format!("expected AUDIT, found {}", audit_tok.lexeme(self.source)),
            ));
        }
        let mut kw_end = audit_tok.span.end;

        // Optional SPECIFICATION (required for the DATABASE form).
        let mut specification = false;
        if let Some(t) = self.peek_non_trivia() {
            if t.lexeme(self.source).eq_ignore_ascii_case("SPECIFICATION") {
                kw_end = t.span.end;
                specification = true;
                self.advance();
            }
        }
        let scope = match (server_scope, specification) {
            (true, false) => AstMssqlAuditScope::ServerAudit,
            (true, true) => AstMssqlAuditScope::ServerAuditSpecification,
            (false, true) => AstMssqlAuditScope::DatabaseAuditSpecification,
            (false, false) => {
                return Err(ParseError::invalid_statement(
                    audit_tok.span,
                    "DATABASE AUDIT requires SPECIFICATION".to_string(),
                ));
            }
        };
        let keyword_span = Span { start, end: kw_end };

        // Audit / specification name, a template writing some of it included.
        let name_span = self.parse_object_name_span()?;
        let mut end = name_span.end;

        // Body: consume to semicolon/EOF; lift STATE = ON|OFF.
        let body_start = end;
        let (clauses_end, server_audit) = self.audit_clauses_end(self.idx);
        let bound = self.clauses_bound(clauses_end);
        let mut state = None;
        let mut saw_state = false;
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
            if state.is_none() {
                if saw_state && saw_eq {
                    if lex.eq_ignore_ascii_case("ON") {
                        state = Some(AstMssqlAuditState::On);
                    } else if lex.eq_ignore_ascii_case("OFF") {
                        state = Some(AstMssqlAuditState::Off);
                    }
                    saw_state = false;
                    saw_eq = false;
                } else if saw_state {
                    saw_eq = matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq));
                    if !saw_eq {
                        saw_state = false;
                    }
                } else {
                    saw_state = lex.eq_ignore_ascii_case("STATE");
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

        let ast = AstMssqlAuditDdl {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            keyword_span,
            action,
            scope,
            name_span,
            state,
            trailing_span,
            server_audit,
        };
        Ok(AstStmt::MssqlAuditDdl(Box::new(ast)))
    }

    /// The index past the clauses of an audit or audit specification
    /// statement at `i`, in any order: `TO {FILE (…) | target}`, `WITH (…)`,
    /// `WHERE predicate`, `REMOVE WHERE`, `MODIFY NAME = name`, `FOR SERVER
    /// AUDIT name` and `[,] {ADD | DROP} (…)`.
    /// Also the audit a `FOR SERVER AUDIT name` clause names.
    fn audit_clauses_end(&self, mut i: usize) -> (usize, Option<AstObjectRef>) {
        let mut server_audit = None;
        while let Some((next, audit)) = self.audit_clause_end(i).filter(|&(next, _)| next > i) {
            i = next;
            server_audit = audit.or(server_audit);
        }
        (i, server_audit)
    }

    /// The index past the clause at `i`, and the audit it names.
    fn audit_clause_end(&self, i: usize) -> Option<(usize, Option<AstObjectRef>)> {
        if let Some(k) = self.words_end(i, &["FOR", "SERVER", "AUDIT"]) {
            return self
                .object_ref_at(k, self.id_gen.next())
                .map(|(end, audit)| (end, Some(audit)));
        }
        self.audit_unnamed_clause_end(i).map(|end| (end, None))
    }

    /// The index past a clause at `i` that names no audit.
    fn audit_unnamed_clause_end(&self, i: usize) -> Option<usize> {
        if let Some(k) = self.words_end(i, &["TO"]) {
            return self
                .words_end(k, &["FILE"])
                .and_then(|f| self.parens_end(f))
                .or_else(|| self.is_word_at(k).then_some(k + 1));
        }
        if let Some(k) = self.words_end(i, &["WITH"]) {
            return self.parens_end(k);
        }
        if let Some(k) = self.words_end(i, &["REMOVE", "WHERE"]) {
            return Some(k);
        }
        if let Some(k) = self.words_end(i, &["WHERE"]) {
            return self.audit_predicate_end(k);
        }
        if let Some(k) = self.words_end(i, &["MODIFY", "NAME"]) {
            return self.eq_value_end(k);
        }
        let action = if self
            .tokens
            .get(i)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
        {
            i + 1
        } else {
            i
        };
        self.any_words_end(action, &[&["ADD"], &["DROP"]])
            .and_then(|k| self.parens_end(k))
    }

    /// The index past an audit predicate at `i`: `[NOT] factor` joined by
    /// `AND` / `OR`, a factor being `field op value` or a parenthesised
    /// predicate.
    fn audit_predicate_end(&self, i: usize) -> Option<usize> {
        let mut end = self.audit_factor_end(i)?;
        while let Some(k) = self.any_words_end(end, &[&["AND"], &["OR"]]) {
            match self.audit_factor_end(k) {
                Some(next) => end = next,
                None => break,
            }
        }
        Some(end)
    }

    fn audit_factor_end(&self, i: usize) -> Option<usize> {
        let i = self.words_end(i, &["NOT"]).unwrap_or(i);
        if let Some(end) = self.parens_end(i) {
            return Some(end);
        }
        if !self.is_word_at(i) {
            return None;
        }
        let op = i + 1;
        let value = if self.tokens.get(op).is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Operator(
                    Operator::Eq
                        | Operator::NotEq
                        | Operator::AngleNotEq
                        | Operator::Lt
                        | Operator::Le
                        | Operator::Gt
                        | Operator::Ge
                )
            )
        }) {
            op + 1
        } else {
            self.words_end(op, &["LIKE"])?
        };
        self.option_value_end(value)
    }
}
