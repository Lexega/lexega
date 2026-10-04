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
    AstMssqlAuditAction, AstMssqlAuditDdl, AstMssqlAuditScope, AstMssqlAuditState, AstStmt,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{Punctuation, Span, TokenKind};
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

        // Audit / specification name.
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["audit name".to_string()])?;
        let name_span = name_tok.span;
        let mut end = name_span.end;

        // Body: consume to semicolon/EOF; lift STATE = ON|OFF.
        let body_start = end;
        let mut state = None;
        let mut saw_state = false;
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
        };
        Ok(AstStmt::MssqlAuditDdl(Box::new(ast)))
    }
}
