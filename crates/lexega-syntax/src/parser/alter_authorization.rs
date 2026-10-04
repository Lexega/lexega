// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `ALTER AUTHORIZATION ON [ <class>:: ] <securable> TO
//! { <principal> | SCHEMA OWNER }` — ownership transfer of a securable.
//!
//! Reuses the MSSQL class-qualified securable shape from
//! [`crate::parser::mssql_grant`] so `OBJECT::dbo.t`, `DATABASE::db`,
//! `SCHEMA::s` and the implicit-OBJECT form all land on the same typed
//! [`crate::ast::AstGrantObject`] that GRANT and REVOKE produce.

use crate::ast::types::{AstAlterAuthorization, AstAuthorizationOwner, AstStmt};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::mssql_grant::parse_mssql_grant_object;

impl<'a> Parser<'a> {
    /// `ALTER AUTHORIZATION ON [class::]securable TO {principal | SCHEMA OWNER}`
    pub(crate) fn try_parse_alter_authorization_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_authorization")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;

        // AUTHORIZATION
        let auth_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AUTHORIZATION".to_string()])?;
        if !auth_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("AUTHORIZATION")
        {
            return Err(ParseError::invalid_statement(
                auth_tok.span,
                format!(
                    "expected AUTHORIZATION, found {}",
                    auth_tok.lexeme(self.source)
                ),
            ));
        }
        let keyword_span = Span {
            start,
            end: auth_tok.span.end,
        };

        // ON
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(ParseError::invalid_statement(
                on_tok.span,
                format!("expected ON, found {}", on_tok.lexeme(self.source)),
            ));
        }

        // [class::]securable
        let object = match parse_mssql_grant_object(self) {
            Ok(o) => o,
            Err(e) => {
                return Err(e);
            }
        };

        // TO
        let to_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
        if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
            return Err(ParseError::invalid_statement(
                to_tok.span,
                format!("expected TO, found {}", to_tok.lexeme(self.source)),
            ));
        }

        // SCHEMA OWNER | <principal>
        let owner_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["principal name".to_string()])?;
        let (new_owner, end) = if owner_tok.lexeme(self.source).eq_ignore_ascii_case("SCHEMA")
            && self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("OWNER"))
                .unwrap_or(false)
        {
            let owner_kw = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["OWNER".to_string()])?;
            (
                AstAuthorizationOwner::SchemaOwner {
                    keyword_span: Span {
                        start: owner_tok.span.start,
                        end: owner_kw.span.end,
                    },
                },
                owner_kw.span.end,
            )
        } else {
            (
                AstAuthorizationOwner::Principal {
                    name_span: owner_tok.span,
                },
                owner_tok.span.end,
            )
        };

        let ast = AstAlterAuthorization {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            keyword_span,
            object,
            new_owner,
        };
        Ok(AstStmt::AlterAuthorization(Box::new(ast)))
    }
}
