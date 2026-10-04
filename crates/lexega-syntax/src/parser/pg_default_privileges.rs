// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the PostgreSQL `ALTER DEFAULT PRIVILEGES` statement:
//! `ALTER DEFAULT PRIVILEGES [ FOR { ROLE | USER } target [, …] ]
//!   [ IN SCHEMA schema [, …] ]
//!   { GRANT privs ON class TO grantee [, …] [ WITH GRANT OPTION ]
//!   | REVOKE [ GRANT OPTION FOR ] privs ON class FROM grantee [, …]
//!            [ CASCADE | RESTRICT ] }`.
//!
//! This sets the privileges automatically applied to objects *created in the
//! future* by the target role(s): a standing policy. A default grant to
//! `PUBLIC` silently makes every future table / function readable by everyone,
//! so recognition (not fragmentation) matters.
//!
//! This parser consumes the whole statement — the trailing `GRANT …` is part
//! of it, not a second statement — reusing the shared
//! `parse_privilege_list` / `parse_grantee` sub-parsers. The
//! governance-bearing primitives (action, object class, privileges, grantees,
//! role/schema scope) are typed; which combination is dangerous is the
//! consumer's verdict.
//!
//! `DEFAULT`, `FOR`, `IN`, `GRANT`, `REVOKE`, `TO`, `FROM` are keywords;
//! `PRIVILEGES`, `ROLE`, `USER`, `SCHEMA`, and the object-class plurals are
//! Identifiers in our lexer.

use crate::ast::types::{
    AstGrantee, AstPgAlterDefaultPrivileges, AstStmt, DefaultPrivilegesAction,
    PgDefaultPrivObjectClass,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::token::Keyword;
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::grant::{
    consume_cascade_mode, consume_grant_option_for, consume_with_grant_option, current_position,
    expect_keyword, parse_grantee, parse_privilege_list, peek_lexeme_eq,
};

impl<'a> Parser<'a> {
    /// `ALTER DEFAULT PRIVILEGES …` — dispatched from the `ALTER` branch on
    /// next significant token `DEFAULT`.
    pub(crate) fn try_parse_alter_default_privileges(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_default_privileges")?;
        let start_span = self.current_span();
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;

        self.parse_default_privileges_body(start)
    }

    fn parse_default_privileges_body(&mut self, start: u32) -> ParseResult<AstStmt> {
        expect_keyword(self, Keyword::Default, "DEFAULT")?;
        // PRIVILEGES (identifier) — mandatory; dispatch confirmed it.
        if peek_lexeme_eq(self, "PRIVILEGES") {
            self.advance();
        } else {
            return Err(self.unexpected_here("PRIVILEGES"));
        }

        // Optional `FOR { ROLE | USER } target [, …]`.
        let mut for_roles = Vec::new();
        if self.peek_is_keyword(Keyword::For) {
            self.advance(); // FOR
                            // ROLE / USER noise word applies to the whole target list.
            if peek_lexeme_eq(self, "ROLE") || peek_lexeme_eq(self, "USER") {
                self.advance();
            }
            self.parse_name_list_into(&mut for_roles)?;
        }

        // Optional `IN SCHEMA schema [, …]`.
        let mut in_schemas = Vec::new();
        if self.peek_is_keyword(Keyword::In) {
            self.advance(); // IN
            if peek_lexeme_eq(self, "SCHEMA") {
                self.advance();
            }
            self.parse_name_list_into(&mut in_schemas)?;
        }

        // `GRANT …` or `REVOKE [ GRANT OPTION FOR ] …`.
        let (action, grant_option_for) = if self.peek_is_keyword(Keyword::Grant) {
            self.advance();
            (DefaultPrivilegesAction::Grant, false)
        } else if self.peek_is_keyword(Keyword::Revoke) {
            self.advance();
            let gof = consume_grant_option_for(self).is_some();
            (DefaultPrivilegesAction::Revoke, gof)
        } else {
            return Err(self.unexpected_here("GRANT or REVOKE"));
        };

        let privileges = parse_privilege_list(self)?;
        expect_keyword(self, Keyword::On, "ON")?;
        let object_class = self.parse_default_priv_object_class()?;

        match action {
            DefaultPrivilegesAction::Grant => expect_keyword(self, Keyword::To, "TO")?,
            DefaultPrivilegesAction::Revoke => expect_keyword(self, Keyword::From, "FROM")?,
        };

        let mut grantees: Vec<AstGrantee> = vec![parse_grantee(self)?];
        while self.peek_is_comma() {
            self.advance(); // comma
            grantees.push(parse_grantee(self)?);
        }

        // `WITH GRANT OPTION` (GRANT) / trailing `CASCADE | RESTRICT` (REVOKE).
        let (with_grant_option, cascade_mode) = match action {
            DefaultPrivilegesAction::Grant => (consume_with_grant_option(self).is_some(), None),
            DefaultPrivilegesAction::Revoke => (false, consume_cascade_mode(self)),
        };

        let end = current_position(self);
        Ok(AstStmt::PgAlterDefaultPrivileges(Box::new(
            AstPgAlterDefaultPrivileges {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                action,
                object_class,
                privileges,
                grantees,
                for_roles,
                in_schemas,
                with_grant_option,
                grant_option_for,
                cascade_mode,
            },
        )))
    }

    /// Parse a comma-separated list of qualified names into `out`.
    fn parse_name_list_into(&mut self, out: &mut Vec<Span>) -> ParseResult<()> {
        out.push(self.parse_qualified_name_span()?);
        while self.peek_is_comma() {
            self.advance(); // comma
            out.push(self.parse_qualified_name_span()?);
        }
        Ok(())
    }

    /// Whether the next significant token is the given keyword.
    fn peek_is_keyword(&mut self, kw: Keyword) -> bool {
        matches!(self.peek_non_trivia(), Some(t) if matches!(t.kind, TokenKind::Keyword(k) if k == kw))
    }

    /// Whether the next significant token is a comma.
    fn peek_is_comma(&mut self) -> bool {
        matches!(self.peek_non_trivia(), Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
    }

    /// `{ TABLES | SEQUENCES | FUNCTIONS | ROUTINES | TYPES | SCHEMAS }`.
    fn parse_default_priv_object_class(&mut self) -> ParseResult<PgDefaultPrivObjectClass> {
        let span = self.current_span();
        let tok = self
            .advance()
            .ok_or_eof(span, vec!["object class".to_string()])?;
        let lx = tok.lexeme(self.source);
        if lx.eq_ignore_ascii_case("TABLES") {
            Ok(PgDefaultPrivObjectClass::Tables)
        } else if lx.eq_ignore_ascii_case("SEQUENCES") {
            Ok(PgDefaultPrivObjectClass::Sequences)
        } else if lx.eq_ignore_ascii_case("FUNCTIONS") {
            Ok(PgDefaultPrivObjectClass::Functions)
        } else if lx.eq_ignore_ascii_case("ROUTINES") {
            Ok(PgDefaultPrivObjectClass::Routines)
        } else if lx.eq_ignore_ascii_case("TYPES") {
            Ok(PgDefaultPrivObjectClass::Types)
        } else if lx.eq_ignore_ascii_case("SCHEMAS") {
            Ok(PgDefaultPrivObjectClass::Schemas)
        } else {
            Err(crate::error::ParseError::invalid_statement(
                tok.span,
                format!(
                    "Expected default-privileges object class \
                     (TABLES / SEQUENCES / FUNCTIONS / ROUTINES / TYPES / SCHEMAS), found '{lx}'"
                ),
            ))
        }
    }

    /// Build an "unexpected token" error at the current position.
    fn unexpected_here(&mut self, expected: &str) -> ParseError {
        let span = self.current_span();
        let found = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).to_string())
            .unwrap_or_else(|| "end of input".to_string());
        crate::error::ParseError::invalid_statement(
            span,
            format!("Expected {expected}, found '{found}'"),
        )
    }
}
