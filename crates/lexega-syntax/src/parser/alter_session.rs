// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake `ALTER SESSION { SET | UNSET }` (session parameters).
//!
//! - `ALTER SESSION SET <param> = <value> [, <param> = <value> ...]`
//! - `ALTER SESSION UNSET <param> [, <param> ...]`
//!
//! `ALTER SESSION POLICY …` routes to `Parser::try_parse_alter_session_policy`;
//! the ALTER dispatcher peeks past SESSION to split the two.
//!
//! Token reference:
//! - ALTER is Keyword; SESSION is Identifier; SET / UNSET are Keywords.
//! - Parameter names (incl. underscored) are single Identifiers; `=` is
//!   Operator(Eq); values lex as Literal(String|Number|Boolean).
//! - Params may be separated by commas, whitespace, or newlines.

use crate::ast::{
    AstAlterSession, AstAlterSessionAction, AstSessionSetParam, AstSessionUnsetParam,
    AstSessionValueKind, AstStmt,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::LiteralKind;
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `ALTER SESSION { SET | UNSET } …`.
    ///
    /// Consumes ALTER and the SESSION identifier itself (the dispatcher has
    /// rewound to the ALTER token before calling).
    pub(crate) fn try_parse_alter_session(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_session")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // SESSION (Identifier)
        let session_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SESSION".to_string()])?;
        if !matches!(session_tok.kind, TokenKind::Identifier { .. })
            || !session_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SESSION")
        {
            return Err(ParseError::new(
                session_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SESSION keyword".to_string(),
                },
            ));
        }
        let session_span = session_tok.span;

        // SET | UNSET
        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["SET or UNSET".to_string()])?;
        let action = match action_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self.advance().expect_invariant("SET keyword after peek");
                let params = match self.parse_session_set_params() {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(e);
                    }
                };
                AstAlterSessionAction::Set {
                    set_span: set_tok.span,
                    params,
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let unset_tok = self.advance().expect_invariant("UNSET keyword after peek");
                let params = match self.parse_session_unset_params() {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(e);
                    }
                };
                AstAlterSessionAction::Unset {
                    unset_span: unset_tok.span,
                    params,
                }
            }
            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SET or UNSET after ALTER SESSION".to_string(),
                    },
                ));
            }
        };

        let end = match &action {
            AstAlterSessionAction::Set { params, set_span } => params
                .last()
                .map(|p| p.value_span.end)
                .unwrap_or(set_span.end),
            AstAlterSessionAction::Unset { params, unset_span } => params
                .last()
                .map(|p| p.name_span.end)
                .unwrap_or(unset_span.end),
        };

        let stmt_span = Span {
            start: alter_span.start,
            end,
        };

        let ast = AstAlterSession {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            session_span,
            action,
        };
        Ok(AstStmt::AlterSession(Box::new(ast)))
    }

    /// Parse the `<param> = <value> [, …]` list after SET. Params may be
    /// separated by a comma or by whitespace alone; the loop continues on a
    /// comma or another bare parameter name and stops at a terminator or any
    /// non-parameter token.
    fn parse_session_set_params(&mut self) -> ParseResult<Vec<AstSessionSetParam>> {
        let mut params = Vec::new();
        loop {
            // Optional separating comma.
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                }
            }

            // Next must be a parameter name; otherwise the list is done.
            match self.peek_non_trivia() {
                Some(tok) if matches!(tok.kind, TokenKind::Identifier { .. }) => {}
                _ => break,
            }

            let name_tok = self.advance().expect_invariant("parameter name after peek");
            let name_span = name_tok.span;

            // `=`
            let eq_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                return Err(ParseError::new(
                    eq_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '=' after session parameter name".to_string(),
                    },
                ));
            }
            let eq_span = Some(eq_tok.span);

            // Value (single token).
            let value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["parameter value".to_string()])?;
            let value_kind = session_value_kind(&value_tok.kind);
            let value_span = value_tok.span;

            params.push(AstSessionSetParam {
                name_span,
                eq_span,
                value_span,
                value_kind,
            });
        }

        if params.is_empty() {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected at least one <param> = <value> after SET".to_string(),
                },
            ));
        }
        Ok(params)
    }

    /// Parse the `<param> [, …]` list after UNSET. Same separator rules as SET.
    fn parse_session_unset_params(&mut self) -> ParseResult<Vec<AstSessionUnsetParam>> {
        let mut params = Vec::new();
        loop {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                }
            }
            match self.peek_non_trivia() {
                Some(tok) if matches!(tok.kind, TokenKind::Identifier { .. }) => {}
                _ => break,
            }
            let name_tok = self.advance().expect_invariant("parameter name after peek");
            params.push(AstSessionUnsetParam {
                name_span: name_tok.span,
            });
        }

        if params.is_empty() {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected at least one <param> after UNSET".to_string(),
                },
            ));
        }
        Ok(params)
    }
}

/// Map a value token's kind to the captured [`AstSessionValueKind`]. The outer
/// non-literal fallback is the sanctioned TokenKind-fallback idiom for parsers.
fn session_value_kind(kind: &TokenKind) -> AstSessionValueKind {
    match kind {
        TokenKind::Literal(lit) => match lit {
            LiteralKind::String | LiteralKind::StringFragment => AstSessionValueKind::String,
            LiteralKind::Number => AstSessionValueKind::Number,
            LiteralKind::Boolean => AstSessionValueKind::Boolean,
            LiteralKind::Position | LiteralKind::Null => AstSessionValueKind::Other,
        },
        _ => AstSessionValueKind::Other,
    }
}
