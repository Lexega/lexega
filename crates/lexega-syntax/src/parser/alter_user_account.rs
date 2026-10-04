// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for the narrow `ALTER USER` / `ALTER ACCOUNT` AUTHENTICATION POLICY
//! attachment slice (Snowflake).
//!
//! Only the principal-attachment forms are recognised here:
//!
//! ```text
//! ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
//! ALTER ACCOUNT          { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
//! ```
//!
//! Other ALTER USER / ALTER ACCOUNT actions deliberately fall through to the
//! existing generic parser path (`PgAlterRole` for ALTER USER; the generic
//! statement handler for ALTER ACCOUNT). The dispatcher in
//! [`crate::parser::core`] peeks the post-`ALTER` prefix via the helpers
//! `peek_alter_user_authpol_attachment_at` /
//! `peek_alter_account_authpol_attachment_at` and routes here only when the
//! prefix matches AUTHENTICATION POLICY attachment.

use crate::ast::types::{
    AstAlterAccount, AstAlterAccountAction, AstAlterAccountActionKind, AstAlterUser,
    AstAlterUserAction, AstAlterUserActionKind, AstStmt,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Lookahead: returns `true` iff the next non-trivia tokens at the current
    /// cursor position match `ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY`.
    /// Cursor is restored before returning.
    pub(crate) fn peek_alter_user_authpol_attachment_at(&mut self) -> bool {
        let saved = self.idx;
        let matched = self.scan_alter_user_authpol_attachment_prefix();
        self.idx = saved;
        matched
    }

    /// Lookahead: returns `true` iff the next non-trivia tokens at the current
    /// cursor position match `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION POLICY`.
    /// Cursor is restored before returning.
    pub(crate) fn peek_alter_account_authpol_attachment_at(&mut self) -> bool {
        let saved = self.idx;
        let matched = self.scan_alter_account_authpol_attachment_prefix();
        self.idx = saved;
        matched
    }

    fn scan_alter_user_authpol_attachment_prefix(&mut self) -> bool {
        // Consume ALTER
        if !self.scan_consume_alter() {
            return false;
        }
        // Consume USER (Identifier, NOT Keyword)
        if !self.scan_consume_identifier_lexeme("USER") {
            return false;
        }
        // Optional IF EXISTS
        self.scan_consume_if_exists();
        // Consume the user name (single identifier; quoted form acceptable)
        if !self.scan_consume_simple_identifier() {
            return false;
        }
        // SET | UNSET
        if !self.scan_consume_set_or_unset() {
            return false;
        }
        // AUTHENTICATION POLICY
        self.scan_consume_authentication_policy_keywords()
    }

    fn scan_alter_account_authpol_attachment_prefix(&mut self) -> bool {
        if !self.scan_consume_alter() {
            return false;
        }
        if !self.scan_consume_identifier_lexeme("ACCOUNT") {
            return false;
        }
        if !self.scan_consume_set_or_unset() {
            return false;
        }
        self.scan_consume_authentication_policy_keywords()
    }

    fn scan_consume_alter(&mut self) -> bool {
        self.skip_trivia();
        match self.peek_non_trivia() {
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Alter)) => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn scan_consume_identifier_lexeme(&mut self, expected: &str) -> bool {
        self.skip_trivia();
        match self.peek_non_trivia() {
            Some(t)
                if matches!(t.kind, TokenKind::Identifier { .. })
                    && t.lexeme(self.source).eq_ignore_ascii_case(expected) =>
            {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn scan_consume_if_exists(&mut self) {
        let saved = self.idx;
        self.skip_trivia();
        let if_seen = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::If))
        );
        if !if_seen {
            self.idx = saved;
            return;
        }
        self.advance(); // IF
        self.skip_trivia();
        let exists_seen = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Exists))
        );
        if exists_seen {
            self.advance(); // EXISTS
        } else {
            // Lone IF without EXISTS — not the AUTHPOL-attachment shape.
            // Restore so the lookahead returns false on the next check.
            self.idx = saved;
        }
    }

    fn scan_consume_simple_identifier(&mut self) -> bool {
        self.skip_trivia();
        match self.peek_non_trivia() {
            Some(t) if matches!(t.kind, TokenKind::Identifier { .. }) => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn scan_consume_set_or_unset(&mut self) -> bool {
        self.skip_trivia();
        match self.peek_non_trivia() {
            Some(t)
                if matches!(
                    t.kind,
                    TokenKind::Keyword(Keyword::Set) | TokenKind::Keyword(Keyword::Unset)
                ) =>
            {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn scan_consume_authentication_policy_keywords(&mut self) -> bool {
        // AUTHENTICATION (Identifier, NOT Keyword)
        if !self.scan_consume_identifier_lexeme("AUTHENTICATION") {
            return false;
        }
        // POLICY (Keyword::Policy)
        self.skip_trivia();
        matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Policy))
        )
    }

    /// Parse `ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY [= <policy>]`.
    ///
    /// Caller has guaranteed via [`Self::peek_alter_user_authpol_attachment_at`]
    /// that the prefix matches.
    pub(crate) fn try_parse_alter_user_authpol_attachment(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_user_authpol_attachment")?;

        // ALTER
        let alter_span = {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
            tok.span
        };

        // USER
        let user_span = expect_identifier_lexeme(self, "USER")?;

        // Optional IF EXISTS
        let if_exists_span = parse_optional_if_exists(self)?;

        // User name (single identifier; quoted form acceptable). We use
        // parse_qualified_name_span which gracefully degrades to a single
        // ident when no dot follows.
        let user_name_span = self.parse_qualified_name_span()?;

        // Action
        let action = self.parse_alter_user_action()?;
        let action_span = action.span;

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        let ast = AstAlterUser {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            user_span,
            if_exists_span,
            user_name_span,
            action,
        };
        Ok(AstStmt::AlterUser(Box::new(ast)))
    }

    /// Parse `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION POLICY [= <policy>]`.
    ///
    /// Caller has guaranteed via [`Self::peek_alter_account_authpol_attachment_at`]
    /// that the prefix matches.
    pub(crate) fn try_parse_alter_account_authpol_attachment(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_account_authpol_attachment")?;

        // ALTER
        let alter_span = {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
            tok.span
        };

        // ACCOUNT
        let account_span = expect_identifier_lexeme(self, "ACCOUNT")?;

        // Action
        let action = self.parse_alter_account_action()?;
        let action_span = action.span;

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        let ast = AstAlterAccount {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            account_span,
            action,
        };
        Ok(AstStmt::AlterAccount(Box::new(ast)))
    }

    /// Parse `ALTER ACCOUNT { SET | UNSET } <property_list>`.
    ///
    /// Called by the dispatcher when the AUTHENTICATION POLICY attachment
    /// lookahead fails. Handles Snowflake account-level property changes
    /// (NETWORK_POLICY, PERIODIC_DATA_REKEYING, DATA_RETENTION_TIME_IN_DAYS,
    /// MIN_DATA_RETENTION_TIME_IN_DAYS, etc.) where the property body is
    /// consumed as a generic span until the next semicolon or EOF.
    pub(crate) fn try_parse_alter_account_generic(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_account_generic")?;

        // ALTER
        let alter_span = {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
            tok.span
        };

        // ACCOUNT (Identifier, not Keyword)
        let account_span = expect_identifier_lexeme(self, "ACCOUNT")?;

        // Action: SET or UNSET
        let kind_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after ACCOUNT".to_string(),
                },
            )
        })?;

        let (action_kind, action_span) = match kind_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self
                    .advance()
                    .expect_invariant("SET: consumed after Keyword::Set match");
                let set_span = set_tok.span;
                let props_start = self
                    .peek_non_trivia()
                    .map(|t| t.span.start)
                    .unwrap_or(set_span.end);
                let properties = crate::parser::snowflake_account_ddl::walk_object_properties(self);
                let end = properties
                    .last()
                    .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                    .unwrap_or(set_span.end);
                (
                    AstAlterAccountActionKind::Set {
                        set_span,
                        properties_span: Span {
                            start: props_start,
                            end,
                        },
                        properties,
                    },
                    Span {
                        start: set_span.start,
                        end,
                    },
                )
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let unset_tok = self
                    .advance()
                    .expect_invariant("UNSET: consumed after Keyword::Unset match");
                let unset_span = unset_tok.span;
                let props_start = self
                    .peek_non_trivia()
                    .map(|t| t.span.start)
                    .unwrap_or(unset_span.end);
                let properties = crate::parser::snowflake_account_ddl::walk_object_properties(self);
                let property_name_spans: Vec<Span> =
                    properties.iter().map(|p| p.name_span).collect();
                let end = property_name_spans
                    .last()
                    .map(|s| s.end)
                    .unwrap_or(unset_span.end);
                (
                    AstAlterAccountActionKind::Unset {
                        unset_span,
                        properties_span: Span {
                            start: props_start,
                            end,
                        },
                        property_name_spans,
                    },
                    Span {
                        start: unset_span.start,
                        end,
                    },
                )
            }
            _ => {
                return Err(ParseError::new(
                    kind_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected SET or UNSET after ACCOUNT".to_string(),
                    },
                ));
            }
        };

        let action = AstAlterAccountAction {
            node_id: self.id_gen.next(),
            span: action_span,
            kind: action_kind,
        };

        let ast = AstAlterAccount {
            node_id: self.id_gen.next(),
            span: Span {
                start: alter_span.start,
                end: action_span.end,
            },
            alter_span,
            account_span,
            action,
        };
        Ok(AstStmt::AlterAccount(Box::new(ast)))
    }

    fn parse_alter_user_action(&mut self) -> ParseResult<AstAlterUserAction> {
        let kind_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after user name".to_string(),
                },
            )
        })?;

        match kind_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let (kind, span) = parse_set_authpol_action_kind_user(self)?;
                Ok(AstAlterUserAction {
                    node_id: self.id_gen.next(),
                    span,
                    kind,
                })
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let (kind, span) = parse_unset_authpol_action_kind_user(self)?;
                Ok(AstAlterUserAction {
                    node_id: self.id_gen.next(),
                    span,
                    kind,
                })
            }
            _ => Err(ParseError::new(
                kind_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET".to_string(),
                },
            )),
        }
    }

    fn parse_alter_account_action(&mut self) -> ParseResult<AstAlterAccountAction> {
        let kind_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET after ACCOUNT".to_string(),
                },
            )
        })?;

        match kind_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                let (kind, span) = parse_set_authpol_action_kind_account(self)?;
                Ok(AstAlterAccountAction {
                    node_id: self.id_gen.next(),
                    span,
                    kind,
                })
            }
            TokenKind::Keyword(Keyword::Unset) => {
                let (kind, span) = parse_unset_authpol_action_kind_account(self)?;
                Ok(AstAlterAccountAction {
                    node_id: self.id_gen.next(),
                    span,
                    kind,
                })
            }
            _ => Err(ParseError::new(
                kind_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET or UNSET".to_string(),
                },
            )),
        }
    }
}

fn parse_set_authpol_action_kind_user(
    parser: &mut Parser<'_>,
) -> ParseResult<(AstAlterUserActionKind, Span)> {
    let (set_span, authentication_span, policy_span, eq_span, policy_name_span) =
        parse_set_authpol_action_spans(parser)?;
    let span = Span {
        start: set_span.start,
        end: policy_name_span.end,
    };
    Ok((
        AstAlterUserActionKind::SetAuthenticationPolicy {
            set_span,
            authentication_span,
            policy_span,
            eq_span,
            policy_name_span,
        },
        span,
    ))
}

fn parse_unset_authpol_action_kind_user(
    parser: &mut Parser<'_>,
) -> ParseResult<(AstAlterUserActionKind, Span)> {
    let (unset_span, authentication_span, policy_span) = parse_unset_authpol_action_spans(parser)?;
    let span = Span {
        start: unset_span.start,
        end: policy_span.end,
    };
    Ok((
        AstAlterUserActionKind::UnsetAuthenticationPolicy {
            unset_span,
            authentication_span,
            policy_span,
        },
        span,
    ))
}

fn parse_set_authpol_action_kind_account(
    parser: &mut Parser<'_>,
) -> ParseResult<(AstAlterAccountActionKind, Span)> {
    let (set_span, authentication_span, policy_span, eq_span, policy_name_span) =
        parse_set_authpol_action_spans(parser)?;
    let span = Span {
        start: set_span.start,
        end: policy_name_span.end,
    };
    Ok((
        AstAlterAccountActionKind::SetAuthenticationPolicy {
            set_span,
            authentication_span,
            policy_span,
            eq_span,
            policy_name_span,
        },
        span,
    ))
}

fn parse_unset_authpol_action_kind_account(
    parser: &mut Parser<'_>,
) -> ParseResult<(AstAlterAccountActionKind, Span)> {
    let (unset_span, authentication_span, policy_span) = parse_unset_authpol_action_spans(parser)?;
    let span = Span {
        start: unset_span.start,
        end: policy_span.end,
    };
    Ok((
        AstAlterAccountActionKind::UnsetAuthenticationPolicy {
            unset_span,
            authentication_span,
            policy_span,
        },
        span,
    ))
}

/// Returns `(set_span, authentication_span, policy_span, eq_span, policy_name_span)`.
///
/// Canonical Snowflake syntax is `SET AUTHENTICATION POLICY <name>`; the
/// `=` between POLICY and the name is accepted but optional.
fn parse_set_authpol_action_spans(
    parser: &mut Parser<'_>,
) -> ParseResult<(Span, Span, Span, Option<Span>, Span)> {
    let set_span = expect_keyword(parser, Keyword::Set, "SET")?;
    let authentication_span = expect_identifier_lexeme(parser, "AUTHENTICATION")?;
    let policy_span = expect_keyword(parser, Keyword::Policy, "POLICY")?;
    let eq_span = consume_optional_eq_operator(parser);
    let policy_name_span = parser.parse_qualified_name_span()?;

    Ok((
        set_span,
        authentication_span,
        policy_span,
        eq_span,
        policy_name_span,
    ))
}

/// Returns `(unset_span, authentication_span, policy_span)`.
fn parse_unset_authpol_action_spans(parser: &mut Parser<'_>) -> ParseResult<(Span, Span, Span)> {
    let unset_span = expect_keyword(parser, Keyword::Unset, "UNSET")?;
    let authentication_span = expect_identifier_lexeme(parser, "AUTHENTICATION")?;
    let policy_span = expect_keyword(parser, Keyword::Policy, "POLICY")?;
    Ok((unset_span, authentication_span, policy_span))
}

fn parse_optional_if_exists(parser: &mut Parser<'_>) -> ParseResult<Option<Span>> {
    let starts_with_if = matches!(
        parser.peek_non_trivia(),
        Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::If))
    );
    if !starts_with_if {
        return Ok(None);
    }
    let if_start = {
        let tok = parser.advance().expect_invariant("IF after peek");
        tok.span.start
    };
    let exists_end = {
        let tok = parser
            .advance()
            .ok_or_eof(parser.current_span(), vec!["EXISTS".to_string()])?;
        if !matches!(tok.kind, TokenKind::Keyword(Keyword::Exists)) {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected EXISTS after IF".to_string(),
                },
            ));
        }
        tok.span.end
    };
    Ok(Some(Span {
        start: if_start,
        end: exists_end,
    }))
}

fn expect_identifier_lexeme(parser: &mut Parser<'_>, expected: &str) -> ParseResult<Span> {
    let tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec![expected.to_string()])?;
    if !matches!(tok.kind, TokenKind::Identifier { .. })
        || !tok.lexeme(parser.source).eq_ignore_ascii_case(expected)
    {
        return Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected {} keyword", expected),
            },
        ));
    }
    Ok(tok.span)
}

fn expect_keyword(
    parser: &mut Parser<'_>,
    expected: Keyword,
    expected_label: &str,
) -> ParseResult<Span> {
    let tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec![expected_label.to_string()])?;
    if !matches!(tok.kind, TokenKind::Keyword(k) if k == expected) {
        return Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected {} keyword", expected_label),
            },
        ));
    }
    Ok(tok.span)
}

fn consume_optional_eq_operator(parser: &mut Parser<'_>) -> Option<Span> {
    match parser.peek_non_trivia() {
        Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) => {
            let tok = parser.advance().expect_invariant("= after peek");
            Some(tok.span)
        }
        _ => None,
    }
}
