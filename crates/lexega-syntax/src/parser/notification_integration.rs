// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for NOTIFICATION INTEGRATION statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] NOTIFICATION INTEGRATION [IF NOT EXISTS] name <properties>`
//! - `ALTER NOTIFICATION INTEGRATION [IF EXISTS] name { SET | UNSET } <action>`
//! - `ALTER NOTIFICATION INTEGRATION name RENAME TO <new_name>`
//! - `DROP NOTIFICATION INTEGRATION [IF EXISTS] name`
//!
//! Token reference (`--debug-tokens`):
//! - `NOTIFICATION` is `Keyword::Notification`
//! - `INTEGRATION` is `Keyword::Integration`
//! - `TYPE` is `Keyword::Type`
//! - `COMMENT` is `Keyword::Comment`
//! - `SET` / `UNSET` / `TAG` / `RENAME` / `TO` are keywords
//! - All other property names (`ENABLED`, `DIRECTION`,
//!   `NOTIFICATION_PROVIDER`, `AWS_SNS_TOPIC_ARN`, `WEBHOOK_URL`, …)
//!   are unquoted `Identifier` tokens.
//!
//! The parser captures `ENABLED`, `TYPE`, `DIRECTION`,
//! `NOTIFICATION_PROVIDER`, and `COMMENT` as typed slots and routes
//! everything else through the `extras` slot. Consumers that need a
//! provider-specific property promote it to a typed
//! slots without re-shaping the parser.

use crate::ast::{
    AstAlterNotificationIntegration, AstAlterNotificationIntegrationAction,
    AstAlterNotificationIntegrationActionKind, AstCreateNotificationIntegration,
    AstDropNotificationIntegration, AstStmt, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE [OR REPLACE] NOTIFICATION INTEGRATION
    /// [IF NOT EXISTS] <name> <properties>`.
    pub(crate) fn try_parse_create_notification_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_notification_integration")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let start = create_span.start;

        // Optional OR REPLACE.
        let or_replace_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword in CREATE NOTIFICATION INTEGRATION");
                let replace_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                if !matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    return Err(ParseError::new(
                        replace_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE after OR".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: or_tok.span.start,
                    end: replace_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        // NOTIFICATION keyword.
        let notification_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NOTIFICATION".to_string()])?;
        if !matches!(
            notification_tok.kind,
            TokenKind::Keyword(Keyword::Notification)
        ) {
            return Err(ParseError::new(
                notification_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected NOTIFICATION keyword".to_string(),
                },
            ));
        }
        let notification_span = notification_tok.span;

        // INTEGRATION keyword.
        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();

        // Optional IF NOT EXISTS.
        let if_not_exists_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant(
                    "IF keyword in CREATE NOTIFICATION INTEGRATION IF NOT EXISTS",
                );
                let not_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::new(
                        not_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected NOT after IF".to_string(),
                        },
                    ));
                }
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after NOT".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        let integration_name_span = self.parse_qualified_name_span()?;
        let mut end = integration_name_span.end;

        let mut enabled_span: Option<Span> = None;
        let mut type_span: Option<Span> = None;
        let mut direction_span: Option<Span> = None;
        let mut notification_provider_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut extras: Vec<AstUnknownClause> = Vec::new();

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Keyword(Keyword::Type) => {
                    self.advance();
                    let _eq = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let val = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                    end = val.span.end;
                    type_span = Some(Span {
                        start: prop_start,
                        end,
                    });
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    let _eq = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let val = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                    end = val.span.end;
                    comment_span = Some(Span {
                        start: prop_start,
                        end,
                    });
                }
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    self.advance();
                    let _eq = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    end = consume_property_value(self)?;
                    let prop_span = Span {
                        start: prop_start,
                        end,
                    };
                    match lexeme_upper.as_str() {
                        "ENABLED" => enabled_span = Some(prop_span),
                        "DIRECTION" => direction_span = Some(prop_span),
                        "NOTIFICATION_PROVIDER" => notification_provider_span = Some(prop_span),
                        _ => {
                            extras.push(AstUnknownClause {
                                introducer: Some(Span {
                                    start: prop_start,
                                    end: tok.span.end,
                                }),
                                span: prop_span,
                                kind: UnknownKind::Property,
                                node_id: self.id_gen.next(),
                            });
                        }
                    }
                }
                _ => break,
            }
        }

        let stmt_span = Span { start, end };
        let ast = AstCreateNotificationIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            create_span,
            or_replace_span,
            if_not_exists_span,
            notification_span,
            integration_span,
            integration_name_span,
            enabled_span,
            type_span,
            direction_span,
            notification_provider_span,
            comment_span,
            extras,
        };
        Ok(AstStmt::CreateNotificationIntegration(Box::new(ast)))
    }

    /// Parse `ALTER NOTIFICATION INTEGRATION [IF EXISTS] <name>
    /// { SET | UNSET | RENAME TO } <action>`.
    pub(crate) fn try_parse_alter_notification_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_notification_integration")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let start = alter_span.start;

        // NOTIFICATION INTEGRATION (both required after ALTER for this
        // typed parser; the dispatcher routes here only on the
        // ALTER NOTIFICATION INTEGRATION prefix).
        let notification_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NOTIFICATION".to_string()])?;
        if !matches!(
            notification_tok.kind,
            TokenKind::Keyword(Keyword::Notification)
        ) {
            return Err(ParseError::new(
                notification_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected NOTIFICATION keyword".to_string(),
                },
            ));
        }
        let notification_span = notification_tok.span;

        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();

        // Optional IF EXISTS.
        let if_exists_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword in ALTER NOTIFICATION INTEGRATION IF EXISTS");
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;
        let mut actions: Vec<AstAlterNotificationIntegrationAction> = Vec::new();

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            let action_start = tok.span.start;

            match &tok.kind {
                TokenKind::Keyword(Keyword::Set) => {
                    let set_tok = self
                        .advance()
                        .expect_invariant("SET keyword in ALTER NOTIFICATION INTEGRATION");
                    let set_span = set_tok.span;

                    let prop_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
                    let property_span = prop_tok.span;

                    if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        let tag_span = property_span;
                        let tags_start = self
                            .peek_non_trivia()
                            .map(|t| t.span.start)
                            .unwrap_or(tag_span.end);
                        let mut action_end;
                        loop {
                            let _tag_name_span = self.parse_qualified_name_span()?;
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            action_end = val.span.end;
                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    self.advance();
                                    continue;
                                }
                            }
                            break;
                        }
                        let tags_span = Span {
                            start: tags_start,
                            end: action_end,
                        };
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind: AstAlterNotificationIntegrationActionKind::SetTag {
                                set_span,
                                tag_span,
                                tags_span,
                            },
                        });
                    } else if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                        let comment_span = property_span;
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let val_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                        let value_span = val_tok.span;
                        let action_end = value_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind: AstAlterNotificationIntegrationActionKind::SetComment {
                                set_span,
                                comment_span,
                                eq_span: eq_tok.span,
                                value_span,
                            },
                        });
                    } else if let TokenKind::Identifier { .. } = prop_tok.kind {
                        let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                        let eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let value_end = consume_property_value(self)?;
                        let value_span = Span {
                            start: eq_tok.span.end,
                            end: value_end,
                        };
                        let action_end = value_end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;

                        let kind = match lexeme_upper.as_str() {
                            "ENABLED" => AstAlterNotificationIntegrationActionKind::SetEnabled {
                                set_span,
                                property_span,
                                eq_span: eq_tok.span,
                                value_span,
                            },
                            _ => AstAlterNotificationIntegrationActionKind::SetOther {
                                set_span,
                                property_span,
                                eq_span: eq_tok.span,
                                value_span,
                            },
                        };
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind,
                        });
                    } else {
                        // Unrecognized SET <thing> shape — bail to keep
                        // span calculation honest. Caller will surface
                        // the ParseError.
                        return Err(ParseError::new(
                            property_span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected property name after SET".to_string(),
                            },
                        ));
                    }
                }
                TokenKind::Keyword(Keyword::Unset) => {
                    let unset_tok = self
                        .advance()
                        .expect_invariant("UNSET keyword in ALTER NOTIFICATION INTEGRATION");
                    let unset_span = unset_tok.span;

                    let prop_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
                    let property_span = prop_tok.span;

                    if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        let tag_span = property_span;
                        let tags_start = self
                            .peek_non_trivia()
                            .map(|t| t.span.start)
                            .unwrap_or(tag_span.end);
                        let mut action_end;
                        loop {
                            let tag_name_span = self.parse_qualified_name_span()?;
                            action_end = tag_name_span.end;
                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    self.advance();
                                    continue;
                                }
                            }
                            break;
                        }
                        let tags_span = Span {
                            start: tags_start,
                            end: action_end,
                        };
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind: AstAlterNotificationIntegrationActionKind::UnsetTag {
                                unset_span,
                                tag_span,
                                tags_span,
                            },
                        });
                    } else if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                        let comment_span = property_span;
                        let action_end = comment_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind: AstAlterNotificationIntegrationActionKind::UnsetComment {
                                unset_span,
                                comment_span,
                            },
                        });
                    } else if let TokenKind::Identifier { .. } = prop_tok.kind {
                        let lexeme_upper = prop_tok.lexeme(self.source).to_uppercase();
                        let action_end = property_span.end;
                        let action_span = Span {
                            start: action_start,
                            end: action_end,
                        };
                        end = action_end;
                        let kind = match lexeme_upper.as_str() {
                            "ENABLED" => AstAlterNotificationIntegrationActionKind::UnsetEnabled {
                                unset_span,
                                property_span,
                            },
                            _ => AstAlterNotificationIntegrationActionKind::UnsetOther {
                                unset_span,
                                property_span,
                            },
                        };
                        actions.push(AstAlterNotificationIntegrationAction {
                            node_id: self.id_gen.next(),
                            span: action_span,
                            kind,
                        });
                    } else {
                        return Err(ParseError::new(
                            property_span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected property name after UNSET".to_string(),
                            },
                        ));
                    }
                }
                TokenKind::Keyword(Keyword::Rename) => {
                    let rename_tok = self
                        .advance()
                        .expect_invariant("RENAME keyword in ALTER NOTIFICATION INTEGRATION");
                    let to_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                    if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                        return Err(ParseError::new(
                            to_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected TO after RENAME".to_string(),
                            },
                        ));
                    }
                    let new_name_span = self.parse_qualified_name_span()?;
                    let action_end = new_name_span.end;
                    let action_span = Span {
                        start: action_start,
                        end: action_end,
                    };
                    end = action_end;
                    actions.push(AstAlterNotificationIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        kind: AstAlterNotificationIntegrationActionKind::Rename {
                            rename_span: rename_tok.span,
                            to_span: to_tok.span,
                            new_name_span,
                        },
                    });
                }
                _ => break,
            }
        }

        let stmt_span = Span { start, end };
        let ast = AstAlterNotificationIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            notification_span,
            integration_span,
            if_exists_span,
            name_span,
            actions,
        };
        Ok(AstStmt::AlterNotificationIntegration(Box::new(ast)))
    }

    /// Parse `DROP NOTIFICATION INTEGRATION [IF EXISTS] <name>`.
    pub(crate) fn try_parse_drop_notification_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_notification_integration")?;

        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let start = drop_span.start;

        let notification_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NOTIFICATION".to_string()])?;
        if !matches!(
            notification_tok.kind,
            TokenKind::Keyword(Keyword::Notification)
        ) {
            return Err(ParseError::new(
                notification_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected NOTIFICATION keyword".to_string(),
                },
            ));
        }
        let notification_span = notification_tok.span;

        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();

        let if_exists_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword in DROP NOTIFICATION INTEGRATION IF EXISTS");
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        let integration_name_span = self.parse_qualified_name_span()?;
        let end = integration_name_span.end;
        let stmt_span = Span { start, end };

        let ast = AstDropNotificationIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            drop_span,
            notification_span,
            integration_span,
            if_exists_span,
            integration_name_span,
        };
        Ok(AstStmt::DropNotificationIntegration(Box::new(ast)))
    }
}

/// Consume a property value: a parenthesized list `(…)` or a single
/// scalar token. Returns the end of the consumed value. Mirrors the
/// API/Storage Integration parser's value-consumption rule so list
/// values like `ALLOWED_RECIPIENTS = ('a@b.com', 'c@d.com')` are
/// preserved as part of the property span.
fn consume_property_value(p: &mut Parser<'_>) -> ParseResult<u32> {
    let Some(first) = p.peek_non_trivia() else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected value".to_string(),
            },
        ));
    };
    if matches!(first.kind, TokenKind::Punctuation(Punctuation::LParen)) {
        let lparen = p.advance().expect_invariant("left paren in property value");
        let mut depth = 1;
        let mut last_end = lparen.span.end;
        while depth > 0 {
            if let Some(t) = p.advance() {
                last_end = t.span.end;
                if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    depth += 1;
                } else if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    depth -= 1;
                }
            } else {
                break;
            }
        }
        Ok(last_end)
    } else {
        let val = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["value".to_string()])?;
        Ok(val.span.end)
    }
}
