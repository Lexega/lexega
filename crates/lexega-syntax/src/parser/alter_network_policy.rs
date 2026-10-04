// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for ALTER NETWORK POLICY statements.
//!
//! Syntax forms:
//!   ALTER NETWORK POLICY [IF EXISTS] name SET ...
//!   ALTER NETWORK POLICY [IF EXISTS] name UNSET COMMENT
//!   ALTER NETWORK POLICY name ADD ...
//!   ALTER NETWORK POLICY name REMOVE ...
//!   ALTER NETWORK POLICY name RENAME TO new_name
//!   ALTER NETWORK POLICY name SET TAG ...
//!   ALTER NETWORK POLICY name UNSET TAG ...

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterNetworkPolicy, AstAlterNetworkPolicyAction, AstAlterNetworkPolicyActionKind,
    AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxAlterNetworkPolicy, SyntaxAlterNetworkPolicyAction};

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_alter_network_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_network_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_token_id = self.last_token_id();

        // NETWORK (Identifier, NOT Keyword!)
        let network_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NETWORK".to_string()])?;

        if !matches!(network_tok.kind, TokenKind::Identifier { .. })
            || !network_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("NETWORK")
        {
            return Err(ParseError::new(
                network_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected NETWORK keyword".to_string(),
                },
            ));
        }
        let network_span = network_tok.span;

        // POLICY
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY keyword".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_token_id = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self
                        .advance()
                        .expect_invariant("IF keyword after peek in alter_network_policy");
                    let if_span = if_tok.span;
                    let if_token_id = self.last_token_id();

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
                    let exists_span = exists_tok.span;
                    let exists_token_id = self.last_token_id();

                    let if_exists_span = Span {
                        start: if_span.start,
                        end: exists_span.end,
                    };
                    (
                        Some(if_exists_span),
                        Some(if_token_id),
                        Some(exists_token_id),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // Policy name
        let name_span = self.parse_qualified_name_span()?;

        // Parse action based on next keyword
        let action_start = self.current_span().start;
        let action = self.parse_alter_network_policy_action()?;
        let action_span = action.span;

        // Statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build syntax nodes
        let action_syntax = SyntaxAlterNetworkPolicyAction { span: action_span };
        let action_id = self
            .syntax_arena
            .alloc_alter_network_policy_action(action_syntax);

        let syntax_node = SyntaxAlterNetworkPolicy {
            alter_keyword: alter_token_id,
            network_span,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            name_span,
            action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_network_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterNetworkPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            network_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span: Span {
                start: action_start,
                end: action_span.end,
            },
            action,
        };
        Ok(AstStmt::AlterNetworkPolicy(Box::new(ast)))
    }

    fn parse_alter_network_policy_action(&mut self) -> ParseResult<AstAlterNetworkPolicyAction> {
        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["action".to_string()])?;

        let action_start = action_tok.span.start;

        match &action_tok.kind {
            TokenKind::Keyword(Keyword::Set) => {
                // SET properties or SET TAG
                self.advance(); // consume SET
                let set_span = action_tok.span;

                // Check if this is SET TAG
                if let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword after peek in SET TAG action");
                        let tag_span = tag_tok.span;

                        // Parse tag assignments: tag1 = 'value1' [, tag2 = 'value2']
                        let assignments_start = self.current_span().start;

                        // Consume tag assignments (minimal parsing - just find span)
                        loop {
                            // Consume tag name (possibly qualified: db.schema.tag_name)
                            self.parse_qualified_name_span()?;
                            // Consume =
                            self.advance();
                            // Consume value
                            self.advance();

                            // Check for comma
                            if let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                    self.advance();
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        let assignments_end = self.current_span().start;
                        let assignments_span = Span {
                            start: assignments_start,
                            end: assignments_end,
                        };

                        let kind = AstAlterNetworkPolicyActionKind::SetTag {
                            set_span,
                            tag_span,
                            assignments_span,
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: assignments_span.end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    } else {
                        // SET properties (not TAG)
                        let mut properties = Vec::new();
                        let mut extras = Vec::new();

                        while let Some(tok) = self.peek_non_trivia() {
                            // Check for end of statement
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }

                            // Try to parse a property
                            match self.try_parse_network_policy_property() {
                                Ok(prop) => properties.push(prop),
                                Err(_) => {
                                    // Unknown property - defensive design
                                    let start_pos = self.current_span().start;
                                    let unknown_tok = self.advance().expect_invariant(
                                        "unknown property token after peek in SET properties",
                                    );

                                    // Consume until next known property or end
                                    while let Some(tok) = self.peek_non_trivia() {
                                        if matches!(
                                            tok.kind,
                                            TokenKind::Punctuation(Punctuation::Semi)
                                        ) {
                                            break;
                                        }
                                        if matches!(tok.kind, TokenKind::Identifier { .. }) {
                                            let lexeme_upper =
                                                tok.lexeme(self.source).to_uppercase();
                                            if lexeme_upper == "ALLOWED_IP_LIST"
                                                || lexeme_upper == "BLOCKED_IP_LIST"
                                                || lexeme_upper == "ALLOWED_NETWORK_RULE_LIST"
                                                || lexeme_upper == "BLOCKED_NETWORK_RULE_LIST"
                                                || lexeme_upper == "COMMENT"
                                            {
                                                break;
                                            }
                                        }
                                        self.advance();
                                    }

                                    let end_pos = self.current_span().start;
                                    extras.push(AstUnknownClause {
                                        introducer: Some(unknown_tok.span),
                                        span: Span {
                                            start: start_pos,
                                            end: end_pos,
                                        },
                                        kind: UnknownKind::Property,
                                        node_id: self.id_gen.next(),
                                    });
                                }
                            }
                        }

                        let action_end = if let Some(last_prop) = properties.last() {
                            last_prop.span.end
                        } else if let Some(last_extra) = extras.last() {
                            last_extra.span.end
                        } else {
                            set_span.end
                        };

                        let kind = AstAlterNetworkPolicyActionKind::Set {
                            set_span,
                            properties,
                            extras,
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: action_end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    }
                } else {
                    // No next token - assume properties
                    let properties = Vec::new();
                    let extras = Vec::new();
                    // Properties loop would go here, but for now return empty
                    let kind = AstAlterNetworkPolicyActionKind::Set {
                        set_span,
                        properties,
                        extras,
                    };
                    Ok(AstAlterNetworkPolicyAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: set_span.end,
                        },
                        syntax_id: None,
                        kind,
                    })
                }
            }

            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = action_tok.span;

                // Check if this is UNSET TAG or UNSET COMMENT
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["TAG or COMMENT".to_string()])?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Tag) => {
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword after peek in UNSET TAG action");
                        let tag_span = tag_tok.span;

                        // Parse tag names: tag1 [, tag2]
                        let names_start = self.current_span().start;

                        // Consume tag names (minimal parsing)
                        loop {
                            self.parse_qualified_name_span()?; // consume tag name (possibly qualified)

                            if let Some(tok) = self.peek_non_trivia() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                    self.advance();
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        let names_end = self.current_span().start;
                        let names_span = Span {
                            start: names_start,
                            end: names_end,
                        };

                        let kind = AstAlterNetworkPolicyActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            names_span,
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: names_span.end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        let comment_tok = self
                            .advance()
                            .expect_invariant("COMMENT keyword after peek in UNSET COMMENT action");
                        let comment_span = comment_tok.span;

                        let kind = AstAlterNetworkPolicyActionKind::UnsetComment {
                            unset_span,
                            comment_span,
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: comment_span.end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    }

                    _ => Err(ParseError::new(
                        next_tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: vec!["TAG".to_string(), "COMMENT".to_string()],
                            found: next_tok.lexeme(self.source).to_string(),
                        },
                    )),
                }
            }

            TokenKind::Keyword(Keyword::Rename) => {
                self.advance(); // consume RENAME
                let rename_span = action_tok.span;

                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TO keyword after RENAME".to_string(),
                        },
                    ));
                }
                let to_span = to_tok.span;

                let new_name_span = self.parse_qualified_name_span()?;

                let kind = AstAlterNetworkPolicyActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                };

                Ok(AstAlterNetworkPolicyAction {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: action_start,
                        end: new_name_span.end,
                    },
                    syntax_id: None,
                    kind,
                })
            }

            TokenKind::Identifier { .. } => {
                // Could be ADD or REMOVE (both are Identifiers, not Keywords!)
                let action_lexeme = action_tok.lexeme(self.source).to_uppercase();

                match action_lexeme.as_str() {
                    "ADD" => {
                        self.advance(); // consume ADD
                        let add_span = action_tok.span;

                        // Parse property (single value form)
                        let property = self.try_parse_network_policy_property()?;

                        let kind = AstAlterNetworkPolicyActionKind::Add {
                            add_span,
                            property: property.clone(),
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: property.span.end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    }

                    "REMOVE" => {
                        self.advance(); // consume REMOVE
                        let remove_span = action_tok.span;

                        // Parse property (single value form)
                        let property = self.try_parse_network_policy_property()?;

                        let kind = AstAlterNetworkPolicyActionKind::Remove {
                            remove_span,
                            property: property.clone(),
                        };

                        Ok(AstAlterNetworkPolicyAction {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: action_start,
                                end: property.span.end,
                            },
                            syntax_id: None,
                            kind,
                        })
                    }

                    _ => Err(ParseError::new(
                        action_tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: vec![
                                "SET".to_string(),
                                "UNSET".to_string(),
                                "RENAME".to_string(),
                                "ADD".to_string(),
                                "REMOVE".to_string(),
                            ],
                            found: action_tok.lexeme(self.source).to_string(),
                        },
                    )),
                }
            }

            _ => Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: vec![
                        "SET".to_string(),
                        "UNSET".to_string(),
                        "RENAME".to_string(),
                        "ADD".to_string(),
                        "REMOVE".to_string(),
                    ],
                    found: action_tok.lexeme(self.source).to_string(),
                },
            )),
        }
    }
}
