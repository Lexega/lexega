// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for CREATE NETWORK POLICY statements.
//!
//! Syntax:
//!   CREATE [OR REPLACE] NETWORK POLICY [IF NOT EXISTS] name
//!     [ALLOWED_NETWORK_RULE_LIST = (...)]
//!     [BLOCKED_NETWORK_RULE_LIST = (...)]
//!     [ALLOWED_IP_LIST = (...)]
//!     [BLOCKED_IP_LIST = (...)]
//!     [COMMENT = '...']

use crate::ast::AstStmt;
use crate::ast::{
    AstCreateNetworkPolicy, AstNetworkPolicyProperty, AstNetworkPolicyPropertyKind,
    AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxCreateNetworkPolicy;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_create_network_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_network_policy")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_token_id = self.last_token_id();

        // Optional OR REPLACE
        let (or_span, or_token_id, _replace_span, replace_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                    let or_tok = self.advance().expect_invariant("OR keyword after peek");
                    let or_span = or_tok.span;
                    let or_token_id = self.last_token_id();

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
                    let replace_span = replace_tok.span;
                    let replace_token_id = self.last_token_id();

                    let or_replace_span = Span {
                        start: or_span.start,
                        end: replace_span.end,
                    };
                    (
                        Some(or_replace_span),
                        Some(or_token_id),
                        Some(replace_span),
                        Some(replace_token_id),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

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

        // POLICY (Keyword)
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

        // Optional IF NOT EXISTS
        let (if_not_exists_span, if_token_id, not_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self.advance().expect_invariant("IF keyword after peek");
                    let if_span = if_tok.span;
                    let if_token_id = self.last_token_id();

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
                    let _not_span = not_tok.span;
                    let not_token_id = self.last_token_id();

                    let exists_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                    if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        return Err(ParseError::new(
                            exists_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected EXISTS after IF NOT".to_string(),
                            },
                        ));
                    }
                    let exists_span = exists_tok.span;
                    let exists_token_id = self.last_token_id();

                    let if_not_exists_span = Span {
                        start: if_span.start,
                        end: exists_span.end,
                    };
                    (
                        Some(if_not_exists_span),
                        Some(if_token_id),
                        Some(not_token_id),
                        Some(exists_token_id),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;

        // Parse properties (all optional)
        let mut properties = Vec::new();
        let mut extras = Vec::new();

        while let Some(tok) = self.peek_non_trivia() {
            // Check if we've reached end of statement
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // Try to parse a property
            match self.try_parse_network_policy_property() {
                Ok(prop) => properties.push(prop),
                Err(_) => {
                    // Unknown property - defensive design
                    let start_pos = self.current_span().start;
                    let unknown_tok = self
                        .advance()
                        .expect_invariant("unknown property token after peek");

                    // Consume until next known property or end
                    while let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                            break;
                        }
                        if matches!(tok.kind, TokenKind::Identifier { .. }) {
                            let lexeme_upper = tok.lexeme(self.source).to_uppercase();
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

        // Calculate statement span
        let stmt_end = if let Some(last_prop) = properties.last() {
            last_prop.span.end
        } else if let Some(last_extra) = extras.last() {
            last_extra.span.end
        } else {
            policy_name_span.end
        };

        let stmt_span = Span {
            start: create_span.start,
            end: stmt_end,
        };

        // Build syntax node
        let syntax_node = SyntaxCreateNetworkPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            if_keyword: if_token_id,
            not_keyword: not_token_id,
            exists_keyword: exists_token_id,
            network_span,
            policy_keyword: policy_token_id,
            policy_name_span,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_create_network_policy(syntax_node);

        // Build AST node
        let ast = AstCreateNetworkPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span: or_span,
            network_span,
            policy_span,
            if_not_exists_span,
            policy_name_span,
            properties,
            extras,
        };
        Ok(AstStmt::CreateNetworkPolicy(Box::new(ast)))
    }

    /// Parse a network policy property: ALLOWED_IP_LIST = (...), etc.
    pub(crate) fn try_parse_network_policy_property(
        &mut self,
    ) -> ParseResult<AstNetworkPolicyProperty> {
        let prop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["property".to_string()])?;

        let property_name_span = prop_tok.span;
        let property_name = prop_tok.lexeme(self.source).to_uppercase();

        // Expect '='
        let eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: vec!["=".to_string()],
                    found: eq_tok.lexeme(self.source).to_string(),
                },
            ));
        }
        let eq_span = eq_tok.span;

        match property_name.as_str() {
            "ALLOWED_IP_LIST" | "BLOCKED_IP_LIST" => {
                // Parse string list: ('value1', 'value2', ...)
                let (list_span, lparen_token, rparen_token, values) = self.parse_string_list()?;

                let kind = if property_name == "ALLOWED_IP_LIST" {
                    AstNetworkPolicyPropertyKind::AllowedIpList {
                        property_name_span,
                        eq_span,
                        list_span,
                        lparen_token: Some(lparen_token),
                        rparen_token: Some(rparen_token),
                        values,
                    }
                } else {
                    AstNetworkPolicyPropertyKind::BlockedIpList {
                        property_name_span,
                        eq_span,
                        list_span,
                        lparen_token: Some(lparen_token),
                        rparen_token: Some(rparen_token),
                        values,
                    }
                };

                Ok(AstNetworkPolicyProperty {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: property_name_span.start,
                        end: list_span.end,
                    },
                    kind,
                })
            }

            "ALLOWED_NETWORK_RULE_LIST" | "BLOCKED_NETWORK_RULE_LIST" => {
                // Parse string list: ('rule1', 'rule2', ...)
                let (list_span, lparen_token, rparen_token, rules) = self.parse_string_list()?;

                let kind = if property_name == "ALLOWED_NETWORK_RULE_LIST" {
                    AstNetworkPolicyPropertyKind::AllowedNetworkRuleList {
                        property_name_span,
                        eq_span,
                        list_span,
                        lparen_token: Some(lparen_token),
                        rparen_token: Some(rparen_token),
                        rules,
                    }
                } else {
                    AstNetworkPolicyPropertyKind::BlockedNetworkRuleList {
                        property_name_span,
                        eq_span,
                        list_span,
                        lparen_token: Some(lparen_token),
                        rparen_token: Some(rparen_token),
                        rules,
                    }
                };

                Ok(AstNetworkPolicyProperty {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: property_name_span.start,
                        end: list_span.end,
                    },
                    kind,
                })
            }

            "COMMENT" => {
                // Parse string literal
                let comment_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
                if !matches!(comment_tok.kind, TokenKind::Literal(LiteralKind::String)) {
                    return Err(ParseError::new(
                        comment_tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: vec!["string literal".to_string()],
                            found: comment_tok.lexeme(self.source).to_string(),
                        },
                    ));
                }
                let comment_span = comment_tok.span;

                Ok(AstNetworkPolicyProperty {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: property_name_span.start,
                        end: comment_span.end,
                    },
                    kind: AstNetworkPolicyPropertyKind::Comment {
                        property_name_span,
                        eq_span,
                        comment_span,
                    },
                })
            }

            _ => Err(ParseError::new(
                property_name_span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Unknown network policy property: {}", property_name),
                },
            )),
        }
    }

    /// Parse a string list: ('value1', 'value2', ...)
    fn parse_string_list(
        &mut self,
    ) -> ParseResult<(Span, crate::cst::TokenId, crate::cst::TokenId, Vec<Span>)> {
        // Opening paren
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: vec!["(".to_string()],
                    found: lparen_tok.lexeme(self.source).to_string(),
                },
            ));
        }
        let lparen_token = self.last_token_id();
        let list_start = lparen_tok.span.start;

        let mut values = Vec::new();

        // Parse values (could be empty list)
        loop {
            // Check for closing paren
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    break;
                }
            }

            // Parse string value
            let val_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["string".to_string()])?;
            if !matches!(val_tok.kind, TokenKind::Literal(LiteralKind::String)) {
                return Err(ParseError::new(
                    val_tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["string literal".to_string()],
                        found: val_tok.lexeme(self.source).to_string(),
                    },
                ));
            }
            values.push(val_tok.span);

            // Check for comma or closing paren
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma
                } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    break;
                } else {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: vec![",".to_string(), ")".to_string()],
                            found: tok.lexeme(self.source).to_string(),
                        },
                    ));
                }
            }
        }

        // Closing paren
        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: vec![")".to_string()],
                    found: rparen_tok.lexeme(self.source).to_string(),
                },
            ));
        }
        let rparen_token = self.last_token_id();
        let list_end = rparen_tok.span.end;

        let list_span = Span {
            start: list_start,
            end: list_end,
        };

        Ok((list_span, lparen_token, rparen_token, values))
    }
}
