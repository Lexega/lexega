// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for EXTERNAL ACCESS INTEGRATION statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] EXTERNAL ACCESS INTEGRATION [IF NOT EXISTS] name <properties>`
//! - `ALTER EXTERNAL ACCESS INTEGRATION [IF EXISTS] name { SET | UNSET } <actions>`
//! - `DROP [EXTERNAL ACCESS] INTEGRATION [IF EXISTS] name`
//!
//! Token reference:
//! - "EXTERNAL" is Identifier, NOT Keyword
//! - Property names (ALLOWED_NETWORK_RULES, ENABLED, etc.) are Identifiers
//! - "ALL" is Keyword(All), "NONE" is Identifier
//! - TRUE/FALSE are Literal(Boolean)
//! - COMMENT is Keyword(Comment), TAG is Keyword(Tag)
//! - Must use lexeme matching with eq_ignore_ascii_case()

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterExternalAccessIntegration, AstAlterExternalAccessIntegrationAction,
    AstAlterExternalAccessIntegrationActionKind, AstCreateExternalAccessIntegration,
    AstDropExternalAccessIntegration, AstUnknownClause, UnknownKind,
};
use crate::cst::TokenId;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterExternalAccessIntegration, SyntaxAlterExternalAccessIntegrationAction,
    SyntaxCreateExternalAccessIntegration, SyntaxDropExternalAccessIntegration,
};

impl<'a> Parser<'a> {
    /// Parse CREATE EXTERNAL ACCESS INTEGRATION statement
    pub(crate) fn try_parse_create_external_access_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_external_access_integration")?;

        // CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_keyword = self.last_token_id();
        let start = create_span.start;

        // Optional: OR REPLACE
        let (or_keyword, replace_keyword, or_replace_span) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(&tok.kind, TokenKind::Keyword(Keyword::Or)) {
                    let or_tok = self
                        .advance()
                        .expect_invariant("OR keyword in CREATE EXTERNAL ACCESS INTEGRATION");
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
                    let replace_token_id = self.last_token_id();
                    let or_replace_span = Span {
                        start: or_tok.span.start,
                        end: replace_tok.span.end,
                    };
                    (
                        Some(or_token_id),
                        Some(replace_token_id),
                        Some(or_replace_span),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // EXTERNAL keyword (Identifier, NOT Keyword!)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !matches!(external_tok.kind, TokenKind::Identifier { .. })
            || !external_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected 'EXTERNAL' keyword (as Identifier)".to_string(),
                },
            ));
        }
        let external_span = external_tok.span;
        let external_token = self.last_token_id();

        // ACCESS keyword
        self.expect_keyword(Keyword::Access)?;
        let access_span = self.current_span();
        let access_keyword = self.last_token_id();

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();
        let integration_keyword = self.last_token_id();

        // Optional: IF NOT EXISTS
        let (if_keyword, not_keyword, exists_keyword, if_not_exists_span) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self.advance().expect_invariant(
                        "IF keyword in CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS",
                    );
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
                    let not_token_id = self.last_token_id();

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
                    let exists_token_id = self.last_token_id();
                    let if_not_exists_span = Span {
                        start: if_tok.span.start,
                        end: exists_tok.span.end,
                    };
                    (
                        Some(if_token_id),
                        Some(not_token_id),
                        Some(exists_token_id),
                        Some(if_not_exists_span),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;
        let mut end = integration_name_span.end;
        let mut allowed_network_rules_span: Option<Span> = None;
        let mut allowed_api_authentication_integrations_span: Option<Span> = None;
        let mut allowed_authentication_secrets_span: Option<Span> = None;
        let mut enabled_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut extras: Vec<AstUnknownClause> = Vec::new();

        // Parse properties until semicolon or EOF
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }

            let prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    match lexeme_upper.as_str() {
                        "ALLOWED_NETWORK_RULES" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                            // Parse list: (rule1, rule2, ...)
                            if let Some(lparen_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &lparen_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    self.advance();
                                    let mut paren_depth = 1;
                                    while paren_depth > 0 {
                                        if let Some(t) = self.advance() {
                                            end = t.span.end;
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::LParen)
                                            ) {
                                                paren_depth += 1;
                                            } else if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::RParen)
                                            ) {
                                                paren_depth -= 1;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                            allowed_network_rules_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "ALLOWED_API_AUTHENTICATION_INTEGRATIONS" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                            // Parse list: (name, ...) | (none)
                            if let Some(lparen_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &lparen_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    self.advance();
                                    let mut paren_depth = 1;
                                    while paren_depth > 0 {
                                        if let Some(t) = self.advance() {
                                            end = t.span.end;
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::LParen)
                                            ) {
                                                paren_depth += 1;
                                            } else if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::RParen)
                                            ) {
                                                paren_depth -= 1;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                            allowed_api_authentication_integrations_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "ALLOWED_AUTHENTICATION_SECRETS" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;

                            // Parse list: (name, ...) | (all) | (none)
                            if let Some(lparen_tok) = self.peek_non_trivia() {
                                if matches!(
                                    &lparen_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    self.advance();
                                    let mut paren_depth = 1;
                                    while paren_depth > 0 {
                                        if let Some(t) = self.advance() {
                                            end = t.span.end;
                                            if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::LParen)
                                            ) {
                                                paren_depth += 1;
                                            } else if matches!(
                                                t.kind,
                                                TokenKind::Punctuation(Punctuation::RParen)
                                            ) {
                                                paren_depth -= 1;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                            allowed_authentication_secrets_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        "ENABLED" => {
                            self.advance();
                            let _eq = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                            let val = self.advance().ok_or_eof(
                                self.current_span(),
                                vec!["TRUE or FALSE".to_string()],
                            )?;
                            end = val.span.end;
                            enabled_span = Some(Span {
                                start: prop_start,
                                end,
                            });
                        }
                        _ => {
                            // Unknown property - defensive design
                            self.advance();
                            if let Some(eq_tok) = self.peek_non_trivia() {
                                if matches!(&eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                    self.advance();
                                    // Consume value (may be parenthesized list)
                                    if let Some(next) = self.peek_non_trivia() {
                                        if matches!(
                                            &next.kind,
                                            TokenKind::Punctuation(Punctuation::LParen)
                                        ) {
                                            self.advance();
                                            let mut paren_depth = 1;
                                            while paren_depth > 0 {
                                                if let Some(t) = self.advance() {
                                                    end = t.span.end;
                                                    if matches!(
                                                        t.kind,
                                                        TokenKind::Punctuation(Punctuation::LParen)
                                                    ) {
                                                        paren_depth += 1;
                                                    } else if matches!(
                                                        t.kind,
                                                        TokenKind::Punctuation(Punctuation::RParen)
                                                    ) {
                                                        paren_depth -= 1;
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                        } else if let Some(val) = self.advance() {
                                            end = val.span.end;
                                        }
                                    }
                                    extras.push(AstUnknownClause {
                                        introducer: Some(Span {
                                            start: prop_start,
                                            end: tok.span.end,
                                        }),
                                        span: Span {
                                            start: prop_start,
                                            end,
                                        },
                                        kind: UnknownKind::Property,
                                        node_id: self.id_gen.next(),
                                    });
                                }
                            }
                        }
                    }
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    self.advance();
                    let _eq = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let val = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                    end = val.span.end;
                    comment_span = Some(Span {
                        start: prop_start,
                        end,
                    });
                }
                _ => {
                    // Unknown token, skip to prevent infinite loop
                    self.advance();
                }
            }
        }

        // Calculate statement span
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxCreateExternalAccessIntegration {
            create_keyword,
            or_keyword,
            replace_keyword,
            external_token,
            access_keyword,
            integration_keyword,
            if_keyword,
            not_keyword,
            exists_keyword,
            integration_name_span,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_create_external_access_integration(syntax_node);

        // Build AST node
        let ast = AstCreateExternalAccessIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            if_not_exists_span,
            external_span,
            access_span,
            integration_span,
            integration_name_span,
            allowed_network_rules_span,
            allowed_api_authentication_integrations_span,
            allowed_authentication_secrets_span,
            enabled_span,
            comment_span,
            extras,
        };
        Ok(AstStmt::CreateExternalAccessIntegration(Box::new(ast)))
    }

    /// Parse ALTER EXTERNAL ACCESS INTEGRATION statement
    pub(crate) fn try_parse_alter_external_access_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_external_access_integration")?;

        // ALTER keyword
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_keyword = self.last_token_id();
        let start = alter_span.start;

        // EXTERNAL keyword (Identifier, NOT Keyword!)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !matches!(external_tok.kind, TokenKind::Identifier { .. })
            || !external_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected 'EXTERNAL' keyword".to_string(),
                },
            ));
        }
        let external_span = external_tok.span;
        let external_token = self.last_token_id();

        // ACCESS keyword
        self.expect_keyword(Keyword::Access)?;
        let access_span = self.current_span();
        let access_keyword = self.last_token_id();

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();
        let integration_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let (if_keyword, exists_keyword, if_exists_span) = if let Some(tok) = self.peek_non_trivia()
        {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword in ALTER EXTERNAL ACCESS INTEGRATION IF EXISTS");
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
                let exists_token_id = self.last_token_id();
                let if_exists_span = Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                };
                (
                    Some(if_token_id),
                    Some(exists_token_id),
                    Some(if_exists_span),
                )
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        // Integration name
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Parse action: SET or UNSET
        let action_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET or UNSET".to_string()])?;
        let action_start = action_tok.span.start;

        let mut actions: Vec<AstAlterExternalAccessIntegrationAction> = Vec::new();

        if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            // SET action
            let set_span = Some(action_tok.span);

            // Check for TAG after SET
            if let Some(next_tok) = self.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // SET TAG
                    let tag_tok = self.advance().expect_invariant(
                        "TAG keyword after SET in ALTER EXTERNAL ACCESS INTEGRATION",
                    );
                    let tag_span = Some(tag_tok.span);

                    // Parse tag assignments: tag_name = 'value' [, ...]
                    let tags_start = self.current_span().start;
                    let mut tags_end;

                    loop {
                        // tag_name (possibly qualified: db.schema.tag_name)
                        let tag_name_span = self.parse_qualified_name_span()?;
                        tags_end = tag_name_span.end;

                        // =
                        let Some(eq) = self.peek_non_trivia() else {
                            break;
                        };
                        if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                            self.advance();
                            tags_end = self.current_span().end;
                        } else {
                            break;
                        }

                        // 'value'
                        let Some(val) = self.advance() else {
                            break;
                        };
                        tags_end = val.span.end;

                        // Check for comma
                        let Some(comma) = self.peek_non_trivia() else {
                            break;
                        };
                        if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            self.advance();
                        } else {
                            break;
                        }
                    }

                    end = tags_end;
                    let tags_span = Span {
                        start: tags_start,
                        end: tags_end,
                    };
                    let action_span = Span {
                        start: action_start,
                        end,
                    };

                    let syntax_action =
                        SyntaxAlterExternalAccessIntegrationAction { span: action_span };
                    let action_id = self
                        .syntax_arena
                        .alloc_alter_external_access_integration_action(syntax_action);

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: Some(action_id),
                        kind: AstAlterExternalAccessIntegrationActionKind::SetTag {
                            set_span,
                            tag_span,
                            tags_span,
                        },
                    });
                } else {
                    // SET property = value
                    self.parse_external_access_set_properties(
                        &mut actions,
                        set_span,
                        action_start,
                        &mut end,
                    )?;
                }
            }
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Unset)) {
            // UNSET action
            let unset_span = Some(action_tok.span);

            // Check for TAG after UNSET
            if let Some(next_tok) = self.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    // UNSET TAG
                    let tag_tok = self.advance().expect_invariant(
                        "TAG keyword after UNSET in ALTER EXTERNAL ACCESS INTEGRATION",
                    );
                    let tag_span = Some(tag_tok.span);

                    // Parse tag names: tag_name [, tag_name, ...]
                    let tags_start = self.current_span().start;
                    let mut tags_end;

                    loop {
                        // tag_name (possibly qualified: db.schema.tag_name)
                        let tag_name_span = self.parse_qualified_name_span()?;
                        tags_end = tag_name_span.end;

                        // Check for comma
                        let Some(comma) = self.peek_non_trivia() else {
                            break;
                        };
                        if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            self.advance();
                        } else {
                            break;
                        }
                    }

                    end = tags_end;
                    let tags_span = Span {
                        start: tags_start,
                        end: tags_end,
                    };
                    let action_span = Span {
                        start: action_start,
                        end,
                    };

                    let syntax_action =
                        SyntaxAlterExternalAccessIntegrationAction { span: action_span };
                    let action_id = self
                        .syntax_arena
                        .alloc_alter_external_access_integration_action(syntax_action);

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: action_span,
                        syntax_id: Some(action_id),
                        kind: AstAlterExternalAccessIntegrationActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            tags_span,
                        },
                    });
                } else {
                    // UNSET property [, property, ...]
                    self.parse_external_access_unset_properties(
                        &mut actions,
                        unset_span,
                        action_start,
                        &mut end,
                    )?;
                }
            }
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            let rename_span = action_tok.span;
            self.expect_keyword(Keyword::To)?;
            let to_span = self.current_span();
            let new_name_span = self.parse_qualified_name_span()?;
            end = new_name_span.end;
            let action_span = Span {
                start: action_start,
                end,
            };

            let syntax_action = SyntaxAlterExternalAccessIntegrationAction { span: action_span };
            let action_id = self
                .syntax_arena
                .alloc_alter_external_access_integration_action(syntax_action);

            actions.push(AstAlterExternalAccessIntegrationAction {
                node_id: self.id_gen.next(),
                span: action_span,
                syntax_id: Some(action_id),
                kind: AstAlterExternalAccessIntegrationActionKind::Rename {
                    rename_span,
                    to_span,
                    new_name_span,
                },
            });
        } else {
            return Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SET, UNSET, or RENAME after integration name".to_string(),
                },
            ));
        }

        // Calculate action_span and statement span
        let action_span = Span {
            start: action_start,
            end,
        };
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_action = SyntaxAlterExternalAccessIntegrationAction { span: action_span };
        let action_id = self
            .syntax_arena
            .alloc_alter_external_access_integration_action(syntax_action);

        let syntax_node = SyntaxAlterExternalAccessIntegration {
            alter_keyword,
            external_token,
            access_keyword,
            integration_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_external_access_integration_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterExternalAccessIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            external_span,
            access_span,
            integration_span,
            if_exists_span,
            name_span,
            action_span,
            actions,
        };
        Ok(AstStmt::AlterExternalAccessIntegration(Box::new(ast)))
    }

    /// Parse SET properties for ALTER EXTERNAL ACCESS INTEGRATION
    fn parse_external_access_set_properties(
        &mut self,
        actions: &mut Vec<AstAlterExternalAccessIntegrationAction>,
        set_span: Option<Span>,
        action_start: u32,
        end: &mut u32,
    ) -> ParseResult<()> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }

            let _prop_start = tok.span.start;

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    let property_span = tok.span;
                    self.advance();

                    // Expect =
                    let eq_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let eq_span = Some(eq_tok.span);

                    // Parse value
                    let value_start = self.current_span().start;
                    let mut value_end = value_start;

                    if let Some(next) = self.peek_non_trivia() {
                        if matches!(&next.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            self.advance();
                            let mut paren_depth = 1;
                            while paren_depth > 0 {
                                if let Some(t) = self.advance() {
                                    value_end = t.span.end;
                                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
                                    {
                                        paren_depth += 1;
                                    } else if matches!(
                                        t.kind,
                                        TokenKind::Punctuation(Punctuation::RParen)
                                    ) {
                                        paren_depth -= 1;
                                    }
                                } else {
                                    break;
                                }
                            }
                        } else if let Some(val) = self.advance() {
                            value_end = val.span.end;
                        }
                    }

                    *end = value_end;
                    let value_span = Span {
                        start: value_start,
                        end: value_end,
                    };
                    let full_span = Span {
                        start: action_start,
                        end: value_end,
                    };

                    let syntax_action =
                        SyntaxAlterExternalAccessIntegrationAction { span: full_span };
                    let action_id = self
                        .syntax_arena
                        .alloc_alter_external_access_integration_action(syntax_action);

                    let kind = match lexeme_upper.as_str() {
                        "ALLOWED_NETWORK_RULES" => {
                            AstAlterExternalAccessIntegrationActionKind::SetAllowedNetworkRules {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "ALLOWED_API_AUTHENTICATION_INTEGRATIONS" => {
                            AstAlterExternalAccessIntegrationActionKind::SetAllowedApiAuthenticationIntegrations {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "ALLOWED_AUTHENTICATION_SECRETS" => {
                            AstAlterExternalAccessIntegrationActionKind::SetAllowedAuthenticationSecrets {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        "ENABLED" => {
                            AstAlterExternalAccessIntegrationActionKind::SetEnabled {
                                set_span,
                                property_span,
                                eq_span,
                                value_span,
                            }
                        }
                        _ => {
                            // Unknown property - skip but don't fail
                            continue;
                        }
                    };

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: full_span,
                        syntax_id: Some(action_id),
                        kind,
                    });
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    let comment_span = tok.span;
                    self.advance();

                    let eq_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                    let eq_span = Some(eq_tok.span);

                    let val_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["comment value".to_string()])?;
                    let value_span = val_tok.span;
                    *end = value_span.end;

                    let full_span = Span {
                        start: action_start,
                        end: *end,
                    };

                    let syntax_action =
                        SyntaxAlterExternalAccessIntegrationAction { span: full_span };
                    let action_id = self
                        .syntax_arena
                        .alloc_alter_external_access_integration_action(syntax_action);

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: full_span,
                        syntax_id: Some(action_id),
                        kind: AstAlterExternalAccessIntegrationActionKind::SetComment {
                            set_span,
                            comment_span,
                            eq_span,
                            value_span,
                        },
                    });
                }
                _ => {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Parse UNSET properties for ALTER EXTERNAL ACCESS INTEGRATION
    fn parse_external_access_unset_properties(
        &mut self,
        actions: &mut Vec<AstAlterExternalAccessIntegrationAction>,
        unset_span: Option<Span>,
        action_start: u32,
        end: &mut u32,
    ) -> ParseResult<()> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                &tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }

            let property_span = tok.span;
            *end = property_span.end;
            let full_span = Span {
                start: action_start,
                end: *end,
            };

            let syntax_action = SyntaxAlterExternalAccessIntegrationAction { span: full_span };
            let action_id = self
                .syntax_arena
                .alloc_alter_external_access_integration_action(syntax_action);

            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let lexeme_upper = tok.lexeme(self.source).to_uppercase();
                    self.advance();

                    let kind = match lexeme_upper.as_str() {
                            "ALLOWED_NETWORK_RULES" => {
                                AstAlterExternalAccessIntegrationActionKind::UnsetAllowedNetworkRules {
                                    unset_span,
                                    property_span,
                                }
                            }
                            "ALLOWED_API_AUTHENTICATION_INTEGRATIONS" => {
                                AstAlterExternalAccessIntegrationActionKind::UnsetAllowedApiAuthenticationIntegrations {
                                    unset_span,
                                    property_span,
                                }
                            }
                            "ALLOWED_AUTHENTICATION_SECRETS" => {
                                AstAlterExternalAccessIntegrationActionKind::UnsetAllowedAuthenticationSecrets {
                                    unset_span,
                                    property_span,
                                }
                            }
                            "ENABLED" => {
                                AstAlterExternalAccessIntegrationActionKind::UnsetEnabled {
                                    unset_span,
                                    property_span,
                                }
                            }
                            _ => {
                                // Unknown property - check for comma and continue
                                if let Some(comma) = self.peek_non_trivia() {
                                    if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                        self.advance();
                                    }
                                }
                                continue;
                            }
                        };

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: full_span,
                        syntax_id: Some(action_id),
                        kind,
                    });
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    let comment_span = tok.span;
                    self.advance();
                    *end = comment_span.end;

                    actions.push(AstAlterExternalAccessIntegrationAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: *end,
                        },
                        syntax_id: Some(action_id),
                        kind: AstAlterExternalAccessIntegrationActionKind::UnsetComment {
                            unset_span,
                            comment_span,
                        },
                    });
                }
                _ => {
                    break;
                }
            }

            // Check for comma
            if let Some(comma) = self.peek_non_trivia() {
                if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Parse DROP EXTERNAL ACCESS INTEGRATION statement
    pub(crate) fn try_parse_drop_external_access_integration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_external_access_integration")?;

        // DROP keyword
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_keyword = self.last_token_id();
        let start = drop_span.start;

        // Check for EXTERNAL (optional - can be just "DROP INTEGRATION")
        let mut external_span: Option<Span> = None;
        let mut external_token: Option<TokenId> = None;
        let mut access_span: Option<Span> = None;
        let mut access_keyword: Option<TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("EXTERNAL")
            {
                let ext_tok = self
                    .advance()
                    .expect_invariant("EXTERNAL identifier in DROP EXTERNAL ACCESS INTEGRATION");
                external_span = Some(ext_tok.span);
                external_token = Some(self.last_token_id());

                // ACCESS keyword
                self.expect_keyword(Keyword::Access)?;
                access_span = Some(self.current_span());
                access_keyword = Some(self.last_token_id());
            }
        }

        // INTEGRATION keyword
        self.expect_keyword(Keyword::Integration)?;
        let integration_span = self.current_span();
        let integration_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let (if_keyword, exists_keyword, if_exists_span) = if let Some(tok) = self.peek_non_trivia()
        {
            if matches!(&tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword in DROP EXTERNAL ACCESS INTEGRATION IF EXISTS");
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
                let exists_token_id = self.last_token_id();
                let if_exists_span = Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                };
                (
                    Some(if_token_id),
                    Some(exists_token_id),
                    Some(if_exists_span),
                )
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        // Integration name
        let integration_name_span = self.parse_qualified_name_span()?;
        let end = integration_name_span.end;

        // Calculate statement span
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxDropExternalAccessIntegration {
            drop_keyword,
            external_token,
            access_keyword,
            integration_keyword,
            if_keyword,
            exists_keyword,
            integration_name_span,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_drop_external_access_integration(syntax_node);

        // Build AST node
        let ast = AstDropExternalAccessIntegration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            external_span,
            access_span,
            integration_span,
            if_exists_span,
            integration_name_span,
        };
        Ok(AstStmt::DropExternalAccessIntegration(Box::new(ast)))
    }
}
