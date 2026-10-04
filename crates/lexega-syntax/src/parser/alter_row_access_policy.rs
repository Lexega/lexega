// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// ALTER ROW ACCESS POLICY statement parsing
//
// Implements parsing for ALTER ROW ACCESS POLICY statements including:
// - RENAME TO <new_name>
// - SET BODY -> <expression>
// - SET TAG / UNSET TAG (governance)
// - SET COMMENT / UNSET COMMENT

use crate::ast::{
    AstAlterRowAccessPolicy, AstAlterRowAccessPolicyAction, AstAlterRowAccessPolicyActionKind,
    AstStmt,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxAlterRowAccessPolicyAction, SyntaxAlterRowAccessPolicyStmt};

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_alter_row_access_policy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_row_access_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_keyword = self.last_token_id();

        // ROW
        let row_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ROW".to_string()])?;
        if !matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row))
            && !row_tok.lexeme(self.source).eq_ignore_ascii_case("ROW")
        {
            return Err(ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ROW after ALTER".to_string(),
                },
            ));
        }
        let row_span = row_tok.span;
        let row_keyword = self.last_token_id();

        // ACCESS
        let access_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ACCESS".to_string()])?;
        if !matches!(access_tok.kind, TokenKind::Keyword(Keyword::Access))
            && !access_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("ACCESS")
        {
            return Err(ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ACCESS after ROW".to_string(),
                },
            ));
        }
        let access_span = access_tok.span;
        let access_keyword = self.last_token_id();

        // POLICY
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy))
            && !policy_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("POLICY")
        {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY after ACCESS".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_keyword = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_keyword, exists_keyword) =
            self.parse_if_exists_clause_for_policy()?;

        // Policy name (qualified identifier)
        let name_span = self.parse_policy_name()?;

        // Parse action
        let action_start = self.current_span().start;
        let action = self.parse_alter_row_access_policy_action()?;
        let action_span = Span {
            start: action_start,
            end: action.span.end,
        };

        // Statement span
        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        // Build CST node
        let action_syntax = SyntaxAlterRowAccessPolicyAction { span: action.span };
        let action_id = self
            .syntax_arena
            .alloc_alter_row_access_policy_action(action_syntax);

        let syntax_node = SyntaxAlterRowAccessPolicyStmt {
            alter_keyword,
            row_keyword,
            access_keyword,
            policy_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_row_access_policy_stmt(syntax_node);

        // Build AST node
        let ast = AstAlterRowAccessPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            row_span,
            access_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterRowAccessPolicy(Box::new(ast)))
    }

    /// Parse IF EXISTS clause for ALTER ROW ACCESS POLICY
    fn parse_if_exists_clause_for_policy(
        &mut self,
    ) -> ParseResult<(
        Option<Span>,
        Option<crate::cst::TokenId>,
        Option<crate::cst::TokenId>,
    )> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword available after peek");
                let if_span_start = if_tok.span.start;
                let if_token_id = self.last_token_id();

                // Expect EXISTS
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::UnexpectedToken {
                            expected: vec!["EXISTS".to_string()],
                            found: format!("{:?}", exists_tok.kind),
                        },
                    ));
                }
                let exists_token_id = self.last_token_id();
                let if_exists_span = Span {
                    start: if_span_start,
                    end: exists_tok.span.end,
                };
                return Ok((
                    Some(if_exists_span),
                    Some(if_token_id),
                    Some(exists_token_id),
                ));
            }
        }
        Ok((None, None, None))
    }

    /// Parse policy name (qualified identifier)
    fn parse_policy_name(&mut self) -> ParseResult<Span> {
        let start_span = self.current_span();
        let first_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["identifier".to_string()])?;

        let mut name_end = first_tok.span.end;

        // Handle qualified names (db.schema.policy)
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                let _dot = self
                    .advance()
                    .expect_invariant("dot punctuation available after peek in policy name");
                let part_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                name_end = part_tok.span.end;
            } else {
                break;
            }
        }

        Ok(Span {
            start: first_tok.span.start,
            end: name_end,
        })
    }

    /// Parse ALTER ROW ACCESS POLICY action
    fn parse_alter_row_access_policy_action(
        &mut self,
    ) -> ParseResult<AstAlterRowAccessPolicyAction> {
        let start = self.current_span().start;

        let tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, SET, or UNSET".to_string()],
        )?;

        let kind = match &tok.kind {
            TokenKind::Keyword(Keyword::Rename) => {
                self.advance(); // consume RENAME
                let rename_span = Some(tok.span);

                // TO
                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                let to_span = if matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    Some(to_tok.span)
                } else {
                    None
                };

                // New name
                let new_name_span = self.parse_policy_name()?;

                AstAlterRowAccessPolicyActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                }
            }

            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = Some(tok.span);

                // Check what comes after SET
                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["BODY, TAG, or COMMENT".to_string()],
                )?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Body) => {
                        let body_tok = self
                            .advance()
                            .expect_invariant("BODY keyword available after peek");
                        let body_span = Some(body_tok.span);

                        // Expect arrow (->)
                        let arrow_tok = self
                            .peek_non_trivia()
                            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
                        let arrow_span = if matches!(
                            arrow_tok.kind,
                            TokenKind::Operator(Operator::RightArrow)
                        ) {
                            let tok = self
                                .advance()
                                .expect_invariant("arrow operator available after peek");
                            Some(tok.span)
                        } else {
                            None
                        };

                        // Parse expression (boolean predicate for row access)
                        let expr_start = self.current_span().start;
                        let body_expr = self.parse_expr()?;
                        let expression_span = Span {
                            start: expr_start,
                            end: body_expr.span().end,
                        };

                        AstAlterRowAccessPolicyActionKind::SetBody {
                            set_span,
                            body_span,
                            arrow_span,
                            expression_span,
                            body: Box::new(body_expr),
                        }
                    }

                    TokenKind::Keyword(Keyword::Tag) => {
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword available after peek in SET TAG");
                        let tag_span = Some(tag_tok.span);

                        // Parse tag assignments (tag_name = 'value', ...)
                        let assignments_start = self.current_span().start;
                        let _ = self.consume_until_statement_end_or_semicolon();
                        let assignments_end = self.current_span().end;
                        let assignments_span = Span {
                            start: assignments_start,
                            end: assignments_end,
                        };

                        AstAlterRowAccessPolicyActionKind::SetTag {
                            set_span,
                            tag_span,
                            assignments_span,
                        }
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        let comment_tok = self.advance().expect_invariant(
                            "COMMENT keyword available after peek in SET COMMENT",
                        );
                        let comment_span = Some(comment_tok.span);

                        // Expect =
                        let eq_tok = self.peek_non_trivia();
                        let eq_span = if let Some(tok) = eq_tok {
                            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                                let t = self
                                    .advance()
                                    .expect_invariant("equals operator available after peek");
                                Some(t.span)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // Parse comment value (string literal)
                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["string literal".to_string()])?;
                        let comment_value_span = value_tok.span;

                        AstAlterRowAccessPolicyActionKind::SetComment {
                            set_span,
                            comment_span,
                            eq_span,
                            comment_value_span,
                        }
                    }

                    _ => {
                        return Err(ParseError::new(
                            next_tok.span,
                            ParseErrorKind::UnexpectedToken {
                                expected: vec!["BODY, TAG, or COMMENT".to_string()],
                                found: format!("{:?}", next_tok.kind),
                            },
                        ));
                    }
                }
            }

            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = Some(tok.span);

                // Check what comes after UNSET
                let next_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["TAG or COMMENT".to_string()])?;

                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::Tag) => {
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword available after peek in UNSET TAG");
                        let tag_span = Some(tag_tok.span);

                        // Parse tag names (tag_name, tag_name, ...)
                        let tags_start = self.current_span().start;
                        let _ = self.consume_until_statement_end_or_semicolon();
                        let tags_end = self.current_span().end;
                        let tags_span = Span {
                            start: tags_start,
                            end: tags_end,
                        };

                        AstAlterRowAccessPolicyActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            tags_span,
                        }
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        let comment_tok = self.advance().expect_invariant(
                            "COMMENT keyword available after peek in UNSET COMMENT",
                        );
                        let comment_span = Some(comment_tok.span);

                        AstAlterRowAccessPolicyActionKind::UnsetComment {
                            unset_span,
                            comment_span,
                        }
                    }

                    _ => {
                        return Err(ParseError::new(
                            next_tok.span,
                            ParseErrorKind::UnexpectedToken {
                                expected: vec!["TAG or COMMENT".to_string()],
                                found: format!("{:?}", next_tok.kind),
                            },
                        ));
                    }
                }
            }

            _ => {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["RENAME, SET, or UNSET".to_string()],
                        found: format!("{:?}", tok.kind),
                    },
                ));
            }
        };

        let end = self.current_span().end;
        let span = Span { start, end };

        Ok(AstAlterRowAccessPolicyAction {
            node_id: self.id_gen.next(),
            span,
            syntax_id: None,
            kind,
        })
    }

    /// Consume tokens until statement end or semicolon
    fn consume_until_statement_end_or_semicolon(&mut self) -> ParseResult<()> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            // Check for potential next statement keywords
            if matches!(
                tok.kind,
                TokenKind::Keyword(
                    Keyword::Select
                        | Keyword::Insert
                        | Keyword::Update
                        | Keyword::Delete
                        | Keyword::Create
                        | Keyword::Alter
                        | Keyword::Drop
                        | Keyword::Grant
                        | Keyword::Revoke
                        | Keyword::Deny
                )
            ) {
                break;
            }
            self.advance();
        }
        Ok(())
    }
}
