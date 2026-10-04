// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for ALTER MASKING POLICY statements.
//! Follows the same pattern as alter_stage.rs for consistency.

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterMaskingPolicy, AstAlterMaskingPolicyAction, AstAlterMaskingPolicyActionKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_alter_masking_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_masking_policy")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_keyword = self.last_token_id();

        // MASKING (identifier, not keyword)
        let masking_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MASKING".to_string()])?;

        if !masking_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("MASKING")
        {
            return Err(ParseError::new(
                masking_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected MASKING keyword".to_string(),
                },
            ));
        }
        let masking_span = masking_tok.span;
        let masking_keyword = self.last_token_id();

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
        let policy_keyword = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_keyword, exists_keyword) = self.parse_if_exists_clause_masking()?;

        // Policy name
        let name_span = self.parse_policy_name_masking_alter()?;

        // Parse action
        let action = self.parse_alter_masking_policy_action()?;
        let action_span = action.span;

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        // Build CST
        let syntax_action = crate::syntax::SyntaxAlterMaskingPolicyAction { span: action_span };
        let syntax_action_id = self
            .syntax_arena
            .alloc_alter_masking_policy_action(syntax_action);

        let syntax_stmt = crate::syntax::SyntaxAlterMaskingPolicyStmt {
            alter_keyword,
            masking_keyword,
            policy_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            action_id: syntax_action_id,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_alter_masking_policy_stmt(syntax_stmt);

        // Build AST
        let ast = AstAlterMaskingPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            alter_span,
            masking_span,
            policy_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterMaskingPolicy(Box::new(ast)))
    }

    fn parse_if_exists_clause_masking(
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
                    .expect_invariant("IF keyword: checked in if-let above");
                let if_keyword = Some(self.last_token_id());

                if let Some(exists_tok) = self.peek_non_trivia() {
                    if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        let e = self
                            .advance()
                            .expect_invariant("EXISTS keyword: checked in if-let above");
                        let exists_keyword = Some(self.last_token_id());
                        let if_exists_span = Some(Span {
                            start: if_tok.span.start,
                            end: e.span.end,
                        });
                        return Ok((if_exists_span, if_keyword, exists_keyword));
                    }
                }

                return Err(ParseError::new(
                    if_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "ALTER MASKING POLICY IF requires EXISTS".to_string(),
                    },
                ));
            }
        }
        Ok((None, None, None))
    }

    fn parse_policy_name_masking_alter(&mut self) -> ParseResult<Span> {
        let first_tok = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                self.advance()
                    .expect_invariant("identifier: checked in if-let above")
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["identifier".to_string()],
                        found: tok.lexeme(self.source).to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected policy name".to_string(),
                },
            ));
        };

        let start_pos = first_tok.span.start;
        let mut end_pos = first_tok.span.end;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance();
                if let Some(id_tok) = self.peek_non_trivia() {
                    if matches!(id_tok.kind, TokenKind::Identifier { .. }) {
                        let t = self
                            .advance()
                            .expect_invariant("qualified name part: checked in if-let above");
                        end_pos = t.span.end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(Span {
            start: start_pos,
            end: end_pos,
        })
    }

    fn parse_alter_masking_policy_action(&mut self) -> ParseResult<AstAlterMaskingPolicyAction> {
        let next_tok = self.peek_non_trivia();

        if let Some(tok) = next_tok {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Rename)) {
                return self.parse_masking_rename_action();
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
                return self.parse_masking_set_action();
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset)) {
                return self.parse_masking_unset_action();
            }
        }

        Err(ParseError::new(
            self.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected RENAME, SET, or UNSET".to_string(),
            },
        ))
    }

    fn parse_masking_rename_action(&mut self) -> ParseResult<AstAlterMaskingPolicyAction> {
        let rename_tok = self
            .advance()
            .expect_invariant("RENAME keyword: verified by caller");
        let rename_span = rename_tok.span;

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
        let to_span = to_tok.span;

        let new_name_span = self.parse_policy_name_masking_alter()?;

        let action_span = Span {
            start: rename_span.start,
            end: new_name_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::RenameTo {
                rename_span: Some(rename_span),
                to_span: Some(to_span),
                new_name_span,
            },
        })
    }

    fn parse_masking_set_action(&mut self) -> ParseResult<AstAlterMaskingPolicyAction> {
        let set_tok = self
            .advance()
            .expect_invariant("SET keyword: verified by caller");
        let set_span = set_tok.span;

        let next_tok = self.peek_non_trivia();
        if let Some(tok) = next_tok {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Body)) {
                return self.parse_masking_set_body(set_span);
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                return self.parse_masking_set_tag(set_span);
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                return self.parse_masking_set_comment(set_span);
            }
        }

        Err(ParseError::new(
            self.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected BODY, TAG, or COMMENT after SET".to_string(),
            },
        ))
    }

    fn parse_masking_set_body(
        &mut self,
        set_span: Span,
    ) -> ParseResult<AstAlterMaskingPolicyAction> {
        let body_tok = self
            .advance()
            .expect_invariant("BODY keyword: verified by caller");
        let body_span = body_tok.span;

        let arrow_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
        if !matches!(arrow_tok.kind, TokenKind::Operator(Operator::RightArrow)) {
            return Err(ParseError::new(
                arrow_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected -> operator".to_string(),
                },
            ));
        }
        let arrow_span = arrow_tok.span;

        let body_expr_start = self.current_span().start;
        let body_expr = self.parse_expr()?;
        let expression_span = Span {
            start: body_expr_start,
            end: body_expr.span().end,
        };

        let action_span = Span {
            start: set_span.start,
            end: expression_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::SetBody {
                set_span: Some(set_span),
                body_span: Some(body_span),
                arrow_span: Some(arrow_span),
                expression_span,
                body: Box::new(body_expr),
            },
        })
    }

    fn parse_masking_set_tag(
        &mut self,
        set_span: Span,
    ) -> ParseResult<AstAlterMaskingPolicyAction> {
        let tag_tok = self
            .advance()
            .expect_invariant("TAG keyword: verified by caller");
        let tag_span = tag_tok.span;

        let assignments_start = self.current_span().start;

        loop {
            let _tag_name_span = self.parse_qualified_name_span()?;

            let eq_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
            if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                return Err(ParseError::new(
                    eq_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected = after tag name".to_string(),
                    },
                ));
            }

            let _value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["tag value".to_string()])?;

            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
            }
            break;
        }

        let assignments_end = self.current_span().start;
        let assignments_span = Span {
            start: assignments_start,
            end: assignments_end,
        };

        let action_span = Span {
            start: set_span.start,
            end: assignments_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::SetTag {
                set_span: Some(set_span),
                tag_span: Some(tag_span),
                assignments_span,
            },
        })
    }

    fn parse_masking_set_comment(
        &mut self,
        set_span: Span,
    ) -> ParseResult<AstAlterMaskingPolicyAction> {
        let comment_tok = self
            .advance()
            .expect_invariant("COMMENT keyword: verified by caller");
        let comment_span = comment_tok.span;

        let eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected = after COMMENT".to_string(),
                },
            ));
        }
        let eq_span = eq_tok.span;

        let value_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
        let comment_value_span = value_tok.span;

        let action_span = Span {
            start: set_span.start,
            end: comment_value_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::SetComment {
                set_span: Some(set_span),
                comment_span: Some(comment_span),
                eq_span: Some(eq_span),
                comment_value_span,
            },
        })
    }

    fn parse_masking_unset_action(&mut self) -> ParseResult<AstAlterMaskingPolicyAction> {
        let unset_tok = self
            .advance()
            .expect_invariant("UNSET keyword: verified by caller");
        let unset_span = unset_tok.span;

        let next_tok = self.peek_non_trivia();
        if let Some(tok) = next_tok {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                return self.parse_masking_unset_tag(unset_span);
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                return self.parse_masking_unset_comment(unset_span);
            }
        }

        Err(ParseError::new(
            self.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected TAG or COMMENT after UNSET".to_string(),
            },
        ))
    }

    fn parse_masking_unset_tag(
        &mut self,
        unset_span: Span,
    ) -> ParseResult<AstAlterMaskingPolicyAction> {
        let tag_tok = self
            .advance()
            .expect_invariant("TAG keyword: verified by caller");
        let tag_span = tag_tok.span;

        let tags_start = self.current_span().start;

        loop {
            let _tag_name_span = self.parse_qualified_name_span()?;

            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
            }
            break;
        }

        let tags_end = self.current_span().start;
        let tags_span = Span {
            start: tags_start,
            end: tags_end,
        };

        let action_span = Span {
            start: unset_span.start,
            end: tags_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::UnsetTag {
                unset_span: Some(unset_span),
                tag_span: Some(tag_span),
                tags_span,
            },
        })
    }

    fn parse_masking_unset_comment(
        &mut self,
        unset_span: Span,
    ) -> ParseResult<AstAlterMaskingPolicyAction> {
        let comment_tok = self
            .advance()
            .expect_invariant("COMMENT keyword: verified by caller");
        let comment_span = comment_tok.span;

        let action_span = Span {
            start: unset_span.start,
            end: comment_span.end,
        };

        Ok(AstAlterMaskingPolicyAction {
            node_id: self.id_gen.next(),
            span: action_span,
            syntax_id: None,
            kind: AstAlterMaskingPolicyActionKind::UnsetComment {
                unset_span: Some(unset_span),
                comment_span: Some(comment_span),
            },
        })
    }
}
