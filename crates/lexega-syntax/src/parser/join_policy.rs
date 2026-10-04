// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake JOIN POLICY statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] JOIN POLICY [IF NOT EXISTS] name AS () RETURNS JOIN_CONSTRAINT -> <body>`
//! - `ALTER JOIN POLICY [IF EXISTS] name { RENAME TO | SET BODY | SET/UNSET TAG | SET/UNSET COMMENT }`
//! - `DROP JOIN POLICY [IF EXISTS] name`
//!
//! Span-only (no CST layer); the formatter emits the statement's span as
//! written (`push_span`). `JOIN` and `JOIN_CONSTRAINT` are Identifier tokens, not
//! Keywords. The body is parsed into an `AstExpr` so consumers can read
//! `JOIN_CONSTRAINT(JOIN_REQUIRED => <bool>)`.

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterJoinPolicy, AstAlterJoinPolicyAction, AstAlterJoinPolicyActionKind,
    AstCreateJoinPolicy, AstDropJoinPolicy,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE [OR REPLACE] JOIN POLICY [IF NOT EXISTS] <name>
    ///   AS () RETURNS JOIN_CONSTRAINT -> <body> [COMMENT = '<text>']`.
    pub(crate) fn try_parse_create_join_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_join_policy")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        let or_replace_span = self.parse_optional_or_replace()?;
        let join_span = self.expect_join_identifier()?;
        let policy_span = self.expect_policy_keyword()?;
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let policy_name_span = self.parse_qualified_name_span()?;

        // AS
        self.expect_keyword(Keyword::As)?;
        // ( )
        self.expect_punct(Punctuation::LParen, "(")?;
        self.expect_punct(Punctuation::RParen, ")")?;
        // RETURNS
        self.expect_keyword(Keyword::Returns)?;
        // JOIN_CONSTRAINT (Identifier)
        let return_type_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["JOIN_CONSTRAINT".to_string()])?;
        if !matches!(return_type_tok.kind, TokenKind::Identifier { .. })
            || !return_type_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("JOIN_CONSTRAINT")
        {
            return Err(ParseError::new(
                return_type_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected JOIN_CONSTRAINT type".to_string(),
                },
            ));
        }
        // ->
        self.expect_arrow()?;

        // Body expression. Propagate a parse failure (matching the masking /
        // row-access policy parsers) so an unparseable body surfaces as
        // OpaqueContent-with-reason at the statement level instead of being
        // silently dropped to `None`.
        let body = self.parse_expr()?;
        let body_end = body.span().end;
        let body_expr = Some(Box::new(body));

        // Optional COMMENT = '<string>'
        let (comment_span, comment_end) = self.parse_optional_policy_comment(body_end)?;

        let ast = AstCreateJoinPolicy {
            node_id: self.id_gen.next(),
            span: Span {
                start: create_span.start,
                end: comment_end,
            },
            create_span,
            or_replace_span,
            join_span,
            policy_span,
            if_not_exists_span,
            policy_name_span,
            body_expr,
            comment_span,
        };
        Ok(AstStmt::CreateJoinPolicy(Box::new(ast)))
    }

    /// Parse `ALTER JOIN POLICY [IF EXISTS] <name> <action>`.
    pub(crate) fn try_parse_alter_join_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_join_policy")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        let join_span = self.expect_join_identifier()?;
        let policy_span = self.expect_policy_keyword()?;
        let if_exists_span = self.parse_optional_if_exists_stmt()?;
        let name_span = self.parse_qualified_name_span()?;

        let action = self.parse_alter_join_policy_action()?;
        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let ast = AstAlterJoinPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            join_span,
            policy_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterJoinPolicy(Box::new(ast)))
    }

    fn parse_alter_join_policy_action(&mut self) -> ParseResult<AstAlterJoinPolicyAction> {
        let action_start = self.current_span().start;
        let tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["action".to_string()])?;

        let kind = match &tok.kind {
            TokenKind::Keyword(Keyword::Rename) => {
                self.advance().expect_invariant("RENAME after peek");
                self.expect_keyword(Keyword::To)?;
                let new_name_span = self.parse_qualified_name_span()?;
                AstAlterJoinPolicyActionKind::RenameTo { new_name_span }
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance().expect_invariant("SET after peek");
                let next = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["BODY | TAG | COMMENT".to_string()],
                )?;
                match &next.kind {
                    TokenKind::Keyword(Keyword::Body) => {
                        self.advance().expect_invariant("BODY after peek");
                        self.expect_arrow()?;
                        // Propagate a parse failure (see the CREATE path) instead
                        // of masking an unparseable body as `None`.
                        let body = self.parse_expr()?;
                        let expression_span = body.span();
                        AstAlterJoinPolicyActionKind::SetBody {
                            expression_span,
                            body_expr: Some(Box::new(body)),
                        }
                    }
                    TokenKind::Keyword(Keyword::Tag) => {
                        self.advance().expect_invariant("TAG after peek");
                        let assignments_span = self.parse_tag_assignment_list()?;
                        AstAlterJoinPolicyActionKind::SetTag { assignments_span }
                    }
                    TokenKind::Keyword(Keyword::Comment) => {
                        self.advance().expect_invariant("COMMENT after peek");
                        self.expect_eq()?;
                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["comment_string".to_string()])?;
                        AstAlterJoinPolicyActionKind::SetComment {
                            comment_value_span: value_tok.span,
                        }
                    }
                    _ => {
                        return Err(ParseError::new(
                            next.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected BODY, TAG, or COMMENT after SET".to_string(),
                            },
                        ));
                    }
                }
            }
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance().expect_invariant("UNSET after peek");
                let next = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["TAG | COMMENT".to_string()])?;
                match &next.kind {
                    TokenKind::Keyword(Keyword::Tag) => {
                        self.advance().expect_invariant("TAG after peek");
                        let tags_span = self.parse_tag_name_list()?;
                        AstAlterJoinPolicyActionKind::UnsetTag { tags_span }
                    }
                    TokenKind::Keyword(Keyword::Comment) => {
                        self.advance().expect_invariant("COMMENT after peek");
                        AstAlterJoinPolicyActionKind::UnsetComment
                    }
                    _ => {
                        return Err(ParseError::new(
                            next.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected TAG or COMMENT after UNSET".to_string(),
                            },
                        ));
                    }
                }
            }
            _ => {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected RENAME, SET, or UNSET".to_string(),
                    },
                ));
            }
        };

        let action_end = self.current_span().start;
        Ok(AstAlterJoinPolicyAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end: action_end,
            },
            kind,
        })
    }

    /// Parse `DROP JOIN POLICY [IF EXISTS] <name>`.
    pub(crate) fn try_parse_drop_join_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_join_policy")?;

        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;

        let join_span = self.expect_join_identifier()?;
        let policy_span = self.expect_policy_keyword()?;
        let if_exists_span = self.parse_optional_if_exists_stmt()?;
        let policy_name_span = self.parse_qualified_name_span()?;

        let ast = AstDropJoinPolicy {
            node_id: self.id_gen.next(),
            span: Span {
                start: drop_span.start,
                end: policy_name_span.end,
            },
            drop_span,
            join_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropJoinPolicy(Box::new(ast)))
    }

    // ── small shared helpers (JOIN POLICY-local) ──

    /// `JOIN` lexes as `Keyword::Join` (the query keyword); accept that or
    /// an Identifier with the matching lexeme.
    fn expect_join_identifier(&mut self) -> ParseResult<Span> {
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["JOIN".to_string()])?;
        let is_join = matches!(tok.kind, TokenKind::Keyword(Keyword::Join))
            || (matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("JOIN"));
        if !is_join {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected JOIN keyword".to_string(),
                },
            ));
        }
        Ok(tok.span)
    }

    fn expect_policy_keyword(&mut self) -> ParseResult<Span> {
        self.expect_keyword(Keyword::Policy)
    }

    fn expect_punct(&mut self, punct: Punctuation, label: &str) -> ParseResult<Span> {
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![label.to_string()])?;
        if !matches!(tok.kind, TokenKind::Punctuation(p) if p == punct) {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected '{}'", label),
                },
            ));
        }
        Ok(tok.span)
    }

    fn expect_arrow(&mut self) -> ParseResult<Span> {
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["->".to_string()])?;
        if !matches!(tok.kind, TokenKind::Operator(Operator::RightArrow)) {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '->' operator".to_string(),
                },
            ));
        }
        Ok(tok.span)
    }

    fn expect_eq(&mut self) -> ParseResult<Span> {
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '='".to_string(),
                },
            ));
        }
        Ok(tok.span)
    }

    /// `IF EXISTS` at statement level (ALTER / DROP).
    fn parse_optional_if_exists_stmt(&mut self) -> ParseResult<Option<Span>> {
        let Some(tok) = self.peek_non_trivia() else {
            return Ok(None);
        };
        if !matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            return Ok(None);
        }
        let if_tok = self.advance().expect_invariant("IF after peek");
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
        Ok(Some(Span {
            start: if_tok.span.start,
            end: exists_tok.span.end,
        }))
    }

    /// Optional trailing `COMMENT = '<string>'`. Returns `(value_span,
    /// new_end)` where `value_span` covers the comment value only.
    fn parse_optional_policy_comment(
        &mut self,
        current_end: u32,
    ) -> ParseResult<(Option<Span>, u32)> {
        let Some(tok) = self.peek_non_trivia() else {
            return Ok((None, current_end));
        };
        if !matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            return Ok((None, current_end));
        }
        self.advance().expect_invariant("COMMENT after peek");
        self.expect_eq()?;
        let value_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["comment_string".to_string()])?;
        Ok((Some(value_tok.span), value_tok.span.end))
    }

    /// `<name> = '<value>' [, ...]` — returns the span covering the list.
    fn parse_tag_assignment_list(&mut self) -> ParseResult<Span> {
        let start = self.current_span().start;
        let mut end;
        loop {
            let _name = self.parse_qualified_name_span()?;
            self.expect_eq()?;
            let value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["tag_value".to_string()])?;
            end = value_tok.span.end;
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
            }
            break;
        }
        Ok(Span { start, end })
    }

    /// `<name> [, ...]` — returns the span covering the list.
    fn parse_tag_name_list(&mut self) -> ParseResult<Span> {
        let start = self.current_span().start;
        let mut end;
        loop {
            let name = self.parse_qualified_name_span()?;
            end = name.end;
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
            }
            break;
        }
        Ok(Span { start, end })
    }
}
