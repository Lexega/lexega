// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Jinja expression parsing.
//!
//! Parses Jinja template expressions inside {{ }} and {% %} delimiters using
//! Pratt operator precedence parsing.
//!
//! ## Grammar
//!
//! ```text
//! expr := or_expr
//! or_expr := and_expr ('or' and_expr)*
//! and_expr := not_expr ('and' not_expr)*
//! not_expr := 'not' not_expr | comparison
//! comparison := concat (('==' | '!=' | '<' | '<=' | '>' | '>=' | 'in' | 'not' 'in' | 'is' | 'is' 'not') concat)?
//! concat := add_expr ('~' add_expr)*
//! add_expr := mult_expr (('+' | '-') mult_expr)*
//! mult_expr := unary_expr (('*' | '/' | '//' | '%') unary_expr)*
//! unary_expr := ('-' | '+') unary_expr | power_expr
//! power_expr := postfix_expr ('**' unary_expr)?
//! postfix_expr := primary ('.' identifier | '[' expr ']' | '(' args ')' | '|' identifier ('(' args ')')? )*
//! primary := identifier | literal | '(' expr ')' | '[' list_items ']' | '{' dict_items '}'
//! ```

use crate::ast::{
    JinjaArg, JinjaBinaryOp, JinjaExpr, JinjaExprKind, JinjaLiteralValue, JinjaUnaryOp,
};
use crate::error::{ExpectInvariant, ParseResult};
use crate::lexer::{Operator, Punctuation, Span, Token, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxJinjaArg, SyntaxJinjaArgKind, SyntaxJinjaBinaryOpTokens, SyntaxJinjaExpr,
    SyntaxJinjaExprKind, SyntaxJinjaFilterArgs,
};

impl<'a> Parser<'a> {
    /// Parse a complete Jinja expression.
    ///
    /// Entry point for parsing Jinja expressions inside {{ }} or {% %} delimiters.
    /// Assumes the opening delimiter has already been consumed.
    ///
    /// Returns `None` if parsing fails (expression is malformed or empty).
    pub(crate) fn parse_jinja_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_expr")?;
        let result = self.parse_jinja_or_expr()?;
        Ok(result)
    }

    #[inline]
    fn attach_jinja_expr_syntax(
        &mut self,
        mut expr: JinjaExpr,
        kind: SyntaxJinjaExprKind,
    ) -> JinjaExpr {
        let syntax_id = self.syntax_arena.alloc_jinja_expr(SyntaxJinjaExpr {
            kind,
            span: expr.span,
        });
        expr.syntax_id = Some(syntax_id);
        expr
    }

    #[inline]
    fn attach_jinja_arg_syntax(&mut self, mut arg: JinjaArg, kind: SyntaxJinjaArgKind) -> JinjaArg {
        let syntax_id = self.syntax_arena.alloc_jinja_arg(SyntaxJinjaArg {
            kind,
            span: arg.span,
        });
        arg.syntax_id = Some(syntax_id);
        arg
    }

    /// Parse 'or' expression (lowest precedence).
    fn parse_jinja_or_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_or")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut left = match self.parse_jinja_and_expr()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while self.peek_jinja_keyword("or") {
                self.advance(); // consume 'or'
                let op_token_id = self.last_token_id();
                let right = match self.parse_jinja_and_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                let left_id = left
                    .syntax_id
                    .expect_invariant("left expression missing syntax_id");
                let right_id = right
                    .syntax_id
                    .expect_invariant("right expression missing syntax_id");
                let expr = JinjaExpr::binary(left, JinjaBinaryOp::Or, right, span);
                left = self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::BinaryOp {
                        left: left_id,
                        op_tokens: SyntaxJinjaBinaryOpTokens {
                            primary: op_token_id,
                            secondary: None,
                        },
                        right: right_id,
                    },
                );
            }

            Ok(Some(left))
        })();
        result
    }

    /// Parse 'and' expression.
    fn parse_jinja_and_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_and")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut left = match self.parse_jinja_not_expr()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while self.peek_jinja_keyword("and") {
                self.advance(); // consume 'and'
                let op_token_id = self.last_token_id();
                let right = match self.parse_jinja_not_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                let left_id = left
                    .syntax_id
                    .expect_invariant("left expression missing syntax_id");
                let right_id = right
                    .syntax_id
                    .expect_invariant("right expression missing syntax_id");
                let expr = JinjaExpr::binary(left, JinjaBinaryOp::And, right, span);
                left = self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::BinaryOp {
                        left: left_id,
                        op_tokens: SyntaxJinjaBinaryOpTokens {
                            primary: op_token_id,
                            secondary: None,
                        },
                        right: right_id,
                    },
                );
            }

            Ok(Some(left))
        })();
        result
    }

    /// Parse 'not' expression.
    fn parse_jinja_not_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_not")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            if self.peek_jinja_keyword("not") {
                let start = match self.peek() {
                    Some(t) => t.span.start,
                    None => return Ok(None),
                };
                self.advance(); // consume 'not'
                let op_token_id = self.last_token_id();

                let operand = match self.parse_jinja_not_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let operand_id = operand
                    .syntax_id
                    .expect_invariant("operand missing syntax_id");
                let span = Span {
                    start,
                    end: operand.span.end,
                };
                let expr = JinjaExpr {
                    kind: JinjaExprKind::UnaryOp {
                        op: JinjaUnaryOp::Not,
                        expr: Box::new(operand),
                    },
                    span,
                    syntax_id: None,
                    node_id: self.id_gen.next(),
                };
                return Ok(Some(self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::UnaryOp {
                        op: op_token_id,
                        expr: operand_id,
                    },
                )));
            }

            self.parse_jinja_comparison()
        })();
        result
    }

    /// Parse comparison expressions.
    fn parse_jinja_comparison(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_comparison")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let left = match self.parse_jinja_concat()? {
                Some(e) => e,
                None => return Ok(None),
            };
            let left_id = left
                .syntax_id
                .expect_invariant("left expression missing syntax_id");

            if self.peek_jinja_keyword("is") {
                let start = left.span.start;
                self.advance(); // consume 'is'
                let is_token_id = self.last_token_id();

                let not_token_id = if self.peek_jinja_keyword("not") {
                    self.advance();
                    Some(self.last_token_id())
                } else {
                    None
                };

                let test_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let test_token_id = self.last_token_id();

                let test_name = match &test_tok.kind {
                    TokenKind::Identifier { .. }
                    | TokenKind::JinjaTrue
                    | TokenKind::JinjaFalse
                    | TokenKind::JinjaNull => test_tok.lexeme(self.source).to_string(),
                    _ => return Ok(None),
                };

                let mut args = Vec::new();
                let mut syntax_args = None;
                let mut end = test_tok.span.end;

                if matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(Punctuation::LParen))
                ) {
                    self.advance(); // consume '('
                    let lparen_id = self.last_token_id();
                    let parsed_args = match self.parse_jinja_args()? {
                        Some(a) => a,
                        None => return Ok(None),
                    };
                    let arg_ids: Vec<_> = parsed_args
                        .iter()
                        .map(|arg| arg.syntax_id.expect_invariant("argument missing syntax_id"))
                        .collect();
                    let rparen_tok = match self.expect_punctuation(Punctuation::RParen) {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let rparen_id = self.last_token_id();
                    end = rparen_tok.span.end;
                    syntax_args = Some((
                        SyntaxJinjaFilterArgs {
                            lparen: lparen_id,
                            rparen: rparen_id,
                        },
                        arg_ids,
                    ));
                    args = parsed_args;
                }

                let span = Span { start, end };
                let expr = JinjaExpr {
                    kind: JinjaExprKind::Test {
                        expr: Box::new(left),
                        test: test_name,
                        args,
                    },
                    span,
                    syntax_id: None,
                    node_id: self.id_gen.next(),
                };

                return Ok(Some(self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::Test {
                        expr: left_id,
                        is_keyword: is_token_id,
                        not_keyword: not_token_id,
                        test_name: test_token_id,
                        args: syntax_args,
                    },
                )));
            }

            // Check for comparison operator
            // If no next token, just return left as-is
            let peek_tok = match self.peek() {
                Some(t) => t,
                None => return Ok(Some(left)),
            };
            let (op, op_tokens) = if self.peek_token_kind(TokenKind::JinjaDoubleEq) {
                self.advance();
                (
                    JinjaBinaryOp::Eq,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::NotEq)) {
                self.advance();
                (
                    JinjaBinaryOp::Ne,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Lt)) {
                self.advance();
                (
                    JinjaBinaryOp::Lt,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Le)) {
                self.advance();
                (
                    JinjaBinaryOp::Le,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Gt)) {
                self.advance();
                (
                    JinjaBinaryOp::Gt,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Ge)) {
                self.advance();
                (
                    JinjaBinaryOp::Ge,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else if self.peek_jinja_keyword("not") {
                let checkpoint = self.idx;
                self.advance();
                let not_token_id = self.last_token_id();

                if self.peek_jinja_keyword("in") {
                    self.advance();
                    (
                        JinjaBinaryOp::NotIn,
                        SyntaxJinjaBinaryOpTokens {
                            primary: not_token_id,
                            secondary: Some(self.last_token_id()),
                        },
                    )
                } else {
                    self.idx = checkpoint;
                    return Ok(Some(left));
                }
            } else if self.peek_jinja_keyword("in") {
                self.advance();
                (
                    JinjaBinaryOp::In,
                    SyntaxJinjaBinaryOpTokens {
                        primary: self.last_token_id(),
                        secondary: None,
                    },
                )
            } else {
                return Ok(Some(left));
            };

            let right = match self.parse_jinja_concat()? {
                Some(e) => e,
                None => return Ok(None),
            };
            let right_id = right
                .syntax_id
                .expect_invariant("right expression missing syntax_id");
            let span = Span {
                start: left.span.start,
                end: right.span.end,
            };

            let expr = JinjaExpr::binary(left, op, right, span);
            Ok(Some(self.attach_jinja_expr_syntax(
                expr,
                SyntaxJinjaExprKind::BinaryOp {
                    left: left_id,
                    op_tokens,
                    right: right_id,
                },
            )))
        })();
        result
    }

    /// Parse concatenation expression (~).
    fn parse_jinja_concat(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_concat")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut left = match self.parse_jinja_add_expr()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while self.peek_token_kind(TokenKind::JinjaTilde) {
                self.advance(); // consume '~'
                let op_token_id = self.last_token_id();
                let right = match self.parse_jinja_add_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                let left_id = left
                    .syntax_id
                    .expect_invariant("left expression missing syntax_id");
                let right_id = right
                    .syntax_id
                    .expect_invariant("right expression missing syntax_id");
                let expr = JinjaExpr::binary(left, JinjaBinaryOp::Concat, right, span);
                left = self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::BinaryOp {
                        left: left_id,
                        op_tokens: SyntaxJinjaBinaryOpTokens {
                            primary: op_token_id,
                            secondary: None,
                        },
                        right: right_id,
                    },
                );
            }

            Ok(Some(left))
        })();
        result
    }

    /// Parse addition/subtraction expression.
    fn parse_jinja_add_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_add")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut left = match self.parse_jinja_mult_expr()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while let Some(peek_tok) = self.peek() {
                let op = if matches!(peek_tok.kind, TokenKind::Operator(Operator::Plus)) {
                    self.advance();
                    (JinjaBinaryOp::Add, self.last_token_id())
                } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Minus)) {
                    self.advance();
                    (JinjaBinaryOp::Sub, self.last_token_id())
                } else {
                    break;
                };

                let right = match self.parse_jinja_mult_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                let (op, op_token_id) = op;
                let left_id = left
                    .syntax_id
                    .expect_invariant("left expression missing syntax_id");
                let right_id = right
                    .syntax_id
                    .expect_invariant("right expression missing syntax_id");
                let expr = JinjaExpr::binary(left, op, right, span);
                left = self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::BinaryOp {
                        left: left_id,
                        op_tokens: SyntaxJinjaBinaryOpTokens {
                            primary: op_token_id,
                            secondary: None,
                        },
                        right: right_id,
                    },
                );
            }

            Ok(Some(left))
        })();
        result
    }

    /// Parse multiplication/division/modulo expression.
    fn parse_jinja_mult_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_mult")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut left = match self.parse_jinja_unary_expr()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while let Some(peek_tok) = self.peek() {
                let op = if matches!(peek_tok.kind, TokenKind::Operator(Operator::Star)) {
                    self.advance();
                    (JinjaBinaryOp::Mul, self.last_token_id())
                } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Slash)) {
                    self.advance();
                    (JinjaBinaryOp::Div, self.last_token_id())
                } else if self.peek_token_kind(TokenKind::JinjaDoubleSlash) {
                    self.advance();
                    (JinjaBinaryOp::FloorDiv, self.last_token_id())
                } else if matches!(peek_tok.kind, TokenKind::Operator(Operator::Percent)) {
                    self.advance();
                    (JinjaBinaryOp::Mod, self.last_token_id())
                } else {
                    break;
                };

                let right = match self.parse_jinja_unary_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = Span {
                    start: left.span.start,
                    end: right.span.end,
                };
                let (op, op_token_id) = op;
                let left_id = left
                    .syntax_id
                    .expect_invariant("left expression missing syntax_id");
                let right_id = right
                    .syntax_id
                    .expect_invariant("right expression missing syntax_id");
                let expr = JinjaExpr::binary(left, op, right, span);
                left = self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::BinaryOp {
                        left: left_id,
                        op_tokens: SyntaxJinjaBinaryOpTokens {
                            primary: op_token_id,
                            secondary: None,
                        },
                        right: right_id,
                    },
                );
            }

            Ok(Some(left))
        })();
        result
    }

    /// Parse unary expression (-, +).
    fn parse_jinja_unary_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };

        match &tok.kind {
            TokenKind::Operator(Operator::Minus) => {
                let start = tok.span.start;
                self.advance();
                let op_token_id = self.last_token_id();

                let _depth = self.track_depth("jinja_unary_minus")?;
                let operand = match self.parse_jinja_unary_expr()? {
                    Some(e) => e,
                    None => {
                        return Ok(None);
                    }
                };
                let operand_id = operand
                    .syntax_id
                    .expect_invariant("operand missing syntax_id");
                let span = Span {
                    start,
                    end: operand.span.end,
                };
                let expr = JinjaExpr {
                    kind: JinjaExprKind::UnaryOp {
                        op: JinjaUnaryOp::Neg,
                        expr: Box::new(operand),
                    },
                    span,
                    syntax_id: None,
                    node_id: self.id_gen.next(),
                };
                Ok(Some(self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::UnaryOp {
                        op: op_token_id,
                        expr: operand_id,
                    },
                )))
            }
            TokenKind::Operator(Operator::Plus) => {
                let start = tok.span.start;
                self.advance();
                let op_token_id = self.last_token_id();

                let _depth = self.track_depth("jinja_unary_plus")?;
                let operand = match self.parse_jinja_unary_expr()? {
                    Some(e) => e,
                    None => {
                        return Ok(None);
                    }
                };
                let operand_id = operand
                    .syntax_id
                    .expect_invariant("operand missing syntax_id");
                let span = Span {
                    start,
                    end: operand.span.end,
                };
                let expr = JinjaExpr {
                    kind: JinjaExprKind::UnaryOp {
                        op: JinjaUnaryOp::Pos,
                        expr: Box::new(operand),
                    },
                    span,
                    syntax_id: None,
                    node_id: self.id_gen.next(),
                };
                Ok(Some(self.attach_jinja_expr_syntax(
                    expr,
                    SyntaxJinjaExprKind::UnaryOp {
                        op: op_token_id,
                        expr: operand_id,
                    },
                )))
            }
            _ => self.parse_jinja_power_expr(),
        }
    }

    /// Parse power expression (**) - right associative.
    fn parse_jinja_power_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let mut left = match self.parse_jinja_postfix_expr()? {
            Some(e) => e,
            None => return Ok(None),
        };

        if self.peek_token_kind(TokenKind::JinjaDoubleStar) {
            self.advance(); // consume '**'
            let op_token_id = self.last_token_id();
            // Right associative - recurse for right operand

            let _depth = self.track_depth("jinja_power")?;
            let right = match self.parse_jinja_power_expr()? {
                Some(e) => e,
                None => {
                    return Ok(None);
                }
            };
            let span = Span {
                start: left.span.start,
                end: right.span.end,
            };
            let left_id = left
                .syntax_id
                .expect_invariant("left expression missing syntax_id");
            let right_id = right
                .syntax_id
                .expect_invariant("right expression missing syntax_id");
            let expr = JinjaExpr::binary(left, JinjaBinaryOp::Pow, right, span);
            left = self.attach_jinja_expr_syntax(
                expr,
                SyntaxJinjaExprKind::BinaryOp {
                    left: left_id,
                    op_tokens: SyntaxJinjaBinaryOpTokens {
                        primary: op_token_id,
                        secondary: None,
                    },
                    right: right_id,
                },
            );
        }

        Ok(Some(left))
    }

    /// Parse postfix expressions (., [], (), |).
    fn parse_jinja_postfix_expr(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_postfix")?;

        // Closure scopes early returns from the postfix loop
        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let mut expr = match self.parse_jinja_primary()? {
                Some(e) => e,
                None => return Ok(None),
            };

            while let Some(tok) = self.peek() {
                match &tok.kind {
                    // Attribute access: expr.attr
                    TokenKind::Punctuation(Punctuation::Dot) => {
                        let base_id = expr
                            .syntax_id
                            .expect_invariant("base expression missing syntax_id");
                        self.advance(); // consume '.'
                        let dot_token_id = self.last_token_id();
                        let attr_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let attr_token_id = self.last_token_id();
                        if let TokenKind::Identifier { .. } = attr_tok.kind {
                            let span = Span {
                                start: expr.span.start,
                                end: attr_tok.span.end,
                            };
                            let new_expr =
                                JinjaExpr::attribute(expr, attr_tok.lexeme(self.source), span);
                            expr = self.attach_jinja_expr_syntax(
                                new_expr,
                                SyntaxJinjaExprKind::Attribute {
                                    base: base_id,
                                    dot: dot_token_id,
                                    attr: attr_token_id,
                                },
                            );
                        } else {
                            return Ok(None); // Expected identifier after '.'
                        }
                    }

                    // Subscript: expr[index]
                    TokenKind::Punctuation(Punctuation::LBracket) => {
                        let base_id = expr
                            .syntax_id
                            .expect_invariant("base expression missing syntax_id");
                        self.advance(); // consume '['
                        let lbracket_id = self.last_token_id();
                        // parse_jinja_expr has its own recursion guard
                        let index = match self.parse_jinja_expr()? {
                            Some(e) => e,
                            None => return Ok(None),
                        };
                        let index_id = index
                            .syntax_id
                            .expect_invariant("index expression missing syntax_id");
                        let rbracket_tok = match self.expect_punctuation(Punctuation::RBracket) {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let rbracket_id = self.last_token_id();
                        let span = Span {
                            start: expr.span.start,
                            end: rbracket_tok.span.end,
                        };
                        let new_expr = JinjaExpr {
                            kind: JinjaExprKind::Subscript {
                                base: Box::new(expr),
                                index: Box::new(index),
                            },
                            span,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        };
                        expr = self.attach_jinja_expr_syntax(
                            new_expr,
                            SyntaxJinjaExprKind::Subscript {
                                base: base_id,
                                lbracket: lbracket_id,
                                index: index_id,
                                rbracket: rbracket_id,
                            },
                        );
                    }

                    // Function call: expr(args)
                    TokenKind::Punctuation(Punctuation::LParen) => {
                        let callee_id = expr
                            .syntax_id
                            .expect_invariant("callee expression missing syntax_id");
                        self.advance(); // consume '('
                        let lparen_id = self.last_token_id();
                        let args = match self.parse_jinja_args()? {
                            Some(a) => a,
                            None => return Ok(None),
                        };
                        let arg_ids: Vec<_> = args
                            .iter()
                            .map(|arg| arg.syntax_id.expect_invariant("argument missing syntax_id"))
                            .collect();
                        let rparen_tok = match self.expect_punctuation(Punctuation::RParen) {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start: expr.span.start,
                            end: rparen_tok.span.end,
                        };
                        let new_expr = JinjaExpr::call(expr, args, span);
                        expr = self.attach_jinja_expr_syntax(
                            new_expr,
                            SyntaxJinjaExprKind::Call {
                                callee: callee_id,
                                lparen: lparen_id,
                                args: arg_ids,
                                rparen: rparen_id,
                            },
                        );
                    }

                    // Filter: expr | filter or expr | filter(args)
                    TokenKind::JinjaPipe => {
                        let base_id = expr
                            .syntax_id
                            .expect_invariant("expression missing syntax_id");
                        self.advance(); // consume '|'
                        let pipe_id = self.last_token_id();
                        let filter_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let filter_id = self.last_token_id();
                        if let TokenKind::Identifier { .. } = filter_tok.kind {
                            let filter_name = filter_tok.lexeme(self.source).to_string();
                            let mut args_vec: Vec<JinjaArg> = Vec::new();
                            let mut syntax_args = None;
                            let mut end = filter_tok.span.end;

                            if matches!(
                                self.peek().map(|t| &t.kind),
                                Some(TokenKind::Punctuation(Punctuation::LParen))
                            ) {
                                self.advance(); // consume '('
                                let lparen_id = self.last_token_id();
                                let args = match self.parse_jinja_args()? {
                                    Some(a) => a,
                                    None => return Ok(None),
                                };
                                let arg_ids: Vec<_> = args
                                    .iter()
                                    .map(|arg| {
                                        arg.syntax_id.expect_invariant("argument missing syntax_id")
                                    })
                                    .collect();
                                let rparen_tok = match self.expect_punctuation(Punctuation::RParen)
                                {
                                    Some(t) => t,
                                    None => return Ok(None),
                                };
                                let rparen_id = self.last_token_id();
                                end = rparen_tok.span.end;
                                syntax_args = Some((
                                    SyntaxJinjaFilterArgs {
                                        lparen: lparen_id,
                                        rparen: rparen_id,
                                    },
                                    arg_ids,
                                ));
                                args_vec = args;
                            }

                            let span = Span {
                                start: expr.span.start,
                                end,
                            };
                            let new_expr = JinjaExpr {
                                kind: JinjaExprKind::Filter {
                                    expr: Box::new(expr),
                                    filter: filter_name,
                                    args: args_vec,
                                },
                                span,
                                syntax_id: None,
                                node_id: self.id_gen.next(),
                            };
                            expr = self.attach_jinja_expr_syntax(
                                new_expr,
                                SyntaxJinjaExprKind::Filter {
                                    expr: base_id,
                                    pipe: pipe_id,
                                    filter: filter_id,
                                    args: syntax_args,
                                },
                            );
                        } else {
                            return Ok(None); // Expected identifier after '|'
                        }
                    }

                    _ => break,
                }
            }

            Ok(Some(expr))
        })();
        result
    }

    /// Parse primary expression (literals, identifiers, parenthesized expressions).
    fn parse_jinja_primary(&mut self) -> ParseResult<Option<JinjaExpr>> {
        let _depth = self.track_depth("jinja_primary")?;

        let result = (|| -> ParseResult<Option<JinjaExpr>> {
            let tok = match self.advance() {
                Some(t) => t,
                None => return Ok(None),
            };
            let token_id = self.last_token_id();

            match &tok.kind {
                // Identifiers
                TokenKind::Identifier { .. } => {
                    let expr = JinjaExpr::name(tok.lexeme(self.source), tok.span);
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Name { token: token_id },
                    )))
                }

                // Literals
                TokenKind::JinjaTrue => {
                    let expr = JinjaExpr::boolean(true, tok.span);
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Literal { token: token_id },
                    )))
                }
                TokenKind::JinjaFalse => {
                    let expr = JinjaExpr::boolean(false, tok.span);
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Literal { token: token_id },
                    )))
                }
                TokenKind::JinjaNull => {
                    let expr = JinjaExpr::null(tok.span);
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Literal { token: token_id },
                    )))
                }
                TokenKind::Literal(crate::lexer::LiteralKind::String) => {
                    let expr = JinjaExpr::string(tok.lexeme(self.source), tok.span);
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Literal { token: token_id },
                    )))
                }
                TokenKind::Literal(crate::lexer::LiteralKind::Number) => {
                    // Try to parse as integer first, then float
                    if let Ok(i) = tok.lexeme(self.source).parse::<i64>() {
                        let expr = JinjaExpr::integer(i, tok.span);
                        Ok(Some(self.attach_jinja_expr_syntax(
                            expr,
                            SyntaxJinjaExprKind::Literal { token: token_id },
                        )))
                    } else if let Ok(f) = tok.lexeme(self.source).parse::<f64>() {
                        let expr = JinjaExpr {
                            kind: JinjaExprKind::Literal {
                                value: JinjaLiteralValue::Float(f),
                            },
                            span: tok.span,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        };
                        Ok(Some(self.attach_jinja_expr_syntax(
                            expr,
                            SyntaxJinjaExprKind::Literal { token: token_id },
                        )))
                    } else {
                        Ok(None) // Malformed number
                    }
                }

                // Parenthesized expression or tuple
                TokenKind::Punctuation(Punctuation::LParen) => {
                    let start = tok.span.start;
                    let lparen_id = token_id;

                    // Check for empty tuple ()
                    let peek_tok = match self.peek() {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    if matches!(peek_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        let end_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start,
                            end: end_tok.span.end,
                        };
                        let expr = JinjaExpr {
                            kind: JinjaExprKind::Tuple {
                                elements: Vec::new(),
                            },
                            span,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        };
                        return Ok(Some(self.attach_jinja_expr_syntax(
                            expr,
                            SyntaxJinjaExprKind::Tuple {
                                lparen: lparen_id,
                                items: Vec::new(),
                                rparen: rparen_id,
                            },
                        )));
                    }

                    // Parse first expression
                    let first_expr = match self.parse_jinja_expr()? {
                        Some(e) => e,
                        None => return Ok(None),
                    };
                    let first_id = first_expr
                        .syntax_id
                        .expect_invariant("expr missing syntax_id");

                    // Check if this is a tuple (has comma) or just a parenthesized expression
                    let is_tuple = match self.peek() {
                        Some(t) => matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)),
                        None => false,
                    };
                    if is_tuple {
                        // This is a tuple
                        let mut items = vec![first_expr];
                        let mut item_ids = vec![first_id];

                        while matches!(
                            self.peek().map(|t| &t.kind),
                            Some(TokenKind::Punctuation(Punctuation::Comma))
                        ) {
                            self.advance(); // consume comma

                            // Check for trailing comma: (a, b,)
                            if matches!(
                                self.peek().map(|t| &t.kind),
                                Some(TokenKind::Punctuation(Punctuation::RParen))
                            ) {
                                break;
                            }

                            let item = match self.parse_jinja_expr()? {
                                Some(e) => e,
                                None => return Ok(None),
                            };
                            item_ids.push(
                                item.syntax_id
                                    .expect_invariant("tuple item missing syntax_id"),
                            );
                            items.push(item);
                        }

                        let end_tok = match self.expect_punctuation(Punctuation::RParen) {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start,
                            end: end_tok.span.end,
                        };

                        let expr = JinjaExpr {
                            kind: JinjaExprKind::Tuple { elements: items },
                            span,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        };
                        Ok(Some(self.attach_jinja_expr_syntax(
                            expr,
                            SyntaxJinjaExprKind::Tuple {
                                lparen: lparen_id,
                                items: item_ids,
                                rparen: rparen_id,
                            },
                        )))
                    } else {
                        // Just a parenthesized expression - preserve parentheses by wrapping in single-item tuple
                        let end_tok = match self.expect_punctuation(Punctuation::RParen) {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start,
                            end: end_tok.span.end,
                        };

                        let expr = JinjaExpr {
                            kind: JinjaExprKind::Tuple {
                                elements: vec![first_expr],
                            },
                            span,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        };
                        Ok(Some(self.attach_jinja_expr_syntax(
                            expr,
                            SyntaxJinjaExprKind::Tuple {
                                lparen: lparen_id,
                                items: vec![first_id],
                                rparen: rparen_id,
                            },
                        )))
                    }
                }

                // List literal: [1, 2, 3]
                TokenKind::Punctuation(Punctuation::LBracket) => {
                    let start = tok.span.start;
                    let lbracket_id = token_id;
                    let mut items = Vec::new();
                    let mut item_ids = Vec::new();

                    // Check for empty list
                    let is_empty = match self.peek() {
                        Some(t) => matches!(t.kind, TokenKind::Punctuation(Punctuation::RBracket)),
                        None => return Ok(None),
                    };
                    if !is_empty {
                        loop {
                            let item = match self.parse_jinja_expr()? {
                                Some(e) => e,
                                None => return Ok(None),
                            };
                            item_ids.push(
                                item.syntax_id
                                    .expect_invariant("list item missing syntax_id"),
                            );
                            items.push(item);

                            let is_comma = match self.peek() {
                                Some(t) => {
                                    matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma))
                                }
                                None => false,
                            };
                            if is_comma {
                                self.advance(); // consume ','
                            } else {
                                break;
                            }
                        }
                    }

                    let end_tok = match self.expect_punctuation(Punctuation::RBracket) {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let rbracket_id = self.last_token_id();
                    let span = Span {
                        start,
                        end: end_tok.span.end,
                    };

                    let expr = JinjaExpr {
                        kind: JinjaExprKind::List { elements: items },
                        span,
                        syntax_id: None,
                        node_id: self.id_gen.next(),
                    };
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::List {
                            lbracket: lbracket_id,
                            items: item_ids,
                            rbracket: rbracket_id,
                        },
                    )))
                }

                // Dictionary literal: {key: value, key2: value2}
                TokenKind::Punctuation(Punctuation::LCurly) => {
                    let start = tok.span.start;
                    let lcurly_id = token_id;
                    let mut pairs = Vec::new();
                    let mut pair_ids = Vec::new();

                    // Check for empty dict
                    let is_empty = match self.peek() {
                        Some(t) => matches!(t.kind, TokenKind::Punctuation(Punctuation::RCurly)),
                        None => return Ok(None),
                    };
                    if !is_empty {
                        loop {
                            // Parse key expression
                            let key = match self.parse_jinja_expr()? {
                                Some(e) => e,
                                None => return Ok(None),
                            };
                            let key_id =
                                key.syntax_id.expect_invariant("dict key missing syntax_id");

                            // Expect colon
                            match self.expect_punctuation(Punctuation::Colon) {
                                Some(_) => {}
                                None => return Ok(None),
                            };
                            let colon_id = self.last_token_id();

                            // Parse value expression
                            let value = match self.parse_jinja_expr()? {
                                Some(e) => e,
                                None => return Ok(None),
                            };
                            let value_id = value
                                .syntax_id
                                .expect_invariant("dict value missing syntax_id");

                            pair_ids.push((key_id, colon_id, value_id));
                            pairs.push((key, value));

                            let is_comma = match self.peek() {
                                Some(t) => {
                                    matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma))
                                }
                                None => false,
                            };
                            if is_comma {
                                self.advance(); // consume ','
                            } else {
                                break;
                            }
                        }
                    }

                    let end_tok = match self.expect_punctuation(Punctuation::RCurly) {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let rcurly_id = self.last_token_id();
                    let span = Span {
                        start,
                        end: end_tok.span.end,
                    };

                    let expr = JinjaExpr {
                        kind: JinjaExprKind::Dict { pairs },
                        span,
                        syntax_id: None,
                        node_id: self.id_gen.next(),
                    };
                    Ok(Some(self.attach_jinja_expr_syntax(
                        expr,
                        SyntaxJinjaExprKind::Dict {
                            lcurly: lcurly_id,
                            pairs: pair_ids,
                            rcurly: rcurly_id,
                        },
                    )))
                }

                _ => Ok(None), // Unexpected token
            }
        })();
        result
    }

    /// Parse function/filter arguments.
    fn parse_jinja_args(&mut self) -> ParseResult<Option<Vec<JinjaArg>>> {
        let mut args = Vec::new();

        // Check for empty args
        let is_rparen = match self.peek() {
            Some(t) => matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
            None => return Ok(None),
        };
        if is_rparen {
            return Ok(Some(args));
        }

        loop {
            // Check for keyword argument: name=value
            if let Some(TokenKind::Identifier { .. }) = self.peek().map(|t| &t.kind) {
                let checkpoint = self.idx;
                let name_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let name_token_id = self.last_token_id();

                let is_eq = match self.peek() {
                    Some(t) => matches!(t.kind, TokenKind::Operator(Operator::Eq)),
                    None => false,
                };
                if is_eq {
                    self.advance(); // consume '='
                    let eq_token_id = self.last_token_id();
                    let value = match self.parse_jinja_expr()? {
                        Some(e) => e,
                        None => return Ok(None),
                    };
                    let value_id = value
                        .syntax_id
                        .expect_invariant("argument value missing syntax_id");
                    let span = Span {
                        start: name_tok.span.start,
                        end: value.span.end,
                    };
                    let arg = JinjaArg::keyword(name_tok.lexeme(self.source), value, span);
                    let arg = self.attach_jinja_arg_syntax(
                        arg,
                        SyntaxJinjaArgKind::Keyword {
                            name: name_token_id,
                            eq: eq_token_id,
                            value: value_id,
                        },
                    );
                    args.push(arg);
                } else {
                    // Not a keyword arg, backtrack and parse as positional
                    self.idx = checkpoint;
                    let value = match self.parse_jinja_expr()? {
                        Some(e) => e,
                        None => return Ok(None),
                    };
                    let value_id = value
                        .syntax_id
                        .expect_invariant("argument value missing syntax_id");
                    let span = value.span;
                    let arg = JinjaArg::positional(value, span);
                    let arg = self.attach_jinja_arg_syntax(
                        arg,
                        SyntaxJinjaArgKind::Positional { expr: value_id },
                    );
                    args.push(arg);
                }
            } else {
                // Positional argument
                let value = match self.parse_jinja_expr()? {
                    Some(e) => e,
                    None => return Ok(None),
                };
                let span = value.span;
                let value_id = value
                    .syntax_id
                    .expect_invariant("argument value missing syntax_id");
                let arg = JinjaArg::positional(value, span);
                let arg = self.attach_jinja_arg_syntax(
                    arg,
                    SyntaxJinjaArgKind::Positional { expr: value_id },
                );
                args.push(arg);
            }

            // Check for more arguments
            let is_comma = match self.peek() {
                Some(t) => matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)),
                None => false,
            };
            if is_comma {
                self.advance(); // consume ','
            } else {
                break;
            }
        }

        Ok(Some(args))
    }

    /// Helper: Check if next token is a specific Jinja keyword.
    fn peek_jinja_keyword(&self, keyword: &str) -> bool {
        if let Some(tok) = self.peek() {
            match keyword {
                "and" => matches!(tok.kind, TokenKind::JinjaAnd),
                "or" => matches!(tok.kind, TokenKind::JinjaOr),
                "not" => matches!(tok.kind, TokenKind::JinjaNot),
                "in" => matches!(tok.kind, TokenKind::JinjaIn),
                "is" => matches!(tok.kind, TokenKind::JinjaIs),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Helper: Check if next token matches a specific token kind.
    fn peek_token_kind(&self, kind: TokenKind) -> bool {
        self.peek().map(|t| t.kind == kind).unwrap_or(false)
    }

    /// Helper: Expect and consume a specific punctuation token.
    fn expect_punctuation(&mut self, expected: Punctuation) -> Option<&'a Token> {
        let tok = self.peek()?;
        if matches!(&tok.kind, TokenKind::Punctuation(p) if *p == expected) {
            self.advance()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::jinja::JinjaArgKind;
    use crate::lexer::tokenize;
    use crate::syntax::SyntaxJinjaExprKind;

    #[test]
    fn test_parse_jinja_literal() {
        let source = "{{ 42 }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        // Skip opening {{
        parser.advance();

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse literal")
            .unwrap();
        assert!(matches!(
            expr.kind,
            JinjaExprKind::Literal {
                value: JinjaLiteralValue::Integer(42)
            }
        ));
    }

    #[test]
    fn test_parse_jinja_identifier() {
        let source = "{{ user_name }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse identifier")
            .unwrap();
        if let JinjaExprKind::Name(name) = &expr.kind {
            assert_eq!(name, "user_name");
        } else {
            panic!("Expected Name, got {:?}", expr.kind);
        }
    }

    #[test]
    fn test_parse_jinja_binary_op() {
        let source = "{{ a + b }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse binary op")
            .unwrap();
        if let JinjaExprKind::BinaryOp { op, .. } = &expr.kind {
            assert_eq!(*op, JinjaBinaryOp::Add);
        } else {
            panic!("Expected BinaryOp, got {:?}", expr.kind);
        }
    }

    #[test]
    fn test_parse_jinja_filter() {
        let source = "{{ name | upper }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse filter")
            .unwrap();
        if let JinjaExprKind::Filter { filter, .. } = &expr.kind {
            assert_eq!(filter, "upper");
        } else {
            panic!("Expected Filter, got {:?}", expr.kind);
        }
    }

    #[test]
    fn test_parse_jinja_attribute() {
        let source = "{{ user.email }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse attribute")
            .unwrap();
        if let JinjaExprKind::Attribute { attr, .. } = &expr.kind {
            assert_eq!(attr, "email");
        } else {
            panic!("Expected Attribute, got {:?}", expr.kind);
        }
    }

    #[test]
    fn test_parse_jinja_call() {
        let source = "{{ range(10) }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse call")
            .unwrap();
        if let JinjaExprKind::Call { args, .. } = &expr.kind {
            assert_eq!(args.len(), 1);
        } else {
            panic!("Expected Call, got {:?}", expr.kind);
        }
    }

    #[test]
    fn test_parse_jinja_not_in_binary_op() {
        let source = "{{ item not in collection }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse not in")
            .unwrap();

        let syntax_id = expr
            .syntax_id
            .expect_invariant("Expression should have syntax id");
        let syntax_expr = &parser.syntax_arena.jinja_exprs[syntax_id.0 as usize];

        match &expr.kind {
            JinjaExprKind::BinaryOp { op, .. } => assert_eq!(*op, JinjaBinaryOp::NotIn),
            other => panic!("Expected BinaryOp, got {:?}", other),
        }

        match &syntax_expr.kind {
            SyntaxJinjaExprKind::BinaryOp { op_tokens, .. } => {
                let primary_idx = op_tokens.primary.0 as usize;
                assert_eq!(result.tokens[primary_idx].lexeme(source), "not");

                let secondary_idx = op_tokens
                    .secondary
                    .expect_invariant("not in should capture secondary token")
                    .0 as usize;
                assert_eq!(result.tokens[secondary_idx].lexeme(source), "in");
            }
            other => panic!("Expected BinaryOp syntax, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_jinja_is_test_without_args() {
        let source = "{{ value is defined }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse is test")
            .unwrap();

        let syntax_id = expr
            .syntax_id
            .expect_invariant("Expression should have syntax id");
        let syntax_expr = &parser.syntax_arena.jinja_exprs[syntax_id.0 as usize];

        match &expr.kind {
            JinjaExprKind::Test { test, args, .. } => {
                assert_eq!(test, "defined");
                assert!(args.is_empty());
            }
            other => panic!("Expected Test expression, got {:?}", other),
        }

        match &syntax_expr.kind {
            SyntaxJinjaExprKind::Test {
                is_keyword,
                not_keyword,
                test_name,
                args,
                ..
            } => {
                assert_eq!(result.tokens[is_keyword.0 as usize].lexeme(source), "is");
                assert!(not_keyword.is_none());
                assert_eq!(
                    result.tokens[test_name.0 as usize].lexeme(source),
                    "defined"
                );
                assert!(args.is_none());
            }
            other => panic!("Expected Test syntax, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_jinja_is_not_test_with_args() {
        let source = "{{ value is not divisibleby(3) }}";
        let result = tokenize(source);
        let mut parser = Parser::new(source, &result.tokens);

        parser.advance(); // Skip {{

        let expr = parser
            .parse_jinja_expr()
            .expect_invariant("Should parse is not test")
            .unwrap();

        let syntax_id = expr
            .syntax_id
            .expect_invariant("Expression should have syntax id");
        let syntax_expr = &parser.syntax_arena.jinja_exprs[syntax_id.0 as usize];

        match &expr.kind {
            JinjaExprKind::Test { test, args, .. } => {
                assert_eq!(test, "divisibleby");
                assert_eq!(args.len(), 1);
                match &args[0].kind {
                    JinjaArgKind::Positional(arg_expr) => {
                        if let JinjaExprKind::Literal { .. } = arg_expr.kind {
                            // ok
                        } else {
                            panic!(
                                "Expected literal positional argument, got {:?}",
                                arg_expr.kind
                            );
                        }
                    }
                    other => panic!("Expected positional argument, got {:?}", other),
                }
            }
            other => panic!("Expected Test expression, got {:?}", other),
        }

        match &syntax_expr.kind {
            SyntaxJinjaExprKind::Test {
                is_keyword,
                not_keyword,
                test_name,
                args,
                ..
            } => {
                assert_eq!(result.tokens[is_keyword.0 as usize].lexeme(source), "is");
                let not_id = not_keyword.expect_invariant("Expected not keyword token");
                assert_eq!(result.tokens[not_id.0 as usize].lexeme(source), "not");
                assert_eq!(
                    result.tokens[test_name.0 as usize].lexeme(source),
                    "divisibleby"
                );

                let (delims, arg_ids) = args.as_ref().expect_invariant("Expected test arguments");
                assert_eq!(result.tokens[delims.lparen.0 as usize].lexeme(source), "(");
                assert_eq!(result.tokens[delims.rparen.0 as usize].lexeme(source), ")");
                assert_eq!(arg_ids.len(), 1);

                let arg_idx = arg_ids[0].0 as usize;
                let syntax_arg = &parser.syntax_arena.jinja_args[arg_idx];
                match &syntax_arg.kind {
                    SyntaxJinjaArgKind::Positional { expr } => {
                        let arg_expr_idx = expr.0 as usize;
                        let literal_token =
                            match &parser.syntax_arena.jinja_exprs[arg_expr_idx].kind {
                                SyntaxJinjaExprKind::Literal { token } => token,
                                other => panic!("Expected literal syntax expr, got {:?}", other),
                            };
                        assert_eq!(result.tokens[literal_token.0 as usize].lexeme(source), "3");
                    }
                    other => panic!("Expected positional syntax arg, got {:?}", other),
                }
            }
            other => panic!("Expected Test syntax, got {:?}", other),
        }
    }
}
