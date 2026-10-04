// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CASE expression parsing.
//!
//! Handles both forms of CASE expressions:
//! - Simple: `CASE expr WHEN val1 THEN result1 ... END`
//! - Searched: `CASE WHEN cond1 THEN result1 ... END`
//!
//! Also handles Jinja blocks within CASE expressions (common in dbt
//! for dynamic WHEN clause generation).
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/functions/case>

use crate::ast::{AstCaseKind, AstCaseWhen, AstExpr};
use crate::error::{ExpectInvariant, ParseError};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn parse_case_expr(
        &mut self,
        case_tok: &Token,
    ) -> crate::error::ParseResult<Option<AstExpr>> {
        // Capture CASE keyword token ID for syntax layer
        // Note: CASE token was already advanced by caller, so use last_token_id()
        let case_token_id = self.last_token_id();
        // Optional simple operand: CASE <expr> WHEN ...
        let operand = if let Some(next) = self.peek() {
            match next.kind {
                TokenKind::Keyword(Keyword::When) => None,
                _ => Some(self.parse_add_expr_in_mode()?),
            }
        } else {
            None
        };

        let mut whens: Vec<AstCaseWhen> = Vec::new();

        loop {
            let tok_opt = self.peek();
            let tok = match tok_opt {
                Some(t) => t,
                None => break,
            };
            match tok.kind {
                // Preserve Jinja comments ({% comment %}) as placeholder expressions.
                // These can appear between WHEN clauses in dbt models.
                TokenKind::JinjaComment => {
                    let jinja_tok = match self.advance() {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let placeholder = AstExpr::JinjaPlaceholder {
                        node_id: self.id_gen.next(),
                        kind: crate::ast::JinjaKind::Comment,
                        span: jinja_tok.span,
                        expr: None,
                        syntax_id: None,
                    };
                    // Create a synthetic WHEN clause with Jinja as both condition and result
                    // This preserves the Jinja token in the AST at the correct position
                    whens.push(AstCaseWhen {
                        node_id: self.id_gen.next(),
                        prefix_inline_fragments: Vec::new(),
                        when_span: jinja_tok.span, // Use Jinja span as a marker
                        cond: placeholder.clone(),
                        then_span: jinja_tok.span, // Use Jinja span as a marker
                        result: placeholder,
                        suffix_inline_fragments: Vec::new(),
                    });
                }
                // Handle Jinja control blocks ({% for %}, {% if %}) that wrap WHEN clauses
                TokenKind::JinjaStmtOpen => {
                    if let Some(kind) = self.peek_jinja_block_kind() {
                        match kind {
                            crate::ast::JinjaBlockKind::For | crate::ast::JinjaBlockKind::If => {
                                // Parse the entire Jinja block - preserve delimiters as synthetic WHENs
                                let closing_kind = match kind {
                                    crate::ast::JinjaBlockKind::For => {
                                        crate::ast::JinjaBlockKind::EndFor
                                    }
                                    crate::ast::JinjaBlockKind::If => {
                                        crate::ast::JinjaBlockKind::EndIf
                                    }
                                    _ => break,
                                };

                                // Capture opening delimiter span {% for/if ... %}
                                let opening_start = match self.peek() {
                                    Some(t) => t.span.start,
                                    None => return Ok(None),
                                };
                                self.advance(); // {%
                                let mut opening_end = opening_start;
                                while let Some(t) = self.peek() {
                                    if matches!(t.kind, TokenKind::JinjaStmtClose) {
                                        opening_end = t.span.end;
                                        self.advance();
                                        break;
                                    }
                                    self.advance();
                                }

                                // Create synthetic WHEN for opening delimiter
                                let opening_span = Span {
                                    start: opening_start,
                                    end: opening_end,
                                };
                                let opening_placeholder = AstExpr::JinjaPlaceholder {
                                    node_id: self.id_gen.next(),
                                    kind: crate::ast::JinjaKind::Statement,
                                    span: opening_span,
                                    expr: None,
                                    syntax_id: None,
                                };
                                whens.push(AstCaseWhen {
                                    node_id: self.id_gen.next(),
                                    prefix_inline_fragments: Vec::new(),
                                    when_span: opening_span,
                                    cond: opening_placeholder.clone(),
                                    then_span: opening_span,
                                    result: opening_placeholder,
                                    suffix_inline_fragments: Vec::new(),
                                });

                                // Parse WHEN clauses inside the block until we hit {% endfor/endif %}
                                while let Some(inner) = self.peek() {
                                    // Check for closing delimiter
                                    if let Some(inner_kind) = self.peek_jinja_block_kind() {
                                        if inner_kind == closing_kind {
                                            // Capture closing delimiter span {% endfor/endif %}
                                            let closing_start = inner.span.start;
                                            self.advance(); // {%
                                            let mut closing_end = closing_start;
                                            while let Some(t) = self.peek() {
                                                if matches!(t.kind, TokenKind::JinjaStmtClose) {
                                                    closing_end = t.span.end;
                                                    self.advance();
                                                    break;
                                                }
                                                self.advance();
                                            }

                                            // Create synthetic WHEN for closing delimiter
                                            let closing_span = Span {
                                                start: closing_start,
                                                end: closing_end,
                                            };
                                            let closing_placeholder = AstExpr::JinjaPlaceholder {
                                                node_id: self.id_gen.next(),
                                                kind: crate::ast::JinjaKind::Statement,
                                                span: closing_span,
                                                expr: None,
                                                syntax_id: None,
                                            };
                                            whens.push(AstCaseWhen {
                                                node_id: self.id_gen.next(),
                                                prefix_inline_fragments: Vec::new(),
                                                when_span: closing_span,
                                                cond: closing_placeholder.clone(),
                                                then_span: closing_span,
                                                result: closing_placeholder,
                                                suffix_inline_fragments: Vec::new(),
                                            });
                                            break;
                                        }
                                    }

                                    // Parse inner WHEN clause or skip other content
                                    if matches!(inner.kind, TokenKind::Keyword(Keyword::When)) {
                                        let when_tok = match self.advance() {
                                            Some(t) => t,
                                            None => break,
                                        };
                                        let cond = match self.parse_expr_in_mode() {
                                            Ok(e) => e,
                                            Err(_) => break,
                                        };
                                        let then_tok = match self.advance() {
                                            Some(t) => t,
                                            None => break,
                                        };
                                        if !matches!(
                                            then_tok.kind,
                                            TokenKind::Keyword(Keyword::Then)
                                        ) {
                                            break;
                                        }
                                        let result = match self.parse_expr_in_mode() {
                                            Ok(e) => e,
                                            Err(_) => break,
                                        };
                                        whens.push(AstCaseWhen {
                                            node_id: self.id_gen.next(),
                                            prefix_inline_fragments: Vec::new(),
                                            when_span: when_tok.span,
                                            cond,
                                            then_span: then_tok.span,
                                            result,
                                            suffix_inline_fragments: Vec::new(),
                                        });
                                    } else if matches!(
                                        inner.kind,
                                        TokenKind::JinjaComment
                                            | TokenKind::LineComment
                                            | TokenKind::BlockComment
                                    ) {
                                        self.advance();
                                    } else {
                                        break;
                                    }
                                }
                            }
                            _ => break,
                        }
                    } else {
                        break;
                    }
                }
                TokenKind::Keyword(Keyword::When) => {
                    let when_tok = self
                        .advance()
                        .expect_invariant("WHEN keyword should be available in CASE expression");
                    let cond = self.parse_expr_in_mode()?;
                    let then_tok = match self.advance() {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    if !matches!(then_tok.kind, TokenKind::Keyword(Keyword::Then)) {
                        return Err(ParseError::unexpected_token(
                            then_tok.span,
                            vec!["THEN".to_string()],
                            Parser::token_description(then_tok, self.source),
                        ));
                    }
                    let result = self.parse_expr_in_mode()?;
                    whens.push(AstCaseWhen {
                        node_id: self.id_gen.next(),
                        prefix_inline_fragments: Vec::new(),
                        when_span: when_tok.span,
                        cond,
                        then_span: then_tok.span,
                        result,
                        suffix_inline_fragments: Vec::new(),
                    });
                }
                _ => break,
            }
        }

        let mut else_expr = None;
        let mut else_token_id: Option<crate::cst::TokenId> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Else)) {
                else_token_id = Some(self.current_token_id());
                let _ = self.advance(); // ELSE
                else_expr = Some(Box::new(self.parse_expr_in_mode()?));
            }
        }

        let end_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        if !matches!(end_tok.kind, TokenKind::Keyword(Keyword::End)) {
            return Err(ParseError::unexpected_token(
                end_tok.span,
                vec!["END".to_string()],
                Parser::token_description(end_tok, self.source),
            ));
        }

        let span = Span {
            start: case_tok.span.start,
            end: end_tok.span.end,
        };
        let end_token_id = self.last_token_id();
        let kind = if operand.is_some() {
            AstCaseKind::Simple
        } else {
            AstCaseKind::Searched
        };
        let syntax_case = crate::syntax::SyntaxCaseExpr {
            case_keyword: case_token_id,
            end_keyword: end_token_id,
            else_keyword: else_token_id,
            span,
        };
        let syntax_id = self.syntax_arena.alloc_case_expr(syntax_case);

        Ok(Some(AstExpr::Case {
            node_id: self.id_gen.next(),
            syntax_id,
            kind,
            operand: operand.map(Box::new),
            whens: whens.into_iter().map(Box::new).collect(),
            else_expr,
            span,
        }))
    }
}
