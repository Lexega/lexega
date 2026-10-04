// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SELECT statement parsing
//!
//! This module handles parsing of SELECT statements including:
//! - Main SELECT parsing (try_parse_select_in_mode)
//! - Projection parsing (columns, expressions, aliases)
//! - Set operations (UNION, INTERSECT, EXCEPT)
//! - Snowflake-specific clauses (SAMPLE, CHANGES, PIVOT, UNPIVOT)
//! - Time travel (AT/BEFORE)
//! - VALUES clause
//! - Jinja template integration in projections

use crate::ast::*;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Span, Token, TokenKind};
use crate::parser::core::Parser;
use crate::parser::scripting::expr_span_end;

/// Parsed components of a SELECT before its FROM clause, threaded from
/// [`Parser::parse_select_head`] into [`Parser::finish_select`] so the prelude
/// and tail locals stay out of the recursive frame that descends into FROM.
struct SelectHead {
    select_span: Span,
    select_as_qualifier: Option<Span>,
    set_quantifier: Option<Box<crate::ast::AstSetQuantifier>>,
    set_quantifier_span: Option<Span>,
    top: Option<crate::ast::AstTop>,
    projection: crate::ast::AstProjection,
    into_target: Option<Box<crate::ast::AstSelectIntoTarget>>,
}

/// Check if a lexeme matches a clause keyword that terminates SELECT list parsing.
/// This avoids allocating a String for case-insensitive comparison.
#[inline]
pub(crate) fn is_clause_keyword_lexeme(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("FROM")
        || lexeme.eq_ignore_ascii_case("WHERE")
        || lexeme.eq_ignore_ascii_case("GROUP")
        || lexeme.eq_ignore_ascii_case("ORDER")
        || lexeme.eq_ignore_ascii_case("HAVING")
        || lexeme.eq_ignore_ascii_case("QUALIFY")
        || lexeme.eq_ignore_ascii_case("LIMIT")
        || lexeme.eq_ignore_ascii_case("OFFSET")
        || lexeme.eq_ignore_ascii_case("UNION")
        || lexeme.eq_ignore_ascii_case("INTERSECT")
        || lexeme.eq_ignore_ascii_case("EXCEPT")
        || lexeme.eq_ignore_ascii_case("INTO")
        || lexeme.eq_ignore_ascii_case("BY")
        || lexeme.eq_ignore_ascii_case("ON")
        || lexeme.eq_ignore_ascii_case("USING")
        || lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("INNER")
        || lexeme.eq_ignore_ascii_case("LEFT")
        || lexeme.eq_ignore_ascii_case("RIGHT")
        || lexeme.eq_ignore_ascii_case("FULL")
        || lexeme.eq_ignore_ascii_case("CROSS")
        || lexeme.eq_ignore_ascii_case("NATURAL")
        || lexeme.eq_ignore_ascii_case("AS")
}

/// Consume any immediately adjacent Jinja expressions after an identifier.
/// Handles patterns like `total_{{ metric }}` where the identifier is followed
/// by a Jinja expression without whitespace between them.
///
/// Returns the extended end position if Jinja expressions were consumed,
/// otherwise returns the original end position.
pub(crate) fn consume_adjacent_jinja_exprs(parser: &mut Parser, mut end_pos: u32) -> u32 {
    // Keep consuming adjacent Jinja expressions
    while let Some(tok) = parser.peek() {
        if matches!(tok.kind, TokenKind::JinjaExprOpen) {
            // Adjacent Jinja expression: identifier{{ suffix }}
            parser.advance(); // consume {{

            // Consume until }}
            while let Some(inner) = parser.peek() {
                if matches!(inner.kind, TokenKind::JinjaExprClose) {
                    end_pos = inner.span.end;
                    parser.advance();
                    break;
                }
                parser.advance();
            }
        } else {
            break;
        }
    }
    end_pos
}

#[derive(Default)]
pub(crate) struct InlineFragmentCollection {
    pub(crate) fragments: Vec<JinjaInlineFragment>,
}

impl InlineFragmentCollection {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_comment(
        &mut self,
        parser: &mut Parser,
        token: &Token,
        token_id: crate::cst::TokenId,
    ) {
        self.fragments
            .push(parser.build_inline_comment_fragment(token, token_id));
    }

    pub(crate) fn push_punctuation(
        &mut self,
        parser: &mut Parser,
        token: &Token,
        token_id: crate::cst::TokenId,
    ) {
        self.fragments
            .push(parser.build_inline_punctuation_fragment(token, token_id));
    }

    pub(crate) fn push_inline_block(&mut self, fragment: JinjaInlineFragment) {
        self.fragments.push(fragment);
    }
}

// Implementation methods will be added here via:
impl<'a> Parser<'a> {
    /// Parse an optional TOP clause: `TOP <number|(expr)> [PERCENT] [WITH TIES]`
    ///
    /// Used by SELECT, DELETE, and UPDATE parsers.
    /// Returns `Ok(None)` if the next token is not `TOP`.
    pub(crate) fn try_parse_top_clause(&mut self) -> ParseResult<Option<AstTop>> {
        let tok = match self.peek() {
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Top)) => t,
            _ => return Ok(None),
        };
        let _ = tok; // consumed via advance below

        let top_kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TOP number".to_string()])?;

        // TOP can take a bare number or a parenthesized expression
        let next_tok = self.peek().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "TOP requires a number or (expression)".to_string(),
                },
            )
        })?;

        let (expr, expr_end) = if matches!(
            next_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            // Parenthesized expression: TOP (expr)
            let lparen = self.advance().unwrap();
            let lparen_token_id = self.last_token_id();
            let inner_expr = self.parse_expr()?;
            let rparen = self.advance().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidSyntax {
                        message: "Expected ')' after TOP expression".to_string(),
                    },
                )
            })?;
            let rparen_token_id = self.last_token_id();
            let paren_span = Span {
                start: lparen.span.start,
                end: rparen.span.end,
            };

            let syntax_paren_expr = crate::syntax::SyntaxParenExpr {
                l_paren: lparen_token_id,
                inner_span: inner_expr.span(),
                r_paren: rparen_token_id,
                span: paren_span,
            };
            let syntax_id = self.syntax_arena.alloc_paren_expr(syntax_paren_expr);

            let paren_expr = AstExpr::Parenthesized {
                node_id: self.id_gen.next(),
                syntax_id,
                expr: Box::new(inner_expr),
                span: paren_span,
            };
            (paren_expr, rparen.span.end)
        } else if matches!(
            next_tok.kind,
            TokenKind::Literal(crate::lexer::LiteralKind::Number)
        ) {
            // Bare number: TOP 10
            let num_tok = self.advance().unwrap();
            let expr = AstExpr::Literal {
                node_id: self.id_gen.next(),
                literal: AstLiteral::Number { span: num_tok.span },
            };
            (expr, num_tok.span.end)
        } else {
            return Err(ParseError::unexpected_token(
                next_tok.span,
                vec!["number".to_string(), "(".to_string()],
                Self::token_description(next_tok, self.source),
            ));
        };

        // Check for optional PERCENT keyword (Identifier token with lexeme "PERCENT")
        let mut percent_span = None;
        let mut span_end = expr_end;
        if let Some(pct_tok) = self.peek() {
            if matches!(pct_tok.kind, TokenKind::Identifier { .. })
                && pct_tok.lexeme(self.source).eq_ignore_ascii_case("PERCENT")
            {
                let pct = self.advance().unwrap();
                percent_span = Some(pct.span);
                span_end = pct.span.end;
            }
        }

        // Check for optional WITH TIES (WITH is Keyword, TIES is Identifier)
        let mut with_ties_span = None;
        if let Some(with_tok) = self.peek() {
            if matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                let save_idx = self.idx;
                let with_t = self.advance().unwrap();
                if let Some(ties_tok) = self.peek() {
                    if matches!(ties_tok.kind, TokenKind::Identifier { .. })
                        && ties_tok.lexeme(self.source).eq_ignore_ascii_case("TIES")
                    {
                        let ties_t = self.advance().unwrap();
                        with_ties_span = Some(Span {
                            start: with_t.span.start,
                            end: ties_t.span.end,
                        });
                        span_end = ties_t.span.end;
                    } else {
                        self.idx = save_idx;
                    }
                } else {
                    self.idx = save_idx;
                }
            }
        }

        let span = Span {
            start: top_kw.span.start,
            end: span_end,
        };
        Ok(Some(crate::parser::sql_stmt::build_top(
            self.id_gen.next(),
            span,
            top_kw.span,
            expr,
            percent_span,
            with_ties_span,
        )))
    }

    pub(crate) fn parse_condition_clause(
        &mut self,
        keyword_span: Span,
        _error_message: &str,
    ) -> crate::error::ParseResult<crate::ast::ConditionClause> {
        let InlineFragmentCollection {
            fragments: prefix_inline_fragments,
        } = self.collect_leading_inline_fragments();

        let expr = self.parse_expr()?;

        let InlineFragmentCollection {
            fragments: suffix_inline_fragments,
        } = self.collect_trailing_inline_fragments();

        // After collecting trailing fragments, check for continuation operators (Jinja pattern)
        // Example: WHERE expr1 {% if %}AND expr2{% endif %} AND expr3
        // The last AND should extend the clause span but remain as source tokens
        // ONLY do this if we have suffix fragments (meaning Jinja blocks are present)
        let mut trailing_end = suffix_inline_fragments
            .last()
            .map(|f| f.span.end)
            .unwrap_or_else(|| expr_span_end(&expr));

        // Consume any continuation AND/OR tokens ONLY if we have Jinja inline fragments
        // This handles patterns like: WHERE expr {% if %}AND expr2{% endif %} AND expr3
        let mut continuation_fragments = Vec::new();
        if !suffix_inline_fragments.is_empty() {
            while let Some(tok) = self.peek() {
                if matches!(
                    tok.kind,
                    TokenKind::Keyword(Keyword::And) | TokenKind::Keyword(Keyword::Or)
                ) {
                    // Try to parse the continuation
                    let save_idx = self.idx;
                    let op_keyword = match &tok.kind {
                        TokenKind::Keyword(kw) => *kw,
                        _ => unreachable!(),
                    };
                    self.advance(); // consume AND/OR

                    // Try to parse the RHS expression
                    match self.parse_expr() {
                        Ok(rhs) => {
                            trailing_end = expr_span_end(&rhs);
                            // Successfully consumed continuation - store in AST for formatting
                            continuation_fragments.push((op_keyword, rhs));
                            continue;
                        }
                        Err(_) => {
                            // Failed to parse continuation, restore and stop
                            self.idx = save_idx;
                            break;
                        }
                    }
                }
                break;
            }
        }

        Ok(crate::ast::ConditionClause {
            node_id: self.id_gen.next(),
            prefix_inline_fragments,
            suffix_inline_fragments,
            expr,
            continuation_fragments,
            span: Span {
                start: keyword_span.start,
                end: trailing_end,
            },
        })
    }

    /// Collect leading inline Jinja fragments (comments and inline blocks)
    ///
    /// # Parameters
    /// * `allow_statement_level_blocks` - If true, do NOT consume {% for %} or {% if %} blocks
    ///   that should be parsed as statement-level constructs in the current context.
    ///   If false, attempt to parse them as inline fragments (within expressions).
    pub(crate) fn collect_leading_inline_fragments(&mut self) -> InlineFragmentCollection {
        self.collect_leading_inline_fragments_with_context(false)
    }

    pub(crate) fn collect_leading_inline_fragments_in_projection_context(
        &mut self,
    ) -> InlineFragmentCollection {
        self.collect_leading_inline_fragments_with_context(true)
    }

    fn collect_leading_inline_fragments_with_context(
        &mut self,
        in_projection_context: bool,
    ) -> InlineFragmentCollection {
        let mut collection = InlineFragmentCollection::new();
        loop {
            if self.try_collect_inline_comment(&mut collection) {
                continue;
            }
            // Leading context: is_trailing=false, so only comma wrappers are consumed as inline
            if self.try_collect_inline_block_fragment_with_context(
                &mut collection,
                in_projection_context,
                false,
            ) {
                continue;
            }
            break;
        }
        collection
    }

    pub(crate) fn collect_trailing_inline_fragments(&mut self) -> InlineFragmentCollection {
        let mut collection = InlineFragmentCollection::new();
        let mut saw_inline = false;
        loop {
            if self.try_collect_inline_comment(&mut collection) {
                saw_inline = true;
                continue;
            }
            // For trailing fragments, allow ANY {% if %} block (not just comma wrappers)
            // because the main expression has already been parsed
            if self.try_collect_inline_block_fragment_trailing(&mut collection) {
                saw_inline = true;
                continue;
            }
            if saw_inline {
                match self.peek() {
                    // Only collect commas as trailing punctuation
                    // Do NOT consume semicolons - they are statement terminators captured by try_parse_script
                    // Do NOT consume ) or other structural punctuation
                    Some(tok)
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) =>
                    {
                        let punct_tok = self
                            .advance()
                            .expect_invariant("Comma consumed after match");
                        let token_id = self.last_token_id();
                        collection.push_punctuation(self, punct_tok, token_id);
                        continue;
                    }
                    _ => {}
                }
            }
            break;
        }
        collection
    }

    /// Check if the current {% if %} block is a "comma wrapper" pattern.
    /// This detects patterns like: {% if not loop.last %},{% endif %}
    /// which should be treated as inline fragments, not statement-level blocks.
    /// Returns true if the block contains only punctuation/comments (inline),
    /// false if it contains identifiers/expressions (statement-level).
    fn is_jinja_block_comma_wrapper(&self) -> bool {
        // Save position for lookahead
        let mut lookahead_idx = self.idx;

        // Skip past the {% if ... %} opening
        // First, verify we're at {%
        if lookahead_idx >= self.tokens.len() {
            return false;
        }
        if !matches!(self.tokens[lookahead_idx].kind, TokenKind::JinjaStmtOpen) {
            return false;
        }
        lookahead_idx += 1; // skip {%

        // Skip tokens until we find %}
        while lookahead_idx < self.tokens.len() {
            if matches!(self.tokens[lookahead_idx].kind, TokenKind::JinjaStmtClose) {
                lookahead_idx += 1; // skip %}
                break;
            }
            lookahead_idx += 1;
        }

        // Now we're past the opening delimiter, look at the content
        // A comma wrapper has content that is only punctuation (comma, semi) and comments
        // until we hit {% endif %}
        while lookahead_idx < self.tokens.len() {
            let tok = &self.tokens[lookahead_idx];
            match &tok.kind {
                // Punctuation and comments are fine for inline
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::JinjaComment
                | TokenKind::LineComment
                | TokenKind::BlockComment => {
                    lookahead_idx += 1;
                }
                // {% ... %} - check if it's endif (end of block) or else/elif (still inline)
                TokenKind::JinjaStmtOpen => {
                    // Peek at the keyword inside
                    let Some(next) = self.tokens.get(lookahead_idx + 1) else {
                        return false;
                    };
                    match &next.kind {
                        TokenKind::JinjaEndIf | TokenKind::JinjaEndFor => {
                            // Reached the closing - this is a comma wrapper
                            return true;
                        }
                        TokenKind::JinjaElse | TokenKind::JinjaElif => {
                            // else/elif branches - skip to next %} and continue
                            lookahead_idx += 2; // skip {% and keyword
                                                // Skip until %}
                            while lookahead_idx < self.tokens.len() {
                                if matches!(
                                    self.tokens[lookahead_idx].kind,
                                    TokenKind::JinjaStmtClose
                                ) {
                                    lookahead_idx += 1;
                                    break;
                                }
                                lookahead_idx += 1;
                            }
                        }
                        _ => {
                            // Some other keyword (nested block?) - not a simple comma wrapper
                            return false;
                        }
                    }
                }
                // Any other token (identifier, expression, etc.) means it's statement-level
                _ => {
                    return false;
                }
            }
        }

        // Reached end of tokens without signal closing - not a valid comma wrapper
        false
    }

    pub(crate) fn try_collect_inline_comment(
        &mut self,
        collection: &mut InlineFragmentCollection,
    ) -> bool {
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::JinjaComment) {
                let comment_tok = self
                    .advance()
                    .expect_invariant("JinjaComment consumed after peek");
                let token_id = self.last_token_id();
                collection.push_comment(self, comment_tok, token_id);
                return true;
            }
        }
        false
    }

    /// Collect inline block fragment in trailing position (after expression parsed).
    /// In trailing position, we allow ANY {% if %} block, not just comma wrappers.
    fn try_collect_inline_block_fragment_trailing(
        &mut self,
        collection: &mut InlineFragmentCollection,
    ) -> bool {
        self.try_collect_inline_block_fragment_with_context(collection, false, true)
    }

    pub(crate) fn try_collect_inline_block_fragment_with_context(
        &mut self,
        collection: &mut InlineFragmentCollection,
        in_projection_context: bool,
        is_trailing: bool,
    ) -> bool {
        if let Some(fragment) =
            self.try_parse_inline_block_fragment_with_context(in_projection_context, is_trailing)
        {
            collection.push_inline_block(fragment);
            return true;
        }
        false
    }

    pub(crate) fn try_parse_inline_block_fragment_with_context(
        &mut self,
        in_projection_context: bool,
        is_trailing: bool,
    ) -> Option<JinjaInlineFragment> {
        let save_idx = self.idx;
        let result = self.parse_inline_block_fragment_internal(in_projection_context, is_trailing);
        if result.is_none() {
            self.idx = save_idx;
        }
        result
    }

    fn parse_inline_block_fragment_internal(
        &mut self,
        _in_projection_context: bool,
        is_trailing: bool,
    ) -> Option<JinjaInlineFragment> {
        use crate::ast::{JinjaBlockKind, JinjaInlineElifBranch, JinjaInlineElseBranch};

        let opening_kind = match self.peek_jinja_block_kind()? {
            JinjaBlockKind::If => {
                // In trailing position (after expression parsed), allow any {% if %} block.
                // In leading position, only allow "comma wrapper" patterns like
                // {% if not loop.last %},{% endif %} to be treated as inline.
                // Non-comma-wrapper blocks in leading position should be left for
                // parse_expr() to handle as JinjaConditional expressions.
                if !is_trailing && !self.is_jinja_block_comma_wrapper() {
                    return None;
                }
                JinjaBlockKind::If
            }
            JinjaBlockKind::For => {
                // {% for %} blocks should NOT be parsed as inline fragments in expression contexts
                // (WHERE, HAVING, JOIN ON, etc.). They should be parsed by the expression parser
                // as JinjaConditional expressions. Only in projection context might we want
                // special handling, but even there we return None to let the proper handler take over.
                return None;
            }
            JinjaBlockKind::Set => {
                // {% set %} statements can appear as inline in projections
                // They're complete single-delimiter blocks: {% set var = expr %}
                return self.parse_set_statement_as_inline_fragment();
            }
            _ => return None,
        };

        let opening = self.parse_inline_block_opening(opening_kind.clone())?;
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => return None,
        };

        // Parse the "then" branch content
        let content = self.parse_inline_block_branch_content(&closing_kind)?;

        // Now handle elif/else branches
        let mut elif_branches: Vec<JinjaInlineElifBranch> = Vec::new();
        let mut else_branch: Option<JinjaInlineElseBranch> = None;

        // Handle elif branches (only for If blocks)
        if opening_kind == JinjaBlockKind::If {
            while let Some(kind) = self.peek_jinja_block_kind() {
                if kind == JinjaBlockKind::Elif {
                    let elif_delim = self.parse_inline_block_opening(JinjaBlockKind::Elif)?;
                    let elif_content = self.parse_inline_block_branch_content(&closing_kind)?;
                    elif_branches.push(JinjaInlineElifBranch {
                        node_id: self.id_gen.next(),
                        delimiter: elif_delim,
                        content: elif_content,
                    });
                } else {
                    break;
                }
            }

            // Handle else branch
            if let Some(JinjaBlockKind::Else) = self.peek_jinja_block_kind() {
                let else_delim = self.parse_inline_block_opening(JinjaBlockKind::Else)?;
                let else_content = self.parse_inline_block_branch_content(&closing_kind)?;
                else_branch = Some(JinjaInlineElseBranch {
                    node_id: self.id_gen.next(),
                    delimiter: else_delim,
                    content: else_content,
                });
            }
        }

        // Now expect the closing delimiter
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == closing_kind {
                let closing = self.parse_inline_block_closing(closing_kind)?;
                return Some(self.build_inline_block_fragment(
                    opening,
                    content,
                    elif_branches,
                    else_branch,
                    Some(closing),
                ));
            }
        }

        None
    }

    /// Parse the content of a single branch within an inline block
    /// Stops at elif, else, or closing delimiter
    fn parse_inline_block_branch_content(
        &mut self,
        closing_kind: &crate::ast::JinjaBlockKind,
    ) -> Option<Option<crate::ast::JinjaInlineBlockContent>> {
        use crate::ast::{JinjaBlockKind, JinjaInlineBlockContent};
        use crate::lexer::Keyword;

        let mut content: Option<JinjaInlineBlockContent> = None;

        loop {
            let tok = self.peek()?;
            match tok.kind {
                TokenKind::JinjaComment => {
                    self.advance();
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                    // Store punctuation as content if we haven't captured anything else
                    if content.is_none() {
                        let tok = self.advance()?;
                        content = Some(JinjaInlineBlockContent::Punctuation(
                            crate::ast::JinjaInlinePunctuation {
                                token_kind: tok.kind.clone(),
                                span: tok.span,
                            },
                        ));
                    } else {
                        self.advance();
                    }
                }
                TokenKind::JinjaStmtOpen => {
                    let kind = self.peek_jinja_block_kind()?;
                    // Stop at closing, elif, or else delimiters
                    if kind == *closing_kind
                        || matches!(kind, JinjaBlockKind::Elif | JinjaBlockKind::Else)
                    {
                        return Some(content);
                    } else if matches!(kind, JinjaBlockKind::If | JinjaBlockKind::For) {
                        // Nested Jinja block - parse it recursively
                        // Pass false for in_projection_context, true for is_trailing (inside block)
                        if content.is_none() {
                            let nested_fragment =
                                self.try_parse_inline_block_fragment_with_context(false, true)?;
                            content = Some(JinjaInlineBlockContent::NestedFragment(Box::new(
                                nested_fragment,
                            )));
                            continue;
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
                // Handle expression continuations (AND/OR at start of content)
                TokenKind::Keyword(Keyword::And) | TokenKind::Keyword(Keyword::Or) => {
                    if content.is_none() {
                        let op_token_id = self.current_token_id();
                        let op_tok = self.advance()?;
                        let operator = match &op_tok.kind {
                            TokenKind::Keyword(Keyword::And) => crate::ast::BinaryOperator::And,
                            TokenKind::Keyword(Keyword::Or) => crate::ast::BinaryOperator::Or,
                            _ => return None,
                        };

                        let rhs = match self.parse_expr() {
                            Ok(e) => e,
                            Err(_) => return None,
                        };
                        let rhs_end = rhs.span().end;
                        let syntax_id =
                            self.syntax_arena
                                .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                                    op_token: op_token_id,
                                    span: op_tok.span,
                                });

                        let expr = crate::ast::AstExpr::BinaryOp {
                            node_id: self.id_gen.next(),
                            left: Box::new(crate::ast::AstExpr::Placeholder {
                                node_id: self.id_gen.next(),
                                span: crate::lexer::Span {
                                    start: op_tok.span.start,
                                    end: op_tok.span.start,
                                },
                            }),
                            operator,
                            syntax_id,
                            right: Box::new(rhs),
                            span: crate::lexer::Span {
                                start: op_tok.span.start,
                                end: rhs_end,
                            },
                        };
                        content = Some(JinjaInlineBlockContent::Expr(Box::new(expr)));
                    } else {
                        return None;
                    }
                }
                // Handle JOIN clause content
                TokenKind::Keyword(Keyword::Join)
                | TokenKind::Keyword(Keyword::Left)
                | TokenKind::Keyword(Keyword::Right)
                | TokenKind::Keyword(Keyword::Full)
                | TokenKind::Keyword(Keyword::Inner)
                | TokenKind::Keyword(Keyword::Cross)
                | TokenKind::Keyword(Keyword::Natural) => {
                    if content.is_none() {
                        let dummy_span = tok.span;
                        let dummy_name = crate::ast::AstObjectRef {
                            node_id: self.id_gen.next(),
                            span: dummy_span,
                            // Synthetic placeholder for error-recovery
                            // path; not a real qualified name.
                            parts: None,
                            identifier_arg: None,
                        };
                        let mut temp_table = crate::ast::AstTableRef {
                            node_id: self.id_gen.next(),
                            span: dummy_span,
                            name: Box::new(dummy_name),
                            prefix_inline_fragments: Box::new(Vec::new()),
                            alias: None,
                            alias_columns: None,
                            result_alias: None,
                            result_alias_columns: None,
                            subquery: None,
                            subquery_lparen_span: None,
                            subquery_rparen_span: None,
                            paren_group: None,
                            values: None,
                            lateral_keyword_span: None,
                            only_span: None,
                            time_travel: None,
                            syntax_id: None,
                            sample: None,
                            changes: None,
                            stage_options: None,
                            table_function: None,
                            tvf_schema_span: None,
                            with_offset: None,
                            pivot: None,
                            unpivot: None,
                            match_recognize: None,
                            table_hints: None,
                            index_hints: None,
                            partition_selection: None,
                            suffix_inline_fragments: Box::new(Vec::new()),
                            joins: Box::new(Vec::new()),
                        };

                        if self.parse_join_chain(&mut temp_table).is_err() {
                            return None;
                        }

                        if !temp_table.joins.is_empty() {
                            // Check if there's a WHERE clause after the JOINs
                            if let Some(next_tok) = self.peek() {
                                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Where)) {
                                    self.advance(); // Consume WHERE
                                    if let Ok(where_expr) = self.parse_expr() {
                                        // We have both JOIN and WHERE
                                        content = Some(JinjaInlineBlockContent::JoinsAndWhere {
                                            joins: *temp_table.joins,
                                            where_clause: Box::new(where_expr),
                                        });
                                    } else {
                                        return None;
                                    }
                                } else {
                                    // Only JOINs, no WHERE
                                    content =
                                        Some(JinjaInlineBlockContent::Joins(*temp_table.joins));
                                }
                            } else {
                                // Only JOINs, no WHERE
                                content = Some(JinjaInlineBlockContent::Joins(*temp_table.joins));
                            }
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
                // Handle WHERE clause content
                TokenKind::Keyword(Keyword::Where) => {
                    if content.is_none() {
                        self.advance();
                        if let Ok(expr) = self.parse_expr() {
                            content = Some(JinjaInlineBlockContent::WhereClause(Box::new(expr)));
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
                // Handle comparison operators at start of content (e.g., `= 'active'`)
                // Pattern: status {% if active %}= 'active'{% endif %}
                TokenKind::Operator(
                    crate::lexer::Operator::Eq
                    | crate::lexer::Operator::NotEq
                    | crate::lexer::Operator::AngleNotEq
                    | crate::lexer::Operator::Lt
                    | crate::lexer::Operator::Le
                    | crate::lexer::Operator::Gt
                    | crate::lexer::Operator::Ge,
                ) => {
                    if content.is_none() {
                        let op_token_id = self.current_token_id();
                        let op_tok = self.advance()?;

                        // Map token to BinaryOperator
                        let operator = match &op_tok.kind {
                            TokenKind::Operator(crate::lexer::Operator::Eq) => {
                                crate::ast::BinaryOperator::Equal
                            }
                            TokenKind::Operator(crate::lexer::Operator::NotEq) => {
                                crate::ast::BinaryOperator::NotEqual
                            }
                            TokenKind::Operator(crate::lexer::Operator::AngleNotEq) => {
                                crate::ast::BinaryOperator::NotEqual
                            }
                            TokenKind::Operator(crate::lexer::Operator::Lt) => {
                                crate::ast::BinaryOperator::LessThan
                            }
                            TokenKind::Operator(crate::lexer::Operator::Le) => {
                                crate::ast::BinaryOperator::LessThanOrEqual
                            }
                            TokenKind::Operator(crate::lexer::Operator::Gt) => {
                                crate::ast::BinaryOperator::GreaterThan
                            }
                            TokenKind::Operator(crate::lexer::Operator::Ge) => {
                                crate::ast::BinaryOperator::GreaterThanOrEqual
                            }
                            _ => return None,
                        };

                        // Parse the right-hand side expression
                        let rhs = match self.parse_expr() {
                            Ok(e) => e,
                            Err(_) => return None,
                        };
                        let rhs_end = rhs.span().end;
                        let syntax_id =
                            self.syntax_arena
                                .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                                    op_token: op_token_id,
                                    span: op_tok.span,
                                });

                        // Create a BinaryOp with placeholder left side (will be filled by caller)
                        let expr = crate::ast::AstExpr::BinaryOp {
                            node_id: self.id_gen.next(),
                            left: Box::new(crate::ast::AstExpr::Placeholder {
                                node_id: self.id_gen.next(),
                                span: crate::lexer::Span {
                                    start: op_tok.span.start,
                                    end: op_tok.span.start,
                                },
                            }),
                            operator,
                            syntax_id,
                            right: Box::new(rhs),
                            span: crate::lexer::Span {
                                start: op_tok.span.start,
                                end: rhs_end,
                            },
                        };
                        content = Some(JinjaInlineBlockContent::Expr(Box::new(expr)));
                    } else {
                        return None;
                    }
                }
                // Handle BETWEEN at start of content (e.g., `BETWEEN 1 AND 10`)
                // Pattern: status {% if x %}BETWEEN 1 AND 10{% endif %}
                TokenKind::Keyword(Keyword::Between) => {
                    if content.is_none() {
                        let between_start = tok.span.start;
                        let between_keyword_id = self.current_token_id();
                        self.advance(); // Consume BETWEEN

                        // Parse lower bound expression
                        let lower = match self.parse_expr() {
                            Ok(e) => e,
                            Err(_) => return None,
                        };

                        // Expect AND keyword
                        let tok = self.peek()?;
                        if !matches!(tok.kind, TokenKind::Keyword(Keyword::And)) {
                            return None;
                        }
                        let and_keyword_id = self.current_token_id();
                        self.advance(); // Consume AND

                        // Parse upper bound expression
                        let upper = match self.parse_expr() {
                            Ok(e) => e,
                            Err(_) => return None,
                        };
                        let upper_end = upper.span().end;

                        // Create a Between expression with placeholder left side
                        // Note: NOT BETWEEN would need to be handled separately if needed
                        let syntax_id = self.syntax_arena.alloc_between_expr(
                            crate::syntax::SyntaxBetweenExpr {
                                not_keyword: None,
                                between_keyword: between_keyword_id,
                                symmetric_keyword: None,
                                and_keyword: and_keyword_id,
                                span: crate::lexer::Span {
                                    start: between_start,
                                    end: upper_end,
                                },
                            },
                        );

                        let expr = crate::ast::AstExpr::Between {
                            node_id: self.id_gen.next(),
                            syntax_id,
                            expr: Box::new(crate::ast::AstExpr::Placeholder {
                                node_id: self.id_gen.next(),
                                span: crate::lexer::Span {
                                    start: between_start,
                                    end: between_start,
                                },
                            }),
                            lower: Box::new(lower),
                            upper: Box::new(upper),
                            // Jinja-inline `BETWEEN` block has no
                            // lexer-visible NOT — the wrapper context
                            // owns negation if any. Default false.
                            negated: false,
                            span: crate::lexer::Span {
                                start: between_start,
                                end: upper_end,
                            },
                        };
                        content = Some(JinjaInlineBlockContent::Expr(Box::new(expr)));
                    } else {
                        return None;
                    }
                }
                // Handle LIKE/ILIKE/RLIKE at start of content (e.g., `LIKE 'pattern'`)
                // Pattern: name {% if x %}LIKE 'John%'{% endif %}
                TokenKind::Keyword(Keyword::Like | Keyword::Ilike | Keyword::Rlike) => {
                    if content.is_none() {
                        let like_start = tok.span.start;
                        let like_kind_span = tok.span;
                        self.advance(); // Consume LIKE/ILIKE/RLIKE

                        // Parse pattern expression
                        let pattern = match self.parse_expr() {
                            Ok(e) => e,
                            Err(_) => return None,
                        };

                        // Check for optional ESCAPE clause (native or ODBC)
                        let (escape_clause, odbc_escape_span) =
                            match self.parse_optional_escape_clause() {
                                Ok(Some(esc)) => (Some(esc.expr), esc.odbc_span),
                                Ok(None) => (None, None),
                                Err(_) => return None,
                            };

                        let pattern_end = odbc_escape_span
                            .map(|s| s.end)
                            .or_else(|| escape_clause.as_ref().map(|e| e.span().end))
                            .unwrap_or_else(|| pattern.span().end);

                        // Create a Like expression with placeholder left side
                        // Note: NOT LIKE would need to be handled separately if needed
                        let expr = crate::ast::AstExpr::Like {
                            node_id: self.id_gen.next(),
                            expr: Box::new(crate::ast::AstExpr::Placeholder {
                                node_id: self.id_gen.next(),
                                span: crate::lexer::Span {
                                    start: like_start,
                                    end: like_start,
                                },
                            }),
                            not_span: None,
                            like_kind_span,
                            pattern: Box::new(pattern),
                            escape_clause,
                            odbc_escape_span,
                            span: crate::lexer::Span {
                                start: like_start,
                                end: pattern_end,
                            },
                        };
                        content = Some(JinjaInlineBlockContent::Expr(Box::new(expr)));
                    } else {
                        return None;
                    }
                }
                // Try to parse SQL content as a regular expression
                _ => {
                    if content.is_none() {
                        if let Ok(expr) = self.parse_expr() {
                            content = Some(JinjaInlineBlockContent::Expr(Box::new(expr)));
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                }
            }
        }
    }

    fn parse_inline_block_opening(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
    ) -> Option<crate::ast::JinjaBlockDelimiter> {
        let open_brace_tok = self.advance()?;
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?;
        let keyword_id = self.last_token_id();
        let condition = match opening_kind {
            crate::ast::JinjaBlockKind::If => {
                // Parse the condition expression
                self.parse_jinja_expr().ok().flatten()
            }
            crate::ast::JinjaBlockKind::For => {
                // For FOR loops, consume all tokens until %} without parsing
                // This preserves comma-separated variables, 'in' keyword, and iterable expression
                // Note: The tokens are consumed and will be emitted by the formatter
                // based on the token range between keyword_id and close_brace_id
                while let Some(t) = self.peek() {
                    if matches!(t.kind, TokenKind::JinjaStmtClose) {
                        break;
                    }
                    self.advance();
                }
                None // Don't try to parse complex FOR syntax as expression
            }
            _ => None,
        };
        if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
            return None;
        }
        let close_brace_tok = self.advance()?;
        let close_brace_id = self.last_token_id();
        let opening_span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };
        Some(self.alloc_jinja_delimiter(
            opening_span,
            opening_kind,
            condition,
            open_brace_id,
            keyword_id,
            close_brace_id,
        ))
    }

    fn parse_inline_block_closing(
        &mut self,
        closing_kind: crate::ast::JinjaBlockKind,
    ) -> Option<crate::ast::JinjaBlockDelimiter> {
        let open_brace_tok = self.advance()?;
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?;
        let keyword_id = self.last_token_id();
        if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
            return None;
        }
        let close_brace_tok = self.advance()?;
        let close_brace_id = self.last_token_id();
        let closing_span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };
        Some(self.alloc_jinja_delimiter(
            closing_span,
            closing_kind,
            None,
            open_brace_id,
            keyword_id,
            close_brace_id,
        ))
    }

    /// Parse a {% set %} statement as an inline fragment
    /// These are single-delimiter blocks: {% set var = expr %}
    fn parse_set_statement_as_inline_fragment(
        &mut self,
    ) -> Option<crate::ast::JinjaInlineFragment> {
        use crate::ast::JinjaBlockKind;

        let open_brace_tok = self.advance()?; // {%
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?; // set
        let keyword_id = self.last_token_id();

        // Use the existing parse_jinja_set_stmt which handles the full set statement
        let _stmt = self.parse_jinja_set_stmt()?;

        // Expect closing %}
        if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
            return None;
        }
        let close_brace_tok = self.advance()?; // %}
        let close_brace_id = self.last_token_id();

        let span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };

        // Build a delimiter that represents the entire {% set ... %} statement
        // The stmt contains the parsed assignment, we can extract it if needed
        let delimiter = self.alloc_jinja_delimiter(
            span,
            JinjaBlockKind::Set,
            None, // Set statements have complex structure, stored in stmt
            open_brace_id,
            keyword_id,
            close_brace_id,
        );

        // Set statements don't have content or closing - they're single delimiters
        // Wrap as an inline fragment with empty content
        Some(self.build_inline_block_fragment(
            delimiter,
            None,       // No content
            Vec::new(), // No elif branches
            None,       // No else branch
            None,       // No closing delimiter (set is single-delimiter)
        ))
    }

    // ========== SELECT Parsing ==========

    /// Parse AT/BEFORE time-travel clause
    /// Syntax: {AT | BEFORE} (TIMESTAMP => expr | OFFSET => expr | STATEMENT => expr | STREAM => expr)
    pub(crate) fn parse_time_travel(&mut self) -> ParseResult<Option<crate::ast::AstTimeTravel>> {
        // Check for AT or BEFORE keyword (they are parsed as identifiers)
        let first_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        let is_before = match &first_tok.kind {
            TokenKind::Identifier { .. } => {
                if first_tok.lexeme(self.source).eq_ignore_ascii_case("BEFORE") {
                    true
                } else if first_tok.lexeme(self.source).eq_ignore_ascii_case("AT") {
                    false
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };

        // Save position before consuming AT/BEFORE so we can backtrack
        // if no '(' follows (e.g., `FROM my_table at` where `at` is an alias).
        let saved_idx = self.idx;

        let start_span = first_tok.span.start;
        self.advance(); // consume AT or BEFORE

        // Expect opening parenthesis — if not found, restore position
        match self.peek() {
            Some(tok)
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) =>
            {
                tok
            }
            _ => {
                self.idx = saved_idx; // Restore: AT/BEFORE was not time travel
                return Ok(None);
            }
        };
        self.advance(); // consume '('

        // Parse the parameter type (TIMESTAMP, OFFSET, STATEMENT, or STREAM)
        let param_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["TIMESTAMP".to_string()])?;
        let param_lexeme = match &param_tok.kind {
            TokenKind::Identifier { .. } | TokenKind::Keyword(_) => &param_tok.lexeme(self.source),
            _ => {
                return Err(ParseError::unexpected_token(
                    param_tok.span,
                    vec![
                        "TIMESTAMP".to_string(),
                        "OFFSET".to_string(),
                        "STATEMENT".to_string(),
                        "STREAM".to_string(),
                    ],
                    Parser::token_description(param_tok, self.source),
                ));
            }
        };
        let param_span = param_tok.span;
        self.advance(); // consume parameter type

        // Expect '=>' operator
        let arrow = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["=>".to_string()])?;
        if !matches!(
            arrow.kind,
            TokenKind::Operator(crate::lexer::Operator::EqGt)
        ) {
            return Err(ParseError::unexpected_token(
                arrow.span,
                vec!["=>".to_string()],
                Parser::token_description(arrow, self.source),
            ));
        }
        self.advance(); // consume '=>'

        // Parse the expression
        let expr = self.parse_expr()?;

        // Expect closing parenthesis
        let rparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rparen.span,
                vec![")".to_string()],
                Parser::token_description(rparen, self.source),
            ));
        }
        let end_span = rparen.span.end;
        self.advance(); // consume ')'

        // Determine the kind based on parameter type
        let kind = if param_lexeme.eq_ignore_ascii_case("TIMESTAMP") {
            crate::ast::AstTimeTravelKind::Timestamp(expr)
        } else if param_lexeme.eq_ignore_ascii_case("OFFSET") {
            crate::ast::AstTimeTravelKind::Offset(expr)
        } else if param_lexeme.eq_ignore_ascii_case("STATEMENT") {
            crate::ast::AstTimeTravelKind::Statement(expr)
        } else if param_lexeme.eq_ignore_ascii_case("STREAM") {
            crate::ast::AstTimeTravelKind::Stream(expr)
        } else {
            return Err(ParseError::new(
                param_span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Invalid time travel parameter type '{}', expected TIMESTAMP, OFFSET, STATEMENT, or STREAM", param_lexeme),
                },
            ));
        };

        Ok(Some(crate::ast::AstTimeTravel {
            node_id: self.id_gen.next(),
            is_before,
            kind,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse FOR SYSTEM_TIME clause (BigQuery AS OF + MSSQL temporal variants).
    ///
    /// Syntax variants:
    ///   FOR SYSTEM_TIME AS OF <expr>           (BigQuery / MSSQL)
    ///   FOR SYSTEM_TIME ALL                     (MSSQL)
    ///   FOR SYSTEM_TIME FROM <expr> TO <expr>   (MSSQL)
    ///   FOR SYSTEM_TIME BETWEEN <expr> AND <expr> (MSSQL)
    ///   FOR SYSTEM_TIME CONTAINED IN (<expr>, <expr>) (MSSQL)
    pub(crate) fn parse_for_system_time(
        &mut self,
    ) -> ParseResult<Option<crate::ast::AstForSystemTime>> {
        // Check for FOR keyword
        let first_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        if !matches!(first_tok.kind, TokenKind::Keyword(Keyword::For)) {
            return Ok(None);
        }

        // Save position so we can backtrack if this isn't FOR SYSTEM_TIME
        let saved_idx = self.idx;
        let start = first_tok.span.start;
        self.advance(); // consume FOR

        // Check for SYSTEM_TIME (lexer produces it as an Identifier)
        match self.peek() {
            Some(tok)
                if self.can_be_identifier_token(tok)
                    && tok.lexeme(self.source).eq_ignore_ascii_case("SYSTEM_TIME") =>
            {
                self.advance(); // consume SYSTEM_TIME
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        }

        // Determine which variant follows SYSTEM_TIME
        let next = match self.peek() {
            Some(tok) => tok,
            None => {
                self.idx = saved_idx;
                return Ok(None);
            }
        };

        // --- AS OF <expr> ---
        if matches!(next.kind, TokenKind::Keyword(Keyword::As)) {
            self.advance(); // AS
            match self.peek() {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Of)) => {
                    self.advance(); // OF
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            let expr = self.parse_expr()?;
            let end = expr.span().end;
            return Ok(Some(crate::ast::AstForSystemTime {
                node_id: self.id_gen.next(),
                expr: Some(Box::new(expr)),
                span: Span { start, end },
            }));
        }

        // --- ALL ---
        if matches!(next.kind, TokenKind::Keyword(Keyword::All)) {
            let all_tok = self.advance().unwrap();
            return Ok(Some(crate::ast::AstForSystemTime {
                node_id: self.id_gen.next(),
                expr: None,
                span: Span {
                    start,
                    end: all_tok.span.end,
                },
            }));
        }

        // --- FROM <expr> TO <expr> ---
        if matches!(next.kind, TokenKind::Keyword(Keyword::From)) {
            self.advance(); // FROM
                            // Use primary expr to avoid consuming TO as a binary operator
            let _from_expr = self.parse_primary_expr_in_mode()?;
            match self.peek() {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::To)) => {
                    self.advance(); // TO
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            let to_expr = self.parse_primary_expr_in_mode()?;
            let end = to_expr.span().end;
            return Ok(Some(crate::ast::AstForSystemTime {
                node_id: self.id_gen.next(),
                expr: None,
                span: Span { start, end },
            }));
        }

        // --- BETWEEN <expr> AND <expr> ---
        if matches!(next.kind, TokenKind::Keyword(Keyword::Between)) {
            self.advance(); // BETWEEN
                            // Use primary expr to avoid consuming AND as a binary operator
            let _from_expr = self.parse_primary_expr_in_mode()?;
            match self.peek() {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::And)) => {
                    self.advance(); // AND
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            let to_expr = self.parse_primary_expr_in_mode()?;
            let end = to_expr.span().end;
            return Ok(Some(crate::ast::AstForSystemTime {
                node_id: self.id_gen.next(),
                expr: None,
                span: Span { start, end },
            }));
        }

        // --- CONTAINED IN (<expr>, <expr>) ---
        if self.can_be_identifier_token(next)
            && next.lexeme(self.source).eq_ignore_ascii_case("CONTAINED")
        {
            self.advance(); // CONTAINED
            match self.peek() {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::In)) => {
                    self.advance(); // IN
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) =>
                {
                    self.advance(); // (
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            let _from_expr = self.parse_expr()?;
            // expect comma
            match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) =>
                {
                    self.advance();
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            }
            let _to_expr = self.parse_expr()?;
            // expect )
            let rparen = match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) =>
                {
                    self.advance().unwrap()
                }
                _ => {
                    self.idx = saved_idx;
                    return Ok(None);
                }
            };
            return Ok(Some(crate::ast::AstForSystemTime {
                node_id: self.id_gen.next(),
                expr: None,
                span: Span {
                    start,
                    end: rparen.span.end,
                },
            }));
        }

        // Not a recognized variant — backtrack
        self.idx = saved_idx;
        Ok(None)
    }

    /// Dialect-gated time travel clause parser.
    /// Snowflake: AT (TIMESTAMP => ...) / BEFORE (OFFSET => ...)
    /// BigQuery:  FOR SYSTEM_TIME AS OF <expr>
    /// Other dialects: no time travel support
    pub(crate) fn parse_time_travel_clause(
        &mut self,
    ) -> ParseResult<Option<Box<crate::ast::AstTimeTravelClause>>> {
        // Try Databricks TIMESTAMP/VERSION AS OF and @ first (backtracks safely)
        if let Some(dbx) = self.parse_databricks_time_travel()? {
            return Ok(Some(Box::new(
                crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx),
            )));
        }
        if self.dialect.supports_time_travel() {
            // Snowflake AT/BEFORE
            Ok(self
                .parse_time_travel()?
                .map(|tt| Box::new(crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt))))
        } else {
            // BigQuery FOR SYSTEM_TIME AS OF
            Ok(self
                .parse_for_system_time()?
                .map(|fst| Box::new(crate::ast::AstTimeTravelClause::ForSystemTime(fst))))
        }
    }

    /// Parse Databricks Delta Lake time travel clause.
    /// Syntax: TIMESTAMP AS OF <timestamp_expression>
    ///       | VERSION AS OF <version>
    ///       | @ <version_or_timestamp>  (Operator::At produced by Databricks lexer)
    pub(crate) fn parse_databricks_time_travel(
        &mut self,
    ) -> ParseResult<Option<crate::ast::AstDatabricksAsOf>> {
        let first_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };

        // Check for @ operator (Databricks: table@v123)
        if matches!(
            first_tok.kind,
            TokenKind::Operator(crate::lexer::Operator::At)
        ) {
            let at_tok = self.advance().expect_invariant("just peeked @"); // consume @
            let start = at_tok.span.start;

            // Parse the version/timestamp expression (usually a simple literal or identifier like v123)
            let expr = self.parse_expr()?;
            let end = expr.span().end;

            return Ok(Some(crate::ast::AstDatabricksAsOf {
                node_id: self.id_gen.next(),
                kind: crate::ast::DatabricksTimeTravelKind::AtSign,
                expr,
                span: Span { start, end },
            }));
        }

        // Check for TIMESTAMP or VERSION identifier
        let lexeme = first_tok.lexeme(self.source);
        let kind = if lexeme.eq_ignore_ascii_case("TIMESTAMP") {
            crate::ast::DatabricksTimeTravelKind::Timestamp
        } else if lexeme.eq_ignore_ascii_case("VERSION") {
            crate::ast::DatabricksTimeTravelKind::Version
        } else {
            return Ok(None);
        };

        // Save position for backtracking
        let saved_idx = self.idx;
        let start = first_tok.span.start;
        self.advance(); // consume TIMESTAMP or VERSION

        // Expect AS keyword
        match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) => {
                self.advance(); // consume AS
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        }

        // Expect OF keyword
        match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Of)) => {
                self.advance(); // consume OF
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        }

        // Parse the value expression (timestamp string, version number, function call, etc.)
        let expr = match self.parse_expr() {
            Ok(e) => e,
            Err(_) => {
                self.idx = saved_idx;
                return Ok(None);
            }
        };

        let end = expr.span().end;

        Ok(Some(crate::ast::AstDatabricksAsOf {
            node_id: self.id_gen.next(),
            kind,
            expr,
            span: Span { start, end },
        }))
    }

    /// Parse a SAMPLE or TABLESAMPLE clause
    /// Syntax: [SAMPLE | TABLESAMPLE] [BERNOULLI | ROW | SYSTEM | BLOCK] (probability | num ROWS) [SEED | REPEATABLE (seed)]
    pub(crate) fn parse_sample_clause(
        &mut self,
    ) -> ParseResult<Option<crate::ast::AstSampleClause>> {
        // Check for SAMPLE or TABLESAMPLE keyword (they are identifiers in the lexer)
        let first_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        let is_sample = match &first_tok.kind {
            TokenKind::Identifier { .. } => {
                first_tok.lexeme(self.source).eq_ignore_ascii_case("SAMPLE")
                    || first_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("TABLESAMPLE")
            }
            _ => return Ok(None),
        };

        if !is_sample {
            return Ok(None);
        }

        let start_span = first_tok.span.start;
        self.advance(); // consume SAMPLE or TABLESAMPLE

        // Optional sampling method: BERNOULLI, ROW, SYSTEM, or BLOCK
        // Note: ROW and ROWS are reserved keywords (Keyword::Row, Keyword::Rows),
        // so `can_be_identifier_token` returns false for them. We must match them explicitly.
        let mut method: Option<crate::ast::AstSampleMethod> = None;
        if let Some(method_tok) = self.peek() {
            let is_row = matches!(method_tok.kind, TokenKind::Keyword(Keyword::Row));
            if self.can_be_identifier_token(method_tok) || is_row {
                if method_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("BERNOULLI")
                    || is_row
                {
                    method = Some(crate::ast::AstSampleMethod::Bernoulli);
                    self.advance(); // consume method
                } else if method_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("SYSTEM")
                    || method_tok.lexeme(self.source).eq_ignore_ascii_case("BLOCK")
                {
                    method = Some(crate::ast::AstSampleMethod::System);
                    self.advance(); // consume method
                }
                // else: No method specified, default to BERNOULLI
            }
        }

        // Expect opening parenthesis
        let lparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen.span,
                vec!["(".to_string()],
                Parser::token_description(lparen, self.source),
            ));
        }
        self.advance(); // consume '('

        // Parse the size: either a probability (expression) or num ROWS
        let size_expr = self.parse_expr()?;

        // Check if followed by ROWS or PERCENT keyword for sampling method
        let size = if let Some(rows_tok) = self.peek() {
            // Check for ROWS as keyword OR as identifier (Snowflake accepts both)
            let is_rows = matches!(rows_tok.kind, TokenKind::Keyword(Keyword::Rows))
                || (self.can_be_identifier_token(rows_tok)
                    && rows_tok.lexeme(self.source).eq_ignore_ascii_case("ROWS"));
            // Check for PERCENT (BigQuery TABLESAMPLE SYSTEM (10 PERCENT))
            let is_percent = self.can_be_identifier_token(rows_tok)
                && rows_tok.lexeme(self.source).eq_ignore_ascii_case("PERCENT");

            if is_rows {
                self.advance(); // consume ROWS
                crate::ast::AstSampleSize::Rows(size_expr)
            } else if is_percent {
                self.advance(); // consume PERCENT
                crate::ast::AstSampleSize::Probability(size_expr)
            } else {
                crate::ast::AstSampleSize::Probability(size_expr)
            }
        } else {
            crate::ast::AstSampleSize::Probability(size_expr)
        };

        // Expect closing parenthesis
        let rparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rparen.span,
                vec![")".to_string()],
                Parser::token_description(rparen, self.source),
            ));
        }
        let mut end_span = rparen.span.end;
        self.advance(); // consume ')'

        // Optional SEED or REPEATABLE clause (only for SYSTEM/BLOCK)
        let mut seed: Option<AstExpr> = None;
        if let Some(seed_tok) = self.peek() {
            if self.can_be_identifier_token(seed_tok)
                && (seed_tok.lexeme(self.source).eq_ignore_ascii_case("SEED")
                    || seed_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("REPEATABLE"))
            {
                self.advance(); // consume SEED or REPEATABLE

                // Expect opening parenthesis
                let lparen = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                if !matches!(
                    lparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        lparen.span,
                        vec!["(".to_string()],
                        Parser::token_description(lparen, self.source),
                    ));
                }
                self.advance(); // consume '('

                // Parse seed expression
                seed = self.parse_expr().ok();

                // Expect closing parenthesis
                let rparen = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                if !matches!(
                    rparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        rparen.span,
                        vec![")".to_string()],
                        Parser::token_description(rparen, self.source),
                    ));
                }
                end_span = rparen.span.end;
                self.advance(); // consume ')'
            }
        }

        Ok(Some(crate::ast::AstSampleClause {
            node_id: self.id_gen.next(),
            method,
            size,
            seed,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse a CHANGES clause for change tracking metadata
    /// Syntax: CHANGES ( INFORMATION => { DEFAULT | APPEND_ONLY } )
    ///         AT|BEFORE ( ... )
    ///         [ END ( ... ) ]
    pub(crate) fn parse_changes_clause(
        &mut self,
    ) -> ParseResult<Option<crate::ast::AstChangesClause>> {
        // Check for CHANGES keyword
        self.skip_trivia();
        let first_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        let is_changes = self.can_be_identifier_token(first_tok)
            && first_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("CHANGES");

        if !is_changes {
            return Ok(None);
        }

        let start_span = first_tok.span.start;
        self.advance(); // consume CHANGES

        // Expect opening parenthesis
        self.skip_trivia();
        let lparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen.span,
                vec!["(".to_string()],
                Parser::token_description(lparen, self.source),
            ));
        }
        self.advance(); // consume '('

        // Expect INFORMATION keyword
        self.skip_trivia();
        let info_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["INFORMATION".to_string()])?;
        if !self.can_be_identifier_token(info_tok) {
            return Err(ParseError::unexpected_token(
                info_tok.span,
                vec!["INFORMATION".to_string()],
                Parser::token_description(info_tok, self.source),
            ));
        }
        if !info_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("INFORMATION")
        {
            return Err(ParseError::unexpected_token(
                info_tok.span,
                vec!["INFORMATION".to_string()],
                info_tok.lexeme(self.source).to_string(),
            ));
        }
        self.advance(); // consume INFORMATION

        // Expect '=>' operator
        self.skip_trivia();
        let arrow = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["=>".to_string()])?;
        if !matches!(
            arrow.kind,
            TokenKind::Operator(crate::lexer::Operator::EqGt)
        ) {
            return Err(ParseError::unexpected_token(
                arrow.span,
                vec!["=>".to_string()],
                Parser::token_description(arrow, self.source),
            ));
        }
        self.advance(); // consume '=>'

        // Parse DEFAULT or APPEND_ONLY
        self.skip_trivia();
        let value_tok = self.peek().ok_or_eof(
            self.current_span(),
            vec!["DEFAULT".to_string(), "APPEND_ONLY".to_string()],
        )?;
        let information = match &value_tok.kind {
            TokenKind::Identifier { .. }
                if value_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("DEFAULT") =>
            {
                crate::ast::AstChangesInformation::Default
            }
            TokenKind::Identifier { .. }
                if value_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("APPEND_ONLY") =>
            {
                crate::ast::AstChangesInformation::AppendOnly
            }
            TokenKind::Keyword(Keyword::Default) => crate::ast::AstChangesInformation::Default,
            _ => {
                return Err(ParseError::unexpected_token(
                    value_tok.span,
                    vec!["DEFAULT".to_string(), "APPEND_ONLY".to_string()],
                    Parser::token_description(value_tok, self.source),
                ))
            }
        };
        self.advance(); // consume DEFAULT or APPEND_ONLY

        // Expect closing parenthesis
        self.skip_trivia();
        let rparen = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rparen.span,
                vec![")".to_string()],
                Parser::token_description(rparen, self.source),
            ));
        }
        self.advance(); // consume ')'

        // Parse required AT or BEFORE clause (reuse parse_time_travel)
        let at_before = self.parse_time_travel()?.ok_or_else(|| {
            ParseError::unexpected_token(
                self.current_span(),
                vec!["AT".to_string(), "BEFORE".to_string()],
                "end of input".to_string(),
            )
        })?;

        let mut end_span = at_before.span.end;

        // Parse optional END clause
        let mut end_clause: Option<crate::ast::AstChangesEnd> = None;
        if let Some(end_tok) = self.peek() {
            let is_end = matches!(end_tok.kind, TokenKind::Keyword(Keyword::End))
                || (self.can_be_identifier_token(end_tok)
                    && end_tok.lexeme(self.source).eq_ignore_ascii_case("END"));

            if is_end {
                self.advance(); // consume END

                // Expect opening parenthesis
                let lparen = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                if !matches!(
                    lparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        lparen.span,
                        vec!["(".to_string()],
                        Parser::token_description(lparen, self.source),
                    ));
                }
                let end_start = lparen.span.start;
                self.advance(); // consume '('

                // Parse parameter type (TIMESTAMP, OFFSET, or STATEMENT)
                // Note: STREAM and BEFORE not allowed in END clause
                // Accept identifiers OR keywords (OFFSET is a keyword that can be a param type)
                let param_tok = self.peek().ok_or_eof(
                    self.current_span(),
                    vec![
                        "TIMESTAMP".to_string(),
                        "OFFSET".to_string(),
                        "STATEMENT".to_string(),
                    ],
                )?;
                let param_lexeme = match &param_tok.kind {
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                        param_tok.lexeme(self.source).to_string()
                    }
                    _ => {
                        return Err(ParseError::unexpected_token(
                            param_tok.span,
                            vec![
                                "TIMESTAMP".to_string(),
                                "OFFSET".to_string(),
                                "STATEMENT".to_string(),
                            ],
                            Parser::token_description(param_tok, self.source),
                        ))
                    }
                };
                self.advance(); // consume parameter type

                // Expect '=>' operator
                let arrow = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["=>".to_string()])?;
                if !matches!(
                    arrow.kind,
                    TokenKind::Operator(crate::lexer::Operator::EqGt)
                ) {
                    return Err(ParseError::unexpected_token(
                        arrow.span,
                        vec!["=>".to_string()],
                        Parser::token_description(arrow, self.source),
                    ));
                }
                self.advance(); // consume '=>'

                // Parse the expression
                let expr = self.parse_expr()?;

                // Expect closing parenthesis
                let rparen = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                if !matches!(
                    rparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        rparen.span,
                        vec![")".to_string()],
                        Parser::token_description(rparen, self.source),
                    ));
                }
                end_span = rparen.span.end;
                self.advance(); // consume ')'

                // Determine the kind based on parameter type (STREAM not allowed in END)
                let kind = if param_lexeme.eq_ignore_ascii_case("TIMESTAMP") {
                    crate::ast::AstTimeTravelKind::Timestamp(expr)
                } else if param_lexeme.eq_ignore_ascii_case("OFFSET") {
                    crate::ast::AstTimeTravelKind::Offset(expr)
                } else if param_lexeme.eq_ignore_ascii_case("STATEMENT") {
                    crate::ast::AstTimeTravelKind::Statement(expr)
                } else {
                    return Err(ParseError::unexpected_token(
                        self.current_span(),
                        vec![
                            "TIMESTAMP".to_string(),
                            "OFFSET".to_string(),
                            "STATEMENT".to_string(),
                        ],
                        param_lexeme,
                    ));
                };

                end_clause = Some(crate::ast::AstChangesEnd {
                    node_id: self.id_gen.next(),
                    kind,
                    span: Span {
                        start: end_start,
                        end: end_span,
                    },
                });
            }
        }

        Ok(Some(crate::ast::AstChangesClause {
            node_id: self.id_gen.next(),
            information,
            at_before,
            end: end_clause,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse a PIVOT clause:
    /// PIVOT(aggregate_function(pivot_column) [AS alias] FOR value_column IN (values/ANY/subquery) [DEFAULT ON NULL (value)])
    pub(crate) fn parse_pivot_clause(&mut self) -> ParseResult<Option<crate::ast::AstPivotClause>> {
        // Check for PIVOT keyword
        let pivot_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        if !pivot_tok.lexeme(self.source).eq_ignore_ascii_case("PIVOT") {
            return Ok(None);
        }

        let start_span = pivot_tok.span.start;
        let pivot_span = pivot_tok.span;
        self.advance(); // consume PIVOT

        // Expect '('
        let lp = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lp.span,
                vec!["(".to_string()],
                Parser::token_description(lp, self.source),
            ));
        }
        self.advance(); // consume '('

        // Parse aggregate function calls: expr [AS alias] [, expr [AS alias], ...]
        let mut aggregates = Vec::new();
        loop {
            let agg_expr = Box::new(self.parse_expr()?);

            // Optional AS alias for aggregate
            let mut agg_alias = None;
            let mut agg_as_span = None;
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                    let as_tok = self.advance().expect_invariant("AS keyword after peek"); // consume AS
                    agg_as_span = Some(as_tok.span);
                    if let Some(alias_tok) = self.peek() {
                        if self.can_be_identifier_token(alias_tok) {
                            let alias_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                            agg_alias = Some(crate::ast::AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });
                        }
                    }
                }
            }

            aggregates.push(crate::ast::AstPivotAggregate {
                node_id: self.id_gen.next(),
                expr: agg_expr,
                as_span: agg_as_span,
                alias: agg_alias,
            });

            // Check for comma to continue with more aggregates
            if let Some(comma_tok) = self.peek() {
                if matches!(
                    comma_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        // Expect FOR keyword
        let for_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?;
        if !matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            return Err(ParseError::unexpected_token(
                for_tok.span,
                vec!["FOR".to_string()],
                Parser::token_description(for_tok, self.source),
            ));
        }
        let for_tok = self.advance().expect_invariant("FOR keyword after peek"); // consume FOR
        let for_span = for_tok.span;

        // Parse value_column (can be an expression, e.g. DATEPART(QUARTER, o.OrderDate))
        // Use parse_add_expr_in_mode to stop before IN (which is a comparison operator)
        let for_column = Box::new(self.parse_add_expr_in_mode()?);

        // Expect IN keyword
        let in_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["IN".to_string()])?;
        if !matches!(in_tok.kind, TokenKind::Keyword(Keyword::In)) {
            return Err(ParseError::unexpected_token(
                in_tok.span,
                vec!["IN".to_string()],
                Parser::token_description(in_tok, self.source),
            ));
        }
        let in_tok = self.advance().expect_invariant("IN keyword after peek"); // consume IN
        let in_span = in_tok.span;

        // Expect '('
        let lp2 = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lp2.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lp2.span,
                vec!["(".to_string()],
                Parser::token_description(lp2, self.source),
            ));
        }
        self.advance(); // consume '('

        // Parse IN values: ANY [ORDER BY ...] | subquery | value list
        let in_values = {
            let next_tok = self.peek().ok_or_eof(
                self.current_span(),
                vec!["ANY".to_string(), "SELECT".to_string(), "value".to_string()],
            )?;
            if next_tok.lexeme(self.source).eq_ignore_ascii_case("ANY") {
                self.advance(); // consume ANY

                // Optional ORDER BY clause
                let order_by = if let Some(ob_tok) = self.peek() {
                    if matches!(ob_tok.kind, TokenKind::Keyword(Keyword::Order)) {
                        // Parse ORDER BY and extract items
                        self.parse_select_order_by()?.map(|ob| ob.items)
                    } else {
                        None
                    }
                } else {
                    None
                };

                crate::ast::AstPivotInValues::Any(order_by)
            } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Select)) {
                // Subquery
                let select = self.try_parse_set_or_select_stmt()?;
                crate::ast::AstPivotInValues::Subquery(Box::new(select))
            } else {
                // Value list: check if it contains Jinja control flow
                // Dead code: contains_jinja_in_parens always returns false with new lexer
                let has_jinja = false;

                if has_jinja {
                    // Opaque mode: capture content between parens as opaque span
                    crate::ast::AstPivotInValues::OpaqueList(
                        Span { start: 0, end: 0 }, // Dead code
                    )
                } else {
                    // Normal mode: parse values with optional AS aliases
                    let mut values = Vec::new();
                    loop {
                        let next = self.peek().ok_or_eof(
                            self.current_span(),
                            vec![")".to_string(), "value".to_string()],
                        )?;
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            break;
                        }
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            continue;
                        }

                        let value_expr = Box::new(self.parse_expr()?);
                        let mut value_alias = None;
                        let mut value_as_span = None;
                        if let Some(tok) = self.peek() {
                            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                                let as_tok =
                                    self.advance().expect_invariant("AS keyword after peek");
                                value_as_span = Some(as_tok.span);
                                if let Some(alias_tok) = self.peek() {
                                    if self.can_be_identifier_token(alias_tok) {
                                        let alias_tok = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["identifier".to_string()],
                                        )?;
                                        value_alias = Some(crate::ast::AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: alias_tok.span,
                                        });
                                    }
                                }
                            }
                        }
                        values.push(crate::ast::AstPivotValue {
                            node_id: self.id_gen.next(),
                            value: value_expr,
                            as_span: value_as_span,
                            alias: value_alias,
                        });
                    }
                    crate::ast::AstPivotInValues::ValueList(values)
                }
            }
        };

        // Expect ')' to close IN clause
        let rp2 = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rp2.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp2.span,
                vec![")".to_string()],
                Parser::token_description(rp2, self.source),
            ));
        }
        self.advance(); // consume ')'

        // Optional DEFAULT ON NULL clause
        let mut default_on_null = None;
        let mut default_on_null_span = None;
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("DEFAULT") {
                let default_tok = self
                    .advance()
                    .expect_invariant("DEFAULT keyword after peek"); // consume DEFAULT
                let mut default_start = default_tok.span.start;

                // Expect ON keyword
                if let Some(on_tok) = self.peek() {
                    if matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
                        let on_tok = self.advance().expect_invariant("ON keyword after peek"); // consume ON
                        default_start = default_start.min(on_tok.span.start);

                        // Expect NULL keyword
                        if let Some(null_tok) = self.peek() {
                            if matches!(
                                null_tok.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::Null)
                            ) {
                                let null_tok =
                                    self.advance().expect_invariant("NULL token after peek"); // consume NULL
                                default_on_null_span = Some(Span {
                                    start: default_start,
                                    end: null_tok.span.end,
                                });

                                // Expect '('
                                if let Some(lp3) = self.peek() {
                                    if matches!(
                                        lp3.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    ) {
                                        self.advance(); // consume '('

                                        // Parse default value expression
                                        default_on_null = Some(Box::new(self.parse_expr()?));

                                        // Expect ')'
                                        if let Some(rp3) = self.peek() {
                                            if matches!(
                                                rp3.kind,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RParen
                                                )
                                            ) {
                                                self.advance(); // consume ')'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Expect ')' to close PIVOT clause
        let rp = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }
        let end_span = rp.span.end;
        self.advance(); // consume ')'

        Ok(Some(crate::ast::AstPivotClause {
            node_id: self.id_gen.next(),
            pivot_span,
            aggregates,
            for_span,
            for_column,
            in_span,
            in_values,
            default_on_null_span,
            default_on_null,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse an UNPIVOT clause:
    /// UNPIVOT [INCLUDE|EXCLUDE NULLS] (value_column FOR name_column IN (columns))
    pub(crate) fn parse_unpivot_clause(
        &mut self,
    ) -> ParseResult<Option<crate::ast::AstUnpivotClause>> {
        // Check for UNPIVOT keyword
        let unpivot_tok = match self.peek() {
            Some(tok) => tok,
            None => return Ok(None),
        };
        if !unpivot_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("UNPIVOT")
        {
            return Ok(None);
        }

        let start_span = unpivot_tok.span.start;
        let unpivot_span = unpivot_tok.span;
        self.advance(); // consume UNPIVOT

        // Optional INCLUDE/EXCLUDE NULLS
        let mut include_nulls = false; // Default is EXCLUDE NULLS
        let mut include_exclude_nulls_span: Option<Span> = None;
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("INCLUDE") {
                let include_tok = self
                    .advance()
                    .expect_invariant("INCLUDE identifier after peek"); // consume INCLUDE
                let nulls_start = include_tok.span.start;
                if let Some(nulls_tok) = self.peek() {
                    if matches!(
                        nulls_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::Null)
                    ) {
                        let nulls_tok = self
                            .advance()
                            .expect_invariant("NULLS literal after INCLUDE"); // consume NULLS (tokenized as NULL literal)
                        include_exclude_nulls_span = Some(Span {
                            start: nulls_start,
                            end: nulls_tok.span.end,
                        });
                        include_nulls = true;
                    } else if nulls_tok.lexeme(self.source).eq_ignore_ascii_case("NULLS") {
                        let nulls_tok = self
                            .advance()
                            .expect_invariant("NULLS identifier after INCLUDE"); // consume NULLS as identifier
                        include_exclude_nulls_span = Some(Span {
                            start: nulls_start,
                            end: nulls_tok.span.end,
                        });
                        include_nulls = true;
                    }
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("EXCLUDE") {
                let exclude_tok = self
                    .advance()
                    .expect_invariant("EXCLUDE identifier after peek"); // consume EXCLUDE
                let nulls_start = exclude_tok.span.start;
                if let Some(nulls_tok) = self.peek() {
                    if matches!(
                        nulls_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::Null)
                    ) {
                        let nulls_tok = self
                            .advance()
                            .expect_invariant("NULLS literal after EXCLUDE"); // consume NULLS (tokenized as NULL literal)
                        include_exclude_nulls_span = Some(Span {
                            start: nulls_start,
                            end: nulls_tok.span.end,
                        });
                    } else if nulls_tok.lexeme(self.source).eq_ignore_ascii_case("NULLS") {
                        let nulls_tok = self
                            .advance()
                            .expect_invariant("NULLS identifier after EXCLUDE"); // consume NULLS as identifier
                        include_exclude_nulls_span = Some(Span {
                            start: nulls_start,
                            end: nulls_tok.span.end,
                        });
                    }
                }
            }
        }

        // Expect '('
        let lp = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lp.span,
                vec!["(".to_string()],
                Parser::token_description(lp, self.source),
            ));
        }
        self.advance(); // consume '('

        // Parse value_column(s): either a single identifier or (col1, col2, ...) tuple
        let value_columns = if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                // Tuple form: (col1, col2, ...)
                self.advance(); // consume '('
                let mut cols = Vec::new();
                loop {
                    let col_tok = self.peek().ok_or_eof(
                        self.current_span(),
                        vec!["identifier".to_string(), ")".to_string()],
                    )?;
                    if !self.can_be_identifier_token(col_tok) {
                        break;
                    }
                    let col_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                    cols.push(crate::ast::AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: col_tok.span,
                    });
                    // Check for comma
                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            continue;
                        }
                    }
                    break;
                }
                // Expect ')'
                let rp = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                if !matches!(
                    rp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        rp.span,
                        vec![")".to_string()],
                        Parser::token_description(rp, self.source),
                    ));
                }
                self.advance(); // consume ')'
                cols
            } else if self.can_be_identifier_token(tok) {
                // Single identifier
                let col_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                vec![crate::ast::AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: col_tok.span,
                }]
            } else {
                return Err(ParseError::unexpected_token(
                    tok.span,
                    vec!["identifier".to_string()],
                    Parser::token_description(tok, self.source),
                ));
            }
        } else {
            return Err(ParseError::unexpected_eof(
                self.current_span(),
                vec!["identifier".to_string()],
            ));
        };

        // Expect FOR keyword
        let for_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?;
        if !matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            return Err(ParseError::unexpected_token(
                for_tok.span,
                vec!["FOR".to_string()],
                Parser::token_description(for_tok, self.source),
            ));
        }
        let for_tok = self.advance().expect_invariant("FOR keyword after peek"); // consume FOR
        let for_span = for_tok.span;

        // Parse name_column (identifier)
        let name_col_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
        if !self.can_be_identifier_token(name_col_tok) {
            return Err(ParseError::unexpected_token(
                name_col_tok.span,
                vec!["identifier".to_string()],
                Parser::token_description(name_col_tok, self.source),
            ));
        }
        let name_col_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
        let name_column = crate::ast::AstIdentifier {
            node_id: self.id_gen.next(),
            span: name_col_tok.span,
        };

        // Expect IN keyword
        let in_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["IN".to_string()])?;
        if !matches!(in_tok.kind, TokenKind::Keyword(Keyword::In)) {
            return Err(ParseError::unexpected_token(
                in_tok.span,
                vec!["IN".to_string()],
                Parser::token_description(in_tok, self.source),
            ));
        }
        let in_tok = self.advance().expect_invariant("IN keyword after peek"); // consume IN
        let in_span = in_tok.span;

        // Expect '('
        let lp2 = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lp2.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lp2.span,
                vec!["(".to_string()],
                Parser::token_description(lp2, self.source),
            ));
        }
        self.advance(); // consume '('

        // Parse column list: col1 [AS alias1], ... OR (col1, col2) [AS alias1], ...
        let mut columns = Vec::new();
        loop {
            let col_tok = self.peek().ok_or_eof(
                self.current_span(),
                vec!["identifier".to_string(), ")".to_string()],
            )?;

            // Check for tuple form (col1, col2) or single identifier
            let col_idents = if matches!(
                col_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                // Tuple form
                self.advance(); // consume '('
                let mut tuple_cols = Vec::new();
                loop {
                    let inner_tok = self.peek().ok_or_eof(
                        self.current_span(),
                        vec!["identifier".to_string(), ")".to_string()],
                    )?;
                    if !self.can_be_identifier_token(inner_tok) {
                        break;
                    }
                    let inner_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                    tuple_cols.push(crate::ast::AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: inner_tok.span,
                    });
                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            continue;
                        }
                    }
                    break;
                }
                // Expect ')'
                let rp = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                if !matches!(
                    rp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        rp.span,
                        vec![")".to_string()],
                        Parser::token_description(rp, self.source),
                    ));
                }
                self.advance(); // consume ')'
                tuple_cols
            } else if self.can_be_identifier_token(col_tok) {
                let col_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                vec![crate::ast::AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: col_tok.span,
                }]
            } else {
                break;
            };

            // Optional AS alias
            let mut col_alias = None;
            let mut col_as_span = None;
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                    let as_tok = self.advance().expect_invariant("AS keyword after peek"); // consume AS
                    col_as_span = Some(as_tok.span);
                    if let Some(alias_tok) = self.peek() {
                        // Accept identifiers, keywords, and string literals as aliases
                        if self.can_be_identifier_token(alias_tok)
                            || matches!(
                                alias_tok.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::String)
                            )
                        {
                            let alias_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                            col_alias = Some(crate::ast::AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });
                        }
                    }
                }
            }

            columns.push(crate::ast::AstUnpivotColumn {
                node_id: self.id_gen.next(),
                columns: col_idents,
                as_span: col_as_span,
                alias: col_alias,
            });

            // Check for comma to continue
            if let Some(comma_tok) = self.peek() {
                if matches!(
                    comma_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        // Expect ')' to close column list
        let rp2 = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rp2.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp2.span,
                vec![")".to_string()],
                Parser::token_description(rp2, self.source),
            ));
        }
        self.advance(); // consume ')'

        // Expect ')' to close UNPIVOT clause
        let rp = self
            .peek()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::unexpected_token(
                rp.span,
                vec![")".to_string()],
                Parser::token_description(rp, self.source),
            ));
        }
        let end_span = rp.span.end;
        self.advance(); // consume ')'

        Ok(Some(crate::ast::AstUnpivotClause {
            node_id: self.id_gen.next(),
            unpivot_span,
            include_nulls,
            include_exclude_nulls_span,
            value_columns,
            for_span,
            name_column,
            in_span,
            columns,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse a VALUES clause: VALUES (expr, ...), (expr, ...), ...
    pub(crate) fn parse_values(&mut self) -> Option<crate::ast::AstValues> {
        // Expect VALUES keyword
        let start_tok = self.peek()?;
        if !matches!(start_tok.kind, TokenKind::Keyword(Keyword::Values)) {
            return None;
        }
        let start_span = start_tok.span.start;
        self.advance(); // consume VALUES
        let values_keyword_id = self.last_token_id();

        let mut rows: Vec<Vec<AstExpr>> = Vec::new();
        let mut row_lparens: Vec<crate::cst::TokenId> = Vec::new();
        let mut row_rparens: Vec<crate::cst::TokenId> = Vec::new();
        let mut end_span = start_span;

        loop {
            // Expect '(' for each row
            let lparen = self.peek()?;
            if !matches!(
                lparen.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                break;
            }
            self.advance(); // consume '('
            let lparen_id = self.last_token_id();
            row_lparens.push(lparen_id);

            // Parse expressions in this row
            let mut row_exprs: Vec<AstExpr> = Vec::new();
            loop {
                if let Some(rparen) = self.peek() {
                    if matches!(
                        rparen.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        end_span = rparen.span.end;
                        self.advance(); // consume ')'
                        let rparen_id = self.last_token_id();
                        row_rparens.push(rparen_id);
                        break;
                    }
                }

                // Parse an expression
                if let Ok(expr) = self.parse_expr() {
                    row_exprs.push(expr);
                } else {
                    break;
                }

                // Check for comma (more expressions) or closing paren
                if let Some(next) = self.peek() {
                    match &next.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                            self.advance(); // consume comma
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            // Will be handled in next iteration
                        }
                        _ => break,
                    }
                }
            }

            if !row_exprs.is_empty() {
                rows.push(row_exprs);
            }

            // Check for comma (more rows) or end
            if let Some(comma) = self.peek() {
                if matches!(
                    comma.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        if rows.is_empty() {
            None
        } else {
            // Create SyntaxValues node
            let syntax_values = crate::syntax::SyntaxValues {
                values_keyword: values_keyword_id,
                row_lparens,
                row_rparens,
                span: Span {
                    start: start_span,
                    end: end_span,
                },
            };
            let syntax_id = Some(self.syntax_arena.alloc_values(syntax_values));

            Some(crate::ast::AstValues {
                node_id: self.id_gen.next(),
                rows,
                span: Span {
                    start: start_span,
                    end: end_span,
                },
                syntax_id,
            })
        }
    }

    /// Parse a SELECT statement with Result-based error handling.
    pub(crate) fn try_parse_select_in_mode(&mut self) -> crate::error::ParseResult<AstSelect> {
        self.try_parse_select_in_mode_boxed().map(|select| *select)
    }

    /// Parse a SELECT statement and return boxed AST to reduce stack pressure
    /// in deeply recursive subquery/set-operation paths.
    pub(crate) fn try_parse_select_in_mode_boxed(
        &mut self,
    ) -> crate::error::ParseResult<Box<AstSelect>> {
        // Recursion guard to prevent stack overflow on deeply nested SELECTs
        let _depth = self.track_depth("select")?;

        self.try_parse_select_in_mode_impl_boxed()
    }

    fn try_parse_select_in_mode_impl_boxed(&mut self) -> crate::error::ParseResult<Box<AstSelect>> {
        // Split around the recursive FROM-clause descent: the prelude and the
        // clause-assembly tail live in child frames (parse_select_head /
        // finish_select), so only this slim frame is held across the recursion.
        let head = self.parse_select_head()?;
        let from = self.parse_select_from_clause(head.select_span)?;
        self.finish_select(head, from)
    }

    /// Parse a SELECT up to (not including) its FROM clause: leading Jinja
    /// comments, SELECT keyword, BigQuery AS STRUCT/VALUE qualifier, set
    /// quantifier (incl. DISTINCT ON), TOP, projection, and optional INTO.
    fn parse_select_head(&mut self) -> crate::error::ParseResult<SelectHead> {
        use crate::error::{ExpectInvariant, ParseError, ParseResultExt};

        // Skip any leading Jinja comments {# ... #} before SELECT
        // Common in dbt: {# comment #} SELECT ...
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::JinjaComment) {
                self.advance();
            } else {
                break;
            }
        }

        // Parse SELECT keyword
        let select_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SELECT".to_string()])?;

        match select_tok.kind {
            TokenKind::Keyword(Keyword::Select) => {}
            _ => {
                return Err(ParseError::unexpected_token(
                    select_tok.span,
                    vec!["SELECT".to_string()],
                    Self::token_description(select_tok, self.source),
                ));
            }
        }
        let select_span = select_tok.span;

        // Parse BigQuery SELECT AS STRUCT / SELECT AS VALUE qualifier
        // Must be checked BEFORE set quantifier (ALL/DISTINCT) since AS is consumed first
        let mut select_as_qualifier: Option<Span> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                // Peek ahead to check if next token is STRUCT or VALUE (both are Identifiers)
                if let Some(next) = self.peek_ahead(1) {
                    let lexeme = next.lexeme(self.source);
                    if lexeme.eq_ignore_ascii_case("STRUCT") || lexeme.eq_ignore_ascii_case("VALUE")
                    {
                        let as_tok = self.advance().expect_invariant("AS keyword after peek");
                        let qualifier_tok =
                            self.advance().expect_invariant("STRUCT/VALUE after AS");
                        select_as_qualifier = Some(Span {
                            start: as_tok.span.start,
                            end: qualifier_tok.span.end,
                        });
                    }
                }
            }
        }

        // Parse [ALL|DISTINCT [ON (expr_list)]]
        let mut set_quantifier: Option<Box<crate::ast::AstSetQuantifier>> = None;
        let mut set_quantifier_span: Option<Span> = None;
        if let Some(tok) = self.peek() {
            if let TokenKind::Keyword(kw) = tok.kind {
                match kw {
                    Keyword::All => {
                        set_quantifier_span = Some(tok.span);
                        set_quantifier =
                            Some(Box::new(crate::parser::sql_stmt::build_set_quantifier_all()));
                        self.advance();
                    }
                    Keyword::Distinct => {
                        let distinct_tok = self
                            .advance()
                            .expect_invariant("DISTINCT keyword after peek");
                        set_quantifier_span = Some(distinct_tok.span);
                        let distinct_token_id = self.last_token_id();

                        // Check for DISTINCT ON (PostgreSQL syntax, parsed permissively)
                        if let Some(on_tok) = self.peek() {
                            if matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
                                // Parse DISTINCT ON (expr_list)
                                let _on_tok = self
                                    .advance()
                                    .expect_invariant("ON keyword after peek in DISTINCT ON");
                                let on_token_id = self.last_token_id();

                                // Expect (
                                let lparen_tok = self.advance().ok_or_else(|| {
                                    ParseError::new(
                                        self.current_span(),
                                        crate::error::ParseErrorKind::InvalidSyntax {
                                            message: "Expected '(' after DISTINCT ON".to_string(),
                                        },
                                    )
                                })?;

                                if !matches!(
                                    lparen_tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    return Err(ParseError::unexpected_token(
                                        lparen_tok.span,
                                        vec!["(".to_string()],
                                        Self::token_description(lparen_tok, self.source),
                                    ));
                                }
                                let lparen_token_id = self.last_token_id();

                                // Parse expression list
                                let mut exprs = Vec::new();
                                loop {
                                    let expr = self.parse_expr()?;
                                    exprs.push(expr);

                                    // Check for comma or closing paren
                                    if let Some(tok) = self.peek() {
                                        if matches!(
                                            tok.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::Comma
                                            )
                                        ) {
                                            self.advance();
                                            continue;
                                        } else if matches!(
                                            tok.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::RParen
                                            )
                                        ) {
                                            break;
                                        }
                                    }

                                    return Err(ParseError::new(
                                        self.current_span(),
                                        crate::error::ParseErrorKind::InvalidSyntax {
                                            message:
                                                "Expected ',' or ')' in DISTINCT ON expression list"
                                                    .to_string(),
                                        },
                                    ));
                                }

                                // Expect )
                                let rparen_tok = self.advance().ok_or_else(|| {
                                    ParseError::new(
                                        self.current_span(),
                                        crate::error::ParseErrorKind::InvalidSyntax {
                                            message:
                                                "Expected ')' after DISTINCT ON expression list"
                                                    .to_string(),
                                        },
                                    )
                                })?;
                                let rparen_token_id = self.last_token_id();

                                // Build CST node
                                let syntax_span = Span {
                                    start: distinct_tok.span.start,
                                    end: rparen_tok.span.end,
                                };
                                let syntax_node = crate::syntax::SyntaxDistinctOn {
                                    distinct_token: distinct_token_id,
                                    on_token: on_token_id,
                                    lparen: lparen_token_id,
                                    rparen: rparen_token_id,
                                    span: syntax_span,
                                };
                                let syntax_id = self.syntax_arena.alloc_distinct_on(syntax_node);

                                // Build AST variant
                                set_quantifier =
                                    Some(Box::new(crate::ast::AstSetQuantifier::DistinctOn {
                                        syntax_id,
                                        exprs,
                                    }));
                            } else {
                                // Just plain DISTINCT
                                set_quantifier = Some(Box::new(
                                    crate::parser::sql_stmt::build_set_quantifier_distinct(),
                                ));
                            }
                        } else {
                            // Just plain DISTINCT
                            set_quantifier = Some(Box::new(
                                crate::parser::sql_stmt::build_set_quantifier_distinct(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Parse [TOP <number|expr> [PERCENT] [WITH TIES]]
        let top = self.try_parse_top_clause()?;

        // Parse projection (column list or *)
        let projection = self.parse_select_projection()?.ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "SELECT requires a projection (columns, *, or expressions)"
                        .to_string(),
                },
            )
        })?;

        // Parse optional INTO clause. Two mutually-exclusive shapes, dialect-driven:
        //   1. Scripting form: `SELECT col INTO :var, :var2 FROM …`
        //      (Snowflake Scripting / MySQL / Oracle PL/SQL).
        //   2. NewTable form: `SELECT col INTO [TEMP|TEMPORARY|UNLOGGED] new_tbl
        //      [ON filegroup] FROM …` (MSSQL / PostgreSQL legacy CTAS).
        // Disambiguation is dialect-only — PL/pgSQL bodies live inside dollar-
        // quoted string literals and do not reach this parser, so PG `INTO`
        // here is always the CTAS form.
        let mut into_target: Option<Box<crate::ast::AstSelectIntoTarget>> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Into)) {
                let into_kw = self
                    .advance()
                    .expect_invariant("INTO keyword confirmed by peek");
                let into_span = into_kw.span;
                // T-SQL `@var` / `@@sysvar` is unambiguously a variable
                // reference — never a table name. If the post-INTO token is
                // an `AtVariable` identifier, fall through to the scripting
                // path even under MSSQL.
                let next_is_at_variable = self.peek().is_some_and(|t| {
                    matches!(
                        t.kind,
                        TokenKind::Identifier {
                            kind: crate::lexer::IdentifierKind::AtVariable
                        }
                    )
                });
                if self.dialect.select_into_creates_table() && !next_is_at_variable {
                    // Parse the NewTable form.
                    use crate::ast::{
                        AstSelectIntoFilegroup, AstSelectIntoNewTable, AstSelectIntoTarget,
                        AstSelectIntoTempKind,
                    };
                    use crate::lexer::IdentifierKind;

                    // Optional PG `TEMP` / `TEMPORARY` / `UNLOGGED` qualifier.
                    // MSSQL has no qualifier keyword (temp-ness is the `#`/`##`
                    // prefix on the identifier itself).
                    let (temp_keyword_span, mut temp_kind) =
                        if self.dialect.select_into_uses_temp_keyword() {
                            if let Some(q) = self.peek() {
                                match q.kind {
                                    TokenKind::Keyword(Keyword::Temp)
                                    | TokenKind::Keyword(Keyword::Temporary) => {
                                        let t = self.advance().expect_invariant("TEMP/TEMPORARY");
                                        (Some(t.span), AstSelectIntoTempKind::Temp)
                                    }
                                    _ if q.lexeme(self.source).eq_ignore_ascii_case("UNLOGGED") => {
                                        let t = self.advance().expect_invariant("UNLOGGED");
                                        (Some(t.span), AstSelectIntoTempKind::Unlogged)
                                    }
                                    _ => (None, AstSelectIntoTempKind::None),
                                }
                            } else {
                                (None, AstSelectIntoTempKind::None)
                            }
                        } else {
                            (None, AstSelectIntoTempKind::None)
                        };

                    // MSSQL: peek the first identifier token; `#tmp`/`##tmp`
                    // is a single Identifier{kind:TempTable} token.
                    if self.dialect.hash_is_identifier_prefix() {
                        if let Some(name_tok) = self.peek() {
                            if matches!(
                                name_tok.kind,
                                TokenKind::Identifier {
                                    kind: IdentifierKind::TempTable
                                }
                            ) {
                                let lex = name_tok.lexeme(self.source);
                                temp_kind = if lex.starts_with("##") {
                                    AstSelectIntoTempKind::GlobalTemp
                                } else if lex.starts_with('#') {
                                    AstSelectIntoTempKind::LocalTemp
                                } else {
                                    AstSelectIntoTempKind::None
                                };
                            }
                        }
                    }

                    let name_span = self.parse_qualified_name_span()?;
                    let name = crate::ast::AstObjectRef {
                        node_id: self.id_gen.next(),
                        span: name_span,
                        parts: None,
                        identifier_arg: None,
                    };

                    // MSSQL: optional `ON [PRIMARY]` filegroup clause.
                    let on_filegroup = if self.dialect.select_into_supports_filegroup() {
                        if let Some(on_tok) = self.peek() {
                            if matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
                                let on_consumed = self.advance().expect_invariant("ON keyword");
                                if let Some(fg_tok) = self.peek() {
                                    if self.can_be_identifier_token(fg_tok) {
                                        let fg =
                                            self.advance().expect_invariant("filegroup identifier");
                                        Some(AstSelectIntoFilegroup {
                                            on_span: on_consumed.span,
                                            filegroup_span: fg.span,
                                        })
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let new_table = AstSelectIntoNewTable {
                        node_id: self.id_gen.next(),
                        into_span,
                        name: Box::new(name),
                        temp_kind,
                        temp_keyword_span,
                        on_filegroup,
                    };
                    into_target =
                        Some(Box::new(AstSelectIntoTarget::NewTable(Box::new(new_table))));
                } else if let Some(outfile) = self.try_parse_into_outfile(into_span)? {
                    // MySQL INTO OUTFILE / DUMPFILE (dialect-gated inside).
                    into_target = Some(Box::new(crate::ast::AstSelectIntoTarget::OutFile(outfile)));
                } else {
                    // Scripting variable list (Snowflake / MySQL / Oracle PL/SQL).
                    use crate::ast::AstSelectIntoTarget;
                    let vars = self.parse_into_scripting_vars();
                    if !vars.is_empty() {
                        into_target = Some(Box::new(AstSelectIntoTarget::ScriptingVars(vars)));
                    }
                }
            }
        }

        Ok(SelectHead {
            select_span,
            select_as_qualifier,
            set_quantifier,
            set_quantifier_span,
            top,
            projection,
            into_target,
        })
    }

    /// Parse the post-FROM tail and assemble the `AstSelect`: Jinja statement
    /// fragments, WHERE/GROUP BY/HAVING/QUALIFY/CONNECT BY/WINDOW/ORDER BY,
    /// dialect extension clauses, LIMIT/OFFSET, FOR UPDATE/SHARE, FOR JSON/XML.
    /// Also handles the FROM-less early-return shapes.
    fn finish_select(
        &mut self,
        head: SelectHead,
        from: Vec<crate::ast::FromItem>,
    ) -> crate::error::ParseResult<Box<AstSelect>> {
        use crate::error::ExpectInvariant;

        let SelectHead {
            select_span,
            select_as_qualifier,
            set_quantifier,
            set_quantifier_span,
            top,
            projection,
            mut into_target,
        } = head;

        // Handle SELECT without FROM - check for early termination
        let mut where_clause = None;
        if from.is_empty() {
            if let Some(tok) = self.peek() {
                let stop = self.should_stop_scan_at_statement_start(tok);
                // Don't early-terminate if this is FOR XML/JSON (MSSQL clause, not a new statement)
                let is_for_xml_json = matches!(tok.kind, TokenKind::Keyword(Keyword::For))
                    && self.peek_ahead(1).is_some_and(|next| {
                        let lex = next.lexeme(self.source);
                        lex.eq_ignore_ascii_case("XML") || lex.eq_ignore_ascii_case("JSON")
                    });
                if stop && !is_for_xml_json {
                    let span = crate::parser::sql_stmt::build_select_span(
                        select_span,
                        projection.span.end,
                    );
                    return Ok(Box::new(crate::parser::sql_stmt::build_select(
                        self.id_gen.next(),
                        span,
                        select_span,
                        select_as_qualifier,
                        set_quantifier,
                        set_quantifier_span,
                        top.map(Box::new),
                        projection,
                        from,
                        Vec::new(),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        into_target.clone(),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )));
                }

                // Check for Jinja structural delimiters (endif, endfor, else, elif)
                if let Some(kind) = self.peek_jinja_block_kind() {
                    if matches!(
                        kind,
                        JinjaBlockKind::EndIf
                            | JinjaBlockKind::EndFor
                            | JinjaBlockKind::Else
                            | JinjaBlockKind::Elif
                    ) {
                        let span = crate::parser::sql_stmt::build_select_span(
                            select_span,
                            projection.span.end,
                        );
                        return Ok(Box::new(crate::parser::sql_stmt::build_select(
                            self.id_gen.next(),
                            span,
                            select_span,
                            select_as_qualifier,
                            set_quantifier,
                            set_quantifier_span,
                            top.map(Box::new),
                            projection,
                            from,
                            Vec::new(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            into_target.clone(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )));
                    }
                }
                match &tok.kind {
                    TokenKind::Eof => {
                        // SELECT without FROM at EOF - build and return
                        let span = crate::parser::sql_stmt::build_select_span(
                            select_span,
                            projection.span.end,
                        );
                        return Ok(Box::new(crate::parser::sql_stmt::build_select(
                            self.id_gen.next(),
                            span,
                            select_span,
                            select_as_qualifier,
                            set_quantifier,
                            set_quantifier_span,
                            top.map(Box::new),
                            projection,
                            from,
                            Vec::new(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            into_target.clone(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )));
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                        // SELECT without FROM at semicolon - build and return (don't consume semicolon)
                        // Semicolons are handled by formatter as gap content
                        let span = crate::parser::sql_stmt::build_select_span(
                            select_span,
                            projection.span.end,
                        );
                        return Ok(Box::new(crate::parser::sql_stmt::build_select(
                            self.id_gen.next(),
                            span,
                            select_span,
                            select_as_qualifier,
                            set_quantifier,
                            set_quantifier_span,
                            top.map(Box::new),
                            projection,
                            from,
                            Vec::new(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            into_target.clone(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )));
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        // SELECT without FROM inside parentheses - build and return (don't consume RParen)
                        let span = crate::parser::sql_stmt::build_select_span(
                            select_span,
                            projection.span.end,
                        );
                        return Ok(Box::new(crate::parser::sql_stmt::build_select(
                            self.id_gen.next(),
                            span,
                            select_span,
                            select_as_qualifier,
                            set_quantifier,
                            set_quantifier_span,
                            top.map(Box::new),
                            projection,
                            from,
                            Vec::new(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            into_target.clone(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )));
                    }
                    // Stop at pipe operator for pipe chains - build and return
                    TokenKind::Operator(Operator::Pipe) => {
                        let span = crate::parser::sql_stmt::build_select_span(
                            select_span,
                            projection.span.end,
                        );
                        return Ok(Box::new(crate::parser::sql_stmt::build_select(
                            self.id_gen.next(),
                            span,
                            select_span,
                            select_as_qualifier,
                            set_quantifier,
                            set_quantifier_span,
                            top.map(Box::new),
                            projection,
                            from,
                            Vec::new(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            into_target.clone(),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        )));
                    }
                    _ => {}
                }
            }
        }

        // Parse Jinja statement fragments ({% if %}FROM/WHERE/HAVING/JOIN{% endif %})
        let mut statement_fragments = Vec::new();
        while self.peek().is_some() {
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(kind, JinjaBlockKind::If | JinjaBlockKind::For) {
                    // Check if this Jinja block contains statement fragment keywords (FROM, WHERE, JOIN, etc.)
                    if self.peek_jinja_block_is_statement_fragment() {
                        // Parse statement fragment: {% if %}FROM/WHERE/JOIN{% endif %}
                        if let Some(fragment) =
                            self.try_parse_statement_fragment_jinja_block(kind, from.len())
                        {
                            statement_fragments.push(fragment);
                            continue;
                        }
                    }
                }
            }
            break;
        }

        // Parse WHERE clause with inline fragment collection
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
                let where_kw = self.advance().expect_invariant("WHERE keyword after peek");
                where_clause = Some(Box::new(self.parse_condition_clause(
                    where_kw.span,
                    "WHERE clause requires a condition expression",
                )?));
            }
        }

        // Parse GROUP BY clause
        let group_by = self.parse_select_group_by()?;

        // Parse HAVING clause
        // Note: HAVING without GROUP BY is valid in Snowflake SQL - it treats the entire
        // result set as a single group (useful for filtering on aggregate conditions)
        let having: Option<Box<crate::ast::ConditionClause>> = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Having)) {
                let having_kw = self.advance().expect_invariant("HAVING keyword after peek");
                Some(Box::new(self.parse_condition_clause(
                    having_kw.span,
                    "HAVING clause requires a condition expression",
                )?))
            } else {
                None
            }
        } else {
            None
        };

        // Parse QUALIFY clause (Snowflake-specific, filters window function results)
        let qualify: Option<Box<crate::ast::ConditionClause>> = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Qualify)) {
                let qualify_kw = self
                    .advance()
                    .expect_invariant("QUALIFY keyword after peek");
                Some(Box::new(self.parse_condition_clause(
                    qualify_kw.span,
                    "QUALIFY clause requires a condition expression",
                )?))
            } else {
                None
            }
        } else {
            None
        };

        // Parse CONNECT BY clause (hierarchical queries - Oracle/Snowflake)
        let connect_by = self.parse_connect_by()?.map(Box::new);

        // Parse WINDOW clause (named window definitions; PostgreSQL and Databricks)
        // Syntax: WINDOW w AS (...) [, w2 AS (...)]
        // WINDOW may be tokenized as either Identifier or Keyword depending on dialect.
        let window_clause = if self.dialect.supports_named_window_clause() {
            if let Some(tok) = self.peek() {
                if tok.lexeme(self.source).eq_ignore_ascii_case("WINDOW") {
                    Some(Box::new(self.parse_window_clause()?))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Parse ORDER BY clause (must come after QUALIFY to avoid confusion with window ORDER BY)
        // If ORDER keyword exists, parsing failure should fail the whole statement
        let order_by = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Order)) {
                // ORDER keyword present - failure to parse is an error
                self.parse_select_order_by()?
            } else {
                None
            }
        } else {
            None
        };

        // Parse dialect extension clauses that appear between ORDER BY and LIMIT/OFFSET.
        // Databricks supports DISTRIBUTE BY / SORT BY / CLUSTER BY here.
        let pre_limit_extension_clauses = self.parse_pre_limit_extension_clauses()?;

        // Parse LIMIT and OFFSET clauses
        let limit_offset = self.parse_select_limit_offset()?;
        let limit = limit_offset.limit_expr.map(Box::new);
        let offset = limit_offset.offset_expr.map(Box::new);
        let limit_keyword_span = limit_offset.limit_keyword_span;
        let fetch_clause_span = limit_offset.fetch_clause_span;
        let offset_keyword_span = limit_offset.offset_keyword_span;

        // Trailing INTO (MySQL): `SELECT ... FROM ... [LIMIT ...] INTO
        // OUTFILE 'f' | DUMPFILE 'f' | @var, ...` — between LIMIT and the
        // locking clause (dialect-gated).
        if self.dialect.supports_trailing_select_into() && into_target.is_none() {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Into)) {
                    let into_kw = self
                        .advance()
                        .expect_invariant("INTO keyword confirmed by peek");
                    if let Some(outfile) = self.try_parse_into_outfile(into_kw.span)? {
                        into_target =
                            Some(Box::new(crate::ast::AstSelectIntoTarget::OutFile(outfile)));
                    } else {
                        let vars = self.parse_into_scripting_vars();
                        if !vars.is_empty() {
                            into_target = Some(Box::new(
                                crate::ast::AstSelectIntoTarget::ScriptingVars(vars),
                            ));
                        }
                    }
                }
            }
        }

        // Parse FOR UPDATE/SHARE locking clauses
        // Must be last clause in SELECT: SELECT ... ORDER BY ... LIMIT ... FOR UPDATE
        let for_locking = self.parse_for_locking_clauses()?;

        // Parse MSSQL FOR JSON / FOR XML clause (must come after FOR locking check,
        // since parse_for_locking_clauses peeks ahead and yields if it sees JSON/XML).
        let for_json_xml = self.parse_for_json_xml_clause()?;

        // Parse dialect extension clauses that trail standard SELECT clauses.
        // MSSQL supports OPTION(...) query hints here.
        let post_locking_extension_clauses = self.parse_post_locking_extension_clauses()?;

        // Determine the end of the SELECT statement span
        // Take the maximum span end from all parsed clauses (in reverse parse order)
        // Trailing INTO (MySQL) sits after LIMIT/OFFSET in source; cover it
        // when it is the last clause before the (absent) locking section.
        let trailing_into_end = into_target
            .as_deref()
            .and_then(|t| t.end_pos())
            .filter(|end| {
                limit_keyword_span.is_none_or(|kw| *end > kw.end)
                    && from
                        .first()
                        .and_then(|f| f.as_table_ref())
                        .is_some_and(|t| *end > t.span.start)
            });
        let last_span_end = if let Some(last_ext) = post_locking_extension_clauses.last() {
            last_ext.end
        } else if let Some(ref fjx) = for_json_xml {
            fjx.end
        } else if let Some(last_lock) = for_locking.last() {
            // FOR locking is the absolute last clause
            last_lock.span.end
        } else if let Some(into_end) = trailing_into_end {
            into_end
        } else if let Some(off_expr) = &offset {
            // OFFSET is parsed last, so if present, it's usually the end.
            // MySQL comma form (`LIMIT offset, count`) inverts the source
            // order — take the max so the count expression is covered.
            limit
                .as_ref()
                .map(|l| expr_span_end(l))
                .unwrap_or(0)
                .max(expr_span_end(off_expr))
        } else if let Some(lim_expr) = &limit {
            // LIMIT is second-to-last
            expr_span_end(lim_expr)
        } else {
            // Find the last clause that was actually parsed
            // Start with the projection span (at minimum we have SELECT <projection>)
            let projection_end = match &projection.kind {
                crate::ast::AstProjectionKind::Star(star) => {
                    // Star projection can have modifiers (EXCLUDE, REPLACE, RENAME)
                    // Find the rightmost span
                    if let Some(rename) = &star.rename {
                        rename
                            .items
                            .last()
                            .map(|item| item.alias.span.end)
                            .unwrap_or(star.star_span.end)
                    } else if let Some(replace) = &star.replace {
                        replace
                            .items
                            .last()
                            .map(|item| item.column.name.span.end)
                            .unwrap_or(star.star_span.end)
                    } else if let Some(exclude) = &star.exclude {
                        exclude
                            .columns
                            .last()
                            .map(|col| col.name.span.end)
                            .unwrap_or(star.star_span.end)
                    } else if let Some(ilike) = &star.ilike {
                        ilike.pattern_span.end
                    } else if let Some(qual) = &star.qualifier {
                        qual.span.end
                    } else {
                        star.star_span.end
                    }
                }
                crate::ast::AstProjectionKind::Columns(items) => {
                    // Find the last projection item span
                    items
                        .iter()
                        .next_back()
                        .map(|item| match &item.kind {
                            crate::ast::ProjectionItemKind::SelectItem(si) => si.span.end,
                            crate::ast::ProjectionItemKind::JinjaBlock(jb) => jb.span.end,
                        })
                        .unwrap_or(select_span.end)
                }
            };
            let mut end = projection_end;

            // Extend end-of-statement to cover an optional INTO clause
            // (both ScriptingVars and NewTable variants).
            if let Some(it_end) = into_target.as_deref().and_then(|t| t.end_pos()) {
                end = end.max(it_end);
            }

            // Check each optional clause and use the latest one
            if let Some(qual_clause) = &qualify {
                end = end.max(qual_clause.span.end);
            }
            if let Some(wc) = &window_clause {
                end = end.max(wc.span.end);
            }
            if let Some(cb) = &connect_by {
                end = end.max(cb.span.end);
            }
            if let Some(ob) = &order_by {
                // Use the ORDER BY span we now track
                end = end.max(ob.span.end);
            }
            if let Some(last_ext) = pre_limit_extension_clauses.last() {
                end = end.max(last_ext.end);
            }
            if let Some(hav_clause) = &having {
                end = end.max(hav_clause.span.end);
            }
            if let Some(gb) = &group_by {
                // Use the GROUP BY span we now track
                end = end.max(gb.span.end);
            }
            if let Some(where_clause) = &where_clause {
                end = end.max(where_clause.span.end);
            }
            if let Some(from_item) = from.last() {
                if let crate::ast::FromItemKind::TableRef(tbl) = &from_item.kind {
                    // Calculate the full table reference span including all modifiers
                    let mut tbl_end = tbl.name.span.end;

                    // Check alias
                    if let Some(alias) = &tbl.alias {
                        tbl_end = tbl_end.max(alias.span.end);
                    }

                    // Check alias columns
                    if let Some(cols) = &tbl.alias_columns {
                        if let Some(last_col) = cols.last() {
                            tbl_end = tbl_end.max(last_col.span.end);
                        }
                    }

                    // Check MATCH_RECOGNIZE
                    if let Some(mr) = &tbl.match_recognize {
                        tbl_end = tbl_end.max(mr.span.end);
                    }

                    // Check PIVOT
                    if let Some(pivot) = &tbl.pivot {
                        tbl_end = tbl_end.max(pivot.span.end);
                    }

                    // Check UNPIVOT
                    if let Some(unpivot) = &tbl.unpivot {
                        tbl_end = tbl_end.max(unpivot.span.end);
                    }

                    // Check MySQL partition selection
                    if let Some(ps) = &tbl.partition_selection {
                        tbl_end = tbl_end.max(ps.span.end);
                    }

                    // Check joins (last join span is the rightmost)
                    if let Some(last_join) = tbl.joins.last() {
                        tbl_end = tbl_end.max(last_join.span.end);
                    }

                    end = end.max(tbl_end);
                }
            }

            end
        };

        let span = crate::parser::sql_stmt::build_select_span(select_span, last_span_end);

        let mut select = crate::parser::sql_stmt::build_select(
            self.id_gen.next(),
            span,
            select_span,
            select_as_qualifier,
            set_quantifier,
            set_quantifier_span,
            top.map(Box::new),
            projection,
            from,
            statement_fragments,
            where_clause,
            group_by,
            having,
            connect_by,
            order_by,
            qualify,
            into_target,
            limit,
            offset,
            limit_keyword_span,
            fetch_clause_span,
            offset_keyword_span,
            if for_locking.is_empty() {
                None
            } else {
                Some(Box::new(for_locking))
            },
            None,
            window_clause,
        );
        select.pre_limit_extension_clauses = Box::new(pre_limit_extension_clauses);
        select.post_locking_extension_clauses = Box::new(post_locking_extension_clauses);
        select.for_json_xml = for_json_xml;
        select.limit_offset_comma_span = limit_offset.limit_comma_span;

        Ok(Box::new(select))
    }

    /// Parse the scripting-variable list after INTO: `:v, :v2` or `v, v2`
    /// or `@v, @v2`. Returns collected spans (empty = nothing consumed).
    fn parse_into_scripting_vars(&mut self) -> Vec<Span> {
        let mut vars: Vec<Span> = Vec::new();
        while let Some(next) = self.peek() {
            match &next.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::Colon) => {
                    let colon_tok = self
                        .advance()
                        .expect_invariant("Colon confirmed by peek for INTO variable");
                    if let Some(id_tok) = self.advance() {
                        if self.can_be_identifier_token(id_tok) {
                            let var_span = crate::parser::sql_stmt::build_into_var_span(
                                colon_tok.span,
                                id_tok.span,
                            );
                            vars.push(var_span);
                            if let Some(comma) = self.peek() {
                                if matches!(
                                    comma.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                ) {
                                    self.advance();
                                    continue;
                                }
                            }
                        }
                    }
                    break;
                }
                TokenKind::Identifier { .. } => {
                    let id_tok = self
                        .advance()
                        .expect_invariant("Identifier confirmed by peek for INTO variable");
                    vars.push(id_tok.span);
                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            continue;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        vars
    }

    /// After INTO has been consumed: parse `OUTFILE 'file' [export opts]` /
    /// `DUMPFILE 'file'` (dialect-gated). Returns Ok(None) when the next
    /// tokens are not a file target, leaving the cursor unchanged.
    fn try_parse_into_outfile(
        &mut self,
        into_span: Span,
    ) -> crate::error::ParseResult<Option<Box<crate::ast::AstSelectIntoOutfile>>> {
        use crate::ast::{AstIntoFileKind, AstSelectIntoOutfile};

        if !self.dialect.supports_select_into_outfile() {
            return Ok(None);
        }
        let kind_tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        if !matches!(
            kind_tok.kind,
            TokenKind::Identifier {
                kind: crate::lexer::IdentifierKind::Unquoted
            }
        ) {
            return Ok(None);
        }
        let kind = if kind_tok.lexeme(self.source).eq_ignore_ascii_case("OUTFILE") {
            AstIntoFileKind::Outfile
        } else if kind_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("DUMPFILE")
        {
            AstIntoFileKind::Dumpfile
        } else {
            return Ok(None);
        };
        // The file path must be a string literal directly after the word.
        if !self.peek_ahead(1).is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Literal(crate::lexer::LiteralKind::String)
            )
        }) {
            return Ok(None);
        }
        let kind_span = self
            .advance()
            .expect_invariant("OUTFILE/DUMPFILE confirmed by peek")
            .span;
        let file_span = self
            .advance()
            .expect_invariant("file literal confirmed by peek_ahead")
            .span;

        // OUTFILE export-options tail: CHARACTER SET name, FIELDS/COLUMNS/
        // LINES [OPTIONALLY] {TERMINATED|ENCLOSED|ESCAPED|STARTING} BY 'str'.
        // Preserved verbatim; the scan stops at any word outside the option
        // vocabulary (FROM, WHERE, semicolon, ...).
        let mut options_start: Option<u32> = None;
        let mut options_end: Option<u32> = None;
        if matches!(kind, AstIntoFileKind::Outfile) {
            let mut after_character_set = false;
            while let Some(tok) = self.peek() {
                let consume = match &tok.kind {
                    TokenKind::Keyword(Keyword::By) | TokenKind::Keyword(Keyword::Set) => true,
                    TokenKind::Literal(crate::lexer::LiteralKind::String) => true,
                    TokenKind::Identifier {
                        kind: crate::lexer::IdentifierKind::Unquoted,
                    } => {
                        let lex = tok.lexeme(self.source);
                        if after_character_set {
                            // charset name directly after CHARACTER SET
                            true
                        } else {
                            lex.eq_ignore_ascii_case("FIELDS")
                                || lex.eq_ignore_ascii_case("COLUMNS")
                                || lex.eq_ignore_ascii_case("LINES")
                                || lex.eq_ignore_ascii_case("TERMINATED")
                                || lex.eq_ignore_ascii_case("ENCLOSED")
                                || lex.eq_ignore_ascii_case("ESCAPED")
                                || lex.eq_ignore_ascii_case("STARTING")
                                || lex.eq_ignore_ascii_case("OPTIONALLY")
                                || lex.eq_ignore_ascii_case("CHARACTER")
                        }
                    }
                    _ => false,
                };
                if !consume {
                    break;
                }
                after_character_set = matches!(tok.kind, TokenKind::Keyword(Keyword::Set));
                let consumed = self.advance().expect_invariant("option token confirmed");
                options_start.get_or_insert(consumed.span.start);
                options_end = Some(consumed.span.end);
            }
        }

        let span_end = options_end.unwrap_or(file_span.end);
        Ok(Some(Box::new(AstSelectIntoOutfile {
            node_id: self.id_gen.next(),
            into_span,
            kind,
            kind_span,
            file_span,
            options_span: options_start
                .zip(options_end)
                .map(|(start, end)| Span { start, end }),
            span: Span {
                start: into_span.start,
                end: span_end,
            },
        })))
    }

    fn parse_pre_limit_extension_clauses(&mut self) -> crate::error::ParseResult<Vec<Span>> {
        let mut spans = Vec::new();
        if !self.dialect.supports_distribute_sort_clauses() {
            return Ok(spans);
        }

        loop {
            let head = match self.peek() {
                Some(tok) if self.can_be_identifier_token(tok) => tok,
                _ => break,
            };

            let head_lexeme = head.lexeme(self.source);
            let is_clause_head = head_lexeme.eq_ignore_ascii_case("DISTRIBUTE")
                || head_lexeme.eq_ignore_ascii_case("SORT")
                || head_lexeme.eq_ignore_ascii_case("CLUSTER");
            if !is_clause_head {
                break;
            }

            let by_span = match self.peek_ahead(1) {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::By)) => tok.span,
                _ => break,
            };

            let head_tok = self
                .advance()
                .expect_invariant("extension clause head after peek");
            self.advance(); // consume BY

            let mut end = by_span.end;
            let mut paren_depth: usize = 0;

            while let Some(tok) = self.peek() {
                if paren_depth == 0 {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) || matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) || matches!(tok.kind, TokenKind::Keyword(Keyword::Limit))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Offset))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Fetch))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::For))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Union))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Intersect))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Except))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Minus))
                    {
                        break;
                    }

                    if self.can_be_identifier_token(tok)
                        && (tok.lexeme(self.source).eq_ignore_ascii_case("DISTRIBUTE")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("SORT")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("CLUSTER"))
                        && self.peek_ahead(1).is_some_and(|next| {
                            matches!(next.kind, TokenKind::Keyword(Keyword::By))
                        })
                    {
                        break;
                    }
                }

                let consumed = self
                    .advance()
                    .expect_invariant("peeked token in extension clause");
                match consumed.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => paren_depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        paren_depth = paren_depth.saturating_sub(1);
                    }
                    _ => {}
                }
                end = consumed.span.end;
            }

            spans.push(Span {
                start: head_tok.span.start,
                end,
            });
        }

        Ok(spans)
    }

    fn parse_post_locking_extension_clauses(&mut self) -> crate::error::ParseResult<Vec<Span>> {
        let mut spans = Vec::new();
        if !self.dialect.supports_query_option_clause() {
            return Ok(spans);
        }

        loop {
            let head = match self.peek() {
                Some(tok) if self.can_be_identifier_token(tok) => tok,
                _ => break,
            };
            if !head.lexeme(self.source).eq_ignore_ascii_case("OPTION") {
                break;
            }

            if !self.peek_ahead(1).is_some_and(|tok| {
                matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            }) {
                break;
            }

            let head_tok = self.advance().expect_invariant("OPTION head after peek");
            let lparen_span = self
                .peek()
                .expect_invariant("LParen exists after OPTION")
                .span;
            self.advance(); // consume '('
            let mut end = lparen_span.end;
            let mut depth: usize = 1;

            while self.peek().is_some() {
                let consumed = self
                    .advance()
                    .expect_invariant("OPTION(...) token after peek");
                end = consumed.span.end;
                match consumed.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if depth != 0 {
                return Err(crate::error::ParseError::new(
                    head_tok.span,
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message: "Missing closing ')' for OPTION(...) clause".to_string(),
                    },
                ));
            }

            spans.push(Span {
                start: head_tok.span.start,
                end,
            });
        }

        Ok(spans)
    }

    /// Parse FOR locking clauses (FOR UPDATE / FOR SHARE / FOR NO KEY UPDATE / FOR KEY SHARE).
    /// Snowflake: FOR UPDATE [ NOWAIT | WAIT <wait_time> ]
    /// PostgreSQL: FOR { UPDATE | NO KEY UPDATE | SHARE | KEY SHARE }
    ///             [ OF table_name [, ...] ] [ NOWAIT | SKIP LOCKED ]
    /// Multiple locking clauses are allowed (PostgreSQL).
    fn parse_for_locking_clauses(
        &mut self,
    ) -> crate::error::ParseResult<Vec<crate::ast::AstForUpdate>> {
        use crate::lexer::{Keyword, TokenKind};

        let mut clauses = Vec::new();

        loop {
            // MySQL `LOCK IN SHARE MODE` — deprecated synonym of FOR SHARE
            // (dialect-gated). All four words otherwise start a phantom
            // statement (LOCK lexes as an identifier).
            if self.dialect.supports_lock_in_share_mode() {
                if let Some(lock_tok) = self.peek_non_trivia() {
                    let lock_span = lock_tok.span;
                    if matches!(
                        lock_tok.kind,
                        TokenKind::Identifier {
                            kind: crate::lexer::IdentifierKind::Unquoted
                        }
                    ) && lock_tok.lexeme(self.source).eq_ignore_ascii_case("LOCK")
                        && self
                            .peek_ahead(1)
                            .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::In)))
                        && self
                            .peek_ahead(2)
                            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("SHARE"))
                        && self
                            .peek_ahead(3)
                            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("MODE"))
                    {
                        self.advance(); // LOCK
                        self.advance(); // IN
                        self.advance(); // SHARE
                        let mode_tok = self
                            .advance()
                            .expect_invariant("MODE confirmed by peek_ahead");
                        let clause_span = crate::lexer::Span {
                            start: lock_span.start,
                            end: mode_tok.span.end,
                        };
                        clauses.push(crate::ast::AstForUpdate {
                            node_id: self.id_gen.next(),
                            for_update_span: clause_span,
                            lock_strength: crate::ast::LockStrength::Share,
                            of_tables: Vec::new(),
                            of_keyword_span: None,
                            wait_policy: None,
                            span: clause_span,
                        });
                        continue;
                    }
                }
            }

            // Check for FOR keyword
            let for_tok = match self.peek_non_trivia() {
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::For)) => tok.clone(),
                _ => break,
            };

            // Peek ahead: if the token after FOR is JSON, XML, or READ (Identifier),
            // this is NOT a locking clause. JSON/XML = MSSQL FOR JSON/XML clause,
            // READ = cursor sensitivity clause (FOR READ ONLY).
            // Do NOT consume FOR — let the caller handle it.
            if let Some(after_for) = self.peek_ahead(1) {
                let lex = after_for.lexeme(self.source);
                if lex.eq_ignore_ascii_case("JSON")
                    || lex.eq_ignore_ascii_case("XML")
                    || lex.eq_ignore_ascii_case("READ")
                {
                    break;
                }
            }

            // Consume FOR
            self.advance();
            let for_start = for_tok.span.start;

            // Determine lock strength by looking at next token(s)
            let next_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    for_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected UPDATE, SHARE, NO KEY UPDATE, or KEY SHARE after FOR"
                            .to_string(),
                    },
                )
            })?;

            let (lock_strength, strength_end) = if matches!(
                next_tok.kind,
                TokenKind::Keyword(Keyword::Update)
            ) {
                // FOR UPDATE
                let tok = self.advance().unwrap();
                (crate::ast::LockStrength::Update, tok.span.end)
            } else if next_tok.lexeme(self.source).eq_ignore_ascii_case("SHARE") {
                // FOR SHARE
                let tok = self.advance().unwrap();
                (crate::ast::LockStrength::Share, tok.span.end)
            } else if next_tok.lexeme(self.source).eq_ignore_ascii_case("NO") {
                // FOR NO KEY UPDATE
                let _no_tok = self.advance().unwrap();
                // Expect KEY
                let key_tok = self.advance().ok_or_else(|| {
                    crate::error::ParseError::new(
                        for_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: "Expected KEY after FOR NO".to_string(),
                        },
                    )
                })?;
                if !matches!(key_tok.kind, TokenKind::Keyword(Keyword::Key)) {
                    return Err(crate::error::ParseError::new(
                        key_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected KEY after FOR NO, found: {}",
                                key_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                // Expect UPDATE
                let update_tok = self.advance().ok_or_else(|| {
                    crate::error::ParseError::new(
                        key_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: "Expected UPDATE after FOR NO KEY".to_string(),
                        },
                    )
                })?;
                if !matches!(update_tok.kind, TokenKind::Keyword(Keyword::Update)) {
                    return Err(crate::error::ParseError::new(
                        update_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected UPDATE after FOR NO KEY, found: {}",
                                update_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                (crate::ast::LockStrength::NoKeyUpdate, update_tok.span.end)
            } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Key)) {
                // FOR KEY SHARE
                let _key_tok = self.advance().unwrap();
                // Expect SHARE
                let share_tok = self.advance().ok_or_else(|| {
                    crate::error::ParseError::new(
                        for_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: "Expected SHARE after FOR KEY".to_string(),
                        },
                    )
                })?;
                if !share_tok.lexeme(self.source).eq_ignore_ascii_case("SHARE") {
                    return Err(crate::error::ParseError::new(
                        share_tok.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected SHARE after FOR KEY, found: {}",
                                share_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                (crate::ast::LockStrength::KeyShare, share_tok.span.end)
            } else {
                return Err(crate::error::ParseError::new(
                    next_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!("Expected UPDATE, SHARE, NO KEY UPDATE, or KEY SHARE after FOR, found: {}", next_tok.lexeme(self.source)),
                    },
                ));
            };

            let for_update_span = crate::lexer::Span {
                start: for_start,
                end: strength_end,
            };

            // Parse optional OF table_name [, ...]
            let mut of_tables = Vec::new();
            let mut of_keyword_span = None;
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Of)) {
                    let of_tok = self.advance().unwrap();
                    of_keyword_span = Some(of_tok.span);

                    // Parse comma-separated table names (possibly qualified: schema.table)
                    loop {
                        // Consume first identifier token
                        let first_tok = self.advance().ok_or_else(|| {
                            crate::error::ParseError::new(
                                of_tok.span,
                                crate::error::ParseErrorKind::InvalidStatement {
                                    message: "Expected table name after OF".to_string(),
                                },
                            )
                        })?;
                        let mut tbl_end = first_tok.span.end;

                        // Consume optional dot-separated qualifiers (schema.table)
                        while let Some(dot_tok) = self.peek_non_trivia() {
                            if matches!(
                                dot_tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                            ) {
                                self.advance(); // consume dot
                                let next_part = self.advance().ok_or_else(|| {
                                    crate::error::ParseError::new(
                                        first_tok.span,
                                        crate::error::ParseErrorKind::InvalidStatement {
                                            message: "Expected identifier after '.'".to_string(),
                                        },
                                    )
                                })?;
                                tbl_end = next_part.span.end;
                            } else {
                                break;
                            }
                        }

                        of_tables.push(crate::lexer::Span {
                            start: first_tok.span.start,
                            end: tbl_end,
                        });

                        // Check for comma
                        if let Some(next) = self.peek_non_trivia() {
                            if matches!(
                                next.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                self.advance(); // consume comma
                                continue;
                            }
                        }
                        break;
                    }
                }
            }

            // Parse optional wait policy: NOWAIT | WAIT <duration> | SKIP LOCKED
            let wait_policy = match self.peek_non_trivia() {
                Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("NOWAIT") => {
                    let nowait_tok = self.advance().unwrap();
                    Some(crate::ast::ForUpdateWaitPolicy::NoWait {
                        nowait_span: nowait_tok.span,
                    })
                }
                Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("WAIT") => {
                    let wait_tok = self.advance().unwrap();
                    let wait_span = wait_tok.span;
                    let duration = Box::new(self.parse_expr()?);
                    Some(crate::ast::ForUpdateWaitPolicy::Wait {
                        wait_span,
                        duration,
                    })
                }
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Skip)) => {
                    let skip_tok = self.advance().unwrap();
                    // Expect LOCKED
                    let locked_tok = self.advance().ok_or_else(|| {
                        crate::error::ParseError::new(
                            skip_tok.span,
                            crate::error::ParseErrorKind::InvalidStatement {
                                message: "Expected LOCKED after SKIP".to_string(),
                            },
                        )
                    })?;
                    if !locked_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("LOCKED")
                    {
                        return Err(crate::error::ParseError::new(
                            locked_tok.span,
                            crate::error::ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "Expected LOCKED after SKIP, found: {}",
                                    locked_tok.lexeme(self.source)
                                ),
                            },
                        ));
                    }
                    Some(crate::ast::ForUpdateWaitPolicy::SkipLocked {
                        skip_locked_span: crate::lexer::Span {
                            start: skip_tok.span.start,
                            end: locked_tok.span.end,
                        },
                    })
                }
                _ => None,
            };

            // Calculate final span
            let end = if let Some(ref wp) = wait_policy {
                match wp {
                    crate::ast::ForUpdateWaitPolicy::NoWait { nowait_span } => nowait_span.end,
                    crate::ast::ForUpdateWaitPolicy::Wait { duration, .. } => {
                        crate::parser::scripting::expr_span_end(duration)
                    }
                    crate::ast::ForUpdateWaitPolicy::SkipLocked { skip_locked_span } => {
                        skip_locked_span.end
                    }
                }
            } else if let Some(last_tbl) = of_tables.last() {
                last_tbl.end
            } else {
                strength_end
            };

            let span = crate::lexer::Span {
                start: for_start,
                end,
            };

            clauses.push(crate::ast::AstForUpdate {
                node_id: self.id_gen.next(),
                for_update_span,
                lock_strength,
                of_tables,
                of_keyword_span,
                wait_policy,
                span,
            });
        }

        Ok(clauses)
    }

    /// Parse MSSQL `FOR JSON ...` or `FOR XML ...` clause as a raw span.
    ///
    /// Called when peek shows `FOR` followed by `JSON` or `XML` identifier.
    /// The `FOR` keyword has NOT been consumed yet.
    ///
    /// MSSQL FOR JSON syntax:
    ///   FOR JSON { AUTO | PATH } [, ROOT('name')] [, INCLUDE_NULL_VALUES] [, WITHOUT_ARRAY_WRAPPER]
    ///
    /// MSSQL FOR XML syntax:
    ///   FOR XML { RAW [('element')] | AUTO | PATH [('element')] | EXPLICIT }
    ///     [, ROOT('name')] [, TYPE] [, ELEMENTS [XSINIL | ABSENT]]
    ///
    /// We parse the entire clause as a raw span — preserving it verbatim for formatting.
    fn parse_for_json_xml_clause(
        &mut self,
    ) -> crate::error::ParseResult<Option<crate::lexer::Span>> {
        use crate::lexer::{Keyword, Punctuation, TokenKind};

        // Check for FOR keyword
        let _for_tok = match self.peek_non_trivia() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::For)) => tok.clone(),
            _ => return Ok(None),
        };

        // Peek at next token: must be JSON or XML identifier
        let after_for = match self.peek_ahead(1) {
            Some(tok) => tok,
            None => return Ok(None),
        };
        let after_lex = after_for.lexeme(self.source);
        if !after_lex.eq_ignore_ascii_case("JSON") && !after_lex.eq_ignore_ascii_case("XML") {
            return Ok(None);
        }

        // Consume FOR
        let for_tok = self.advance().unwrap();
        let start = for_tok.span.start;
        #[allow(unused_assignments)]
        let mut end = for_tok.span.end;

        // Consume JSON or XML
        let mode_tok = self.advance().unwrap();
        end = mode_tok.span.end;

        // Consume mode keyword (PATH, AUTO, RAW, EXPLICIT) — may be Keyword or Identifier
        if let Some(mode_next) = self.peek_non_trivia() {
            let mode_lex = mode_next.lexeme(self.source);
            let is_mode = mode_lex.eq_ignore_ascii_case("PATH")
                || mode_lex.eq_ignore_ascii_case("AUTO")
                || matches!(mode_next.kind, TokenKind::Keyword(Keyword::Auto))
                || mode_lex.eq_ignore_ascii_case("RAW")
                || mode_lex.eq_ignore_ascii_case("EXPLICIT");
            if is_mode {
                let tok = self.advance().unwrap();
                end = tok.span.end;

                // Optional parenthesized element name: PATH('name') or RAW('name')
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        self.advance(); // consume '('
                                        // Consume tokens until matching ')'
                        let mut depth = 1u32;
                        while depth > 0 {
                            if let Some(_inner) = self.peek_non_trivia() {
                                let t = self.advance().unwrap();
                                end = t.span.end;
                                match t.kind {
                                    TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                                    TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                                    _ => {}
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Consume comma-separated options:
        // ROOT('name'), INCLUDE_NULL_VALUES, WITHOUT_ARRAY_WRAPPER, TYPE, ELEMENTS [XSINIL|ABSENT]
        while let Some(comma) = self.peek_non_trivia() {
            if !matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                break;
            }
            // Consume comma
            self.advance();

            // Consume option keyword/identifier
            let opt = match self.peek_non_trivia() {
                Some(tok) => tok,
                None => break,
            };

            let opt_lex = opt.lexeme(self.source);
            let is_known_option = opt_lex.eq_ignore_ascii_case("ROOT")
                || opt_lex.eq_ignore_ascii_case("INCLUDE_NULL_VALUES")
                || opt_lex.eq_ignore_ascii_case("WITHOUT_ARRAY_WRAPPER")
                || opt_lex.eq_ignore_ascii_case("ELEMENTS")
                || matches!(opt.kind, TokenKind::Keyword(Keyword::Type));

            if !is_known_option {
                // Not a recognized FOR JSON/XML option — stop consuming. The
                // comma before it is already consumed, so the next token is
                // included as a best-effort span extension.
                break;
            }

            let opt_tok = self.advance().unwrap();
            end = opt_tok.span.end;

            // Some options have parenthesized arguments: ROOT('name')
            if opt_lex.eq_ignore_ascii_case("ROOT") {
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        self.advance(); // consume '('
                        let mut depth = 1u32;
                        while depth > 0 {
                            if let Some(_inner) = self.peek_non_trivia() {
                                let t = self.advance().unwrap();
                                end = t.span.end;
                                match t.kind {
                                    TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                                    TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                                    _ => {}
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            }

            // ELEMENTS may be followed by XSINIL or ABSENT
            if opt_lex.eq_ignore_ascii_case("ELEMENTS") {
                if let Some(sub) = self.peek_non_trivia() {
                    let sub_lex = sub.lexeme(self.source);
                    if sub_lex.eq_ignore_ascii_case("XSINIL")
                        || sub_lex.eq_ignore_ascii_case("ABSENT")
                    {
                        let sub_tok = self.advance().unwrap();
                        end = sub_tok.span.end;
                    }
                }
            }
        }

        Ok(Some(crate::lexer::Span { start, end }))
    }

    /// Parse a WINDOW clause: WINDOW w AS (...) [, w2 AS (...)]
    /// Called when the current token is `WINDOW` (Identifier or Keyword).
    fn parse_window_clause(&mut self) -> crate::error::ParseResult<crate::ast::AstWindowClause> {
        // Consume the WINDOW keyword (it's an Identifier, not a Keyword)
        let window_tok = self
            .advance()
            .expect_invariant("WINDOW identifier after peek");
        let window_keyword_span = window_tok.span;
        let start = window_keyword_span.start;

        let mut definitions = Vec::new();

        loop {
            // Parse window name (identifier)
            let name_tok = self.advance().ok_or_else(|| {
                crate::error::ParseError::new(
                    window_keyword_span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected window name after WINDOW".to_string(),
                    },
                )
            })?;
            let name_span = name_tok.span;

            // Expect AS keyword
            let as_tok = self.advance().ok_or_else(|| {
                crate::error::ParseError::new(
                    name_span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected AS after window name".to_string(),
                    },
                )
            })?;
            if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                return Err(crate::error::ParseError::new(
                    as_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected AS after window name, found: {}",
                            as_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let as_keyword_span = as_tok.span;

            // Expect '(' then delegate to the shared parenthesized-spec parser
            // (same components as OVER (...), including the frame clause).
            let at_lparen = self
                .peek()
                .map(|t| {
                    matches!(
                        t.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    )
                })
                .unwrap_or(false);
            if !at_lparen {
                return Err(crate::error::ParseError::new(
                    as_keyword_span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected '(' after AS in WINDOW clause".to_string(),
                    },
                ));
            }
            let (spec_span, window_spec) =
                match self.parse_parenthesized_window_spec(None, None, None) {
                    Some(Ok(v)) => v,
                    Some(Err(e)) => return Err(e),
                    None => {
                        return Err(crate::error::ParseError::new(
                            as_keyword_span,
                            crate::error::ParseErrorKind::InvalidStatement {
                                message: "Expected window specification after AS".to_string(),
                            },
                        ))
                    }
                };
            let def_end = spec_span.end;

            let def_span = Span {
                start: name_span.start,
                end: def_end,
            };

            definitions.push(crate::ast::AstWindowDefinition {
                node_id: self.id_gen.next(),
                span: def_span,
                name_span,
                as_keyword_span,
                window_spec,
            });

            // Check for comma (more definitions)
            if let Some(tok) = self.peek() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        let end = definitions
            .last()
            .map(|d| d.span.end)
            .unwrap_or(window_keyword_span.end);

        Ok(crate::ast::AstWindowClause {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            window_keyword_span,
            definitions,
        })
    }
}
