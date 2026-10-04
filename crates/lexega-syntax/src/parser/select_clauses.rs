// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SELECT clause parsing (FROM, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT)
//!
//! This module handles parsing of SELECT statement clauses:
//! - FROM clause (table references, JOINs handled in table_ref.rs)
//! - WHERE clause
//! - GROUP BY clause (including GROUPING SETS, ROLLUP, CUBE)
//! - HAVING clause
//! - ORDER BY clause
//! - LIMIT and OFFSET clauses
//! - CONNECT BY (hierarchical queries)
//! - MATCH_RECOGNIZE

use crate::ast::*;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::Parser;
use crate::parser::scripting::expr_span_end;
use crate::parser::select::InlineFragmentCollection;

/// Result of parsing LIMIT/OFFSET clauses
pub(crate) struct LimitOffsetParsed {
    pub limit_expr: Option<AstExpr>,
    pub offset_expr: Option<AstExpr>,
    pub limit_keyword_span: Option<Span>,
    pub fetch_clause_span: Option<Span>,
    pub offset_keyword_span: Option<Span>,
    /// Span of the comma in the MySQL `LIMIT offset, count` form.
    /// When `Some`, `offset_expr` precedes `limit_expr` in source and the
    /// formatter must re-emit the comma form, not synthesize OFFSET.
    pub limit_comma_span: Option<Span>,
}

// Implementation methods will be added here via:
impl<'a> Parser<'a> {
    /// Peek ahead to check if the current Jinja block contains StatementFragment content
    /// (JOINs, WHERE, HAVING). Used to decide whether to parse as StatementFragment vs
    /// leave for outer parser (e.g., set operations like UNION).
    ///
    /// Returns true if the token AFTER the current Jinja statement starts a StatementFragment.
    pub(crate) fn peek_jinja_block_is_statement_fragment(&self) -> bool {
        // Current token should be {% (JinjaStmtOpen)
        // A Jinja block is a statement fragment if the FIRST SQL keyword at depth 1 is FROM/WHERE/JOIN/etc.
        // If the first SQL content at depth 1 is something else (expression, identifier), it's a projection block.

        // Verify we're at a Jinja statement opener
        let tok = match self.peek() {
            Some(t) => t,
            None => return false,
        };

        if !matches!(tok.kind, TokenKind::JinjaStmtOpen) {
            return false;
        }

        // Determine the block type
        let next_tok = match self.peek_ahead(1) {
            Some(t) => t,
            None => return false,
        };
        match &next_tok.kind {
            TokenKind::JinjaIf | TokenKind::JinjaFor => {}
            _ => return false, // Not an if/for block
        };

        // Skip past the opening delimiter ({% if/for ... %})
        let mut temp_idx = self.idx;
        while temp_idx < self.tokens.len() {
            if matches!(self.tokens[temp_idx].kind, TokenKind::JinjaStmtClose) {
                temp_idx += 1; // Position after %}
                break;
            }
            temp_idx += 1;
        }

        // Scan the body content at depth 1, looking for the FIRST meaningful SQL keyword
        let mut depth = 1; // We're inside one if/for block
        while temp_idx < self.tokens.len() {
            let t = &self.tokens[temp_idx];

            match &t.kind {
                // Track nesting: increment depth for any new block openers
                TokenKind::JinjaIf | TokenKind::JinjaFor => {
                    depth += 1;
                }
                // Decrement depth for ANY closer (both IF and FOR)
                TokenKind::JinjaEndIf | TokenKind::JinjaEndFor => {
                    depth -= 1;
                    if depth == 0 {
                        // Reached end of block without signal statement fragment keywords
                        break;
                    }
                }
                // At depth 1, check what the FIRST SQL keyword is
                TokenKind::Keyword(kw) if depth == 1 => {
                    // Found a keyword at immediate level - is it a statement fragment keyword?
                    let is_fragment = matches!(
                        kw,
                        Keyword::From
                            | Keyword::Join
                            | Keyword::Left
                            | Keyword::Right
                            | Keyword::Full
                            | Keyword::Inner
                            | Keyword::Cross
                            | Keyword::Natural
                            | Keyword::Asof
                            | Keyword::Where
                            | Keyword::Having
                    );
                    return is_fragment;
                }
                _ => {}
            }

            temp_idx += 1;
        }

        false
    }

    /// Parse the FROM clause and return a vector of FromItem (table references or Jinja blocks)
    pub(crate) fn parse_select_from_clause(
        &mut self,
        select_span: Span,
    ) -> ParseResult<Vec<crate::ast::FromItem>> {
        // Check if there's a Jinja block that contains a statement fragment (FROM, WHERE, JOIN, etc.)
        // If so, don't parse it here - let the statement fragment parser handle it
        if let Some(kind) = self.peek_jinja_block_kind() {
            if matches!(
                kind,
                crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For
            ) && self.peek_jinja_block_is_statement_fragment()
            {
                // This Jinja block contains FROM/WHERE/JOIN - return empty FROM so
                // statement fragment parser can handle the entire block
                return Ok(Vec::new());
            }
        }

        // Check for FROM keyword
        if let Some(tok) = self.peek() {
            if !matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
                return Ok(Vec::new()); // No FROM clause
            }
            self.advance(); // Consume FROM
        } else {
            return Ok(Vec::new());
        }

        let mut from = Vec::new();
        while let Some(tok) = self.peek() {
            // Stop the FROM list when we hit another clause keyword or closing paren (for subqueries)
            match &tok.kind {
                TokenKind::Keyword(Keyword::Where)
                | TokenKind::Keyword(Keyword::Group)
                | TokenKind::Keyword(Keyword::Order)
                | TokenKind::Keyword(Keyword::Qualify)
                | TokenKind::Keyword(Keyword::Limit)
                | TokenKind::Keyword(Keyword::Offset)
                | TokenKind::Keyword(Keyword::Fetch)
                | TokenKind::Keyword(Keyword::Having)
                | TokenKind::Keyword(Keyword::For)  // Stop at FOR UPDATE clause
                | TokenKind::Operator(crate::lexer::Operator::Pipe)
                // Stop on ) for scalar subqueries: SELECT func((SELECT x FROM tbl))
                | TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => break,
                _ if self.dialect.supports_named_window_clause()
                    && tok.lexeme(self.source).eq_ignore_ascii_case("WINDOW") =>
                {
                    break
                }
                // Dialect-gated clause boundaries (e.g., RETURNING in PostgreSQL)
                _ if self.can_be_identifier_token(tok)
                    && self.dialect.is_clause_boundary_keyword(tok.lexeme(self.source)) =>
                {
                    break
                }
                _ => {}
            }

            // Parse base table factor FIRST
            // This handles both regular tables AND Jinja blocks producing table names
            // Example: {% if prod %}schema1{% else %}schema2{% endif %}.orders
            // The parse_table_factor function detects Jinja at the start and
            // calls parse_jinja_wrapped_table_reference for structured parsing.
            //
            // For Jinja blocks that wrap COMPLETE table references (not name fragments),
            // parse_table_factor will return None and we fall back to parse_from_jinja_block.

            // Check if this is a Jinja opener - parse_table_factor handles Jinja table name fragments
            // NOTE: Do NOT call collect_leading_inline_fragments here - it would consume
            // {% if %} blocks that should be parsed as Jinja-wrapped table references.
            // Only collect comments before the table reference.
            let mut prefix_inline_fragments = Vec::new();
            while let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::JinjaComment) {
                    let comment_tok = self
                        .advance()
                        .expect_invariant("JinjaComment consumed after peek");
                    prefix_inline_fragments.push(crate::ast::JinjaInlineFragment {
                        node_id: self.id_gen.next(),
                        span: comment_tok.span,
                        syntax_id: None,
                        kind: crate::ast::JinjaInlineFragmentKind::Comment(
                            crate::ast::JinjaInlineComment {
                                node_id: self.id_gen.next(),
                                body_span: comment_tok.span,
                            },
                        ),
                    });
                } else {
                    break;
                }
            }

            let base_result = self.parse_table_factor(select_span);

            let mut base = match base_result {
                Ok(Some(b)) => b,
                Ok(None) => {
                    return Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected table reference in FROM clause".to_string(),
                        },
                    ));
                }
                Err(e) => {
                    return Err(e);
                }
            };

            *base.prefix_inline_fragments = prefix_inline_fragments;

            // Parse regular join chain (handles non-Jinja joins)
            self.parse_join_chain(&mut base)?;

            // Check for dangling DIRECTED JOIN (syntax error)
            // But NOT if we just consumed a comma (valid: "FROM t1 AS directed, LATERAL...")
            if let Some(next) = self.peek() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Directed)) {
                    // Check if previous token was a comma - if so, this is a new FROM item, not dangling JOIN
                    let mut should_check_dangling = true;
                    if self.idx > 0 {
                        if let Some(prev) = self.tokens.get(self.idx - 1) {
                            if matches!(
                                prev.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                // This is fine - DIRECTED after comma starts new FROM item
                                should_check_dangling = false;
                            }
                        }
                    }

                    if should_check_dangling {
                        // Not after comma - check for dangling DIRECTED JOIN
                        let save_idx = self.idx;
                        self.advance();
                        let after = self.peek();
                        self.idx = save_idx;
                        if let Some(tok2) = after {
                            if matches!(tok2.kind, TokenKind::Keyword(Keyword::Join)) {
                                return Err(ParseError::new(
                                    next.span,
                                    ParseErrorKind::InvalidSyntax {
                                        message: "Unsupported DIRECTED JOIN syntax".to_string(),
                                    },
                                ));
                            }
                        }
                    }
                }
            }

            // Wrap the table ref in a FromItem
            let InlineFragmentCollection {
                fragments: suffix_inline_fragments,
            } = self.collect_trailing_inline_fragments();
            if let Some(last) = suffix_inline_fragments.last() {
                base.span.end = base.span.end.max(last.span.end);
            }
            base.suffix_inline_fragments.extend(suffix_inline_fragments);

            let from_item = crate::ast::FromItem {
                node_id: self.id_gen.next(),
                kind: crate::ast::FromItemKind::TableRef(base),
            };
            from.push(from_item);

            // Check for comma to continue
            match self.peek() {
                Some(Token {
                    kind: TokenKind::Punctuation(crate::lexer::Punctuation::Comma),
                    ..
                }) => {
                    self.advance();
                }
                _ => break,
            }
        }
        Ok(from)
    }

    /// Parse a StatementFragment (FROM + JOINs + WHERE + HAVING) that appears after table references
    /// or as a standalone fragment starting with FROM
    /// Used when Jinja wraps clause fragments like:
    /// - FROM table {% if cond %}JOIN ... WHERE ...{% endif %}
    /// - {% if cond %}FROM table1 JOIN table2 WHERE ...{% endif %}
    /// - {% if is_incremental() %}AND expr{% endif %}
    pub(crate) fn parse_statement_fragment(
        &mut self,
        _from_item_index: usize,
    ) -> ParseResult<Option<crate::ast::StatementFragment>> {
        // Get start span - if we're at a Jinja delimiter, use current position
        let start_span = self
            .peek()
            .map(|t| t.span.start)
            .unwrap_or_else(|| self.current_span().start);
        let mut from_items: Option<Vec<crate::ast::FromItem>> = None;
        let mut joins = Vec::new();
        let mut where_clause = None;
        let mut having_clause = None;
        let mut end_span = start_span;
        let mut parsed_anything = false;

        // Check if fragment starts with AND/OR (condition continuation)
        // This handles patterns like: {% if is_incremental() %}AND col = value{% endif %}
        if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::And) | TokenKind::Keyword(Keyword::Or)
            ) {
                let op_kw_span = tok.span;
                self.advance(); // Consume AND/OR

                // Parse the condition expression
                match self.parse_condition_clause(
                    op_kw_span,
                    "Condition continuation requires expression",
                ) {
                    Ok(condition_clause) => {
                        end_span = condition_clause.span.end;
                        // Store as WHERE clause (semantically it's a condition fragment)
                        where_clause = Some(Box::new(condition_clause));
                        parsed_anything = true;
                    }
                    Err(_) => {
                        // Error recovery - parse as expression
                        let expr = self.parse_expr_with_recovery()?;
                        end_span = crate::parser::scripting::expr_span_end(&expr);
                        where_clause = Some(Box::new(crate::ast::ConditionClause {
                            node_id: self.id_gen.next(),
                            prefix_inline_fragments: Vec::new(),
                            suffix_inline_fragments: Vec::new(),
                            expr,
                            continuation_fragments: Vec::new(),
                            span: Span {
                                start: op_kw_span.start,
                                end: end_span,
                            },
                        }));
                        parsed_anything = true;
                    }
                }
            }
        }

        // Check if fragment starts with FROM keyword
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
                // Parse FROM clause using existing logic
                let select_span = Span {
                    start: start_span,
                    end: tok.span.end,
                };
                from_items = Some(self.parse_select_from_clause(select_span)?);
                if let Some(ref items) = from_items {
                    parsed_anything = true;
                    if let Some(last_item) = items.last() {
                        // Get span from FromItem by matching on kind
                        end_span = match &last_item.kind {
                            crate::ast::FromItemKind::TableRef(table_ref) => table_ref.span.end,
                            crate::ast::FromItemKind::JinjaBlock(jinja_block) => {
                                jinja_block.span.end
                            }
                            crate::ast::FromItemKind::JinjaTableName(jinja_name) => {
                                jinja_name.span.end
                            }
                        };
                    }
                }
            }
        }

        // Parse JOINs - check for JOIN keywords and parse them
        if let Some(tok) = self.peek() {
            // Check if this is a JOIN keyword
            let is_join = matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Join)
                    | TokenKind::Keyword(Keyword::Left)
                    | TokenKind::Keyword(Keyword::Right)
                    | TokenKind::Keyword(Keyword::Full)
                    | TokenKind::Keyword(Keyword::Inner)
                    | TokenKind::Keyword(Keyword::Cross)
                    | TokenKind::Keyword(Keyword::Natural)
                    | TokenKind::Keyword(Keyword::Asof)
            );

            if is_join {
                parsed_anything = true;
                // Use parse_join_chain on a dummy table to extract joins
                // Create minimal valid table ref
                let dummy_name = crate::ast::AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: tok.span,
                    // Synthetic placeholder used only to feed
                    // `parse_join_chain`; not a real qualified name.
                    parts: None,
                    identifier_arg: None,
                };
                let mut temp_table = crate::ast::AstTableRef {
                    node_id: self.id_gen.next(),
                    span: tok.span,
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

                // parse_join_chain will populate temp_table.joins
                self.parse_join_chain(&mut temp_table)?;
                joins.append(&mut temp_table.joins);

                if let Some(last_join) = joins.last() {
                    end_span = last_join.span.end;
                }
            }
        }

        // Parse WHERE clause
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
                let where_kw_span = tok.span;
                self.advance(); // Consume WHERE
                parsed_anything = true;

                // Parse as a ConditionClause to properly handle inline Jinja blocks
                match self.parse_condition_clause(where_kw_span, "WHERE clause requires condition")
                {
                    Ok(condition_clause) => {
                        end_span = condition_clause.span.end;
                        where_clause = Some(Box::new(condition_clause));
                    }
                    Err(_) => {
                        // Error recovery - use parse_expr_with_recovery as fallback
                        let expr = self.parse_expr_with_recovery()?;
                        end_span = crate::parser::scripting::expr_span_end(&expr);
                        // Wrap in minimal ConditionClause
                        where_clause = Some(Box::new(crate::ast::ConditionClause {
                            node_id: self.id_gen.next(),
                            prefix_inline_fragments: Vec::new(),
                            suffix_inline_fragments: Vec::new(),
                            expr,
                            continuation_fragments: Vec::new(),
                            span: Span {
                                start: where_kw_span.start,
                                end: end_span,
                            },
                        }));
                    }
                }
            }
        }

        // Parse GROUP BY clause
        let mut group_by: Option<AstGroupBy> = None;
        match self.parse_group_by_content() {
            Ok(Some(gb)) => {
                end_span = gb.span.end;
                group_by = Some(gb);
                parsed_anything = true;
            }
            Ok(None) => {
                // No GROUP BY
            }
            Err(_) => {
                // Error recovery - skip GROUP BY
            }
        }

        // Parse HAVING clause
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Having)) {
                let having_kw_span = tok.span;
                self.advance(); // Consume HAVING
                parsed_anything = true;

                // Parse as a ConditionClause to properly handle inline Jinja blocks
                match self
                    .parse_condition_clause(having_kw_span, "HAVING clause requires condition")
                {
                    Ok(condition_clause) => {
                        end_span = condition_clause.span.end;
                        having_clause = Some(Box::new(condition_clause));
                    }
                    Err(_) => {
                        // Error recovery - use parse_expr_with_recovery as fallback
                        let expr = self.parse_expr_with_recovery()?;
                        end_span = crate::parser::scripting::expr_span_end(&expr);
                        // Wrap in minimal ConditionClause
                        having_clause = Some(Box::new(crate::ast::ConditionClause {
                            node_id: self.id_gen.next(),
                            prefix_inline_fragments: Vec::new(),
                            suffix_inline_fragments: Vec::new(),
                            expr,
                            continuation_fragments: Vec::new(),
                            span: Span {
                                start: having_kw_span.start,
                                end: end_span,
                            },
                        }));
                    }
                }
            }
        }

        // Return Ok(None) if nothing was parsed - this prevents infinite loops
        // when the caller retries on an unrecognized token
        if !parsed_anything {
            return Ok(None);
        }

        Ok(Some(crate::ast::StatementFragment {
            node_id: self.id_gen.next(),
            from_items: from_items.map(|items| items.into_iter().map(Box::new).collect()),
            joins,
            where_clause,
            group_by,
            having_clause,
            span: Span {
                start: start_span,
                end: end_span,
            },
        }))
    }

    /// Parse a Jinja block wrapping StatementFragment (JOINs + WHERE + HAVING)
    /// Example: FROM table {% if is_incremental() %}LEFT JOIN ... WHERE ...{% endif %}
    pub(crate) fn parse_statement_fragment_jinja_block(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
        from_item_index: usize,
    ) -> Option<crate::ast::JinjaStatementFragment> {
        use crate::ast::{
            JinjaBlockKind, JinjaStatementFragmentElifBranch, JinjaStatementFragmentElseBranch,
        };

        // Consume opening token ({% if %} or {% for %})
        let open_brace_tok = self.advance()?;
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?;
        let keyword_id = self.last_token_id();
        let condition = self.parse_jinja_expr().ok().flatten();
        let close_brace_tok = self.advance()?;
        let close_brace_id = self.last_token_id();
        let opening_span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };
        let opening = self.alloc_jinja_delimiter(
            opening_span,
            opening_kind.clone(),
            condition,
            open_brace_id,
            keyword_id,
            close_brace_id,
        );

        // Determine closing kind
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => return None, // Only if/for supported
        };

        // Parse the THEN fragment (JOINs + WHERE + HAVING in the primary branch)
        let then_fragment = self
            .parse_statement_fragment(from_item_index)
            .ok()
            .flatten()?;

        // Parse optional elif branches (only for If blocks)
        let mut elif_branches = Vec::new();
        if opening_kind == JinjaBlockKind::If {
            while let Some(_tok) = self.peek() {
                if let Some(JinjaBlockKind::Elif) = self.peek_jinja_block_kind() {
                    let open_brace_tok = self.advance()?;
                    let open_brace_id = self.last_token_id();
                    let _keyword_tok = self.advance()?;
                    let keyword_id = self.last_token_id();
                    let condition = self.parse_jinja_expr().ok().flatten();
                    let close_brace_tok = self.advance()?;
                    let close_brace_id = self.last_token_id();
                    let elif_span = Span {
                        start: open_brace_tok.span.start,
                        end: close_brace_tok.span.end,
                    };
                    let elif_delimiter = self.alloc_jinja_delimiter(
                        elif_span,
                        JinjaBlockKind::Elif,
                        condition,
                        open_brace_id,
                        keyword_id,
                        close_brace_id,
                    );

                    let elif_fragment = self
                        .parse_statement_fragment(from_item_index)
                        .ok()
                        .flatten()?;

                    elif_branches.push(JinjaStatementFragmentElifBranch {
                        node_id: self.id_gen.next(),
                        delimiter: elif_delimiter,
                        fragment: elif_fragment,
                    });
                } else {
                    break;
                }
            }
        }

        // Parse optional else branch
        let mut else_branch = None;
        if let Some(_tok) = self.peek() {
            if let Some(JinjaBlockKind::Else) = self.peek_jinja_block_kind() {
                let open_brace_tok = self.advance()?;
                let open_brace_id = self.last_token_id();
                let _keyword_tok = self.advance()?;
                let keyword_id = self.last_token_id();
                let close_brace_tok = self.advance()?;
                let close_brace_id = self.last_token_id();
                let else_span = Span {
                    start: open_brace_tok.span.start,
                    end: close_brace_tok.span.end,
                };
                let else_delimiter = self.alloc_jinja_delimiter(
                    else_span,
                    JinjaBlockKind::Else,
                    None,
                    open_brace_id,
                    keyword_id,
                    close_brace_id,
                );

                let else_fragment = self
                    .parse_statement_fragment(from_item_index)
                    .ok()
                    .flatten()?;

                else_branch = Some(JinjaStatementFragmentElseBranch {
                    node_id: self.id_gen.next(),
                    delimiter: else_delimiter,
                    fragment: else_fragment,
                });
            }
        }

        // Consume closing delimiter ({% endif %} or {% endfor %})
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == closing_kind {
                let open_brace_tok = self.advance()?;
                let open_brace_id = self.last_token_id();
                let _keyword_tok = self.advance()?;
                let keyword_id = self.last_token_id();
                let close_brace_tok = self.advance()?;
                let close_brace_id = self.last_token_id();
                let closing_span = Span {
                    start: open_brace_tok.span.start,
                    end: close_brace_tok.span.end,
                };
                let closing = self.alloc_jinja_delimiter(
                    closing_span,
                    closing_kind,
                    None,
                    open_brace_id,
                    keyword_id,
                    close_brace_id,
                );

                let span = Span {
                    start: opening.span.start,
                    end: closing.span.end,
                };

                return Some(crate::ast::JinjaStatementFragment {
                    node_id: self.id_gen.next(),
                    opening,
                    then_fragment,
                    elif_branches,
                    else_branch,
                    closing,
                    from_item_index,
                    span,
                });
            }
        }

        None
    }

    pub(crate) fn try_parse_statement_fragment_jinja_block(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
        from_item_index: usize,
    ) -> Option<crate::ast::JinjaStatementFragment> {
        let saved_idx = self.idx;
        let result = self.parse_statement_fragment_jinja_block(opening_kind, from_item_index);
        if result.is_none() {
            self.idx = saved_idx;
        }
        result
    }

    /// Parse GROUP BY clause
    /// Handles both direct GROUP BY and Jinja-wrapped GROUP BY: {% if cond %}GROUP BY...{% endif %}
    /// Also handles Jinja expression that generates entire GROUP BY: {{ dbt_utils.group_by(n=13) }}
    pub(crate) fn parse_select_group_by(&mut self) -> ParseResult<Option<AstGroupBy>> {
        // Check for direct GROUP keyword
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Group)) {
                return self.parse_group_by_content();
            }

            // Check for Jinja block containing GROUP BY
            if matches!(tok.kind, TokenKind::JinjaStmtOpen)
                && self.jinja_block_contains_keyword(Keyword::Group)
            {
                return self.parse_jinja_wrapped_group_by();
            }

            // Check for Jinja expression that generates GROUP BY clause
            // e.g., {{ dbt_utils.group_by(n=13) }} which expands to GROUP BY 1, 2, ..., 13
            if matches!(tok.kind, TokenKind::JinjaExprOpen) {
                // Look ahead to see if this is followed by ORDER BY, QUALIFY, LIMIT, or end of statement
                // If so, this Jinja expression is generating the GROUP BY clause
                if self.jinja_expr_is_group_by_clause() {
                    return self.parse_jinja_expr_as_group_by();
                }
            }
        }

        Ok(None)
    }

    /// Check if a Jinja expression is likely generating a GROUP BY clause
    /// This happens when the expression appears after WHERE (or FROM) and before ORDER BY/QUALIFY/LIMIT
    fn jinja_expr_is_group_by_clause(&self) -> bool {
        // Look ahead past the Jinja expression to see what follows
        let mut idx = self.idx;
        let mut depth = 0;

        // Skip past the Jinja expression {{ ... }}
        while let Some(tok) = self.tokens.get(idx) {
            match &tok.kind {
                TokenKind::JinjaExprOpen => depth += 1,
                TokenKind::JinjaExprClose => {
                    depth -= 1;
                    if depth == 0 {
                        idx += 1;
                        break;
                    }
                }
                _ => {}
            }
            idx += 1;
        }

        // Skip comments/trivia tokens
        while let Some(tok) = self.tokens.get(idx) {
            match &tok.kind {
                TokenKind::LineComment | TokenKind::BlockComment | TokenKind::JinjaComment => {
                    idx += 1;
                }
                _ => break,
            }
        }

        // Check what comes after the Jinja expression
        if let Some(tok) = self.tokens.get(idx) {
            // If followed by ORDER BY, QUALIFY, LIMIT, HAVING, or end of query,
            // this is likely a GROUP BY generating expression
            matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Order)
                    | TokenKind::Keyword(Keyword::Qualify)
                    | TokenKind::Keyword(Keyword::Limit)
                    | TokenKind::Keyword(Keyword::Having)
                    | TokenKind::Keyword(Keyword::Union)
                    | TokenKind::Keyword(Keyword::Intersect)
                    | TokenKind::Keyword(Keyword::Except)
                    | TokenKind::Keyword(Keyword::Minus)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    | TokenKind::Eof
            )
        } else {
            // End of tokens - likely end of query
            true
        }
    }

    /// Parse a Jinja expression as a GROUP BY clause placeholder
    fn parse_jinja_expr_as_group_by(&mut self) -> ParseResult<Option<AstGroupBy>> {
        let start_tok = self.peek().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(self.current_span(), vec!["{{".to_string()])
        })?;
        let start_span = start_tok.span;

        self.advance(); // consume {{

        // Consume tokens until }}
        let mut end_span = start_span;
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::JinjaExprClose) {
                end_span = tok.span;
                self.advance(); // consume }}
                break;
            }
            end_span = tok.span;
            self.advance();
        }

        let full_span = Span {
            start: start_span.start,
            end: end_span.end,
        };

        // Create a GROUP BY with JinjaPlaceholder variant
        Ok(Some(AstGroupBy {
            node_id: self.id_gen.next(),
            variant: crate::ast::AstGroupByVariant::JinjaPlaceholder(full_span),
            syntax_id: None, // No syntax node for Jinja-generated GROUP BY
            with_modifier: None,
            with_modifier_span: None,
            prefix_inline_fragments: vec![],
            suffix_inline_fragments: vec![],
            span: full_span,
        }))
    }

    /// Check if a Jinja control block contains a specific keyword
    pub(crate) fn jinja_block_contains_keyword(&self, keyword: Keyword) -> bool {
        // Look ahead past the opening {% if/for %}
        let mut idx = self.idx + 1;
        while let Some(tok) = self.tokens.get(idx) {
            match &tok.kind {
                TokenKind::Keyword(kw) if *kw == keyword => return true,
                // Stop at next statement
                TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Insert)
                | TokenKind::Keyword(Keyword::Update)
                | TokenKind::Keyword(Keyword::Delete) => return false,
                _ => {}
            }
            idx += 1;
        }
        false
    }

    /// Parse Jinja-wrapped GROUP BY: {% if cond %}GROUP BY col{% endif %}
    /// We preserve the Jinja delimiters as inline fragments so formatting can emit them.
    fn parse_jinja_wrapped_group_by(&mut self) -> ParseResult<Option<AstGroupBy>> {
        use crate::ast::JinjaBlockKind;

        // Opening delimiter: {% if/for ... %}
        let opening_kind = self.peek_jinja_block_kind().unwrap_or(JinjaBlockKind::If);
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => JinjaBlockKind::EndIf,
        };

        // Parse the opening delimiter to obtain a fully populated JinjaBlockDelimiter
        let open_brace_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(self.current_span(), vec!["{%".to_string()])
        })?;
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(
                self.current_span(),
                vec!["if/for".to_string()],
            )
        })?;
        let keyword_id = self.last_token_id();
        let condition = match opening_kind {
            JinjaBlockKind::If => self.parse_jinja_expr()?,
            JinjaBlockKind::For => {
                // For FOR loops, consume all tokens until %} without parsing
                // This preserves comma-separated variables, 'in' keyword, and iterable expression
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
        if !matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::JinjaStmtClose)
        ) {
            return Ok(None);
        }
        let close_brace_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(self.current_span(), vec!["%}".to_string()])
        })?;
        let close_brace_id = self.last_token_id();
        let opening_span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };
        let opening = self.alloc_jinja_delimiter(
            opening_span,
            opening_kind.clone(),
            condition,
            open_brace_id,
            keyword_id,
            close_brace_id,
        );

        // Parse the GROUP BY content inside the block
        let mut group_by = self.parse_group_by_content()?;

        // Parse the closing delimiter: {% endif/endfor %}
        let close_open_brace_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(self.current_span(), vec!["{%".to_string()])
        })?;
        let close_open_brace_id = self.last_token_id();
        let _close_keyword_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(
                self.current_span(),
                vec!["endif/endfor".to_string()],
            )
        })?;
        let close_keyword_id = self.last_token_id();
        if !matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::JinjaStmtClose)
        ) {
            return Ok(group_by);
        }
        let close_close_brace_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(self.current_span(), vec!["%}".to_string()])
        })?;
        let close_close_brace_id = self.last_token_id();
        let closing_span = Span {
            start: close_open_brace_tok.span.start,
            end: close_close_brace_tok.span.end,
        };
        let closing = self.alloc_jinja_delimiter(
            closing_span,
            closing_kind.clone(),
            None,
            close_open_brace_id,
            close_keyword_id,
            close_close_brace_id,
        );

        // Build inline fragments for the opening and closing delimiters so formatting can emit them.
        use crate::ast::{JinjaInlineBlock, JinjaInlineFragment, JinjaInlineFragmentKind};

        let opening_fragment = JinjaInlineFragment {
            node_id: self.id_gen.next(),
            span: opening.span,
            syntax_id: None,
            kind: JinjaInlineFragmentKind::InlineBlock(Box::new(JinjaInlineBlock {
                opening: opening.clone(),
                content: None,
                elif_branches: Vec::new(),
                else_branch: None,
                closing: None,
            })),
        };

        let closing_fragment = JinjaInlineFragment {
            node_id: self.id_gen.next(),
            span: closing.span,
            syntax_id: None,
            kind: JinjaInlineFragmentKind::InlineBlock(Box::new(JinjaInlineBlock {
                opening: closing.clone(),
                content: None,
                elif_branches: Vec::new(),
                else_branch: None,
                closing: None,
            })),
        };

        // Attach the fragments so formatting can emit the delimiters around the clause.
        if let Some(ref mut gb) = group_by {
            gb.span.start = gb.span.start.min(opening.span.start);
            gb.span.end = gb.span.end.max(closing.span.end);
            gb.prefix_inline_fragments.push(opening_fragment);
            gb.suffix_inline_fragments.push(closing_fragment);
        }

        Ok(group_by)
    }

    /// Skip a full Jinja delimiter ({% keyword ... %})
    fn skip_jinja_delimiter(&mut self) {
        while let Some(tok) = self.peek() {
            let is_close = matches!(tok.kind, TokenKind::JinjaStmtClose);
            self.advance();
            if is_close {
                break;
            }
        }
    }

    /// Parse the actual GROUP BY content (after GROUP keyword is confirmed)
    fn parse_group_by_content(&mut self) -> ParseResult<Option<AstGroupBy>> {
        use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

        if let Some(tok) = self.peek() {
            if !matches!(tok.kind, TokenKind::Keyword(Keyword::Group)) {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        let group_tok = self
            .advance()
            .expect_invariant("GROUP keyword consumed after peek match"); // Consume GROUP
        let group_keyword_span = group_tok.span;
        let group_keyword_token_id = self.last_token_id();
        let group_start = group_tok.span;

        let by_tok = self
            .advance()
            .ok_or_eof(group_start, vec!["BY".to_string()])?;
        if !matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
            return Err(ParseError::new(
                by_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected BY after GROUP, found {}",
                        Self::token_description(by_tok, self.source)
                    ),
                },
            ));
        }
        let by_keyword_span = by_tok.span;
        let by_keyword_token_id = self.last_token_id();

        // Check if current token is a Jinja control block (if/for/etc) - if so, skip inline fragment collection
        // because the Jinja block is meant to wrap GROUP BY items, not be consumed as a fragment
        let prefix_inline_fragments = if let Some(kind) = self.peek_jinja_block_kind() {
            if matches!(
                kind,
                crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For
            ) {
                Vec::new() // Skip - let the grouping-element loop handle the Jinja block
            } else {
                let InlineFragmentCollection { fragments } =
                    self.collect_leading_inline_fragments();
                fragments
            }
        } else {
            let InlineFragmentCollection { fragments } = self.collect_leading_inline_fragments();
            fragments
        };

        let suffix_inline_fragments: Vec<crate::ast::JinjaInlineFragment>;
        let mut span_end: u32;

        // Create syntax node for GROUP BY keywords
        let syntax_id = Some(
            self.syntax_arena
                .alloc_group_by(crate::syntax::SyntaxGroupBy {
                    group_keyword: group_keyword_token_id,
                    by_keyword: by_keyword_token_id,
                    span: Span {
                        start: group_keyword_span.start,
                        end: by_keyword_span.end,
                    },
                }),
        );

        // Check for GROUP BY ALL
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::All)) {
                let all_tok = self
                    .advance()
                    .expect_invariant("ALL keyword consumed after peek match"); // Consume ALL
                span_end = all_tok.span.end;
                let InlineFragmentCollection {
                    fragments: trailing,
                } = self.collect_trailing_inline_fragments();
                suffix_inline_fragments = trailing;
                if let Some(last) = suffix_inline_fragments.last() {
                    span_end = span_end.max(last.span.end);
                }

                return Ok(Some(AstGroupBy {
                    node_id: self.id_gen.next(),
                    variant: crate::ast::AstGroupByVariant::All,
                    syntax_id,
                    with_modifier: None,
                    with_modifier_span: None,
                    prefix_inline_fragments,
                    suffix_inline_fragments,
                    span: Span {
                        start: group_start.start,
                        end: span_end,
                    },
                }));
            }
        }

        // Parse the grouping-element list. Standard SQL allows a
        // comma-separated mix of ordinary expressions and grouping operators
        // (CUBE / ROLLUP / GROUPING SETS), e.g. `GROUP BY a, ROLLUP(b, c)`.
        // The clause is `Standard` iff it contains no grouping operator;
        // otherwise `Elements` (this includes a lone `GROUP BY CUBE(a)`).
        let mut elements: Vec<crate::ast::AstGroupElement> = Vec::new();
        let mut has_grouping_op = false;

        while let Some(expr_tok) = self.peek() {
            // Stop at a clause keyword that ends GROUP BY.
            if matches!(
                expr_tok.kind,
                TokenKind::Keyword(Keyword::Order)
                    | TokenKind::Keyword(Keyword::Where)
                    | TokenKind::Keyword(Keyword::Qualify)
                    | TokenKind::Keyword(Keyword::Having)
                    | TokenKind::Keyword(Keyword::Limit)
                    | TokenKind::Keyword(Keyword::Union)
                    | TokenKind::Keyword(Keyword::Intersect)
                    | TokenKind::Keyword(Keyword::Except)
                    | TokenKind::Keyword(Keyword::Minus)
                    | TokenKind::Keyword(Keyword::Connect)
                    | TokenKind::Keyword(Keyword::Start)
                    | TokenKind::Keyword(Keyword::On)
                    | TokenKind::Keyword(Keyword::With)
            ) {
                break;
            }

            // Stop at a semicolon or closing paren (subqueries / CTEs).
            if matches!(
                expr_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                break;
            }

            // Stop at a dialect-specific clause boundary (e.g. WINDOW in PostgreSQL).
            if self.can_be_identifier_token(expr_tok)
                && self
                    .dialect
                    .is_clause_boundary_keyword(expr_tok.lexeme(self.source))
            {
                break;
            }

            // Stop at a Jinja closing delimiter belonging to an outer wrapper.
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(
                    kind,
                    crate::ast::JinjaBlockKind::EndIf
                        | crate::ast::JinjaBlockKind::EndFor
                        | crate::ast::JinjaBlockKind::Else
                        | crate::ast::JinjaBlockKind::Elif
                ) {
                    break;
                }
            }

            let element = self.parse_group_element()?;
            if !matches!(element.kind, crate::ast::AstGroupElementKind::Expr(_)) {
                has_grouping_op = true;
            }
            elements.push(element);

            // Consume an optional separating comma; stop otherwise.
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance();
                    continue;
                }
            }
            break;
        }

        if elements.is_empty() {
            return Ok(None);
        }

        span_end = elements
            .last()
            .map(|e| e.span.end)
            .unwrap_or(group_start.end);

        // MySQL `WITH ROLLUP` / legacy T-SQL `WITH CUBE` suffix. Only consume
        // WITH when the modifier word follows — a bare WITH belongs to the
        // next statement's CTE.
        let mut with_modifier = None;
        let mut with_modifier_span = None;
        if let Some(with_tok) = self.peek() {
            if matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                let with_start = with_tok.span.start;
                let modifier = self.peek_ahead(1).and_then(|t| {
                    let lex = t.lexeme(self.source);
                    if lex.eq_ignore_ascii_case("ROLLUP") {
                        Some(crate::ast::AstGroupByWithModifier::Rollup)
                    } else if lex.eq_ignore_ascii_case("CUBE") {
                        Some(crate::ast::AstGroupByWithModifier::Cube)
                    } else {
                        None
                    }
                });
                if let Some(m) = modifier {
                    self.advance(); // WITH
                    let m_tok = self
                        .advance()
                        .expect_invariant("modifier word consumed after peek_ahead match");
                    with_modifier = Some(m);
                    with_modifier_span = Some(Span {
                        start: with_start,
                        end: m_tok.span.end,
                    });
                    span_end = m_tok.span.end;
                }
            }
        }
        let InlineFragmentCollection {
            fragments: trailing,
        } = self.collect_trailing_inline_fragments();
        suffix_inline_fragments = trailing;
        if let Some(last) = suffix_inline_fragments.last() {
            span_end = span_end.max(last.span.end);
        }

        let variant = if has_grouping_op {
            crate::ast::AstGroupByVariant::Elements(elements)
        } else {
            // No grouping operator: collapse to the standard form.
            let items = elements
                .into_iter()
                .filter_map(|e| match e.kind {
                    crate::ast::AstGroupElementKind::Expr(item) => Some(item),
                    crate::ast::AstGroupElementKind::Cube(_)
                    | crate::ast::AstGroupElementKind::Rollup(_)
                    | crate::ast::AstGroupElementKind::GroupingSets(_) => None,
                })
                .collect();
            crate::ast::AstGroupByVariant::Standard(items)
        };

        Ok(Some(AstGroupBy {
            node_id: self.id_gen.next(),
            variant,
            syntax_id,
            with_modifier,
            with_modifier_span,
            prefix_inline_fragments,
            suffix_inline_fragments,
            span: Span {
                start: group_start.start,
                end: span_end,
            },
        }))
    }

    /// Parse one element of a GROUP BY grouping-element list: an ordinary
    /// expression, or a CUBE / ROLLUP / GROUPING SETS operator.
    fn parse_group_element(&mut self) -> ParseResult<crate::ast::AstGroupElement> {
        use crate::ast::{AstGroupElement, AstGroupElementKind};
        use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

        let start = self.current_span().start;

        // CUBE(...) / ROLLUP(...)
        let cube_or_rollup = self.peek().and_then(|tok| {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Cube)) {
                Some(true)
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Rollup)) {
                Some(false)
            } else {
                None
            }
        });
        if let Some(is_cube) = cube_or_rollup {
            self.advance(); // Consume CUBE / ROLLUP
            let items = self.parse_group_by_items_in_parens()?;
            let end_paren = self.idx.saturating_sub(1);
            let end = self
                .tokens
                .get(end_paren)
                .map(|t| t.span.end)
                .unwrap_or(start);
            let kind = if is_cube {
                AstGroupElementKind::Cube(items)
            } else {
                AstGroupElementKind::Rollup(items)
            };
            return Ok(AstGroupElement {
                node_id: self.id_gen.next(),
                kind,
                span: Span { start, end },
            });
        }

        // GROUPING SETS(...)
        let is_grouping_sets = self
            .peek()
            .map(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::Grouping)))
            .unwrap_or(false);
        if is_grouping_sets {
            self.advance(); // Consume GROUPING
            let sets_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["SETS".to_string()])?;
            if !matches!(sets_tok.kind, TokenKind::Keyword(Keyword::Sets)) {
                return Err(ParseError::new(
                    sets_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Expected SETS after GROUPING, found {}",
                            Self::token_description(sets_tok, self.source)
                        ),
                    },
                ));
            }

            // Parse GROUPING SETS ( (col1, col2), (col3), ... )
            let lparen_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
            if !matches!(
                lparen_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::new(
                    lparen_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Expected '(' after GROUPING SETS, found {}",
                            Self::token_description(lparen_tok, self.source)
                        ),
                    },
                ));
            }

            let mut sets = Vec::new();
            loop {
                // Each set is either a parenthesized group or a single item
                if let Some(tok) = self.peek() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        self.advance(); // Consume opening paren
                        let items = self.parse_group_by_items_until_rparen()?;
                        let rparen_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        if !matches!(
                            rparen_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            return Err(ParseError::new(
                                rparen_tok.span,
                                ParseErrorKind::InvalidSyntax {
                                    message: format!(
                                        "Expected ')' after grouping set items, found {}",
                                        Self::token_description(rparen_tok, self.source)
                                    ),
                                },
                            ));
                        }
                        sets.push(items);
                    } else {
                        // Single item without parentheses
                        let item = self.parse_single_group_item()?;
                        sets.push(vec![item]);
                    }
                } else {
                    return Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::UnexpectedEof {
                            expected: vec!["grouping set".to_string()],
                        },
                    ));
                }

                // Check for comma or closing paren
                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        self.advance();
                        continue;
                    } else if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        self.advance(); // Consume closing paren
                        break;
                    }
                }
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidSyntax {
                        message: "Expected ',' or ')' after grouping set".to_string(),
                    },
                ));
            }

            let end_paren = self.idx.saturating_sub(1);
            let end = self
                .tokens
                .get(end_paren)
                .map(|t| t.span.end)
                .unwrap_or(start);
            return Ok(AstGroupElement {
                node_id: self.id_gen.next(),
                kind: AstGroupElementKind::GroupingSets(sets),
                span: Span { start, end },
            });
        }

        // Ordinary grouping expression.
        let item = self.parse_single_group_item()?;
        let span = item.expr.span();
        Ok(AstGroupElement {
            node_id: self.id_gen.next(),
            kind: AstGroupElementKind::Expr(item),
            span,
        })
    }

    /// Parse a single GROUP BY item (column, position ref, or expression)
    fn parse_single_group_item(&mut self) -> ParseResult<AstGroupItem> {
        use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

        let expr_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["expression".to_string()])?;

        let expr = match &expr_tok.kind {
            // $1, $2, etc. - position references with dollar sign
            TokenKind::Literal(crate::lexer::LiteralKind::Position) => {
                let pos_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["position literal".to_string()])?;
                let full_span = pos_tok.span;
                let dollar_span = Span {
                    start: full_span.start,
                    end: full_span.start + 1,
                };
                let index_span = Span {
                    start: full_span.start + 1,
                    end: full_span.end,
                };
                AstExpr::PositionRef {
                    node_id: self.id_gen.next(),
                    qualifier: None,
                    dot_span: None,
                    dollar_span,
                    index_span,
                }
            }
            // Simple numbers like 1, 2 can also be positional references in GROUP BY
            TokenKind::Literal(crate::lexer::LiteralKind::Number) => {
                let num_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["number literal".to_string()])?;
                // Parse the number as a positional reference in GROUP BY context
                // Create a synthetic position reference using the number's span
                let full_span = num_tok.span;
                AstExpr::PositionRef {
                    node_id: self.id_gen.next(),
                    qualifier: None,
                    dot_span: None,
                    dollar_span: Span {
                        start: full_span.start,
                        end: full_span.start,  // Empty span for implicit $
                    },
                    index_span: full_span,
                }
            }
            // Handle expressions: CASE, parens, identifiers, and keywords that can be identifiers
            // Many keywords like ID, TYPE, KEY, etc. are valid column names
            kind if matches!(kind,
                TokenKind::JinjaComment
                | TokenKind::JinjaStmtOpen
                | TokenKind::Keyword(Keyword::Case)
                | TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) || self.can_be_identifier_token(expr_tok) => {
                // Parse as full expression to handle function calls, qualified names, Jinja, etc.
                self.parse_expr()?
            }
            _ => {
                return Err(ParseError::new(
                    expr_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!("Expected column name, position reference, or expression in GROUP BY, found {}", Self::token_description(expr_tok, self.source)),
                    },
                ))
            }
        };

        Ok(AstGroupItem {
            node_id: self.id_gen.next(),
            expr,
        })
    }

    /// Parse GROUP BY items inside parentheses: CUBE(...) or ROLLUP(...)
    fn parse_group_by_items_in_parens(&mut self) -> ParseResult<Vec<AstGroupItem>> {
        use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected '(' after CUBE/ROLLUP, found {}",
                        Self::token_description(lparen_tok, self.source)
                    ),
                },
            ));
        }

        let items = self.parse_group_by_items_until_rparen()?;

        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(
            rparen_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected ')' after CUBE/ROLLUP items, found {}",
                        Self::token_description(rparen_tok, self.source)
                    ),
                },
            ));
        }

        Ok(items)
    }

    /// Parse GROUP BY items until we hit a closing paren
    fn parse_group_by_items_until_rparen(&mut self) -> ParseResult<Vec<AstGroupItem>> {
        let mut items = Vec::new();

        loop {
            if let Some(tok) = self.peek() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }

            let item = self.parse_single_group_item()?;
            items.push(item);

            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance();
                    continue;
                } else if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }
            break;
        }

        Ok(items)
    }

    /// Parse CONNECT BY clause (hierarchical queries)
    pub(crate) fn parse_connect_by(&mut self) -> ParseResult<Option<AstConnectBy>> {
        // Parse optional START WITH clause
        let start_with_span;
        let start_with_condition;

        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Start)) {
                let start_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["START".to_string()])?;
                start_with_span = Some(start_tok.span);

                // Consume WITH
                let with_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                    return Err(ParseError::unexpected_token(
                        with_tok.span,
                        vec!["WITH".to_string()],
                        Parser::token_description(with_tok, self.source),
                    ));
                }

                // Parse the START WITH condition
                start_with_condition = Some(self.parse_expr()?);
            } else {
                start_with_span = None;
                start_with_condition = None;
            }
        } else {
            start_with_span = None;
            start_with_condition = None;
        }

        // Parse CONNECT BY clause
        // If we parsed START WITH, then CONNECT BY is required.
        // Otherwise, if no CONNECT keyword is found, return Ok(None) without error.
        if let Some(tok) = self.peek() {
            if !matches!(tok.kind, TokenKind::Keyword(Keyword::Connect)) {
                if start_with_span.is_some() {
                    // START WITH was present, so CONNECT BY is required
                    return Err(ParseError::unexpected_token(
                        tok.span,
                        vec!["CONNECT".to_string()],
                        Parser::token_description(tok, self.source),
                    ));
                }
                // No CONNECT keyword and no START WITH = no hierarchical query
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        let connect_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CONNECT".to_string()])?;
        let connect_by_span = connect_tok.span;

        // Consume BY
        let by_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["BY".to_string()])?;
        if !matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
            return Err(ParseError::unexpected_token(
                by_tok.span,
                vec!["BY".to_string()],
                Parser::token_description(by_tok, self.source),
            ));
        }

        // Parse CONNECT BY conditions (can include PRIOR)
        let mut conditions = Vec::new();
        let expr = self.parse_expr()?;
        conditions.push(expr);

        // Parse optional ORDER SIBLINGS BY clause
        let order_siblings_by = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Order)) {
                // Look ahead to check if it's ORDER SIBLINGS BY
                let order_idx = self.idx;
                self.advance(); // consume ORDER

                if let Some(siblings_tok) = self.peek() {
                    if self.can_be_identifier_token(siblings_tok)
                        && siblings_tok
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("SIBLINGS")
                    {
                        self.advance(); // consume SIBLINGS

                        if let Some(by_tok) = self.peek() {
                            if matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                                self.advance(); // consume BY

                                // Parse ORDER BY items using existing helper
                                let mut items = Vec::new();
                                while let Some(item) = self.parse_order_by_item()? {
                                    items.push(Box::new(item));

                                    // Check for comma to continue
                                    if let Some(tok) = self.peek() {
                                        if matches!(
                                            tok.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::Comma
                                            )
                                        ) {
                                            self.advance();
                                            continue;
                                        }
                                    }
                                    break;
                                }

                                if !items.is_empty() {
                                    // Calculate span for ORDER BY in PIVOT
                                    let order_start = self
                                        .tokens
                                        .get(self.idx.saturating_sub(items.len() * 2 + 2))
                                        .map(|t| t.span.start)
                                        .unwrap_or(0);
                                    let order_end = items
                                        .last()
                                        .map(|item| item.expr.span().end)
                                        .unwrap_or(order_start);
                                    let span = Span {
                                        start: order_start,
                                        end: order_end,
                                    };
                                    Some(AstOrderBy {
                                        node_id: self.id_gen.next(),
                                        items,
                                        prefix_inline_fragments: Vec::new(),
                                        suffix_inline_fragments: Vec::new(),
                                        span,
                                    })
                                } else {
                                    // No items parsed, restore position
                                    self.idx = order_idx;
                                    None
                                }
                            } else {
                                // Not ORDER SIBLINGS BY, restore position
                                self.idx = order_idx;
                                None
                            }
                        } else {
                            // Not ORDER SIBLINGS BY, restore position
                            self.idx = order_idx;
                            None
                        }
                    } else {
                        // Not ORDER SIBLINGS BY, restore position
                        self.idx = order_idx;
                        None
                    }
                } else {
                    // Not ORDER SIBLINGS BY, restore position
                    self.idx = order_idx;
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Calculate span
        let span_start = start_with_span
            .map(|s| s.start)
            .unwrap_or(connect_by_span.start);
        let span_end = if let Some(order_by) = &order_siblings_by {
            if let Some(last_item) = order_by.items.last() {
                expr_span_end(&last_item.expr)
            } else if let Some(last_cond) = conditions.last() {
                expr_span_end(last_cond)
            } else {
                connect_by_span.end
            }
        } else if let Some(last_cond) = conditions.last() {
            expr_span_end(last_cond)
        } else {
            connect_by_span.end
        };

        Ok(Some(AstConnectBy {
            node_id: self.id_gen.next(),
            start_with_span,
            start_with_condition,
            connect_by_span,
            conditions,
            order_siblings_by,
            span: Span {
                start: span_start,
                end: span_end,
            },
        }))
    }

    /// Parse MATCH_RECOGNIZE clause for pattern matching
    /// Syntax: MATCH_RECOGNIZE (
    ///     [ PARTITION BY ... ]
    ///     [ ORDER BY ... ]
    ///     [ MEASURES ... ]
    ///     [ ONE ROW PER MATCH | ALL ROWS PER MATCH ... ]
    ///     [ AFTER MATCH SKIP ... ]
    ///     PATTERN ( ... )
    ///     DEFINE ...
    /// )
    pub(crate) fn parse_match_recognize(&mut self) -> ParseResult<Option<AstMatchRecognize>> {
        // Check for MATCH_RECOGNIZE keyword
        let match_recognize_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::MatchRecognize)) => tok,
            _ => return Ok(None),
        };
        let match_recognize_span = match_recognize_tok.span;
        self.advance(); // consume MATCH_RECOGNIZE
        let match_recognize_keyword_id = self.last_token_id();

        // Expect opening parenthesis
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
        let mr_lparen_id = self.last_token_id();

        let start_span = match_recognize_span.start;

        // Parse optional PARTITION BY
        let mut partition_keyword_id = None;
        let mut partition_by_keyword_id = None;
        let mut partition_by_commas = [crate::cst::TokenId(0); 16];
        let mut partition_by_comma_count = 0u8;
        let partition_by = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Partition)) {
                self.advance(); // consume PARTITION
                partition_keyword_id = Some(self.last_token_id());
                let by_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["BY".to_string()])?;
                partition_by_keyword_id = Some(self.last_token_id());
                if !matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                    return Err(ParseError::unexpected_token(
                        by_tok.span,
                        vec!["BY".to_string()],
                        Parser::token_description(by_tok, self.source),
                    ));
                }

                let mut exprs = Vec::new();
                loop {
                    let expr = self.parse_expr()?;
                    exprs.push(expr);

                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            if (partition_by_comma_count as usize) < partition_by_commas.len() {
                                partition_by_commas[partition_by_comma_count as usize] =
                                    self.last_token_id();
                                partition_by_comma_count += 1;
                            }
                            continue;
                        }
                    }
                    break;
                }
                Some(exprs)
            } else {
                None
            }
        } else {
            None
        };

        // Parse optional ORDER BY
        let mut order_keyword_id = None;
        let mut order_by_keyword_id = None;
        let mut order_by_commas = [crate::cst::TokenId(0); 16];
        let mut order_by_comma_count = 0u8;
        let order_by = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Order)) {
                order_keyword_id = Some(self.current_token_id());
                self.advance(); // consume ORDER

                // Capture BY keyword
                if let Some(by_tok) = self.peek() {
                    if matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                        self.advance();
                        order_by_keyword_id = Some(self.last_token_id());
                    }
                }

                // Parse order items manually to capture commas
                let mut items = Vec::new();
                while let Some(tok) = self.peek() {
                    // Check stop conditions
                    if matches!(
                        tok.kind,
                        TokenKind::Keyword(Keyword::Measures)
                            | TokenKind::Keyword(Keyword::One)
                            | TokenKind::Keyword(Keyword::All)
                            | TokenKind::Keyword(Keyword::After)
                            | TokenKind::Keyword(Keyword::Pattern)
                            | TokenKind::Keyword(Keyword::Define)
                            | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        break;
                    }

                    // Parse order item
                    if let Some(item) = self.parse_order_by_item()? {
                        items.push(Box::new(item));

                        // Capture comma
                        if let Some(comma_tok) = self.peek() {
                            if matches!(
                                comma_tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                self.advance();
                                if (order_by_comma_count as usize) < order_by_commas.len() {
                                    order_by_commas[order_by_comma_count as usize] =
                                        self.last_token_id();
                                    order_by_comma_count += 1;
                                }
                                continue;
                            }
                        }
                        break;
                    } else {
                        break;
                    }
                }

                if items.is_empty() {
                    None
                } else {
                    Some(AstOrderBy {
                        node_id: self.id_gen.next(),
                        items,
                        prefix_inline_fragments: Vec::new(),
                        suffix_inline_fragments: Vec::new(),
                        span: Span {
                            start: match_recognize_span.start,
                            end: self.current_span().end,
                        },
                    })
                }
            } else {
                None
            }
        } else {
            None
        };

        // Parse optional MEASURES
        let mut measures_keyword_id = None;
        let mut measures_commas = [crate::cst::TokenId(0); 16];
        let mut measures_comma_count = 0u8;
        let mut measures = Vec::new();
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Measures)) {
                self.advance(); // consume MEASURES
                measures_keyword_id = Some(self.last_token_id());

                loop {
                    let measure_start = self.idx;

                    // Check for optional RUNNING or FINAL semantic modifier
                    let (semantic_modifier, semantic_modifier_token_id) =
                        if let Some(semantic_tok) = self.peek() {
                            match semantic_tok.kind {
                                TokenKind::Keyword(Keyword::Running) => {
                                    self.advance(); // consume RUNNING
                                    (
                                        Some(crate::ast::AstMeasureSemanticModifier::Running),
                                        Some(self.last_token_id()),
                                    )
                                }
                                TokenKind::Keyword(Keyword::Final) => {
                                    self.advance(); // consume FINAL
                                    (
                                        Some(crate::ast::AstMeasureSemanticModifier::Final),
                                        Some(self.last_token_id()),
                                    )
                                }
                                _ => (None, None),
                            }
                        } else {
                            (None, None)
                        };

                    let expr = self.parse_expr()?;

                    // Capture AS keyword token
                    let mut as_keyword_id = None;
                    if let Some(as_tok) = self.peek() {
                        if matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                            self.advance();
                            as_keyword_id = Some(self.last_token_id());
                        }
                    }

                    // Required alias
                    let alias_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                    if !self.can_be_identifier_token(alias_tok) {
                        return Err(ParseError::unexpected_token(
                            alias_tok.span,
                            vec!["identifier".to_string()],
                            Parser::token_description(alias_tok, self.source),
                        ));
                    }

                    let measure_end = alias_tok.span.end;
                    let measure_span = Span {
                        start: if measure_start < self.tokens.len() {
                            self.tokens[measure_start].span.start
                        } else {
                            alias_tok.span.start
                        },
                        end: measure_end,
                    };

                    // Create syntax node for this measure
                    let measure_syntax_id = if let Some(as_kw) = as_keyword_id {
                        Some(self.syntax_arena.alloc_measure_item(
                            crate::syntax::SyntaxMeasureItem {
                                semantic_modifier: semantic_modifier_token_id,
                                as_keyword: as_kw,
                                span: measure_span,
                            },
                        ))
                    } else {
                        None
                    };

                    measures.push(AstMeasure {
                        node_id: self.id_gen.next(),
                        syntax_id: measure_syntax_id,
                        semantic_modifier,
                        expr,
                        alias: AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: alias_tok.span,
                        },
                        span: measure_span,
                    });

                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance();
                            if (measures_comma_count as usize) < measures_commas.len() {
                                measures_commas[measures_comma_count as usize] =
                                    self.last_token_id();
                                measures_comma_count += 1;
                            }
                            continue;
                        }
                    }
                    break;
                }
            }
        }

        // Parse optional rows per match mode
        let mut rows_per_match_keyword_id = None;
        let mut rows_per_match_tokens = [crate::cst::TokenId(0); 8];
        let mut rows_per_match_token_count = 0u8;
        let rows_per_match = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::One)) {
                rows_per_match_keyword_id = Some(self.current_token_id());
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                Some(AstRowsPerMatch::OneRowPerMatch)
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::All)) {
                rows_per_match_keyword_id = Some(self.current_token_id());
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();
                rows_per_match_tokens[rows_per_match_token_count as usize] =
                    self.current_token_id();
                rows_per_match_token_count += 1;
                self.advance();

                // Check for optional modifiers
                let empty_matches = if let Some(next_tok) = self.peek() {
                    if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Show)) {
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        Some(AstEmptyMatchesMode::Show)
                    } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Omit)) {
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        Some(AstEmptyMatchesMode::Omit)
                    } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::With)) {
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        rows_per_match_tokens[rows_per_match_token_count as usize] =
                            self.current_token_id();
                        rows_per_match_token_count += 1;
                        self.advance();
                        Some(AstEmptyMatchesMode::WithUnmatched)
                    } else {
                        None // No explicit mode specified
                    }
                } else {
                    None // No explicit mode specified
                };

                Some(AstRowsPerMatch::AllRowsPerMatch { empty_matches })
            } else {
                None
            }
        } else {
            None
        };

        // Parse optional AFTER MATCH SKIP
        let mut after_match_keyword_id = None;
        let mut after_match_skip_tokens = [crate::cst::TokenId(0); 6];
        let mut after_match_skip_token_count = 0u8;
        let after_match_skip = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::After)) {
                after_match_keyword_id = Some(self.current_token_id());
                after_match_skip_tokens[after_match_skip_token_count as usize] =
                    self.current_token_id();
                after_match_skip_token_count += 1;
                self.advance();
                after_match_skip_tokens[after_match_skip_token_count as usize] =
                    self.current_token_id();
                after_match_skip_token_count += 1;
                self.advance();
                after_match_skip_tokens[after_match_skip_token_count as usize] =
                    self.current_token_id();
                after_match_skip_token_count += 1;
                self.advance();

                if let Some(next_tok) = self.peek() {
                    if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Past)) {
                        after_match_skip_tokens[after_match_skip_token_count as usize] =
                            self.current_token_id();
                        after_match_skip_token_count += 1;
                        self.advance();
                        after_match_skip_tokens[after_match_skip_token_count as usize] =
                            self.current_token_id();
                        after_match_skip_token_count += 1;
                        self.advance();
                        after_match_skip_tokens[after_match_skip_token_count as usize] =
                            self.current_token_id();
                        after_match_skip_token_count += 1;
                        self.advance();
                        Some(AstAfterMatchSkip::PastLastRow)
                    } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::To))
                        || (self.can_be_identifier_token(next_tok)
                            && next_tok.lexeme(self.source).eq_ignore_ascii_case("TO"))
                    {
                        after_match_skip_tokens[after_match_skip_token_count as usize] =
                            self.current_token_id();
                        after_match_skip_token_count += 1;
                        self.advance();

                        if let Some(next) = self.peek() {
                            if matches!(next.kind, TokenKind::Keyword(Keyword::Next)) {
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                self.advance();
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                self.advance();
                                Some(AstAfterMatchSkip::ToNextRow)
                            } else if matches!(next.kind, TokenKind::Keyword(Keyword::First)) {
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                self.advance();
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                let symbol_tok = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["symbol identifier".to_string()],
                                )?;
                                if let TokenKind::Identifier { .. } = symbol_tok.kind {
                                    Some(AstAfterMatchSkip::ToFirstSymbol(
                                        symbol_tok.lexeme(self.source).to_string(),
                                    ))
                                } else {
                                    None
                                }
                            } else if matches!(next.kind, TokenKind::Keyword(Keyword::Last)) {
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                self.advance();
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                let symbol_tok = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["symbol identifier".to_string()],
                                )?;
                                if let TokenKind::Identifier { .. } = symbol_tok.kind {
                                    Some(AstAfterMatchSkip::ToLastSymbol(
                                        symbol_tok.lexeme(self.source).to_string(),
                                    ))
                                } else {
                                    None
                                }
                            } else if self.can_be_identifier_token(next) {
                                // TO <symbol> (defaults to LAST)
                                after_match_skip_tokens[after_match_skip_token_count as usize] =
                                    self.current_token_id();
                                after_match_skip_token_count += 1;
                                let symbol_tok = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["symbol identifier".to_string()],
                                )?;
                                Some(AstAfterMatchSkip::ToLastSymbol(
                                    symbol_tok.lexeme(self.source).to_string(),
                                ))
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
            }
        } else {
            None
        };

        // Parse required PATTERN clause
        let pattern_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["PATTERN".to_string()])?;
        if !matches!(pattern_tok.kind, TokenKind::Keyword(Keyword::Pattern)) {
            return Err(ParseError::unexpected_token(
                pattern_tok.span,
                vec!["PATTERN".to_string()],
                Parser::token_description(pattern_tok, self.source),
            ));
        }

        self.advance(); // PATTERN
        let pattern_keyword_id = self.last_token_id();

        // Expect '('
        let pattern_lp = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        let pattern_lparen_id = self.last_token_id();
        if !matches!(
            pattern_lp.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                pattern_lp.span,
                vec!["(".to_string()],
                Parser::token_description(pattern_lp, self.source),
            ));
        }

        let pattern_start = pattern_lp.span.end;

        // Collect pattern tokens until matching ')'
        // We need to preserve the original spacing to maintain pattern syntax like A+ B* C+
        let mut pattern_parts = Vec::new();
        let mut pattern_tokens = Vec::new();
        let mut depth = 1;
        let mut pattern_end = pattern_start;
        let mut pattern_rparen_id = None;
        while let Some(t) = self.advance() {
            let tok_id = self.last_token_id();
            match t.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                    depth += 1;
                    pattern_parts.push(t.lexeme(self.source).to_string());
                    pattern_tokens.push(tok_id);
                    pattern_end = t.span.end;
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        pattern_rparen_id = Some(tok_id);
                        break;
                    }
                    pattern_parts.push(t.lexeme(self.source).to_string());
                    pattern_tokens.push(tok_id);
                    pattern_end = t.span.end;
                }
                // For operators like + and *, attach them to the previous token without space
                TokenKind::Operator(
                    crate::lexer::Operator::Plus | crate::lexer::Operator::Star,
                ) => {
                    // Append to previous part without space
                    if let Some(last) = pattern_parts.last_mut() {
                        last.push_str(t.lexeme(self.source));
                    } else {
                        pattern_parts.push(t.lexeme(self.source).to_string());
                    }
                    pattern_tokens.push(tok_id);
                    pattern_end = t.span.end;
                }
                _ => {
                    // Add space before this token unless it's the first one
                    if !pattern_parts.is_empty() {
                        pattern_parts.push(" ".to_string());
                    }
                    pattern_parts.push(t.lexeme(self.source).to_string());
                    pattern_tokens.push(tok_id);
                    pattern_end = t.span.end;
                }
            }
        }

        // Join the pattern parts (spaces already included where appropriate)
        let pattern_text = pattern_parts.concat();

        let pattern = AstPattern {
            node_id: self.id_gen.next(),
            pattern_text,
            span: Span {
                start: pattern_start,
                end: pattern_end,
            },
        };

        // Parse required DEFINE clause
        let define_tok = self
            .peek()
            .ok_or_eof(self.current_span(), vec!["DEFINE".to_string()])?;
        if !matches!(define_tok.kind, TokenKind::Keyword(Keyword::Define)) {
            return Err(ParseError::unexpected_token(
                define_tok.span,
                vec!["DEFINE".to_string()],
                Parser::token_description(define_tok, self.source),
            ));
        }

        self.advance(); // DEFINE
        let define_keyword_id = self.last_token_id();

        let mut define_commas = [crate::cst::TokenId(0); 16];
        let mut define_comma_count = 0u8;
        let mut define = Vec::new();
        loop {
            let symbol_start = self.idx;
            let symbol_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
            let symbol_token_id = self.last_token_id();
            if !self.can_be_identifier_token(symbol_tok) {
                return Err(ParseError::unexpected_token(
                    symbol_tok.span,
                    vec!["identifier".to_string()],
                    Parser::token_description(symbol_tok, self.source),
                ));
            }
            let symbol = symbol_tok.lexeme(self.source).to_string();

            // Expect AS
            let as_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
            let as_keyword_id = self.last_token_id();
            if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                return Err(ParseError::unexpected_token(
                    as_tok.span,
                    vec!["AS".to_string()],
                    Parser::token_description(as_tok, self.source),
                ));
            }

            // Parse expression
            let expr = self.parse_expr()?;
            let expr_end = expr_span_end(&expr);

            let define_span = Span {
                start: if symbol_start < self.tokens.len() {
                    self.tokens[symbol_start].span.start
                } else {
                    symbol_tok.span.start
                },
                end: expr_end,
            };

            // Create syntax node for this define symbol
            let define_syntax_id =
                self.syntax_arena
                    .alloc_define_symbol(crate::syntax::SyntaxDefineSymbol {
                        symbol_token: symbol_token_id,
                        as_keyword: as_keyword_id,
                        span: define_span,
                    });

            define.push(AstDefineSymbol {
                node_id: self.id_gen.next(),
                syntax_id: Some(define_syntax_id),
                symbol,
                expr,
                span: define_span,
            });

            if let Some(comma) = self.peek() {
                if matches!(
                    comma.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance();
                    if (define_comma_count as usize) < define_commas.len() {
                        define_commas[define_comma_count as usize] = self.last_token_id();
                        define_comma_count += 1;
                    }
                    continue;
                }
            }
            break;
        }

        // Expect closing ')'
        let rp = self
            .advance()
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
        let mr_rparen_id = self.last_token_id();

        let end_span = rp.span.end;
        let mr_span = Span {
            start: start_span,
            end: end_span,
        };

        // Create syntax node for MATCH_RECOGNIZE
        let match_recognize_syntax_id =
            self.syntax_arena
                .alloc_match_recognize(crate::syntax::SyntaxMatchRecognize {
                    match_recognize_keyword: match_recognize_keyword_id,
                    mr_lparen: mr_lparen_id,
                    mr_rparen: mr_rparen_id,
                    partition_keyword: partition_keyword_id,
                    partition_by_keyword: partition_by_keyword_id,
                    partition_by_commas,
                    partition_by_comma_count,
                    order_keyword: order_keyword_id,
                    order_by_keyword: order_by_keyword_id,
                    order_by_commas,
                    order_by_comma_count,
                    measures_keyword: measures_keyword_id,
                    measures_commas,
                    measures_comma_count,
                    rows_per_match_keyword: rows_per_match_keyword_id,
                    rows_per_match_tokens,
                    rows_per_match_token_count,
                    after_match_keyword: after_match_keyword_id,
                    after_match_skip_tokens,
                    after_match_skip_token_count,
                    pattern_keyword: pattern_keyword_id,
                    pattern_lparen: pattern_lparen_id,
                    pattern_rparen: pattern_rparen_id.unwrap_or(pattern_lparen_id), // fallback
                    pattern_tokens,
                    define_keyword: define_keyword_id,
                    define_commas,
                    define_comma_count,
                    span: mr_span,
                });

        Ok(Some(AstMatchRecognize {
            node_id: self.id_gen.next(),
            syntax_id: Some(match_recognize_syntax_id),
            match_recognize_span,
            partition_by,
            order_by,
            measures,
            rows_per_match,
            after_match_skip,
            pattern,
            define,
            span: mr_span,
        }))
    }

    /// Parse a single ORDER BY item (expression with optional ASC/DESC and NULLS FIRST/LAST)
    /// This is shared between window function ORDER BY and SELECT ORDER BY
    pub(crate) fn parse_order_by_item(&mut self) -> ParseResult<Option<AstOrderItem>> {
        // Parse expression - handle Jinja blocks via parse_expr() which supports JinjaConditional
        let expr = match self.parse_expr() {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        let mut asc: Option<bool> = None;
        let mut direction_keyword: Option<crate::cst::TokenId> = None;
        let mut nulls_first: Option<bool> = None;
        let mut nulls_keyword: Option<crate::cst::TokenId> = None;
        let mut nulls_order_keyword: Option<crate::cst::TokenId> = None;
        let mut span_end = expr.span().end;

        // Parse ASC/DESC - can be a keyword, identifier, or Jinja block
        if let Some(dir_tok) = self.peek() {
            match &dir_tok.kind {
                TokenKind::Identifier { .. }
                    if dir_tok.lexeme(self.source).eq_ignore_ascii_case("ASC") =>
                {
                    direction_keyword = Some(self.current_token_id());
                    let tok = self
                        .advance()
                        .expect_invariant("ASC identifier consumed after peek match");
                    asc = Some(true);
                    span_end = tok.span.end;
                }
                TokenKind::Identifier { .. }
                    if dir_tok.lexeme(self.source).eq_ignore_ascii_case("DESC") =>
                {
                    direction_keyword = Some(self.current_token_id());
                    let tok = self
                        .advance()
                        .expect_invariant("DESC identifier consumed after peek match");
                    asc = Some(false);
                    span_end = tok.span.end;
                }
                _ => {}
            }
        }

        // Parse NULLS FIRST/LAST
        if let Some(nulls_tok) = self.peek() {
            if matches!(nulls_tok.kind, TokenKind::Keyword(Keyword::Nulls)) {
                let _nulls_start = nulls_tok.span.start;
                nulls_keyword = Some(self.current_token_id());
                self.advance(); // consume NULLS

                if let Some(fl_tok) = self.peek() {
                    match fl_tok.kind {
                        TokenKind::Keyword(Keyword::First) => {
                            nulls_order_keyword = Some(self.current_token_id());
                            let tok = self
                                .advance()
                                .expect_invariant("FIRST keyword consumed after peek match");
                            nulls_first = Some(true);
                            span_end = tok.span.end;
                        }
                        TokenKind::Keyword(Keyword::Last) => {
                            nulls_order_keyword = Some(self.current_token_id());
                            let tok = self
                                .advance()
                                .expect_invariant("LAST keyword consumed after peek match");
                            nulls_first = Some(false);
                            span_end = tok.span.end;
                        }
                        _ => {
                            // Invalid token after NULLS - return error
                            return Err(ParseError::unexpected_token(
                                fl_tok.span,
                                vec!["FIRST".to_string(), "LAST".to_string()],
                                Parser::token_description(fl_tok, self.source),
                            ));
                        }
                    }
                }
            }
        }

        let span = Span {
            start: expr.span().start,
            end: span_end,
        };

        // Allocate syntax node if we have any syntax tokens
        let syntax_id = if direction_keyword.is_some() || nulls_keyword.is_some() {
            Some(
                self.syntax_arena
                    .alloc_order_item(crate::syntax::SyntaxOrderItem {
                        direction_keyword,
                        nulls_keyword,
                        nulls_order_keyword,
                        span,
                    }),
            )
        } else {
            None
        };

        Ok(Some(AstOrderItem {
            node_id: self.id_gen.next(),
            expr,
            asc,
            syntax_id,
            nulls_first,
            span,
        }))
    }

    /// Parse ORDER BY clause
    /// Parse ORDER BY clause
    /// Supports Jinja templates where consecutive {% if %} blocks represent conditional items
    /// and items following Jinja blocks without explicit commas (comma is inside the block)
    pub(crate) fn parse_select_order_by(&mut self) -> ParseResult<Option<AstOrderBy>> {
        use crate::ast::JinjaBlockKind;

        if let Some(tok) = self.peek() {
            if !matches!(tok.kind, TokenKind::Keyword(Keyword::Order)) {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        let order_tok = self
            .advance()
            .expect_invariant("ORDER keyword consumed after peek match"); // Consume ORDER
        let order_start = order_tok.span.start;

        let by_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["BY".to_string()])
        })?;
        if !matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
            return Ok(None);
        }

        let InlineFragmentCollection {
            fragments: prefix_inline_fragments,
        } = self.collect_leading_inline_fragments();

        let mut items = Vec::new();
        while let Some(tok) = self.peek() {
            // Stop at clause keywords
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Limit)
                    | TokenKind::Keyword(Keyword::Offset)
                    | TokenKind::Keyword(Keyword::Qualify)
                    | TokenKind::Keyword(Keyword::Fetch)
                    | TokenKind::Keyword(Keyword::For)
                    | TokenKind::Keyword(Keyword::Union)
                    | TokenKind::Keyword(Keyword::Intersect)
                    | TokenKind::Keyword(Keyword::Except)
                    | TokenKind::Keyword(Keyword::Minus)
                    // MATCH_RECOGNIZE clauses that follow ORDER BY
                    | TokenKind::Keyword(Keyword::Measures)
                    | TokenKind::Keyword(Keyword::One)
                    | TokenKind::Keyword(Keyword::All)
                    | TokenKind::Keyword(Keyword::After)
                    | TokenKind::Keyword(Keyword::Pattern)
                    | TokenKind::Keyword(Keyword::Define)
            ) {
                break;
            }

            // Stop at semicolon
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                break;
            }

            // Stop at closing paren (subquery context)
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                break;
            }

            // Stop at MSSQL OPTION(...) query hints (OPTION is an Identifier, not a Keyword)
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTION")
            {
                break;
            }

            // Stop at Jinja closing/branch delimiters ({% endif %}, {% endfor %}, {% else %}, {% elif %})
            // These belong to an outer Jinja wrapper, not to ORDER BY items
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(
                    kind,
                    JinjaBlockKind::EndIf
                        | JinjaBlockKind::EndFor
                        | JinjaBlockKind::Else
                        | JinjaBlockKind::Elif
                ) {
                    break;
                }
                // Opening blocks ({% if %}, {% for %}) are handled by parse_order_by_item -> parse_expr
            }

            // Parse ORDER BY item
            let item = match self.parse_order_by_item()? {
                Some(item) => item,
                None => {
                    // If we haven't parsed any items yet, this is an error
                    if items.is_empty() {
                        return Err(ParseError::invalid_expression(
                            self.current_span(),
                            "ORDER BY clause requires at least one expression".to_string(),
                        ));
                    }
                    // Otherwise we're done
                    break;
                }
            };
            items.push(Box::new(item));

            // Consume optional comma (in Jinja templates, comma may be inside the block)
            if let Some(next) = self.peek() {
                if matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    self.advance();
                }
            }
            // Continue loop - stop conditions checked at start of next iteration
        }

        let last_item_end = items
            .last()
            .map(|item| item.span.end)
            .unwrap_or(order_start);
        let InlineFragmentCollection {
            fragments: trailing,
        } = self.collect_trailing_inline_fragments();
        let suffix_inline_fragments: Vec<crate::ast::JinjaInlineFragment> = trailing;
        let span_end = suffix_inline_fragments
            .last()
            .map(|f| f.span.end)
            .unwrap_or(last_item_end);

        Ok(Some(AstOrderBy {
            node_id: self.id_gen.next(),
            items,
            prefix_inline_fragments,
            suffix_inline_fragments,
            span: Span {
                start: order_start,
                end: span_end,
            },
        }))
    }

    /// Parse LIMIT and OFFSET clauses (supports both PostgreSQL and ANSI syntax)
    /// Also handles Jinja-wrapped OFFSET: LIMIT n {% if cond %}OFFSET m{% endif %}
    /// Parse LIMIT/OFFSET clauses (Snowflake LIMIT syntax or ANSI FETCH syntax).
    pub(crate) fn parse_select_limit_offset(&mut self) -> ParseResult<LimitOffsetParsed> {
        let mut limit: Option<AstExpr> = None;
        let mut offset: Option<AstExpr> = None;
        let mut limit_keyword_span: Option<Span> = None;
        let mut fetch_clause_span: Option<Span> = None;
        let mut offset_keyword_span: Option<Span> = None;
        let mut limit_comma_span: Option<Span> = None;

        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Limit)) {
                let limit_tok = self
                    .advance()
                    .expect_invariant("LIMIT keyword consumed after peek match"); // Consume LIMIT
                limit_keyword_span = Some(limit_tok.span);
                limit = Some(self.parse_expr()?);

                // MySQL comma form: LIMIT offset, count — the first expr is
                // the OFFSET, the second the row count (dialect-gated).
                if self.dialect.supports_limit_comma_offset() {
                    if let Some(comma_tok) = self.peek() {
                        if matches!(
                            comma_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            let comma = self
                                .advance()
                                .expect_invariant("comma consumed after peek match");
                            limit_comma_span = Some(comma.span);
                            offset = limit.take();
                            limit = Some(self.parse_expr()?);
                        }
                    }
                }

                // Optional OFFSET after LIMIT (may be wrapped in Jinja)
                if let Some(offset_tok) = self.peek() {
                    if matches!(offset_tok.kind, TokenKind::Keyword(Keyword::Offset)) {
                        let offset_kw = self
                            .advance()
                            .expect_invariant("OFFSET keyword consumed after peek match");
                        let offset_start = offset_kw.span.start;
                        offset = Some(self.parse_expr()?);
                        // Check for optional ROW/ROWS after OFFSET expression
                        let offset_end = if let Some(row_tok) = self.peek() {
                            if matches!(
                                row_tok.kind,
                                TokenKind::Keyword(Keyword::Row)
                                    | TokenKind::Keyword(Keyword::Rows)
                            ) {
                                let row = self
                                    .advance()
                                    .expect_invariant("ROW/ROWS keyword consumed after peek match");
                                row.span.end
                            } else {
                                offset
                                    .as_ref()
                                    .map(|e| e.span().end)
                                    .unwrap_or(offset_kw.span.end)
                            }
                        } else {
                            offset
                                .as_ref()
                                .map(|e| e.span().end)
                                .unwrap_or(offset_kw.span.end)
                        };
                        offset_keyword_span = Some(Span {
                            start: offset_start,
                            end: offset_end,
                        });
                    }
                    // Handle Jinja-wrapped OFFSET: {% if cond %}OFFSET n{% endif %}
                    else if let Some(kind) = self.peek_jinja_block_kind() {
                        if matches!(
                            kind,
                            crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For
                        ) && self.jinja_block_contains_keyword(Keyword::Offset)
                        {
                            // Capture the entire Jinja-wrapped OFFSET block as a placeholder expression
                            let block_start = self.current_span().start;

                            // Skip opening delimiter
                            self.skip_jinja_delimiter();

                            // Consume OFFSET keyword if present
                            if let Some(offset_tok) = self.peek() {
                                if matches!(offset_tok.kind, TokenKind::Keyword(Keyword::Offset)) {
                                    self.advance();
                                    let _ = self.parse_expr();
                                }
                            }

                            // Skip closing delimiter and record end
                            let mut block_end = self.current_span().end;
                            if let Some(kind) = self.peek_jinja_block_kind() {
                                if matches!(
                                    kind,
                                    crate::ast::JinjaBlockKind::EndIf
                                        | crate::ast::JinjaBlockKind::EndFor
                                ) {
                                    self.skip_jinja_delimiter();
                                    block_end = self.current_span().start;
                                }
                            }

                            offset = Some(AstExpr::JinjaPlaceholder {
                                node_id: self.id_gen.next(),
                                kind: crate::ast::JinjaKind::Statement,
                                span: Span {
                                    start: block_start,
                                    end: block_end,
                                },
                                expr: None,
                                syntax_id: None,
                            });
                        }
                    }
                }
            }
            // ANSI syntax: OFFSET ... FETCH ...
            else if matches!(tok.kind, TokenKind::Keyword(Keyword::Offset)) {
                let offset_kw = self
                    .advance()
                    .expect_invariant("OFFSET keyword consumed after peek match");
                let offset_start = offset_kw.span.start;
                offset = self.parse_expr().ok();

                // Optional ROW/ROWS after OFFSET
                let mut offset_end = offset
                    .as_ref()
                    .map(|e| e.span().end)
                    .unwrap_or(offset_kw.span.end);
                if let Some(row_tok) = self.peek() {
                    if matches!(
                        row_tok.kind,
                        TokenKind::Keyword(Keyword::Row) | TokenKind::Keyword(Keyword::Rows)
                    ) {
                        let row = self
                            .advance()
                            .expect_invariant("ROW/ROWS keyword consumed after peek match");
                        offset_end = row.span.end;
                    }
                }
                offset_keyword_span = Some(Span {
                    start: offset_start,
                    end: offset_end,
                });

                // FETCH [FIRST|NEXT] <count> [ROW|ROWS] [ONLY]
                if let Some(fetch_tok) = self.peek() {
                    if matches!(fetch_tok.kind, TokenKind::Keyword(Keyword::Fetch)) {
                        let fetch_kw = self
                            .advance()
                            .expect_invariant("FETCH keyword consumed after peek match");
                        let fetch_start = fetch_kw.span.start;
                        let mut fetch_end = fetch_kw.span.end;

                        // Optional FIRST or NEXT
                        if let Some(first_next) = self.peek() {
                            if matches!(
                                first_next.kind,
                                TokenKind::Keyword(Keyword::First)
                                    | TokenKind::Keyword(Keyword::Next)
                            ) {
                                let kw = self.advance().expect_invariant(
                                    "FIRST/NEXT keyword consumed after peek match",
                                );
                                fetch_end = kw.span.end;
                            }
                        }

                        limit = self.parse_expr().ok();
                        if let Some(ref e) = limit {
                            fetch_end = e.span().end;
                        }

                        // Optional ROW or ROWS
                        if let Some(row_tok) = self.peek() {
                            if matches!(
                                row_tok.kind,
                                TokenKind::Keyword(Keyword::Row)
                                    | TokenKind::Keyword(Keyword::Rows)
                            ) {
                                let row = self
                                    .advance()
                                    .expect_invariant("ROW/ROWS keyword consumed after peek match");
                                fetch_end = row.span.end;
                            }
                        }

                        // Optional ONLY
                        if let Some(only_tok) = self.peek() {
                            if matches!(only_tok.kind, TokenKind::Keyword(Keyword::Only)) {
                                let only = self
                                    .advance()
                                    .expect_invariant("ONLY keyword consumed after peek match");
                                fetch_end = only.span.end;
                            }
                        }

                        fetch_clause_span = Some(Span {
                            start: fetch_start,
                            end: fetch_end,
                        });
                    }
                }
            }
            // Standalone FETCH without OFFSET
            else if matches!(tok.kind, TokenKind::Keyword(Keyword::Fetch)) {
                let fetch_kw = self
                    .advance()
                    .expect_invariant("FETCH keyword consumed after peek match");
                let fetch_start = fetch_kw.span.start;
                let mut fetch_end = fetch_kw.span.end;

                // Optional FIRST or NEXT
                if let Some(first_next) = self.peek() {
                    if matches!(
                        first_next.kind,
                        TokenKind::Keyword(Keyword::First) | TokenKind::Keyword(Keyword::Next)
                    ) {
                        let kw = self
                            .advance()
                            .expect_invariant("FIRST/NEXT keyword consumed after peek match");
                        fetch_end = kw.span.end;
                    }
                }

                limit = self.parse_expr().ok();
                if let Some(ref e) = limit {
                    fetch_end = e.span().end;
                }

                // Optional ROW or ROWS
                if let Some(row_tok) = self.peek() {
                    if matches!(
                        row_tok.kind,
                        TokenKind::Keyword(Keyword::Row) | TokenKind::Keyword(Keyword::Rows)
                    ) {
                        let row = self
                            .advance()
                            .expect_invariant("ROW/ROWS keyword consumed after peek match");
                        fetch_end = row.span.end;
                    }
                }

                // Optional ONLY
                if let Some(only_tok) = self.peek() {
                    if matches!(only_tok.kind, TokenKind::Keyword(Keyword::Only)) {
                        let only = self
                            .advance()
                            .expect_invariant("ONLY keyword consumed after peek match");
                        fetch_end = only.span.end;
                    }
                }

                fetch_clause_span = Some(Span {
                    start: fetch_start,
                    end: fetch_end,
                });
            }
        }

        Ok(LimitOffsetParsed {
            limit_expr: limit,
            offset_expr: offset,
            limit_keyword_span,
            fetch_clause_span,
            offset_keyword_span,
            limit_comma_span,
        })
    }
}
