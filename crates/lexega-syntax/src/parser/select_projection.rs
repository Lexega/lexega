// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SELECT projection parsing (column lists, star expressions).
//!
//! Handles the SELECT clause projection list:
//! - Star expressions: `SELECT *`, `SELECT t.*`
//! - Column modifiers: `EXCLUDE`, `REPLACE`, `RENAME`, `ILIKE`
//! - Column lists: `SELECT a, b, c AS alias`
//! - Expressions: `SELECT a + b, func(x)`
//! - Jinja-interleaved projections (for dbt)
//!
//! Reference: <https://docs.snowflake.com/en/sql-reference/sql/select>

use crate::ast::{
    AstIdentifier, AstIdentifierWithAs, AstProjection, AstSelectItem, AstStarProjection,
};
use crate::error::{ExpectInvariant, ParseError};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::scripting::expr_span_end;
use crate::parser::select::InlineFragmentCollection;
use crate::parser::select::{consume_adjacent_jinja_exprs, is_clause_keyword_lexeme};

impl<'a> Parser<'a> {
    /// Peek-ahead recognition for variable-assignment projections:
    /// T-SQL `SELECT @v = expr FROM ...` and MySQL `SELECT @v := expr`.
    /// The `=` form is caller-gated via `allow_eq` (it is a comparison
    /// in every other dialect); the `:=` form is unambiguous — no other
    /// grammar puts `:=` after an `AtVariable` — and accepted whenever
    /// it appears. Guards `=` against `=>` (named-arg operator).
    /// Consumes `@v` and the operator on match; otherwise leaves the
    /// parser cursor unchanged and returns `None`.
    fn try_parse_tsql_assignment_target_lifted(
        &mut self,
        allow_eq: bool,
    ) -> Option<crate::ast::AstSelectItemAssignTarget> {
        let saved_idx = self.idx;
        let first = self.peek()?;
        let first_span = first.span;
        let is_at_variable = matches!(
            first.kind,
            TokenKind::Identifier {
                kind: crate::lexer::IdentifierKind::AtVariable
            }
        );
        if !is_at_variable {
            return None;
        }
        // Provisional consume.
        self.advance();
        let eq_tok = match self.peek() {
            Some(t) => t,
            None => {
                self.idx = saved_idx;
                return None;
            }
        };
        let eq_span = eq_tok.span;
        let is_eq =
            allow_eq && matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq));
        let is_colon_eq = matches!(
            eq_tok.kind,
            TokenKind::Operator(crate::lexer::Operator::ColonEq)
        );
        if !is_eq && !is_colon_eq {
            self.idx = saved_idx;
            return None;
        }
        // Guard against `=>` (named-arg / fat-arrow operator). If the
        // very next token is `>` adjacent to the `=`, restore and
        // treat as a comparison. (`:=` has no such ambiguity.)
        let eq_end = eq_tok.span.end;
        self.advance();
        if is_eq {
            if let Some(next) = self.peek() {
                if next.span.start == eq_end
                    && matches!(next.kind, TokenKind::Operator(crate::lexer::Operator::Gt))
                {
                    self.idx = saved_idx;
                    return None;
                }
            }
        }
        Some(crate::ast::AstSelectItemAssignTarget {
            target: crate::ast::AstIdentifier {
                node_id: self.id_gen.next(),
                span: first_span,
            },
            assign_op_span: eq_span,
        })
    }

    /// Parse a star projection: `*`, `t.*`, with optional ILIKE/EXCLUDE/REPLACE/RENAME modifiers.
    ///
    /// This is a Parser method that properly captures TokenIds for syntax nodes,
    /// enabling trivia-preserving formatting.
    fn parse_star_projection(&mut self) -> Option<AstStarProjection> {
        use crate::ast::{
            AstColumnRef, AstExclude, AstIdentifier, AstIlikeFilter, AstObjectRef, AstRename,
            AstRenameItem, AstReplace, AstReplaceItem, AstStarProjection,
        };
        use crate::lexer::{Keyword, Span};

        let tok0 = self.peek()?;
        let mut star: AstStarProjection;

        match &tok0.kind {
            // SELECT * ...
            TokenKind::Operator(crate::lexer::Operator::Star) => {
                let star_span = tok0.span;
                self.advance();
                star = AstStarProjection {
                    node_id: self.id_gen.next(),
                    star_span,
                    qualifier: None,
                    ilike: None,
                    exclude: None,
                    replace: None,
                    rename: None,
                };
            }
            // SELECT e.* ...
            TokenKind::Identifier { .. } => {
                let ident_span = tok0.span;
                // Look ahead for `.` and `*`
                if self.idx + 2 >= self.tokens.len() {
                    return None;
                }
                let dot_tok = &self.tokens[self.idx + 1];
                let star_tok = &self.tokens[self.idx + 2];

                let dot_is_valid = match &dot_tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => true,
                    TokenKind::Literal(crate::lexer::LiteralKind::Number)
                        if dot_tok.lexeme(self.source) == "." =>
                    {
                        true
                    }
                    _ => false,
                };
                if !dot_is_valid
                    || !matches!(
                        star_tok.kind,
                        TokenKind::Operator(crate::lexer::Operator::Star)
                    )
                {
                    return None;
                }

                self.advance(); // consume identifier
                self.advance(); // consume '.'
                let star_span = self.peek()?.span;
                self.advance(); // consume '*'

                let qualifier = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: ident_span,
                    parts: None, // single-identifier projection qualifier; span IS the part
                    identifier_arg: None,
                };
                star = AstStarProjection {
                    node_id: self.id_gen.next(),
                    star_span,
                    qualifier: Some(qualifier),
                    ilike: None,
                    exclude: None,
                    replace: None,
                    rename: None,
                };
            }
            _ => return None,
        }

        // Parse optional ILIKE / EXCLUDE / REPLACE / RENAME modifiers
        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Keyword(Keyword::Ilike) => {
                    let ilike_span = tok.span;
                    self.advance(); // consume ILIKE

                    if let Some(pat_tok) = self.peek() {
                        if matches!(
                            pat_tok.kind,
                            TokenKind::Literal(crate::lexer::LiteralKind::String)
                        ) {
                            let pattern_span = pat_tok.span;
                            self.advance(); // consume pattern
                            star.ilike = Some(AstIlikeFilter {
                                node_id: self.id_gen.next(),
                                ilike_span,
                                pattern_span,
                                span: Span {
                                    start: ilike_span.start,
                                    end: pattern_span.end,
                                },
                            });
                        }
                    }
                }

                // EXCLUDE (Snowflake/DuckDB) or EXCEPT (BigQuery) for column exclusion on star
                // For EXCEPT: disambiguate from EXCEPT set operator by checking for '(' after
                TokenKind::Keyword(Keyword::Exclude) | TokenKind::Keyword(Keyword::Except) => {
                    // If EXCEPT, only treat as column exclusion if the dialect supports it
                    // and it's followed by '(' (otherwise it's a set operator)
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::Except)) {
                        if !self.dialect.except_is_star_modifier() {
                            break;
                        }
                        let has_lparen = self.peek_ahead(1).is_some_and(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        });
                        if !has_lparen {
                            break; // Not column exclusion, let outer parser handle as set operation
                        }
                    }

                    // Capture keyword TokenId (EXCLUDE or EXCEPT)
                    let exclude_kw_token_id = self.current_token_id();
                    let exclude_span = tok.span;
                    self.advance(); // consume EXCLUDE/EXCEPT

                    // Check for parentheses
                    let has_parens = self
                        .peek()
                        .map(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        })
                        .unwrap_or(false);

                    let lparen_token_id = if has_parens {
                        let id = self.current_token_id();
                        self.advance(); // consume '('
                        Some(id)
                    } else {
                        None
                    };

                    let mut cols: Vec<AstColumnRef> = Vec::new();
                    let mut end_span = exclude_span.end;
                    let mut rparen_token_id: Option<crate::cst::TokenId> = None;

                    while let Some(first_tok) = self.peek() {
                        match &first_tok.kind {
                            _ if self.can_be_identifier_token(first_tok) => {
                                let mut qualifier = None;
                                let mut name_span = first_tok.span;
                                self.advance(); // consume identifier

                                // Check for dotted qualifier
                                if let Some(dot_tok) = self.peek() {
                                    let is_dot = matches!(
                                        dot_tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                                    ) || (matches!(
                                        dot_tok.kind,
                                        TokenKind::Literal(crate::lexer::LiteralKind::Number)
                                    ) && dot_tok.lexeme(self.source) == ".");

                                    if is_dot {
                                        self.advance(); // consume '.'
                                        if let Some(second_tok) = self.peek() {
                                            if matches!(
                                                second_tok.kind,
                                                TokenKind::Identifier { .. }
                                            ) {
                                                qualifier = Some(AstObjectRef {
                                                    node_id: self.id_gen.next(),
                                                    span: first_tok.span,
                                                    parts: None, // column qualifier; see AstObjectRef::parts
                                                    identifier_arg: None,
                                                });
                                                name_span = second_tok.span;
                                                end_span = second_tok.span.end;
                                                self.advance(); // consume second identifier
                                            }
                                        }
                                    } else {
                                        end_span = first_tok.span.end;
                                    }
                                } else {
                                    end_span = first_tok.span.end;
                                }

                                cols.push(AstColumnRef {
                                    node_id: self.id_gen.next(),
                                    qualifier,
                                    name: AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: name_span,
                                    },
                                });

                                if !has_parens {
                                    break;
                                }
                            }
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                rparen_token_id = Some(self.current_token_id());
                                end_span = first_tok.span.end;
                                self.advance(); // consume ')'
                                break;
                            }
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                self.advance(); // skip comma
                                continue;
                            }
                            _ => break,
                        }

                        // After a column, check for comma or closing paren
                        if let Some(next) = self.peek() {
                            match &next.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                    self.advance();
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    rparen_token_id = Some(self.current_token_id());
                                    end_span = next.span.end;
                                    self.advance();
                                    break;
                                }
                                _ => break,
                            }
                        } else {
                            break;
                        }
                    }

                    let span = Span {
                        start: exclude_span.start,
                        end: end_span,
                    };

                    // Allocate SyntaxExclude
                    let syntax_node = crate::syntax::SyntaxExclude {
                        exclude_keyword: exclude_kw_token_id,
                        lparen: lparen_token_id,
                        rparen: rparen_token_id,
                        span,
                    };
                    let syntax_id = self.syntax_arena.alloc_exclude(syntax_node);

                    star.exclude = Some(Box::new(AstExclude {
                        node_id: self.id_gen.next(),
                        syntax_id: Some(syntax_id),
                        exclude_span,
                        columns: cols,
                        has_parens,
                        span,
                    }));
                }

                TokenKind::Keyword(Keyword::Replace) => {
                    let replace_kw_token_id = self.current_token_id();
                    let replace_span = tok.span;
                    self.advance(); // consume REPLACE

                    // Expect '('
                    let lparen_token_id = self.current_token_id();
                    if let Some(lparen) = self.peek() {
                        if !matches!(
                            lparen.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            continue;
                        }
                        self.advance(); // consume '('
                    } else {
                        break;
                    }

                    let mut items: Vec<AstReplaceItem> = Vec::new();
                    let mut end_span = replace_span.end;
                    let mut rparen_token_id: Option<crate::cst::TokenId> = None;

                    while let Some(next) = self.peek() {
                        match &next.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                rparen_token_id = Some(self.current_token_id());
                                end_span = next.span.end;
                                self.advance();
                                break;
                            }
                            _ => {
                                // Parse a full expression for the replacement value.
                                // This supports constructs like LOWER(email), CASE, literals, etc.
                                let expr = match self.parse_expr() {
                                    Ok(expr) => expr,
                                    Err(_) => break,
                                };

                                // Expect AS
                                let as_tok = self.peek()?;
                                if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                                    break;
                                }
                                let as_keyword_token_id = self.current_token_id();
                                self.advance(); // consume AS

                                // Expect column name
                                let col_tok = self.peek()?;
                                if !self.can_be_identifier_token(col_tok) {
                                    break;
                                }
                                let col_span = col_tok.span;
                                end_span = col_span.end;
                                self.advance(); // consume column name

                                // Allocate syntax node for this REPLACE item
                                let item_span = Span {
                                    start: expr.span().start,
                                    end: col_span.end,
                                };
                                let syntax_id = self.syntax_arena.alloc_replace_item(
                                    crate::syntax::SyntaxReplaceItem {
                                        as_keyword: as_keyword_token_id,
                                        span: item_span,
                                    },
                                );
                                items.push(AstReplaceItem {
                                    node_id: self.id_gen.next(),
                                    syntax_id,
                                    expr,
                                    as_span: as_tok.span,
                                    column: AstColumnRef {
                                        node_id: self.id_gen.next(),
                                        qualifier: None,
                                        name: AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: col_span,
                                        },
                                    },
                                });

                                // Check for comma or closing paren
                                if let Some(next2) = self.peek() {
                                    match &next2.kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::Comma,
                                        ) => {
                                            self.advance();
                                        }
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => {
                                            rparen_token_id = Some(self.current_token_id());
                                            end_span = next2.span.end;
                                            self.advance();
                                            break;
                                        }
                                        _ => break,
                                    }
                                }
                            }
                        }
                    }

                    let span = Span {
                        start: replace_span.start,
                        end: end_span,
                    };

                    let syntax_node = crate::syntax::SyntaxReplace {
                        replace_keyword: replace_kw_token_id,
                        lparen: lparen_token_id,
                        rparen: rparen_token_id.unwrap_or(lparen_token_id),
                        span,
                    };
                    let syntax_id = self.syntax_arena.alloc_replace(syntax_node);

                    star.replace = Some(Box::new(AstReplace {
                        node_id: self.id_gen.next(),
                        syntax_id: Some(syntax_id),
                        replace_span,
                        items,
                        span,
                    }));
                }

                TokenKind::Keyword(Keyword::Rename) => {
                    let rename_kw_token_id = self.current_token_id();
                    let rename_span = tok.span;
                    self.advance(); // consume RENAME

                    let has_parens = self
                        .peek()
                        .map(|t| {
                            matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        })
                        .unwrap_or(false);

                    let lparen_token_id = if has_parens {
                        let id = self.current_token_id();
                        self.advance(); // consume '('
                        Some(id)
                    } else {
                        None
                    };

                    let mut items: Vec<AstRenameItem> = Vec::new();
                    let mut end_span = rename_span.end;
                    let mut rparen_token_id: Option<crate::cst::TokenId> = None;

                    while let Some(old_name_tok) = self.peek() {
                        // Check for closing paren
                        if has_parens
                            && matches!(
                                old_name_tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            )
                        {
                            rparen_token_id = Some(self.current_token_id());
                            end_span = old_name_tok.span.end;
                            self.advance();
                            break;
                        }

                        if !self.can_be_identifier_token(old_name_tok) {
                            break;
                        }

                        let old_span = old_name_tok.span;
                        self.advance(); // consume old name

                        // Expect AS
                        let as_tok = self.peek()?;
                        if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                            break;
                        }
                        let as_keyword_token_id = self.current_token_id();
                        self.advance(); // consume AS

                        // Expect new name
                        let new_name_tok = self.peek()?;
                        if !self.can_be_identifier_token(new_name_tok) {
                            break;
                        }
                        let new_span = new_name_tok.span;
                        end_span = new_span.end;
                        self.advance(); // consume new name

                        // Allocate syntax node for this RENAME item
                        let item_span = Span {
                            start: old_span.start,
                            end: new_span.end,
                        };
                        let syntax_id =
                            self.syntax_arena
                                .alloc_rename_item(crate::syntax::SyntaxRenameItem {
                                    as_keyword: Some(as_keyword_token_id),
                                    span: item_span,
                                });
                        items.push(AstRenameItem {
                            node_id: self.id_gen.next(),
                            syntax_id,
                            column: AstColumnRef {
                                node_id: self.id_gen.next(),
                                qualifier: None,
                                name: AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: old_span,
                                },
                            },
                            as_span: Some(as_tok.span),
                            alias: AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: new_span,
                            },
                        });

                        if !has_parens {
                            break;
                        }

                        // Check for comma or closing paren
                        if let Some(next) = self.peek() {
                            match &next.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                    self.advance();
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    rparen_token_id = Some(self.current_token_id());
                                    end_span = next.span.end;
                                    self.advance();
                                    break;
                                }
                                _ => break,
                            }
                        } else {
                            break;
                        }
                    }

                    let span = Span {
                        start: rename_span.start,
                        end: end_span,
                    };

                    let syntax_node = crate::syntax::SyntaxRename {
                        rename_keyword: rename_kw_token_id,
                        lparen: lparen_token_id,
                        rparen: rparen_token_id,
                        span,
                    };
                    let syntax_id = self.syntax_arena.alloc_rename(syntax_node);

                    star.rename = Some(Box::new(AstRename {
                        node_id: self.id_gen.next(),
                        syntax_id: Some(syntax_id),
                        rename_span,
                        items,
                        has_parens,
                        span,
                    }));
                }

                _ => break,
            }
        }

        Some(star)
    }

    /// Parse the projection (column list or *) for a SELECT statement
    pub(crate) fn parse_select_projection(
        &mut self,
    ) -> crate::error::ParseResult<Option<AstProjection>> {
        // Try to parse as a pure star projection first (SELECT * or SELECT t.* with modifiers)
        // But only if what follows is a clause keyword (FROM, WHERE, etc.) or EOF.
        // If there's a comma, Jinja expression, Jinja control block, etc., fall through to column list.
        let save_idx = self.idx;
        if let Some(star) = self.parse_star_projection() {
            // Collect any trailing Jinja comments after the star (they're trivia, not projection content)
            let mut trailing_inline_comments: Vec<crate::lexer::Span> = Vec::new();
            while let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::JinjaComment) {
                    trailing_inline_comments.push(tok.span);
                    self.advance();
                } else {
                    break;
                }
            }

            // Now check what follows (after skipping Jinja comments)
            let is_pure_star = if let Some(tok) = self.peek() {
                // Pure star if followed by clause keyword or EOF
                matches!(
                    tok.kind,
                    TokenKind::Keyword(Keyword::From)
                        | TokenKind::Keyword(Keyword::Where)
                        | TokenKind::Keyword(Keyword::Group)
                        | TokenKind::Keyword(Keyword::Order)
                        | TokenKind::Keyword(Keyword::Union)
                        | TokenKind::Keyword(Keyword::Intersect)
                        | TokenKind::Keyword(Keyword::Except)
                        | TokenKind::Keyword(Keyword::Minus)
                        | TokenKind::Keyword(Keyword::Qualify)
                        | TokenKind::Keyword(Keyword::Limit)
                        | TokenKind::Keyword(Keyword::Into)
                        | TokenKind::Operator(crate::lexer::Operator::Pipe)
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                )
            } else {
                // EOF - it's a pure star
                true
            };

            if is_pure_star {
                // Pure star projection - include trailing Jinja comments in the span
                let end = trailing_inline_comments
                    .last()
                    .map(|s| s.end)
                    .unwrap_or(star.star_span.end);
                let span = crate::lexer::Span {
                    start: star.star_span.start,
                    end,
                };
                return Ok(Some(AstProjection {
                    kind: crate::ast::AstProjectionKind::Star(Box::new(star)),
                    exclude: None,
                    span,
                    node_id: self.id_gen.next(),
                }));
            } else {
                // Not a pure star - reset and parse as column list
                // This handles cases like:
                // - SELECT *, other_col FROM t  (comma)
                // - SELECT * {% if x %}, extra{% endif %} FROM t  (Jinja control block)
                // - SELECT * {{ extra_cols }} FROM t  (Jinja expression)
                self.idx = save_idx;
            }
        }

        // Parse column list with potential Jinja blocks
        let items = match self.parse_projection_items()? {
            Some(items) => items,
            None => return Ok(None),
        };
        let span = if let (Some(first), Some(last)) = (items.first(), items.last()) {
            let first_span = match &first.kind {
                crate::ast::ProjectionItemKind::SelectItem(item) => item.span,
                crate::ast::ProjectionItemKind::JinjaBlock(block) => block.span,
            };
            let last_span = match &last.kind {
                crate::ast::ProjectionItemKind::SelectItem(item) => item.span,
                crate::ast::ProjectionItemKind::JinjaBlock(block) => block.span,
            };
            Span {
                start: first_span.start,
                end: last_span.end,
            }
        } else {
            // Empty projection shouldn't happen, but handle gracefully
            Span { start: 0, end: 0 }
        };
        // Projection-level trailing `EXCLUDE (cols)` (e.g.
        // `SELECT *, NULL AS x EXCLUDE (a, b)`). Dialect-gated — only dialects
        // whose grammar has this clause (Redshift) parse it; elsewhere EXCLUDE
        // stays a bare alias / error. Gated on EXCLUDE only (a trailing EXCEPT
        // is the set operator). Reuses `parse_star_exclude` (AstExclude + CST).
        let exclude = if self.dialect.supports_projection_exclude()
            && matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Exclude))
            ) {
            self.parse_star_exclude()?.map(Box::new)
        } else {
            None
        };
        let span = match &exclude {
            Some(ex) => Span {
                start: span.start,
                end: ex.span.end,
            },
            None => span,
        };
        Ok(Some(AstProjection {
            kind: crate::ast::AstProjectionKind::Columns(items.into_iter().map(Box::new).collect()),
            exclude,
            span,
            node_id: self.id_gen.next(),
        }))
    }
    /// Parse a list of projection items, handling both regular columns and Jinja control blocks
    fn parse_projection_items(
        &mut self,
    ) -> crate::error::ParseResult<Option<Vec<crate::ast::ProjectionItem>>> {
        use crate::ast::{JinjaBlockKind, ProjectionItem};

        let mut items: Vec<ProjectionItem> = Vec::new();

        loop {
            let first_tok = match self.peek() {
                Some(t) => t,
                None => return Ok(None),
            };

            // Stop at FROM or other clause keywords or ) for subqueries
            let stop_projection = match &first_tok.kind {
                TokenKind::Keyword(Keyword::From)
                | TokenKind::Keyword(Keyword::Where)
                | TokenKind::Operator(crate::lexer::Operator::Pipe)
                | TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => true,
                TokenKind::Keyword(Keyword::Group) | TokenKind::Keyword(Keyword::Order) => self
                    .peek_ahead(1)
                    .is_some_and(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::By))),
                TokenKind::Keyword(Keyword::Union)
                | TokenKind::Keyword(Keyword::Intersect)
                | TokenKind::Keyword(Keyword::Except)
                | TokenKind::Keyword(Keyword::Minus) => !items.is_empty(),
                TokenKind::Keyword(Keyword::Qualify) => !self.can_be_identifier_token(first_tok),
                _ => false,
            };
            if stop_projection {
                break;
            }

            // Check if this is a statement-level Jinja control block ({% if/for %}) FIRST
            // This must come BEFORE collect_leading_inline_fragments() to prevent
            // multi-line Jinja blocks from being incorrectly parsed as inline fragments
            if let Some(kind) = self.peek_jinja_block_kind() {
                match kind {
                    JinjaBlockKind::If | JinjaBlockKind::For => {
                        // Check if this Jinja block contains statement fragment keywords (FROM, WHERE, JOIN, etc.)
                        // If so, stop projection parsing - this is a statement fragment, not a projection item
                        if self.peek_jinja_block_is_statement_fragment() {
                            break;
                        }

                        // Parse complete Jinja block at projection level
                        if let Some(block) = self.parse_jinja_block(kind) {
                            // Check for optional alias after the block
                            // NOTE: parse_optional_alias will NOT consume identifiers that look like
                            // the start of a new projection item (e.g., "o.updated_at" or "col,")
                            let alias = self.parse_optional_alias();

                            // Collect trailing inline fragments (e.g., {% if not loop.last %},{% endif %})
                            // This captures comma-wrapper patterns that follow the block
                            let InlineFragmentCollection {
                                fragments: trailing_inline_fragments,
                            } = self.collect_trailing_inline_fragments();

                            // Check for comma after block (only if no trailing inline fragments captured it)
                            let has_comma = if trailing_inline_fragments.is_empty() {
                                if let Some(next) = self.peek() {
                                    if matches!(
                                        next.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                    ) {
                                        self.advance(); // Consume the comma
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            items.push(ProjectionItem {
                                node_id: self.id_gen.next(),
                                kind: crate::ast::ProjectionItemKind::JinjaBlock(block),
                                has_trailing_comma: has_comma,
                                prefix_inline_fragments: Vec::new(), // No prefix fragments for statement-level blocks
                                suffix_inline_fragments: trailing_inline_fragments,
                                alias,
                            });

                            continue;
                        } else {
                            return Ok(None);
                        }
                    }
                    // {% endif %}, {% endfor %}, {% else %}, {% elif %} should not appear here (they close/branch blocks)
                    JinjaBlockKind::EndIf
                    | JinjaBlockKind::EndFor
                    | JinjaBlockKind::Else
                    | JinjaBlockKind::Elif => break,
                    // {% set %} - fall through to regular parsing
                    _ => {}
                }
            }

            // Collect any leading Jinja inline fragments prior to this item
            // Use projection context to prevent consuming statement-level blocks
            let InlineFragmentCollection {
                fragments: prefix_inline_fragments,
            } = self.collect_leading_inline_fragments_in_projection_context();

            // Re-peek after consuming leading comments
            let first_tok = match self.peek() {
                Some(t) => t,
                None => {
                    // Only trailing comments with nothing after: done.
                    break;
                }
            };

            // Stop at FROM or other clause keywords or ) for subqueries
            let stop_projection = match &first_tok.kind {
                TokenKind::Keyword(Keyword::From)
                | TokenKind::Keyword(Keyword::Where)
                | TokenKind::Operator(crate::lexer::Operator::Pipe)
                | TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => true,
                TokenKind::Keyword(Keyword::Group) | TokenKind::Keyword(Keyword::Order) => self
                    .peek_ahead(1)
                    .is_some_and(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::By))),
                TokenKind::Keyword(Keyword::Union)
                | TokenKind::Keyword(Keyword::Intersect)
                | TokenKind::Keyword(Keyword::Except)
                | TokenKind::Keyword(Keyword::Minus) => !items.is_empty(),
                TokenKind::Keyword(Keyword::Qualify) => !self.can_be_identifier_token(first_tok),
                _ => false,
            };
            if stop_projection {
                break;
            }

            // Assignment-projection peek-ahead (T-SQL `@v = expr`,
            // MySQL `@v := expr`) — see the block-context twin in
            // parse_single_projection_item_in_block.
            let assign_target_lifted: Option<crate::ast::AstSelectItemAssignTarget> = self
                .try_parse_tsql_assignment_target_lifted(
                    self.dialect.supports_select_variable_assignment(),
                );

            // Parse regular column expression with error recovery
            // This allows parsing to continue even if one projection item is invalid
            let expr = self.parse_expr_with_recovery()?;

            // Calculate span using expr_span_start and expr_span_end helpers
            let mut span = Span {
                start: crate::parser::scripting::expr_span_start(&expr),
                end: expr_span_end(&expr),
            };

            // Collect any Jinja inline comments between expression and alias
            // These should be preserved but not block alias detection
            // Example: SELECT 1 {# comment #} AS x
            let mut inline_comments_before_alias = Vec::new();
            while let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::JinjaComment) {
                    let comment_tok = self
                        .advance()
                        .expect_invariant("JinjaComment token confirmed by peek");
                    let token_id = self.last_token_id();
                    let fragment = self.build_inline_comment_fragment(comment_tok, token_id);
                    inline_comments_before_alias.push(fragment);
                } else {
                    break;
                }
            }

            // Parse optional alias (AS or bare identifier)
            let mut alias: Option<AstIdentifierWithAs> = None;
            if let Some(next) = self.peek() {
                match next.kind {
                    TokenKind::Keyword(Keyword::As) => {
                        let as_tok = self
                            .advance()
                            .expect_invariant("AS keyword confirmed by peek");

                        // Check if alias is a Jinja expression {{ ... }} or control block {% if %}...{% endif %}
                        if let Some(alias_tok) = self.peek() {
                            if matches!(alias_tok.kind, TokenKind::JinjaExprOpen) {
                                // Consume the Jinja expression tokens directly without parsing
                                let start_span = alias_tok.span.start;
                                self.advance(); // consume {{

                                // Consume all tokens until }}
                                let mut end_span = start_span;
                                while let Some(tok) = self.peek() {
                                    if matches!(tok.kind, TokenKind::JinjaExprClose) {
                                        end_span = tok.span.end;
                                        self.advance(); // consume }}
                                        break;
                                    }
                                    end_span = tok.span.end;
                                    self.advance();
                                }

                                let alias_span = Span {
                                    start: start_span,
                                    end: end_span,
                                };
                                let aid = AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_span,
                                };
                                alias = Some(AstIdentifierWithAs {
                                    node_id: self.id_gen.next(),
                                    as_span: Some(as_tok.span),
                                    ident: aid,
                                });
                                span.end = alias_span.end;
                            } else if matches!(alias_tok.kind, TokenKind::JinjaStmtOpen) {
                                // Handle Jinja control block: AS {% if %}...{% else %}...{% endif %}
                                let start_span = alias_tok.span.start;
                                self.advance(); // consume {%

                                // Track nesting depth to handle nested if blocks
                                let mut depth = 1;
                                let mut end_span = start_span;

                                while let Some(tok) = self.peek() {
                                    // Track opening of nested blocks
                                    if matches!(tok.kind, TokenKind::JinjaStmtOpen) {
                                        // Look ahead to see if it's an if/for (opening) or endif/endfor (closing)
                                        if let Some(next_tok) = self.peek_ahead(1) {
                                            if matches!(
                                                next_tok.kind,
                                                TokenKind::JinjaIf | TokenKind::JinjaFor
                                            ) {
                                                depth += 1;
                                            } else if matches!(
                                                next_tok.kind,
                                                TokenKind::JinjaEndIf | TokenKind::JinjaEndFor
                                            ) {
                                                depth -= 1;
                                            }
                                        }
                                    }

                                    end_span = tok.span.end;
                                    self.advance();

                                    // Check if we just consumed the closing %}
                                    if matches!(tok.kind, TokenKind::JinjaStmtClose) && depth == 0 {
                                        break;
                                    }
                                }

                                let alias_span = Span {
                                    start: start_span,
                                    end: end_span,
                                };
                                let aid = AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_span,
                                };
                                alias = Some(AstIdentifierWithAs {
                                    node_id: self.id_gen.next(),
                                    as_span: Some(as_tok.span),
                                    ident: aid,
                                });
                                span.end = alias_span.end;
                            } else if let Some(alias_tok) = self.advance() {
                                // Accept both identifiers and keywords as aliases (context-sensitive parsing)
                                if self.can_be_identifier_token(alias_tok) {
                                    // Check for adjacent Jinja expressions: total_{{ metric }}
                                    let alias_end =
                                        consume_adjacent_jinja_exprs(self, alias_tok.span.end);
                                    let alias_span = Span {
                                        start: alias_tok.span.start,
                                        end: alias_end,
                                    };
                                    let aid = AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_span,
                                    };
                                    alias = Some(AstIdentifierWithAs {
                                        node_id: self.id_gen.next(),
                                        as_span: Some(as_tok.span),
                                        ident: aid,
                                    });
                                    span.end = alias_span.end;
                                } else {
                                    // Reserved keyword cannot be used as column alias
                                    return Err(ParseError::unexpected_token(
                                        alias_tok.span,
                                        vec!["identifier".to_string()],
                                        Parser::token_description(alias_tok, self.source),
                                    ));
                                }
                            }
                        }
                    }
                    TokenKind::Identifier { .. } => {
                        if !self.should_stop_scan_at_statement_start(next) {
                            let alias_tok = self.advance().expect_invariant(
                                "Identifier token confirmed by peek for bare alias",
                            );
                            // Check for adjacent Jinja expressions: total_{{ metric }}
                            let alias_end = consume_adjacent_jinja_exprs(self, alias_tok.span.end);
                            let alias_span = Span {
                                start: alias_tok.span.start,
                                end: alias_end,
                            };
                            let aid = AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_span,
                            };
                            alias = Some(AstIdentifierWithAs {
                                node_id: self.id_gen.next(),
                                as_span: None,
                                ident: aid,
                            });
                            span.end = alias_span.end;
                        }
                    }
                    TokenKind::Keyword(_) => {
                        // Keywords can be used as bare column aliases (context-sensitive parsing)
                        // Check if this is actually a clause keyword that should terminate the SELECT list
                        let lexeme = next.lexeme(self.source);
                        // A trailing `EXCLUDE (...)` is the projection-level
                        // exclusion clause, not a bare alias — an alias is never
                        // followed by `(`. Only dialects with the clause treat it
                        // this way; leave it for the trailing-exclude hook.
                        let is_trailing_exclude_clause = self.dialect.supports_projection_exclude()
                            && matches!(next.kind, TokenKind::Keyword(Keyword::Exclude))
                            && self.peek_ahead(1).is_some_and(|t| {
                                matches!(
                                    t.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                )
                            });
                        if !is_clause_keyword_lexeme(lexeme)
                            && !self.dialect.is_clause_boundary_keyword(lexeme)
                            && !self.should_stop_scan_at_statement_start(next)
                            && !is_trailing_exclude_clause
                        {
                            let alias_tok = self.advance().expect_invariant(
                                "Keyword token confirmed by peek for context-sensitive alias",
                            );
                            // Check for adjacent Jinja expressions: total_{{ metric }}
                            let alias_end = consume_adjacent_jinja_exprs(self, alias_tok.span.end);
                            let alias_span = Span {
                                start: alias_tok.span.start,
                                end: alias_end,
                            };
                            let aid = AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_span,
                            };
                            alias = Some(AstIdentifierWithAs {
                                node_id: self.id_gen.next(),
                                as_span: None,
                                ident: aid,
                            });
                            span.end = alias_span.end;
                        }
                    }
                    _ => {}
                }
            }

            let mut select_item =
                crate::parser::sql_stmt::build_select_item(self.id_gen.next(), expr, alias, span);
            select_item.assign_target = assign_target_lifted;

            // Collect inline Jinja statements/comments after this item (e.g., {% if not loop.last %},{% endif %})
            // These are distinct from block-level Jinja ({% for %}...{% endfor %}) which wrap multiple items
            // Also collect any commas/punctuation that appear WITHIN the inline Jinja pattern
            // Jinja comments {# ... #} are also collected here to preserve them after columns
            let InlineFragmentCollection {
                fragments: trailing_inline_fragments,
            } = self.collect_trailing_inline_fragments();

            // Combine inline comments before alias with trailing fragments
            // Order: [comments before alias] + [comments/blocks after alias]
            // This preserves the source order: expr {# comment #} AS alias {# another #}
            let mut all_suffix_fragments = inline_comments_before_alias.clone();
            all_suffix_fragments.extend(trailing_inline_fragments.clone());

            // Check for comma ONLY if we didn't collect any inline Jinja
            // The comma is NOT consumed here - the outer loop will consume it
            let has_comma = if all_suffix_fragments.is_empty() {
                matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(crate::lexer::Punctuation::Comma))
                )
            } else {
                false
            };

            items.push(crate::ast::ProjectionItem {
                node_id: self.id_gen.next(),
                kind: crate::ast::ProjectionItemKind::SelectItem(select_item),
                has_trailing_comma: has_comma,
                prefix_inline_fragments: prefix_inline_fragments.clone(),
                suffix_inline_fragments: all_suffix_fragments,
                alias: None, // Alias is stored inside SelectItem for regular columns
            });

            // Consume comma if present (only when we didn't collect trailing jinja)
            // If we collected trailing jinja that contains a comma (like {% if not loop.last %},{% endif %}),
            // we should continue parsing more items rather than breaking
            if has_comma {
                self.advance();
            } else if trailing_inline_fragments.is_empty() {
                // Before breaking, check if next token is a Jinja block ({% if/for %})
                // These blocks can appear in projections without a preceding comma
                // Example: SELECT id {% for col in cols %}, {{col}}{% endfor %} FROM t
                if let Some(kind) = self.peek_jinja_block_kind() {
                    if matches!(kind, JinjaBlockKind::If | JinjaBlockKind::For) {
                        // Continue to next iteration to parse the Jinja block
                        continue;
                    }
                }
                // No comma, no trailing jinja, and no upcoming Jinja block - end of projection list
                break;
            }
            // If trailing inline fragments are present, continue parsing more items
            // The trailing inline fragments may contain a conditional comma pattern
        }
        Ok(Some(items))
    }
    /// Parse projection items until we hit one of the specified Jinja delimiters
    /// Returns the items parsed, leaving the delimiter as the next token
    pub(crate) fn parse_projection_items_until_delimiter(
        &mut self,
        _stop_delimiters: &[crate::ast::JinjaBlockKind],
    ) -> crate::error::ParseResult<Option<Vec<crate::ast::ProjectionItem>>> {
        let mut items = Vec::new();
        let mut pending_prefix_comma: Option<crate::ast::JinjaInlineFragment> = None;

        loop {
            let tok = match self.peek() {
                Some(t) => t,
                None => return Ok(None),
            };

            // Check if we've hit a stop delimiter
            if let Some(kind) = self.peek_jinja_block_kind() {
                if _stop_delimiters.contains(&kind) {
                    return Ok(Some(items));
                }
            }

            // Stop at clause keywords (unclosed block error)
            match &tok.kind {
                TokenKind::Keyword(Keyword::From)
                | TokenKind::Keyword(Keyword::Where)
                | TokenKind::Keyword(Keyword::Group)
                | TokenKind::Keyword(Keyword::Order) => {
                    return Ok(None);
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                    let comma_tok = match self.advance() {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let token_id = self.last_token_id();
                    let fragment = self.build_inline_punctuation_fragment(comma_tok, token_id);

                    if let Some(last_item) = items.last_mut() {
                        // Comma after an item: attach to suffix of previous item
                        last_item.suffix_inline_fragments.push(fragment);
                    } else {
                        // Comma before the first item: save for next item's prefix
                        pending_prefix_comma = Some(fragment);
                    }
                    continue;
                }
                _ => {}
            }

            // Parse next item (this handles nested blocks via recursion)
            // JinjaComment tokens will be collected as trailing inline fragments of the previous item
            // or leading inline fragments of this item by parse_single_projection_item_in_block
            if let Some(mut item) = self.parse_single_projection_item_in_block()? {
                // If we have a pending prefix comma, prepend it to the item's prefix fragments
                if let Some(comma_fragment) = pending_prefix_comma.take() {
                    item.prefix_inline_fragments.insert(0, comma_fragment);
                }
                items.push(item);
            } else {
                return Ok(None);
            }
        }
    }

    /// Parse a single projection item when inside a Jinja block
    /// Same as parse_single_projection_item but doesn't consume trailing Jinja control delimiters
    fn parse_single_projection_item_in_block(
        &mut self,
    ) -> crate::error::ParseResult<Option<crate::ast::ProjectionItem>> {
        use crate::ast::{JinjaBlockKind, ProjectionItem, ProjectionItemKind};

        // First, collect any leading Jinja comments {# ... #}
        // These get attached to the next item, just like in parse_projection_items
        // Use projection context since we're inside a Jinja block's projection list
        let InlineFragmentCollection {
            fragments: prefix_inline_fragments,
        } = self.collect_leading_inline_fragments_in_projection_context();

        let _first_tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };

        // Check if this is a Jinja control block starter (nested block)
        if let Some(kind) = self.peek_jinja_block_kind() {
            match kind {
                JinjaBlockKind::If | JinjaBlockKind::For => {
                    if let Some(block) = self.parse_jinja_block(kind) {
                        // After nested block, check for trailing Jinja comma pattern
                        let InlineFragmentCollection {
                            fragments: trailing_inline_fragments,
                        } = self.collect_trailing_inline_fragments();

                        // Check for plain comma only if no trailing jinja
                        let has_comma = if trailing_inline_fragments.is_empty() {
                            if let Some(next) = self.peek() {
                                matches!(
                                    next.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                )
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if has_comma {
                            self.advance();
                        }

                        return Ok(Some(ProjectionItem {
                            node_id: self.id_gen.next(),
                            kind: ProjectionItemKind::JinjaBlock(block),
                            has_trailing_comma: has_comma,
                            prefix_inline_fragments: prefix_inline_fragments.clone(),
                            suffix_inline_fragments: trailing_inline_fragments,
                            alias: None, // Blocks inside blocks don't have aliases
                        }));
                    }
                    return Ok(None);
                }
                // Stop at closing delimiters - they terminate the projection list
                JinjaBlockKind::EndIf | JinjaBlockKind::EndFor => {
                    return Ok(None);
                }
                _ => {}
            }
        }

        // Assignment-projection peek-ahead. T-SQL `SELECT @v = expr` and
        // MySQL `SELECT @v := expr` are `SET @v := expr` rewritten as a
        // projection; without this peek, the parser sees
        // `BinaryOp(=, Variable, expr)` (or fails on `:=`) and the
        // assignment is invisible to dynamic-SQL tracking. The `=
        // form is dialect-gated; `:=` after `@var` is unambiguous.
        let assign_target_lifted: Option<crate::ast::AstSelectItemAssignTarget> = self
            .try_parse_tsql_assignment_target_lifted(
                self.dialect.supports_select_variable_assignment(),
            );

        // Parse regular column expression with error recovery
        let expr = self.parse_expr_with_recovery()?;
        let mut span = Span {
            start: crate::parser::scripting::expr_span_start(&expr),
            end: expr_span_end(&expr),
        };

        // Parse optional alias
        let mut alias: Option<AstIdentifierWithAs> = None;
        if let Some(next) = self.peek() {
            match next.kind {
                TokenKind::Keyword(Keyword::As) => {
                    let as_tok = match self.advance() {
                        Some(t) => t,
                        None => return Ok(None),
                    };

                    // Check if alias is a Jinja expression {{ ... }}
                    if let Some(alias_tok) = self.peek() {
                        if matches!(alias_tok.kind, TokenKind::JinjaExprOpen) {
                            // Parse the Jinja expression as the alias
                            let alias_expr = self.parse_expr_with_recovery()?;
                            let alias_span = Span {
                                start: crate::parser::scripting::expr_span_start(&alias_expr),
                                end: expr_span_end(&alias_expr),
                            };

                            let aid = AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_span,
                            };
                            alias = Some(AstIdentifierWithAs {
                                node_id: self.id_gen.next(),
                                as_span: Some(as_tok.span),
                                ident: aid,
                            });
                            span.end = alias_span.end;
                        } else if let Some(alias_tok) = self.advance() {
                            if self.can_be_identifier_token(alias_tok) {
                                let mut alias_span = alias_tok.span;

                                // Check for immediately adjacent tokens
                                while let Some(next_tok) = self.peek() {
                                    if next_tok.span.start == alias_span.end
                                        && matches!(next_tok.kind, TokenKind::Identifier { .. })
                                    {
                                        self.advance();
                                        alias_span.end = next_tok.span.end;
                                    } else {
                                        break;
                                    }
                                }

                                let aid = AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_span,
                                };
                                alias = Some(AstIdentifierWithAs {
                                    node_id: self.id_gen.next(),
                                    as_span: Some(as_tok.span),
                                    ident: aid,
                                });
                                span.end = alias_span.end;
                            } else {
                                // Reserved keyword cannot be used as column alias
                                return Err(ParseError::unexpected_token(
                                    alias_tok.span,
                                    vec!["identifier".to_string()],
                                    Parser::token_description(alias_tok, self.source),
                                ));
                            }
                        }
                    }
                }
                TokenKind::Identifier { .. } => {
                    let alias_tok = match self.advance() {
                        Some(t) => t,
                        None => return Ok(None),
                    };
                    let mut alias_span = alias_tok.span;

                    while let Some(next_tok) = self.peek() {
                        if next_tok.span.start == alias_span.end
                            && matches!(next_tok.kind, TokenKind::Identifier { .. })
                        {
                            self.advance();
                            alias_span.end = next_tok.span.end;
                        } else {
                            break;
                        }
                    }

                    let aid = AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: alias_span,
                    };
                    alias = Some(AstIdentifierWithAs {
                        node_id: self.id_gen.next(),
                        as_span: None,
                        ident: aid,
                    });
                    span.end = alias_span.end;
                }
                _ => {}
            }
        }

        let select_item = AstSelectItem {
            node_id: self.id_gen.next(),
            expr,
            alias,
            assign_target: assign_target_lifted,
            span,
        };

        // When inside a Jinja block, we still need to collect inline trailing Jinja for comma patterns
        // E.g., {% if not loop.last %},{% endif %} after an item
        // Also collect Jinja comments {# ... #} that appear after the item
        // But we DON'T consume block-level delimiters like {% endfor %}
        // Use projection context to prevent consuming statement-level blocks
        let mut collection = InlineFragmentCollection::new();
        let mut saw_inline = false;
        loop {
            if self.try_collect_inline_comment(&mut collection) {
                saw_inline = true;
                continue;
            }
            // Trailing context with projection: in_projection_context=true, is_trailing=true
            if self.try_collect_inline_block_fragment_with_context(&mut collection, true, true) {
                saw_inline = true;
                continue;
            }
            if saw_inline {
                match self.peek() {
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
        let trailing_inline_fragments = collection.fragments;

        // Check for comma ONLY if we didn't collect any inline Jinja
        let has_comma = if trailing_inline_fragments.is_empty() {
            if let Some(next) = self.peek() {
                matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                )
            } else {
                false
            }
        } else {
            false
        };

        if has_comma {
            self.advance();
        }

        Ok(Some(ProjectionItem {
            node_id: self.id_gen.next(),
            kind: ProjectionItemKind::SelectItem(select_item),
            has_trailing_comma: has_comma,
            prefix_inline_fragments: prefix_inline_fragments.clone(),
            suffix_inline_fragments: trailing_inline_fragments,
            alias: None, // Alias is stored inside SelectItem
        }))
    }
    /// Parse optional table alias (AS identifier or just identifier).
    pub(crate) fn parse_optional_alias(&mut self) -> Option<AstIdentifierWithAs> {
        let tok = self.peek()?;

        // Check for AS keyword
        let as_span = if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_tok = self.advance()?;
            Some(as_tok.span)
        } else {
            None
        };

        // Check for identifier
        let tok = self.peek()?;
        if self.can_be_identifier_token(tok) {
            // Make sure it's not a clause keyword
            let lexeme = tok.lexeme(self.source);
            if is_clause_keyword_lexeme(lexeme) || self.dialect.is_clause_boundary_keyword(lexeme) {
                return None;
            }

            // If there's no AS keyword, check if this looks like the start of a new item
            // rather than an alias:
            // - identifier.something → qualified name, not an alias
            // - identifier, → next column in list, not an alias
            if as_span.is_none() {
                if let Some(next_tok) = self.peek_ahead(1) {
                    match next_tok.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            // This is "id.field" - a qualified name, not an alias
                            return None;
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                            // This is "id," - next column, not an alias
                            return None;
                        }
                        _ => {}
                    }
                }
            }

            let alias_tok = self.advance()?;
            let ident = AstIdentifier {
                node_id: self.id_gen.next(),
                span: alias_tok.span,
            };
            return Some(AstIdentifierWithAs {
                node_id: self.id_gen.next(),
                as_span,
                ident,
            });
        }

        None
    }
}
