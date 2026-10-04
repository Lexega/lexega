// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Jinja block parsing for SELECT statements.
//!
//! Handles Jinja templating constructs within SQL projections:
//! - Control flow: `{% if %}`, `{% elif %}`, `{% else %}`, `{% endif %}`
//! - Loops: `{% for col in columns %}...{% endfor %}`
//! - Variables: `{% set var = value %}`
//! - Expressions: `{{ column_name }}`, `{{ ref('model') }}`
//!
//! These constructs are common in dbt models where SQL is dynamically
//! generated based on configuration or macros.

use crate::ast::{AstExpr, AstObjectRef, AstTableRef, JinjaBlockKind};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::select::is_clause_keyword_lexeme;

impl<'a> Parser<'a> {
    /// Parse Jinja statements (like {% set %}) that appear before projection items
    /// within a Jinja block ({% for %} or {% if %})
    fn parse_jinja_statements_before_items(
        &mut self,
        _stop_delimiters: &[crate::ast::JinjaBlockKind],
    ) -> Vec<crate::ast::JinjaStmt> {
        let mut statements = Vec::new();

        loop {
            // Check if we've hit a stop delimiter
            if let Some(kind) = self.peek_jinja_block_kind() {
                if _stop_delimiters.contains(&kind) {
                    break;
                }

                // Check if this is a {% set %} statement
                if kind == crate::ast::JinjaBlockKind::Set {
                    // Capture opening delimiter tokens
                    let open_brace_tok = match self.advance() {
                        Some(t) => t,
                        None => break,
                    };
                    let open_brace_id = self.last_token_id();
                    let stmt_start = open_brace_tok.span.start;

                    let _set_kw_tok = match self.advance() {
                        Some(t) => t,
                        None => break,
                    };
                    let keyword_id = self.last_token_id();

                    // Parse the statement content (variable and expression)
                    if let Some(mut stmt) = self.parse_jinja_set_stmt() {
                        // Consume closing %}
                        if matches!(
                            self.peek().map(|t| &t.kind),
                            Some(TokenKind::JinjaStmtClose)
                        ) {
                            let close_tok = self.advance().expect_invariant("parse_jinja_statements_before_items: JinjaStmtClose '%}' confirmed by peek");
                            let close_brace_id = self.last_token_id();

                            // Update statement span to include delimiters
                            stmt.span = crate::lexer::Span {
                                start: stmt_start,
                                end: close_tok.span.end,
                            };

                            // Build CST node for the statement (no separate expr CST node - just tokens)
                            let syntax_node = crate::syntax::jinja::SyntaxJinjaStmt {
                                open_brace: open_brace_id,
                                keyword: keyword_id,
                                expr: None, // SET statements don't have a separate expr CST node
                                close_brace: close_brace_id,
                                span: stmt.span,
                            };

                            // Allocate in syntax arena
                            let syntax_id = self.syntax_arena.alloc_jinja_stmt(syntax_node);
                            stmt.syntax_id = Some(syntax_id);

                            statements.push(stmt);
                            continue;
                        }
                    }
                    // If we failed to parse, break to avoid infinite loop
                    break;
                }

                // Not a {% set %} and not a stop delimiter - must be a projection item
                break;
            }

            // Check if we've hit a clause keyword or projection item
            if let Some(tok) = self.peek() {
                match &tok.kind {
                    // Stop at clause keywords
                    TokenKind::Keyword(Keyword::From)
                    | TokenKind::Keyword(Keyword::Where)
                    | TokenKind::Keyword(Keyword::Group)
                    | TokenKind::Keyword(Keyword::Order) => break,

                    // Skip Jinja comments
                    TokenKind::JinjaComment => {
                        self.advance();
                        continue;
                    }

                    // Any other token indicates start of projection item
                    _ => break,
                }
            } else {
                // EOF
                break;
            }
        }

        statements
    }

    /// Parse a Jinja control block ({% if/for %} ... {% endif/endfor %})
    pub(crate) fn parse_jinja_block(
        &mut self,

        opening_kind: crate::ast::JinjaBlockKind,
    ) -> Option<crate::ast::JinjaBlock> {
        use crate::ast::{JinjaBlock, JinjaBlockKind};

        // Expect opening delimiter: {% keyword [condition] %}
        // The {% token should already be current (from peek_jinja_block_kind check)
        let open_brace_tok = self.advance()?; // consume {%
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?; // consume if/for keyword
        let keyword_id = self.last_token_id();

        // Parse condition expression for if/elif/for blocks
        let condition = match opening_kind {
            JinjaBlockKind::If => {
                // Parse expression until we hit %}
                self.parse_jinja_expr().ok().flatten()
            }
            JinjaBlockKind::For => {
                // For loops have special syntax: {% for var1, var2, ... in iterable %}
                // parse_jinja_for_condition handles parsing the variables and iterable separately
                self.parse_jinja_for_condition()
            }
            _ => None, // No condition for else, endif, endfor
        };

        // Expect closing %}
        if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
            return None;
        }
        let close_brace_tok = self.advance()?; // consume %}
        let close_brace_id = self.last_token_id();

        // Build the opening delimiter with parsed condition
        let opening_span = crate::lexer::Span {
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

        // Determine what closes this block
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => return None, // Only if/for supported as openers
        };

        // Parse any Jinja statements (like {% set %}) before projection items
        let then_statements = self.parse_jinja_statements_before_items(&[
            JinjaBlockKind::Elif,
            JinjaBlockKind::Else,
            closing_kind.clone(),
        ]);

        // Parse items in the primary branch until we hit elif/else/endif
        let then_items = self
            .parse_projection_items_until_delimiter(&[
                JinjaBlockKind::Elif,
                JinjaBlockKind::Else,
                closing_kind.clone(),
            ])
            .ok()
            .flatten()?;

        // Check what delimiter we hit and handle elif/else branches
        let mut elif_branches = Vec::new();
        let mut else_branch = None;

        // Handle elif branches (only for If blocks)
        if opening_kind == JinjaBlockKind::If {
            while let Some(kind) = self.peek_jinja_block_kind() {
                if kind == JinjaBlockKind::Elif {
                    // Parse elif delimiter
                    let elif_open = self.advance()?; // {%
                    let elif_open_id = self.last_token_id();
                    let _elif_kw = self.advance()?; // elif
                    let elif_kw_id = self.last_token_id();
                    let elif_condition = self.parse_jinja_expr().ok().flatten();
                    if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
                        return None;
                    }
                    let elif_close = self.advance()?; // %}
                    let elif_close_id = self.last_token_id();

                    let elif_span = Span {
                        start: elif_open.span.start,
                        end: elif_close.span.end,
                    };
                    let elif_delimiter = self.alloc_jinja_delimiter(
                        elif_span,
                        JinjaBlockKind::Elif,
                        elif_condition,
                        elif_open_id,
                        elif_kw_id,
                        elif_close_id,
                    );

                    // Parse any Jinja statements before items
                    let elif_statements = self.parse_jinja_statements_before_items(&[
                        JinjaBlockKind::Elif,
                        JinjaBlockKind::Else,
                        closing_kind.clone(),
                    ]);

                    // Parse elif branch items
                    let elif_items = self
                        .parse_projection_items_until_delimiter(&[
                            JinjaBlockKind::Elif,
                            JinjaBlockKind::Else,
                            closing_kind.clone(),
                        ])
                        .ok()
                        .flatten()?;

                    elif_branches.push(crate::ast::JinjaElifBranch {
                        node_id: self.id_gen.next(),
                        delimiter: elif_delimiter,
                        statements: elif_statements,
                        items: elif_items,
                    });
                } else {
                    break;
                }
            }
        }

        // Handle else branch
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == JinjaBlockKind::Else {
                // Parse else delimiter
                let else_open = self.advance()?; // {%
                let else_open_id = self.last_token_id();
                let _else_kw = self.advance()?; // else
                let else_kw_id = self.last_token_id();
                if !matches!(self.peek()?.kind, TokenKind::JinjaStmtClose) {
                    return None;
                }
                let else_close = self.advance()?; // %}
                let else_close_id = self.last_token_id();

                let else_span = Span {
                    start: else_open.span.start,
                    end: else_close.span.end,
                };
                let else_delimiter = self.alloc_jinja_delimiter(
                    else_span,
                    JinjaBlockKind::Else,
                    None,
                    else_open_id,
                    else_kw_id,
                    else_close_id,
                );

                // Parse any Jinja statements before items
                let else_statements =
                    self.parse_jinja_statements_before_items(std::slice::from_ref(&closing_kind));

                // Parse else branch items
                let else_items = self
                    .parse_projection_items_until_delimiter(std::slice::from_ref(&closing_kind))
                    .ok()
                    .flatten()?;

                else_branch = Some(crate::ast::JinjaElseBranch {
                    node_id: self.id_gen.next(),
                    delimiter: else_delimiter,
                    statements: else_statements,
                    items: else_items,
                });
            }
        }

        // Consume closing delimiter
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == closing_kind {
                // Parse the closing delimiter: {% endif %} or {% endfor %}
                let open_brace_tok = self.advance()?; // consume {%
                let open_brace_id = self.last_token_id();
                let _keyword_tok = self.advance()?; // consume endif/endfor keyword
                let keyword_id = self.last_token_id();
                let close_brace_tok = self.advance()?; // consume %}
                let close_brace_id = self.last_token_id();

                let closing_span = Span {
                    start: open_brace_tok.span.start,
                    end: close_brace_tok.span.end,
                };
                let closing = self.alloc_jinja_delimiter(
                    closing_span,
                    closing_kind,
                    None, // Closing delimiters have no condition
                    open_brace_id,
                    keyword_id,
                    close_brace_id,
                );
                let span = Span {
                    start: opening.span.start,
                    end: closing.span.end,
                };
                return Some(JinjaBlock {
                    node_id: self.id_gen.next(),
                    opening,
                    then_statements,
                    then_items,
                    elif_branches,
                    else_branch,
                    closing,
                    span,
                });
            }
        }

        // Missing closing delimiter
        None
    }

    /// Parse the condition part of a {% for %} loop
    /// Format: {% for var1, var2, ... in iterable %}
    /// We parse the entire sequence and build a binary expression: targets IN iterable
    fn parse_jinja_for_condition(&mut self) -> Option<crate::ast::JinjaExpr> {
        use crate::ast::{JinjaExpr, JinjaExprKind};
        use crate::syntax::{SyntaxJinjaBinaryOpTokens, SyntaxJinjaExpr, SyntaxJinjaExprKind};

        // Parse the loop variables: var1, var2, ...
        let start_span = self.peek()?.span.start;
        let mut var_exprs = Vec::new();
        let mut var_syntax_ids = Vec::new();
        let mut comma_tokens = Vec::new();

        loop {
            let tok = self.peek()?;
            match tok.kind {
                TokenKind::Identifier { .. } => {
                    let var_tok = self.advance()?;
                    let var_token_id = self.last_token_id();
                    let var_name = var_tok.lexeme(self.source).to_string();
                    let var_span = var_tok.span;

                    // Create syntax node for this variable
                    let syntax_id = self.syntax_arena.alloc_jinja_expr(SyntaxJinjaExpr {
                        kind: SyntaxJinjaExprKind::Name {
                            token: var_token_id,
                        },
                        span: var_span,
                    });
                    var_syntax_ids.push(syntax_id);
                    var_exprs.push(JinjaExpr {
                        kind: JinjaExprKind::Name(var_name),
                        span: var_span,
                        syntax_id: Some(syntax_id),
                        node_id: self.id_gen.next(),
                    });

                    // Check for comma (more variables) or 'in' keyword
                    let next = self.peek()?;
                    match next.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                            self.advance(); // consume comma
                            comma_tokens.push(self.last_token_id());
                            continue;
                        }
                        TokenKind::JinjaIn => {
                            break; // Found 'in', stop collecting variables
                        }
                        _ => return None, // Unexpected token
                    }
                }
                _ => return None,
            }
        }

        // Consume the 'in' keyword
        let in_tok = self.advance()?;
        let in_token_id = self.last_token_id();
        if !matches!(in_tok.kind, TokenKind::JinjaIn) {
            return None;
        }

        // Parse the iterable expression
        let iterable = match self.parse_jinja_expr() {
            Ok(Some(e)) => e,
            _ => return None,
        };
        let iterable_syntax_id = iterable
            .syntax_id
            .expect_invariant("iterable missing syntax_id");

        // Build the full for-loop expression
        // For single variable: var IN iterable (use BinaryOp)
        // For multiple variables (tuple unpacking): return None to let formatter emit tokens as-is
        // This preserves the comma-separated variables correctly
        if var_exprs.len() == 1 {
            // Single variable - build proper BinaryOp structure
            let left_expr = var_exprs.into_iter().next().unwrap();
            let left_syntax_id = left_expr
                .syntax_id
                .expect_invariant("left expression missing syntax_id");

            let span = crate::lexer::Span {
                start: start_span,
                end: iterable.span.end,
            };

            let syntax_id = self.syntax_arena.alloc_jinja_expr(SyntaxJinjaExpr {
                kind: SyntaxJinjaExprKind::BinaryOp {
                    left: left_syntax_id,
                    op_tokens: SyntaxJinjaBinaryOpTokens {
                        primary: in_token_id,
                        secondary: None,
                    },
                    right: iterable_syntax_id,
                },
                span,
            });

            Some(JinjaExpr {
                kind: JinjaExprKind::BinaryOp {
                    op: crate::ast::JinjaBinaryOp::In,
                    left: Box::new(left_expr),
                    right: Box::new(iterable),
                },
                span,
                syntax_id: Some(syntax_id),
                node_id: self.id_gen.next(),
            })
        } else {
            // Multiple variables (tuple unpacking) - can't represent in JinjaExpr
            // Return None so formatter emits raw tokens preserving commas
            // This fixes: {% for old, new in items %}
            None
        }
    }

    /// Parse a Jinja conditional expression: {% if %}expr{% elif %}expr{% else %}expr{% endif %}
    /// Used when Jinja control flow appears in expression contexts (FROM, WHERE, JOIN, etc.)
    /// Parse a Jinja control block (IF/FOR) in expression context
    /// Returns a structured JinjaConditional with parsed or unparsed bodies
    /// Used when Jinja control flow appears in FROM, WHERE, JOIN, ORDER BY, etc.
    pub(crate) fn parse_jinja_conditional_expr(
        &mut self,

        opening_kind: crate::ast::JinjaBlockKind,
    ) -> ParseResult<Option<AstExpr>> {
        use crate::ast::JinjaBlockKind;

        // Consume opening delimiter tokens: {% keyword %}
        let open_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        }; // {%
        let open_brace_id = self.last_token_id();
        let _keyword_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        }; // if/for keyword
        let keyword_id = self.last_token_id();
        let condition = self.parse_jinja_expr().ok().flatten(); // Parse condition
        let close_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        }; // %}
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

        // Determine what closes this block
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => {
                return Err(ParseError::new(
                    opening.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Unsupported Jinja block type in expression context: {:?}",
                            opening_kind
                        ),
                    },
                ));
            }
        };

        // Parse the "then" branch body
        // Try to parse as expression first; if that fails or we detect it's a fragment, use unparsed span
        let then_body = match self.parse_jinja_body(opening_kind.clone(), closing_kind.clone())? {
            Some(b) => b,
            None => return Ok(None),
        };

        // Parse optional elif/else branches
        let mut elif_branches = Vec::new();
        let mut else_branch = None;

        loop {
            let tok = match self.peek() {
                Some(t) => t,
                None => {
                    return Err(ParseError::new(
                        opening.span,
                        ParseErrorKind::UnclosedJinjaBlock {
                            block_type: format!("{:?}", opening_kind),
                            opening_span: opening.span,
                        },
                    ));
                }
            };

            // Check for Jinja statements
            if let Some(kind) = self.peek_jinja_block_kind() {
                match kind {
                    JinjaBlockKind::Elif => {
                        let open_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let open_brace_id = self.last_token_id();
                        let _keyword_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let keyword_id = self.last_token_id();
                        let condition = self.parse_jinja_expr().ok().flatten();
                        let close_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let close_brace_id = self.last_token_id();
                        let elif_span = Span {
                            start: open_brace_tok.span.start,
                            end: close_brace_tok.span.end,
                        };
                        let elif_delim = self.alloc_jinja_delimiter(
                            elif_span,
                            JinjaBlockKind::Elif,
                            condition,
                            open_brace_id,
                            keyword_id,
                            close_brace_id,
                        );
                        let elif_body = match self
                            .parse_jinja_body(opening_kind.clone(), closing_kind.clone())?
                        {
                            Some(b) => b,
                            None => return Ok(None),
                        };
                        elif_branches.push((elif_delim, elif_body));
                    }
                    JinjaBlockKind::Else => {
                        let open_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let open_brace_id = self.last_token_id();
                        let _keyword_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let keyword_id = self.last_token_id();
                        let close_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let close_brace_id = self.last_token_id();
                        let else_span = Span {
                            start: open_brace_tok.span.start,
                            end: close_brace_tok.span.end,
                        };
                        let else_delim = self.alloc_jinja_delimiter(
                            else_span,
                            JinjaBlockKind::Else,
                            None,
                            open_brace_id,
                            keyword_id,
                            close_brace_id,
                        );
                        let else_body = match self
                            .parse_jinja_body(opening_kind.clone(), closing_kind.clone())?
                        {
                            Some(b) => b,
                            None => return Ok(None),
                        };
                        else_branch = Some((else_delim, else_body));
                    }
                    k if k == closing_kind => {
                        // Found closing delimiter
                        let open_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let open_brace_id = self.last_token_id();
                        let _keyword_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        let keyword_id = self.last_token_id();
                        let close_brace_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
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
                        return Ok(Some(AstExpr::JinjaConditional {
                            node_id: self.id_gen.next(),
                            opening: Box::new(opening),
                            then_body: Box::new(then_body),
                            elif_branches: Box::new(elif_branches),
                            else_branch: else_branch.map(Box::new),
                            closing: Box::new(closing),
                            span,
                        }));
                    }
                    _ => {
                        // Unexpected Jinja block type
                        return Err(ParseError::new(
                            tok.span,
                            ParseErrorKind::MismatchedJinjaEndTag {
                                expected: format!("{:?}", closing_kind),
                                found: "None".to_string(), // Dead code
                            },
                        ));
                    }
                }
            } else {
                // Non-Jinja token where we expected Jinja control flow
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidJinjaExpression {
                        message: format!(
                            "Expected Jinja control flow (elif/else/{:?}), found {:?}",
                            closing_kind, tok.kind
                        ),
                        span: tok.span,
                    },
                ));
            }
        }
    }

    /// Parse the body content of a Jinja block (IF/FOR)
    /// Returns either a parsed expression or an unparsed span for SQL fragments
    fn parse_jinja_body(
        &mut self,

        opening_kind: crate::ast::JinjaBlockKind,
        closing_kind: crate::ast::JinjaBlockKind,
    ) -> ParseResult<Option<crate::ast::JinjaBody>> {
        use crate::ast::JinjaBody;

        let save_idx = self.idx;

        // Try to parse as a complete SQL expression
        if let Ok(expr) = self.parse_expr() {
            // Check if the next token suggests this isn't a complete expression parse
            if let Some(tok) = self.peek() {
                // Check for nested Jinja blocks (not elif/else/closing)
                if let Some(kind) = self.peek_jinja_block_kind() {
                    if matches!(kind, JinjaBlockKind::If | JinjaBlockKind::For)
                        && kind != closing_kind
                    {
                        // Nested control block - body is too complex, use unparsed
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                }

                // Check for ORDER BY modifiers (ASC/DESC/NULLS) that indicate SQL syntax, not expression
                match &tok.kind {
                    TokenKind::Identifier { .. }
                        if tok.lexeme(self.source).eq_ignore_ascii_case("ASC")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("DESC") =>
                    {
                        // ORDER BY syntax - use unparsed
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                    TokenKind::Keyword(Keyword::Nulls) => {
                        // NULLS FIRST/LAST - use unparsed
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                    // Comma after expression indicates inline pattern like:
                    // {% if include_prefix %}'PREFIX_',{% endif %}
                    // The comma is part of the Jinja body, not a separator
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                    // Jinja expression after parsed expression indicates the body contains Jinja interpolation:
                    // {% if order_by_price %}price {{ price_direction }} ASC,{% endif %}
                    // We only parsed "price" but the body includes the Jinja expression too
                    TokenKind::JinjaExprOpen => {
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                    // SQL clause keywords after parsed expression indicate we parsed too little:
                    // {% if cond %}{# comment #} WHERE ... {% endif %}
                    // The comment was parsed but WHERE is part of the same Jinja body
                    TokenKind::Keyword(Keyword::Where)
                    | TokenKind::Keyword(Keyword::Group)
                    | TokenKind::Keyword(Keyword::Order)
                    | TokenKind::Keyword(Keyword::Having)
                    | TokenKind::Keyword(Keyword::Limit)
                    | TokenKind::Keyword(Keyword::Offset)
                    | TokenKind::Keyword(Keyword::When)
                    | TokenKind::Keyword(Keyword::Then)
                    | TokenKind::Keyword(Keyword::And)
                    | TokenKind::Keyword(Keyword::Or) => {
                        self.idx = save_idx;
                        return self.parse_jinja_body_unparsed(opening_kind, closing_kind);
                    }
                    _ => {}
                }
            }

            // Successfully parsed as expression
            return Ok(Some(JinjaBody::Expression(Box::new(expr))));
        }

        // Failed to parse as expression - use unparsed span
        self.idx = save_idx;
        self.parse_jinja_body_unparsed(opening_kind, closing_kind)
    }

    /// Parse Jinja body as an unparsed span (for SQL fragments and complex template logic)
    fn parse_jinja_body_unparsed(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
        closing_kind: crate::ast::JinjaBlockKind,
    ) -> ParseResult<Option<crate::ast::JinjaBody>> {
        use crate::ast::JinjaBody;

        let start_tok = match self.peek() {
            Some(t) => t,
            None => {
                return Err(ParseError::new(
                    Span { start: 0, end: 0 },
                    ParseErrorKind::InvalidSyntax {
                        message: format!("Unexpected EOF after Jinja {:?} block", opening_kind),
                    },
                ));
            }
        };
        let start = start_tok.span.start;
        let mut depth = 0; // Track nested blocks of the same type

        // Consume tokens until we find elif/else/closing tag
        loop {
            let tok = match self.peek() {
                Some(t) => t,
                None => {
                    return Err(ParseError::new(
                        Span { start, end: start },
                        ParseErrorKind::InvalidSyntax {
                            message: format!("Unclosed Jinja block: expected {:?}", closing_kind),
                        },
                    ));
                }
            };

            // Check for Jinja control flow tokens
            if let Some(kind) = self.peek_jinja_block_kind() {
                // Check if this is a nested block of the same opening type
                if kind == opening_kind {
                    depth += 1;
                    self.advance();
                    continue;
                }

                // Check if this is a matching closing tag
                if kind == closing_kind {
                    if depth == 0 {
                        // Found our closing tag - capture span and return
                        let end = tok.span.start;
                        return Ok(Some(JinjaBody::Unparsed(Span { start, end })));
                    } else {
                        // Nested closing tag
                        depth -= 1;
                        self.advance();
                        continue;
                    }
                }

                // Check for elif/else at depth 0 (our level)
                if depth == 0 && matches!(kind, JinjaBlockKind::Elif | JinjaBlockKind::Else) {
                    // Found elif/else - capture span up to here
                    let end = tok.span.start;
                    return Ok(Some(JinjaBody::Unparsed(Span { start, end })));
                }
            }

            // Consume the token
            self.advance();
        }
    }
    /// Parse a table reference that starts with a Jinja control block.
    /// Uses proper recursive descent to create a structured `JinjaTableNameBlock`.
    ///
    /// Example: FROM {% if prod %}schema1{% else %}schema2{% endif %}.orders
    ///
    /// Returns a `FromItem` with `JinjaTableName` kind containing:
    /// - Opening delimiter ({% if %})
    /// - Then branch content (schema name fragment)
    /// - Optional elif/else branches with their content
    /// - Closing delimiter ({% endif %})
    /// - Optional continuation (.orders)
    /// - Optional alias
    pub(crate) fn parse_jinja_wrapped_table_reference(
        &mut self,
        _select_span: Span,
        _lateral: bool,
    ) -> ParseResult<Option<AstTableRef>> {
        // Determine the opening block kind
        let jinja_table_name =
            match self.parse_jinja_table_name_block(crate::ast::JinjaBlockKind::If)? {
                Some(b) => b,
                None => return Ok(None),
            };

        // For backward compatibility, we need to return AstTableRef
        // But the proper structure is now in JinjaTableNameBlock
        // Create a minimal AstTableRef that spans the entire construct
        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: jinja_table_name.span,
            // Span covers a Jinja table-name block (`{{ ref(...) }}`).
            // Lowering opaques out via `is_jinja_templated_span`.
            parts: None,
            identifier_arg: None,
        };

        // Extract alias and AS token
        let (alias, as_token) = if let Some(ref alias_with_as) = jinja_table_name.alias {
            let as_tok = alias_with_as.as_span.map(|as_sp| {
                // Find the token at this span's position
                let idx = self
                    .tokens
                    .iter()
                    .position(|t| t.span.start == as_sp.start)
                    .unwrap_or(0);
                crate::cst::TokenId(idx as u32)
            });
            (Some(alias_with_as.ident.clone()), as_tok)
        } else {
            (None, None)
        };

        // Create SyntaxTableRef if we have an alias
        let syntax_id = if alias.is_some() {
            let syntax_ref = crate::syntax::SyntaxTableRef {
                as_keyword: as_token,
                result_alias_as_keyword: None,
                subquery_lparen: None,
                subquery_rparen: None,
                alias_columns_lparen: None,
                alias_columns_rparen: None,
                result_alias_columns_lparen: None,
                result_alias_columns_rparen: None,
                span: jinja_table_name.span,
            };
            Some(self.syntax_arena.alloc_table_ref(syntax_ref))
        } else {
            None
        };

        Ok(Some(crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            jinja_table_name.span,
            name,
            alias,
            None,      // alias_columns
            None,      // result_alias
            None,      // result_alias_columns
            None,      // subquery
            None,      // subquery_lparen_span
            None,      // subquery_rparen_span
            None,      // values
            None,      // lateral keyword span
            None,      // time_travel
            None,      // sample
            None,      // changes
            None,      // stage
            None,      // func_expr
            None,      // with_offset
            None,      // pivot
            None,      // unpivot
            None,      // match_recognize
            None,      // table_hints
            syntax_id, // syntax_id with AS tracking
        )))
    }

    /// Parse a Jinja control block that produces a table name fragment.
    /// Proper recursive descent - parses each branch's content separately.
    fn parse_jinja_table_name_block(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
    ) -> ParseResult<Option<crate::ast::JinjaTableNameBlock>> {
        use crate::ast::{JinjaTableNameBlock, JinjaTableNameElifBranch, JinjaTableNameElseBranch};

        // Determine closing kind
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => return Ok(None),
        };

        // 1. Consume opening delimiter ({% if condition %})
        let open_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        let open_brace_id = self.last_token_id();
        let _keyword_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        let keyword_id = self.last_token_id();
        let condition = self.parse_jinja_expr().ok().flatten(); // Parse condition for If/For
        let close_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
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
        let block_start = opening.span.start;

        // 2. Parse "then" branch content (table name fragment until {% elif/else/endif %})
        let then_content = match self.parse_table_name_fragment_until_delimiter() {
            Some(s) => s,
            None => return Ok(None),
        };

        // 3. Parse optional elif branches
        let mut elif_branches = Vec::new();
        while let Some(kind) = self.peek_jinja_block_kind() {
            if matches!(kind, JinjaBlockKind::Elif) {
                let open_brace_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let open_brace_id = self.last_token_id();
                let _keyword_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let keyword_id = self.last_token_id();
                let condition = self.parse_jinja_expr().ok().flatten();
                let close_brace_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
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
                let elif_content = match self.parse_table_name_fragment_until_delimiter() {
                    Some(s) => s,
                    None => return Ok(None),
                };
                elif_branches.push(JinjaTableNameElifBranch {
                    node_id: self.id_gen.next(),
                    delimiter: elif_delimiter,
                    content: elif_content,
                });
            } else {
                break;
            }
        }

        // 4. Parse optional else branch
        let mut else_branch = None;
        if let Some(kind) = self.peek_jinja_block_kind() {
            if matches!(kind, JinjaBlockKind::Else) {
                let open_brace_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let open_brace_id = self.last_token_id();
                let _keyword_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                let keyword_id = self.last_token_id();
                let close_brace_tok = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
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
                let else_content = match self.parse_table_name_fragment_until_delimiter() {
                    Some(s) => s,
                    None => return Ok(None),
                };
                else_branch = Some(JinjaTableNameElseBranch {
                    node_id: self.id_gen.next(),
                    delimiter: else_delimiter,
                    content: else_content,
                });
            }
        }

        // 5. Consume closing delimiter ({% endif %} or {% endfor %})
        let detected = self.peek_jinja_block_kind();
        if detected != Some(closing_kind.clone()) {
            let tok = match self.peek() {
                Some(t) => t,
                None => return Ok(None),
            };
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected {:?} but found {:?}", closing_kind, detected),
                },
            ));
        }
        let open_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        let open_brace_id = self.last_token_id();
        let _keyword_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        let keyword_id = self.last_token_id();
        let close_brace_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
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

        // 6. Parse optional continuation after {% endif %} (e.g., ".orders" or ".schema.table")
        let continuation = self.parse_table_name_continuation();

        // Calculate span end before parsing alias
        let mut span_end = continuation.map(|c| c.end).unwrap_or(closing.span.end);

        // 7. Parse optional alias
        let alias = self.parse_optional_alias();
        if let Some(ref a) = alias {
            span_end = a.ident.span.end;
        }

        Ok(Some(JinjaTableNameBlock {
            node_id: self.id_gen.next(),
            opening,
            then_content,
            elif_branches,
            else_branch,
            closing,
            continuation,
            alias,
            span: Span {
                start: block_start,
                end: span_end,
            },
        }))
    }

    /// Parse table name fragment content inside a Jinja branch.
    /// Collects tokens until we hit {% elif %}, {% else %}, {% endif %}, or {% endfor %}.
    fn parse_table_name_fragment_until_delimiter(&mut self) -> Option<Span> {
        let first_tok = self.peek()?;
        let start = first_tok.span.start;
        let mut end = start;

        while let Some(_tok) = self.peek() {
            // Check if we've hit a branch delimiter
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(
                    kind,
                    JinjaBlockKind::Elif
                        | JinjaBlockKind::Else
                        | JinjaBlockKind::EndIf
                        | JinjaBlockKind::EndFor
                ) {
                    break;
                }
            }

            // Consume this token as part of the fragment
            let tok = self.advance()?;
            end = tok.span.end;
        }

        // Allow empty content (though unusual)
        Some(Span { start, end })
    }

    /// Parse optional continuation after a Jinja block closing delimiter.
    /// Returns the span covering table name parts like ".schema.table", ".table",
    /// another Jinja block `{% if %}...{% endif %}orders`, or just `orders`.
    fn parse_table_name_continuation(&mut self) -> Option<Span> {
        let tok = self.peek()?;
        let start = tok.span.start;
        let mut end = start;
        let mut consumed_any = false;

        // Loop to handle sequential Jinja blocks, identifiers, dots, expressions
        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Identifier { .. } => {
                    let t = self.advance()?;
                    end = t.span.end;
                    consumed_any = true;
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                    let t = self.advance()?;
                    end = t.span.end;
                    consumed_any = true;
                }
                TokenKind::JinjaExprOpen => {
                    // Jinja expression: {{ table_name }}
                    self.advance(); // consume {{
                    let _ = self.parse_jinja_expr().ok();

                    if let Some(close) = self.peek() {
                        if matches!(close.kind, TokenKind::JinjaExprClose) {
                            let close_tok = self.advance()?;
                            end = close_tok.span.end;
                            consumed_any = true;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                TokenKind::JinjaStmtOpen => {
                    // Another Jinja block: {% if %}...{% endif %}
                    if let Some(kind) = self.peek_jinja_block_kind() {
                        if matches!(kind, JinjaBlockKind::If | JinjaBlockKind::For) {
                            // Recursively parse the nested Jinja block as span
                            if let Some(nested_span) = self.parse_jinja_block_as_continuation_span()
                            {
                                end = nested_span.end;
                                consumed_any = true;
                                // Continue loop to parse any content after this nested block
                                continue;
                            }
                        }
                    }
                    break;
                }
                TokenKind::Keyword(_) if self.can_be_identifier_token(tok) => {
                    // Check for clause keywords that end the continuation
                    let lexeme = tok.lexeme(self.source);
                    if is_clause_keyword_lexeme(lexeme)
                        || self.dialect.is_clause_boundary_keyword(lexeme)
                    {
                        break;
                    }
                    let t = self.advance()?;
                    end = t.span.end;
                    consumed_any = true;
                }
                _ => break,
            }
        }

        if consumed_any {
            Some(Span { start, end })
        } else {
            None
        }
    }

    /// Parse a Jinja block ({% if %}...{% endif %} or {% for %}...{% endfor %}) and return its span.
    /// Used within table name continuation for chained Jinja blocks.
    fn parse_jinja_block_as_continuation_span(&mut self) -> Option<Span> {
        let opening_kind = self.peek_jinja_block_kind()?;
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => return None,
        };

        // Record start position
        let start_tok = self.peek()?;
        let start = start_tok.span.start;
        let mut end = start;

        // Consume opening delimiter ({% if condition %})
        self.advance(); // {%
        self.advance(); // if/for
        let _ = self.parse_jinja_expr().ok(); // condition
        if let Some(close) = self.peek() {
            if matches!(close.kind, TokenKind::JinjaStmtClose) {
                let close_tok = self.advance()?;
                end = close_tok.span.end;
            }
        }

        // Consume content until we hit a delimiter (elif/else/endif/endfor)
        // We also need to handle nested Jinja blocks at depth 1
        let mut depth = 1;
        while depth > 0 {
            let tok = self.peek()?;

            match &tok.kind {
                TokenKind::JinjaStmtOpen => {
                    if let Some(kind) = self.peek_jinja_block_kind() {
                        match kind {
                            JinjaBlockKind::If | JinjaBlockKind::For => {
                                // Nested opening - increase depth
                                depth += 1;
                            }
                            JinjaBlockKind::EndIf | JinjaBlockKind::EndFor => {
                                depth -= 1;
                                if depth == 0 {
                                    // This is our closing delimiter
                                    break;
                                }
                            }
                            JinjaBlockKind::Elif | JinjaBlockKind::Else => {
                                // Branch at depth 1 - just consume
                            }
                            _ => {}
                        }
                    }
                    // Consume the block delimiter tokens
                    self.advance(); // {%
                    self.advance(); // keyword
                    let _ = self.parse_jinja_expr().ok(); // optional condition
                    if let Some(close) = self.peek() {
                        if matches!(close.kind, TokenKind::JinjaStmtClose) {
                            let close_tok = self.advance()?;
                            end = close_tok.span.end;
                        }
                    }
                }
                TokenKind::Eof => break,
                _ => {
                    // Regular content token - consume
                    let t = self.advance()?;
                    end = t.span.end;
                }
            }
        }

        // Consume the closing delimiter ({% endif %} or {% endfor %})
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == closing_kind {
                self.advance(); // {%
                self.advance(); // endif/endfor
                if let Some(close) = self.peek() {
                    if matches!(close.kind, TokenKind::JinjaStmtClose) {
                        let close_tok = self.advance()?;
                        end = close_tok.span.end;
                    }
                }
            }
        }

        Some(Span { start, end })
    }
}
