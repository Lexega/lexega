// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for Databricks-specific SQL statements.
//!
//! - `OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]`
//! - `DESCRIBE HISTORY table_name`
//! - `RESTORE [TABLE] table_name [TO] {TIMESTAMP AS OF expr | VERSION AS OF int}`
//! - `CACHE [LAZY] TABLE table_name [OPTIONS (...)] [[AS] query]`
//! - `UNCACHE TABLE [IF EXISTS] table_name`
//!
//! Each parser extracts real structural fields and builds both AST and CST
//! nodes so that the formatter can emit individual tokens with proper
//! keyword casing and spacing.

use crate::ast::types::{
    AstCacheTable, AstCreateFlow, AstDescribeHistory, AstOptimize, AstRepairTable, AstRestore,
    AstRestoreTimeTravel, AstStmt, AstUncacheTable, RepairPartitionsMode, RestoreTimeTravelKind,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxDescribeHistoryStmt, SyntaxOptimizeStmt, SyntaxRestoreStmt};

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]
    // -----------------------------------------------------------------------

    /// Parse Databricks OPTIMIZE statement.
    ///
    /// Token reference (from --debug-tokens):
    ///   OPTIMIZE  → Identifier (not a Keyword!)
    ///   FULL      → Keyword(Full)
    ///   WHERE     → Keyword(Where)
    ///   ZORDER    → Identifier (not a Keyword!)
    ///   BY        → Keyword(By)
    pub(crate) fn try_parse_optimize_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("optimize")?;
        let start_span = self.current_span();

        // 1. OPTIMIZE keyword (Identifier in our lexer)
        let optimize_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["OPTIMIZE".to_string()])?;
        let optimize_keyword_id = self.last_token_id();
        let optimize_keyword_span = optimize_tok.span;
        let start = optimize_tok.span.start;

        // 2. Table name (required, possibly qualified: catalog.schema.table)
        let table_name_span = self.parse_qualified_name_span()?;
        let mut end = table_name_span.end;

        // 3. Optional FULL keyword
        let mut full_keyword_span = None;
        let mut full_keyword_id = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Full)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["FULL".to_string()])?;
                full_keyword_span = Some(t.span);
                full_keyword_id = Some(self.last_token_id());
                end = t.span.end;
            }
        }

        // 4. Optional WHERE clause
        let mut where_keyword_span = None;
        let mut where_keyword_id = None;
        let mut where_predicate = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WHERE".to_string()])?;
                where_keyword_span = Some(t.span);
                where_keyword_id = Some(self.last_token_id());

                // Parse predicate expression — stops naturally before ZORDER/semicolon
                let expr = self.parse_expr()?;
                end = expr.span().end;
                where_predicate = Some(Box::new(expr));
            }
        }

        // 5. Optional ZORDER BY (col1, col2, ...)
        let mut zorder_keyword_span = None;
        let mut zorder_keyword_id = None;
        let mut by_keyword_span = None;
        let mut by_keyword_id = None;
        let mut zorder_columns: Vec<Span> = Vec::new();
        let mut zorder_columns_span = None;
        let mut zorder_l_paren_id = None;
        let mut zorder_r_paren_id = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("ZORDER")
            {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ZORDER".to_string()])?;
                zorder_keyword_span = Some(t.span);
                zorder_keyword_id = Some(self.last_token_id());
                end = t.span.end;

                // BY keyword (required after ZORDER)
                if let Some(by_tok) = self.peek_non_trivia() {
                    if matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                        let b = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["BY".to_string()])?;
                        by_keyword_span = Some(b.span);
                        by_keyword_id = Some(self.last_token_id());
                        end = b.span.end;
                    }
                }

                // Parse parenthesized column list: (col1, col2, ...)
                if let Some(lp_tok) = self.peek_non_trivia() {
                    if matches!(lp_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let lp = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                        zorder_l_paren_id = Some(self.last_token_id());
                        let cols_start = lp.span.start;
                        end = lp.span.end;

                        // Parse comma-separated column names
                        while let Some(peek) = self.peek_non_trivia() {
                            if matches!(peek.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                                break;
                            }
                            if matches!(peek.kind, TokenKind::Eof) {
                                break;
                            }

                            // Parse column name (possibly qualified)
                            let col_span = self.parse_qualified_name_span()?;
                            zorder_columns.push(col_span);
                            end = col_span.end;

                            // Skip comma if present
                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    let c = self
                                        .advance()
                                        .ok_or_eof(self.current_span(), vec![",".to_string()])?;
                                    end = c.span.end;
                                }
                            }
                        }

                        // Closing paren
                        if let Some(rparen) = self.peek_non_trivia() {
                            if matches!(rparen.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                                let rp = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                zorder_r_paren_id = Some(self.last_token_id());
                                end = rp.span.end;
                            }
                        }

                        zorder_columns_span = Some(Span {
                            start: cols_start,
                            end,
                        });
                    } else {
                        // ZORDER BY without parens: ZORDER BY col1, col2
                        while let Some(peek) = self.peek_non_trivia() {
                            if matches!(
                                peek.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                break;
                            }
                            // Stop if we see something clearly not a column name
                            if matches!(peek.kind, TokenKind::Keyword(_))
                                && !matches!(peek.kind, TokenKind::Keyword(Keyword::As))
                            {
                                // Keywords generally can be identifiers after dot,
                                // but if we're not after a dot, this is likely
                                // a clause boundary.
                                break;
                            }

                            let col_span = self.parse_qualified_name_span()?;
                            let col_start_for_span = if zorder_columns.is_empty() {
                                col_span.start
                            } else {
                                zorder_columns_span
                                    .map(|s: Span| s.start)
                                    .unwrap_or(col_span.start)
                            };
                            zorder_columns.push(col_span);
                            end = col_span.end;
                            zorder_columns_span = Some(Span {
                                start: col_start_for_span,
                                end,
                            });

                            // Skip comma if present
                            if let Some(comma_tok) = self.peek_non_trivia() {
                                if matches!(
                                    comma_tok.kind,
                                    TokenKind::Punctuation(Punctuation::Comma)
                                ) {
                                    let c = self
                                        .advance()
                                        .ok_or_eof(self.current_span(), vec![",".to_string()])?;
                                    end = c.span.end;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build spans
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxOptimizeStmt {
            optimize_keyword: optimize_keyword_id,
            table_name_span,
            full_keyword: full_keyword_id,
            where_keyword: where_keyword_id,
            zorder_keyword: zorder_keyword_id,
            by_keyword: by_keyword_id,
            zorder_l_paren: zorder_l_paren_id,
            zorder_r_paren: zorder_r_paren_id,
            stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_optimize_stmt(syntax_node);

        // Build AST node
        let ast = AstOptimize {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            optimize_keyword_span,
            table_name_span,
            full_keyword_span,
            where_predicate,
            where_keyword_span,
            zorder_keyword_span,
            zorder_by_keyword_span: by_keyword_span,
            zorder_columns,
            zorder_columns_span,
        };
        Ok(AstStmt::Optimize(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DESCRIBE HISTORY table_name
    // -----------------------------------------------------------------------

    /// Parse Databricks DESCRIBE HISTORY statement.
    ///
    /// Token reference (from --debug-tokens):
    ///   DESCRIBE  → Keyword(Describe)
    ///   DESC      → Identifier (alias for DESCRIBE)
    ///   HISTORY   → Identifier (not a Keyword!)
    ///   table     → Identifier
    ///   .         → Punctuation(Dot)
    pub(crate) fn try_parse_describe_history_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("describe_history")?;
        let start_span = self.current_span();

        // 1. DESCRIBE / DESC keyword
        let describe_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DESCRIBE".to_string()])?;
        let describe_keyword_id = self.last_token_id();
        let describe_keyword_span = describe_tok.span;
        let start = describe_tok.span.start;

        // 2. HISTORY keyword (Identifier in our lexer)
        let history_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["HISTORY".to_string()])?;
        let history_keyword_id = self.last_token_id();
        let history_keyword_span = history_tok.span;

        // 3. Table name (required, possibly qualified: catalog.schema.table)
        let table_name_span = self.parse_qualified_name_span()?;
        let end = table_name_span.end;

        // Build spans
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxDescribeHistoryStmt {
            describe_keyword: describe_keyword_id,
            history_keyword: history_keyword_id,
            table_name_span,
            stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_describe_history_stmt(syntax_node);

        // Build AST node
        let ast = AstDescribeHistory {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            describe_keyword_span,
            history_keyword_span,
            table_name_span,
        };
        Ok(AstStmt::DescribeHistory(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // RESTORE [TABLE] table_name [TO] {TIMESTAMP AS OF expr | VERSION AS OF int}
    // -----------------------------------------------------------------------

    /// Parse Databricks RESTORE statement.
    ///
    /// Token reference (from --debug-tokens):
    ///   RESTORE   → Identifier (not a Keyword!)
    ///   TABLE     → Keyword(Table) — optional
    ///   TO        → Keyword(To) — optional
    ///   TIMESTAMP → Identifier (not a Keyword!)
    ///   VERSION   → Identifier (not a Keyword!)
    ///   AS        → Keyword(As)
    ///   OF        → Keyword(Of)
    pub(crate) fn try_parse_restore_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("restore")?;
        let start_span = self.current_span();

        // 1. RESTORE keyword (Identifier in our lexer)
        let restore_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["RESTORE".to_string()])?;
        let restore_keyword_id = self.last_token_id();
        let restore_keyword_span = restore_tok.span;
        let start = restore_tok.span.start;

        // 2. Optional TABLE keyword
        let mut table_keyword_span = None;
        let mut table_keyword_id = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Table)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
                table_keyword_span = Some(t.span);
                table_keyword_id = Some(self.last_token_id());
            }
        }

        // 3. Table name (required, possibly qualified: catalog.schema.table)
        let table_name_span = self.parse_qualified_name_span()?;

        // 4. Optional TO keyword
        let mut to_keyword_span = None;
        let mut to_keyword_id = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::To)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                to_keyword_span = Some(t.span);
                to_keyword_id = Some(self.last_token_id());
            }
        }

        // 5. Time travel clause: TIMESTAMP AS OF expr | VERSION AS OF int
        let tt_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected TIMESTAMP or VERSION after RESTORE table".to_string(),
                },
            )
        })?;

        let tt_lexeme = tt_tok.lexeme(self.source).to_ascii_uppercase();
        let time_travel_kind = match tt_lexeme.as_str() {
            "TIMESTAMP" => RestoreTimeTravelKind::TimestampAsOf,
            "VERSION" => RestoreTimeTravelKind::VersionAsOf,
            _ => {
                return Err(ParseError::new(
                    tt_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TIMESTAMP or VERSION, found '{}'",
                            tt_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
        };

        // Consume TIMESTAMP/VERSION
        let tt_keyword_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TIMESTAMP/VERSION".to_string()])?;
        let time_travel_keyword_id = self.last_token_id();
        let tt_keyword_span = tt_keyword_tok.span;
        let tt_start = tt_keyword_tok.span.start;

        // 6. AS keyword (required)
        let as_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected AS after TIMESTAMP/VERSION".to_string(),
                },
            )
        })?;
        if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
            return Err(ParseError::new(
                as_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected AS, found '{}'", as_tok.lexeme(self.source)),
                },
            ));
        }
        let as_tok = self.advance().unwrap();
        let as_keyword_id = self.last_token_id();
        let as_keyword_span = as_tok.span;

        // 7. OF keyword (required)
        let of_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected OF after AS".to_string(),
                },
            )
        })?;
        if !matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
            return Err(ParseError::new(
                of_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected OF, found '{}'", of_tok.lexeme(self.source)),
                },
            ));
        }
        let of_tok = self.advance().unwrap();
        let of_keyword_id = self.last_token_id();
        let of_keyword_span = of_tok.span;

        // 8. Parse the value expression (timestamp expression or version number)
        let value_expr = self.parse_expr()?;
        let value_end = value_expr.span().end;

        let time_travel_span = Span {
            start: tt_start,
            end: value_end,
        };

        let time_travel = AstRestoreTimeTravel {
            kind: time_travel_kind,
            keyword_span: tt_keyword_span,
            as_keyword_span,
            of_keyword_span,
            value: Box::new(value_expr),
            span: time_travel_span,
        };

        // Build full statement span
        let stmt_span = Span {
            start,
            end: value_end,
        };

        // Build CST node
        let syntax_node = SyntaxRestoreStmt {
            restore_keyword: restore_keyword_id,
            table_keyword: table_keyword_id,
            table_name_span,
            to_keyword: to_keyword_id,
            time_travel_keyword: time_travel_keyword_id,
            as_keyword: as_keyword_id,
            of_keyword: of_keyword_id,
            stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_restore_stmt(syntax_node);

        // Build AST node
        let ast = AstRestore {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            restore_keyword_span,
            table_keyword_span,
            table_name_span,
            to_keyword_span,
            time_travel,
        };
        Ok(AstStmt::Restore(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // CACHE [LAZY] TABLE table_name [OPTIONS ('key' [=] 'val')] [[AS] query]
    // -----------------------------------------------------------------------

    /// Parse Databricks CACHE TABLE statement.
    ///
    /// Token reference (from --debug-tokens):
    ///   CACHE   → Identifier (not a Keyword!)
    ///   LAZY    → Identifier (not a Keyword!)
    ///   TABLE   → Keyword(Table)
    ///   OPTIONS → Identifier (not a Keyword!)
    ///   AS      → Keyword(As)
    ///   SELECT  → Keyword(Select) (the cached query)
    pub(crate) fn try_parse_cache_table_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("cache_table")?;
        let start_span = self.current_span();

        // 1. CACHE keyword (Identifier in our lexer)
        let cache_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CACHE".to_string()])?;
        let cache_keyword_span = cache_tok.span;
        let start = cache_tok.span.start;

        // 2. Optional LAZY keyword (Identifier)
        let mut lazy_keyword_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("LAZY")
            {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["LAZY".to_string()])?;
                lazy_keyword_span = Some(t.span);
            }
        }

        // 3. TABLE keyword (required)
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TABLE keyword after CACHE, found '{}'",
                        table_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let table_keyword_span = table_tok.span;

        // 4. Table name (required, possibly qualified: catalog.schema.table)
        let table_name_span = self.parse_qualified_name_span()?;
        let mut end = table_name_span.end;

        // 5. Optional OPTIONS clause: OPTIONS ('storageLevel' [=] 'value')
        let mut options_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
            {
                let options_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIONS".to_string()])?;
                let options_start = options_tok.span.start;

                // Expect LParen
                let lp_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                if !matches!(lp_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    return Err(ParseError::new(
                        lp_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected '(' after OPTIONS".to_string(),
                        },
                    ));
                }

                // Consume everything inside parens until RParen
                let mut depth = 1u32;
                while depth > 0 {
                    let inner = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    match inner.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                        TokenKind::Eof => {
                            return Err(ParseError::new(
                                inner.span,
                                ParseErrorKind::InvalidStatement {
                                    message: "Unexpected end of input inside OPTIONS clause"
                                        .to_string(),
                                },
                            ));
                        }
                        _ => {}
                    }
                    end = inner.span.end;
                }

                options_span = Some(Span {
                    start: options_start,
                    end,
                });
            }
        }

        // 6. Optional AS keyword + query, or bare query (SELECT ...)
        let mut as_keyword_span = None;
        let mut query = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
                as_keyword_span = Some(as_tok.span);

                // Parse the query (SELECT, WITH, or parenthesized subquery)
                let q = self.try_parse_set_or_select_stmt()?;
                end = q.span().end;
                query = Some(Box::new(q));
            } else if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Select)
                    | TokenKind::Keyword(Keyword::With)
                    | TokenKind::Punctuation(Punctuation::LParen)
            ) {
                // Bare query without AS
                let q = self.try_parse_set_or_select_stmt()?;
                end = q.span().end;
                query = Some(Box::new(q));
            }
        }

        let stmt_span = Span { start, end };

        let ast = AstCacheTable {
            node_id: self.id_gen.next(),
            span: stmt_span,
            cache_keyword_span,
            lazy_keyword_span,
            table_keyword_span,
            table_name_span,
            options_span,
            as_keyword_span,
            query,
        };
        Ok(AstStmt::CacheTable(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // UNCACHE TABLE [IF EXISTS] table_name
    // -----------------------------------------------------------------------

    /// Parse Databricks UNCACHE TABLE statement.
    ///
    /// Token reference (from --debug-tokens):
    ///   UNCACHE → Identifier (not a Keyword!)
    ///   TABLE   → Keyword(Table)
    ///   IF      → Keyword(If)
    ///   EXISTS  → Keyword(Exists)
    pub(crate) fn try_parse_uncache_table_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("uncache_table")?;
        let start_span = self.current_span();

        // 1. UNCACHE keyword (Identifier in our lexer)
        let uncache_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["UNCACHE".to_string()])?;
        let uncache_keyword_span = uncache_tok.span;
        let start = uncache_tok.span.start;

        // 2. TABLE keyword (required)
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TABLE keyword after UNCACHE, found '{}'",
                        table_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let table_keyword_span = table_tok.span;

        // 3. Optional IF EXISTS
        let mut if_exists = false;
        let mut if_exists_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                let if_start = if_tok.span.start;

                // Expect EXISTS
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected EXISTS after IF, found '{}'",
                                exists_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                if_exists = true;
                if_exists_span = Some(Span {
                    start: if_start,
                    end: exists_tok.span.end,
                });
            }
        }

        // 4. Table name (required, possibly qualified: catalog.schema.table)
        let table_name_span = self.parse_qualified_name_span()?;
        let end = table_name_span.end;

        let stmt_span = Span { start, end };

        let ast = AstUncacheTable {
            node_id: self.id_gen.next(),
            span: stmt_span,
            uncache_keyword_span,
            table_keyword_span,
            if_exists,
            if_exists_span,
            table_name_span,
        };
        Ok(AstStmt::UncacheTable(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // [MSCK] REPAIR TABLE table_identifier [{ADD|DROP|SYNC} PARTITIONS]
    // -----------------------------------------------------------------------

    /// Parse SparkSQL / Databricks REPAIR TABLE statement.
    ///
    /// Token reference (--debug-tokens --dialect databricks):
    ///   MSCK       → Identifier (not a Keyword!)
    ///   REPAIR     → Identifier (not a Keyword!)
    ///   TABLE      → Keyword(Table)
    ///   ADD        → Identifier (not a Keyword!)
    ///   DROP       → Keyword(Drop)
    ///   SYNC       → Identifier (not a Keyword!)
    ///   PARTITIONS → Identifier (not a Keyword!)
    pub(crate) fn try_parse_repair_table_stmt(&mut self) -> ParseResult<AstStmt> {
        self.try_parse_repair_table_stmt_impl(false)
    }

    /// Parse SparkSQL / Databricks MSCK REPAIR TABLE statement.
    pub(crate) fn try_parse_msck_repair_table_stmt(&mut self) -> ParseResult<AstStmt> {
        self.try_parse_repair_table_stmt_impl(true)
    }

    fn try_parse_repair_table_stmt_impl(&mut self, has_msck_prefix: bool) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("repair_table")?;
        let start_span = self.current_span();

        let mut start = start_span.start;

        let mut msck_keyword_span = None;

        if has_msck_prefix {
            let msck_tok = self
                .advance()
                .ok_or_eof(start_span, vec!["MSCK".to_string()])?;
            msck_keyword_span = Some(msck_tok.span);
            start = msck_tok.span.start;

            // Expect REPAIR next (Identifier)
            let repair_peek = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected REPAIR after MSCK".to_string(),
                    },
                )
            })?;
            if !(matches!(repair_peek.kind, TokenKind::Identifier { .. })
                && repair_peek
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("REPAIR"))
            {
                return Err(ParseError::new(
                    repair_peek.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected REPAIR after MSCK".to_string(),
                    },
                ));
            }
        }

        // REPAIR keyword (Identifier)
        let repair_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["REPAIR".to_string()])?;
        let repair_keyword_span = repair_tok.span;
        if !has_msck_prefix {
            start = repair_tok.span.start;
        }

        // TABLE keyword (required)
        let table_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after REPAIR".to_string(),
                },
            )
        })?;
        if !matches!(table_peek.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::new(
                table_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after REPAIR".to_string(),
                },
            ));
        }
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        let table_keyword_span = table_tok.span;

        // table_identifier (1/2/3-part)
        let table_name_span = self.parse_qualified_name_span()?;
        let mut end = table_name_span.end;

        // Optional: {ADD|DROP|SYNC} PARTITIONS
        let mut partitions_mode = None;
        let mut partitions_mode_span = None;
        let mut partitions_keyword_span = None;

        if let Some(tok) = self.peek_non_trivia() {
            // If we see a semicolon or EOF, there is no suffix
            if !matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                let is_add = matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("ADD");
                let is_sync = matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("SYNC");
                let is_drop = matches!(tok.kind, TokenKind::Keyword(Keyword::Drop))
                    || tok.lexeme(self.source).eq_ignore_ascii_case("DROP");

                if is_add || is_drop || is_sync {
                    let action_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["ADD/DROP/SYNC".to_string()])?;
                    partitions_mode_span = Some(action_tok.span);

                    partitions_mode = Some(if is_add {
                        RepairPartitionsMode::Add
                    } else if is_sync {
                        RepairPartitionsMode::Sync
                    } else {
                        RepairPartitionsMode::Drop
                    });

                    // Expect PARTITIONS next
                    let part_peek = self.peek_non_trivia().ok_or_else(|| {
                        ParseError::new(
                            self.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message: "Expected PARTITIONS after ADD/DROP/SYNC".to_string(),
                            },
                        )
                    })?;
                    if !(matches!(part_peek.kind, TokenKind::Identifier { .. })
                        && part_peek
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("PARTITIONS"))
                    {
                        return Err(ParseError::new(
                            part_peek.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected PARTITIONS after ADD/DROP/SYNC".to_string(),
                            },
                        ));
                    }
                    let part_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["PARTITIONS".to_string()])?;
                    partitions_keyword_span = Some(part_tok.span);
                    end = part_tok.span.end;
                }
            }
        }

        let stmt_span = Span { start, end };

        let ast = AstRepairTable {
            node_id: self.id_gen.next(),
            span: stmt_span,
            msck_keyword_span,
            repair_keyword_span,
            table_keyword_span,
            table_name_span,
            partitions_mode,
            partitions_mode_span,
            partitions_keyword_span,
        };
        Ok(AstStmt::RepairTable(Box::new(ast)))
    }

    /// Parse Databricks Lakeflow CREATE FLOW statement.
    ///
    /// Supported heads:
    /// - CREATE FLOW <name> AS AUTO CDC INTO <target> ...
    /// - CREATE FLOW <name> AS APPLY CHANGES INTO <target> ...
    pub(crate) fn try_parse_create_flow_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_flow")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Optional OR REPLACE / OR REFRESH
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                let _or_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OR".to_string()])?;

                let next = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE or REFRESH after OR in CREATE FLOW"
                                .to_string(),
                        },
                    )
                })?;

                if next.lexeme(self.source).eq_ignore_ascii_case("REPLACE")
                    || next.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                {
                    let _repl_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["REPLACE or REFRESH".to_string()])?;
                } else {
                    return Err(ParseError::new(
                        next.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE or REFRESH after OR in CREATE FLOW"
                                .to_string(),
                        },
                    ));
                }
            }
        }

        // FLOW keyword (identifier in current lexer)
        let flow_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected FLOW after CREATE".to_string(),
                },
            )
        })?;
        if !(matches!(flow_peek.kind, TokenKind::Identifier { .. })
            && flow_peek.lexeme(self.source).eq_ignore_ascii_case("FLOW"))
        {
            return Err(ParseError::new(
                flow_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FLOW after CREATE".to_string(),
                },
            ));
        }
        let flow_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FLOW".to_string()])?;
        let _flow_tok = flow_tok;

        // Flow name
        let _flow_name_span = self.parse_qualified_name_span()?;

        // AS
        let as_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected AS in CREATE FLOW statement".to_string(),
                },
            )
        })?;
        if !matches!(as_peek.kind, TokenKind::Keyword(Keyword::As)) {
            return Err(ParseError::new(
                as_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AS in CREATE FLOW statement".to_string(),
                },
            ));
        }
        let _as_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;

        // AUTO CDC INTO | APPLY CHANGES INTO
        let mode_start = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message:
                        "Expected AUTO CDC INTO or APPLY CHANGES INTO in CREATE FLOW statement"
                            .to_string(),
                },
            )
        })?;

        if matches!(mode_start.kind, TokenKind::Keyword(Keyword::Auto)) {
            let _auto_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["AUTO".to_string()])?;

            let cdc_peek = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected CDC after AUTO".to_string(),
                    },
                )
            })?;
            if !(matches!(cdc_peek.kind, TokenKind::Identifier { .. })
                && cdc_peek.lexeme(self.source).eq_ignore_ascii_case("CDC"))
            {
                return Err(ParseError::new(
                    cdc_peek.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected CDC after AUTO".to_string(),
                    },
                ));
            }
            let _cdc_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["CDC".to_string()])?;
        } else if matches!(mode_start.kind, TokenKind::Identifier { .. })
            && mode_start.lexeme(self.source).eq_ignore_ascii_case("APPLY")
        {
            let _apply_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["APPLY".to_string()])?;

            let changes_peek = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected CHANGES after APPLY".to_string(),
                    },
                )
            })?;
            if !(matches!(changes_peek.kind, TokenKind::Identifier { .. })
                && changes_peek
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("CHANGES"))
            {
                return Err(ParseError::new(
                    changes_peek.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected CHANGES after APPLY".to_string(),
                    },
                ));
            }
            let _changes_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["CHANGES".to_string()])?;
        } else {
            return Err(ParseError::new(
                mode_start.span,
                ParseErrorKind::InvalidStatement {
                    message:
                        "Expected AUTO CDC INTO or APPLY CHANGES INTO in CREATE FLOW statement"
                            .to_string(),
                },
            ));
        }

        let into_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTO in CREATE FLOW statement".to_string(),
                },
            )
        })?;
        if !matches!(into_peek.kind, TokenKind::Keyword(Keyword::Into)) {
            return Err(ParseError::new(
                into_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTO in CREATE FLOW statement".to_string(),
                },
            ));
        }
        let _into_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INTO".to_string()])?;

        // Target table/view name
        let _target_name_span = self.parse_qualified_name_span()?;

        // FROM <source>
        let from_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected FROM in CREATE FLOW statement".to_string(),
                },
            )
        })?;
        if !matches!(from_peek.kind, TokenKind::Keyword(Keyword::From)) {
            return Err(ParseError::new(
                from_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FROM in CREATE FLOW statement".to_string(),
                },
            ));
        }
        let _from_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;

        // Source can be STREAM(...) or a regular relation.
        if let Some(src_peek) = self.peek_non_trivia() {
            if matches!(src_peek.kind, TokenKind::Identifier { .. })
                && src_peek.lexeme(self.source).eq_ignore_ascii_case("STREAM")
            {
                let _stream_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["STREAM".to_string()])?;
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let _stream_args = self.consume_balanced_parens()?;
                    }
                }
            } else {
                let _src_name_span = self.parse_qualified_name_span()?;
            }
        }

        // KEYS (...) is required
        let keys_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected KEYS clause in CREATE FLOW statement".to_string(),
                },
            )
        })?;
        if !(matches!(keys_peek.kind, TokenKind::Identifier { .. })
            && keys_peek.lexeme(self.source).eq_ignore_ascii_case("KEYS"))
        {
            return Err(ParseError::new(
                keys_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected KEYS clause in CREATE FLOW statement".to_string(),
                },
            ));
        }
        let keys_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["KEYS".to_string()])?;
        let mut end = keys_tok.span.end;

        if let Some(lp) = self.peek_non_trivia() {
            if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                end = self.consume_balanced_parens()?.end;
            } else {
                return Err(ParseError::new(
                    lp.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected parenthesized KEYS list in CREATE FLOW statement"
                            .to_string(),
                    },
                ));
            }
        }

        // Consume trailing optional clauses until statement boundary.
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof => break,
                TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                TokenKind::Punctuation(Punctuation::LParen) => {
                    end = self.consume_balanced_parens()?.end;
                }
                _ => {
                    let t = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["trailing CREATE FLOW clause token".to_string()],
                    )?;
                    end = t.span.end;
                }
            }
        }

        let stmt = AstCreateFlow {
            node_id: self.id_gen.next(),
            span: Span { start, end },
        };
        Ok(AstStmt::CreateFlow(Box::new(stmt)))
    }

    /// Parse legacy Databricks Lakeflow APPLY CHANGES INTO statement.
    ///
    /// Form:
    /// APPLY CHANGES INTO <target>
    /// FROM <source>
    /// KEYS (...)
    /// [optional clauses...]
    pub(crate) fn try_parse_apply_changes_into_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("apply_changes_into")?;

        let apply_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["APPLY".to_string()])?;
        let start = apply_tok.span.start;

        let changes_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected CHANGES after APPLY".to_string(),
                },
            )
        })?;
        if !(matches!(changes_peek.kind, TokenKind::Identifier { .. })
            && changes_peek
                .lexeme(self.source)
                .eq_ignore_ascii_case("CHANGES"))
        {
            return Err(ParseError::new(
                changes_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected CHANGES after APPLY".to_string(),
                },
            ));
        }
        let _changes_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CHANGES".to_string()])?;

        let into_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTO after APPLY CHANGES".to_string(),
                },
            )
        })?;
        if !matches!(into_peek.kind, TokenKind::Keyword(Keyword::Into)) {
            return Err(ParseError::new(
                into_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected INTO after APPLY CHANGES".to_string(),
                },
            ));
        }
        let _into_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INTO".to_string()])?;

        let _target_name_span = self.parse_qualified_name_span()?;

        let from_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected FROM in APPLY CHANGES INTO statement".to_string(),
                },
            )
        })?;
        if !matches!(from_peek.kind, TokenKind::Keyword(Keyword::From)) {
            return Err(ParseError::new(
                from_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FROM in APPLY CHANGES INTO statement".to_string(),
                },
            ));
        }
        let _from_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;

        if let Some(src_peek) = self.peek_non_trivia() {
            if matches!(src_peek.kind, TokenKind::Identifier { .. })
                && src_peek.lexeme(self.source).eq_ignore_ascii_case("STREAM")
            {
                let _stream_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["STREAM".to_string()])?;
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let _stream_args = self.consume_balanced_parens()?;
                    }
                }
            } else {
                let _src_name_span = self.parse_qualified_name_span()?;
            }
        }

        let keys_peek = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected KEYS clause in APPLY CHANGES INTO statement".to_string(),
                },
            )
        })?;
        if !(matches!(keys_peek.kind, TokenKind::Identifier { .. })
            && keys_peek.lexeme(self.source).eq_ignore_ascii_case("KEYS"))
        {
            return Err(ParseError::new(
                keys_peek.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected KEYS clause in APPLY CHANGES INTO statement".to_string(),
                },
            ));
        }
        let keys_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["KEYS".to_string()])?;
        let mut end = keys_tok.span.end;

        if let Some(lp) = self.peek_non_trivia() {
            if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                end = self.consume_balanced_parens()?.end;
            } else {
                return Err(ParseError::new(
                    lp.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected parenthesized KEYS list in APPLY CHANGES INTO statement"
                            .to_string(),
                    },
                ));
            }
        }

        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof => break,
                TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                TokenKind::Punctuation(Punctuation::LParen) => {
                    end = self.consume_balanced_parens()?.end;
                }
                _ => {
                    let t = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["trailing APPLY CHANGES clause token".to_string()],
                    )?;
                    end = t.span.end;
                }
            }
        }

        let stmt = AstCreateFlow {
            node_id: self.id_gen.next(),
            span: Span { start, end },
        };
        Ok(AstStmt::CreateFlow(Box::new(stmt)))
    }
}
