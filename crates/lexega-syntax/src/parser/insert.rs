// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::ast::*;
use crate::error::{ExpectInvariant, ParseError};
use crate::lexer::{Keyword, TokenKind};
use crate::parser::Parser;
use crate::Span;

/// Result of parsing an INSERT body (VALUES or SELECT query)
struct InsertBodyParsed {
    body_span: Option<Span>,
    source_kind: AstInsertSourceKind,
    values_span: Option<Span>,
    values_keyword_span: Option<Span>,
    values_rows_spans: Vec<Span>,
    values_rows: Vec<Vec<AstExpr>>,
    query_span: Option<Span>,
    query: Option<Box<AstStmt>>,
    default_values_span: Option<Span>,
    set_clause_span: Option<Span>,
    set_assignments: Vec<(String, AstExpr)>,
    values_row_constructor: bool,
}

/// Result of parsing the INSERT/REPLACE target (INTO, table, PARTITION,
/// table hints, column list).
struct InsertTargetParsed {
    target_table_span: Option<Span>,
    partition_span: Option<Span>,
    columns_span: Option<Span>,
    column_count: Option<usize>,
    end: u32,
    into_span: Option<Span>,
    table_hints: Option<Box<crate::ast::AstTableHintClause>>,
}

impl<'a> Parser<'a> {
    fn parse_values_row(&mut self) -> crate::error::ParseResult<Option<(Vec<AstExpr>, Span)>> {
        // Expect opening paren
        let lparen = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
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
        let lparen_tok = match self.advance() {
            Some(t) => t,
            None => return Ok(None),
        };
        let start = lparen_tok.span.start;

        let mut exprs = Vec::new();

        // Check for empty row: ()
        if let Some(rp) = self.peek() {
            if matches!(
                rp.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                let rparen = match self.advance() {
                    Some(t) => t,
                    None => return Ok(None),
                };
                return Ok(Some((
                    exprs,
                    Span {
                        start,
                        end: rparen.span.end,
                    },
                )));
            }
        }

        // Parse comma-separated expressions
        loop {
            // Parse expression (could be DEFAULT, NULL, or any expression)
            let expr = if let Some(tok) = self.peek() {
                match &tok.kind {
                    TokenKind::Keyword(Keyword::Default) => {
                        let default_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        // Represent DEFAULT as a special identifier
                        AstExpr::Ident {
                            node_id: self.id_gen.next(),
                            column_ref: crate::ast::AstColumnRef {
                                node_id: self.id_gen.next(),
                                qualifier: None,
                                name: AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: default_tok.span,
                                },
                            },
                        }
                    }
                    TokenKind::Keyword(Keyword::Null) => {
                        let null_tok = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        AstExpr::Literal {
                            node_id: self.id_gen.next(),
                            literal: crate::ast::AstLiteral::Null {
                                span: null_tok.span,
                            },
                        }
                    }
                    _ => self.parse_expr()?,
                }
            } else {
                return Ok(None);
            };

            exprs.push(expr);

            // Check for comma (more expressions) or closing paren
            if let Some(next) = self.peek() {
                match &next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        self.advance();
                        continue;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let rparen = match self.advance() {
                            Some(t) => t,
                            None => return Ok(None),
                        };
                        return Ok(Some((
                            exprs,
                            Span {
                                start,
                                end: rparen.span.end,
                            },
                        )));
                    }
                    _ => {
                        return Err(ParseError::unexpected_token(
                            next.span,
                            vec![",".to_string(), ")".to_string()],
                            Parser::token_description(next, self.source),
                        ));
                    }
                }
            } else {
                return Ok(None);
            }
        }
    }

    /// Helper to parse INSERT target table and optional column list.
    fn parse_insert_target_and_columns(
        &mut self,
        span_end: u32,
    ) -> crate::error::ParseResult<InsertTargetParsed> {
        let mut target_table_span: Option<Span> = None;
        let mut partition_span: Option<Span> = None;
        let mut columns_span: Option<Span> = None;
        let mut column_count: Option<usize> = None;
        let mut updated_end = span_end;
        let mut into_span: Option<Span> = None;
        let mut table_hints: Option<Box<crate::ast::AstTableHintClause>> = None;

        // Expect INTO next, but stay tolerant if it's missing.
        let mut has_into = false;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Into)) {
                let into_tok = self
                    .advance()
                    .expect_invariant("INTO keyword confirmed by peek");
                into_span = Some(into_tok.span);
                has_into = true;
            }
        }

        // Capture target table span. MySQL also allows the table directly
        // after INSERT/REPLACE (no INTO).
        if has_into || self.dialect.supports_insert_optional_into() {
            let stop_at_set = self.dialect.supports_insert_set_form();
            let stop_at_partition = self.dialect.supports_insert_partition_clause();
            let stop_at_value = self.dialect.supports_insert_value_synonym();
            // Consume tokens up to LParen, VALUES, SELECT, WITH (hints), or
            // a dialect-gated clause head (SET / PARTITION / VALUE-synonym).
            let start_idx = self.idx;
            while let Some(t) = self.peek() {
                match &t.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    | TokenKind::Keyword(Keyword::Values)
                    | TokenKind::Keyword(Keyword::Default)
                    | TokenKind::Keyword(Keyword::Select)
                    | TokenKind::Keyword(Keyword::With) => break,
                    TokenKind::Keyword(Keyword::Set) if stop_at_set => break,
                    TokenKind::Keyword(Keyword::Partition) if stop_at_partition => break,
                    // MySQL `INSERT ... TABLE tbl` — TABLE heads a query
                    // source, not part of the target name.
                    TokenKind::Keyword(Keyword::Table)
                        if self.dialect.supports_table_query_statement() =>
                    {
                        break
                    }
                    // `VALUE` synonym lexes as an identifier; only a clause
                    // head when directly followed by '('.
                    TokenKind::Identifier {
                        kind: crate::lexer::IdentifierKind::Unquoted,
                    } if stop_at_value
                        && t.lexeme(self.source).eq_ignore_ascii_case("VALUE")
                        && self.peek_ahead(1).is_some_and(|n| {
                            matches!(
                                n.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        }) =>
                    {
                        break
                    }
                    TokenKind::Eof | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                        break
                    }
                    _ => {
                        let _ = self.advance();
                    }
                }
            }
            let end_idx = self.idx;
            if end_idx > start_idx {
                let first = &self.tokens[start_idx];
                let last = &self.tokens[end_idx - 1];
                target_table_span = Some(Span {
                    start: first.span.start,
                    end: last.span.end,
                });
                updated_end = last.span.end;
            }
        }

        // MySQL: PARTITION (p, ...) selection between target and column list.
        if self.dialect.supports_insert_partition_clause() {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Partition)) {
                    let p_tok = self
                        .advance()
                        .expect_invariant("PARTITION keyword confirmed by peek");
                    let p_start = p_tok.span.start;
                    let mut p_end = p_tok.span.end;
                    if let Some(lp) = self.peek() {
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let mut depth: usize = 0;
                            while let Some(t) = self.advance() {
                                match t.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                        depth += 1
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                        depth -= 1;
                                        if depth == 0 {
                                            p_end = t.span.end;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    partition_span = Some(Span {
                        start: p_start,
                        end: p_end,
                    });
                    updated_end = p_end;
                }
            }
        }

        // MSSQL: Parse optional table hints, e.g. INSERT INTO t WITH (TABLOCK) (col1, col2)
        // This must be parsed BEFORE the column list since hints come first.
        let hints = self.try_parse_table_hint_clause()?;
        if let Some(h) = hints {
            updated_end = h.span.end;
            table_hints = Some(h);
        }

        // Optional column list starting with '('. Capture up to matching ')' and count columns.
        if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                let start = tok.span.start;
                let mut depth: usize = 0;
                let mut col_count: usize = 0;
                let mut seen_content = false; // Track if we've seen content in current column

                while let Some(t) = self.advance() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                            depth += 1;
                            if depth == 1 {
                                // First lparen, reset for counting
                                col_count = 0;
                                seen_content = false;
                            }
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            depth -= 1;
                            if depth == 0 {
                                // Closing the column list
                                if seen_content {
                                    col_count += 1; // Count the last column
                                }
                                columns_span = Some(Span {
                                    start,
                                    end: t.span.end,
                                });
                                column_count = Some(col_count);
                                updated_end = t.span.end;
                                break;
                            }
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                            if depth == 1 && seen_content {
                                col_count += 1; // Count this column
                                seen_content = false;
                            }
                        }
                        _ => {
                            if depth == 1 {
                                seen_content = true; // We've seen content for this column
                            }
                        }
                    }
                }
            }
        }

        Ok(InsertTargetParsed {
            target_table_span,
            partition_span,
            columns_span,
            column_count,
            end: updated_end,
            into_span,
            table_hints,
        })
    }

    /// Helper to parse INSERT body (VALUES or SELECT query) using natural descent.
    fn parse_insert_body_natural(&mut self) -> crate::error::ParseResult<InsertBodyParsed> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind};

        let mut source_kind = AstInsertSourceKind::Unknown;
        let mut values_span: Option<Span> = None;
        let mut values_keyword_span: Option<Span> = None;
        let mut values_rows_spans: Vec<Span> = Vec::new();
        let mut values_rows: Vec<Vec<AstExpr>> = Vec::new();
        let mut query_span: Option<Span> = None;
        let mut query: Option<Box<AstStmt>> = None;
        let mut default_values_span: Option<Span> = None;
        let mut values_row_constructor = false;
        let body_start: u32;
        let mut body_end: Option<u32> = None;

        // Check what comes next: DEFAULT VALUES, VALUES, SET, or SELECT/WITH
        let next_tok = self.peek();
        if next_tok.is_none() {
            return Ok(InsertBodyParsed {
                body_span: None,
                source_kind,
                values_span,
                values_keyword_span,
                values_rows_spans,
                values_rows,
                query_span,
                query,
                default_values_span,
                set_clause_span: None,
                set_assignments: Vec::new(),
                values_row_constructor: false,
            });
        }

        let tok = next_tok.unwrap();

        // MySQL: INSERT/REPLACE ... SET col = expr, ...
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Set))
            && self.dialect.supports_insert_set_form()
        {
            let (set_span, assignments) = self.parse_insert_set_assignments()?;
            return Ok(InsertBodyParsed {
                body_span: Some(set_span),
                source_kind: AstInsertSourceKind::SetAssignments,
                values_span: None,
                values_keyword_span: None,
                values_rows_spans: Vec::new(),
                values_rows: Vec::new(),
                query_span: None,
                query: None,
                default_values_span: None,
                set_clause_span: Some(set_span),
                set_assignments: assignments,
                values_row_constructor: false,
            });
        }

        // PostgreSQL: DEFAULT VALUES (check before plain VALUES)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
            // Look ahead: DEFAULT must be followed by VALUES
            let next_after = self.peek_ahead(1);
            if next_after.is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Values))) {
                let default_tok = self.advance().expect_invariant("DEFAULT confirmed by peek");
                let values_tok = self
                    .advance()
                    .expect_invariant("VALUES confirmed by peek_ahead");
                let dv_span = Span {
                    start: default_tok.span.start,
                    end: values_tok.span.end,
                };
                source_kind = AstInsertSourceKind::DefaultValues;
                default_values_span = Some(dv_span);

                let body_span = Some(dv_span);
                return Ok(InsertBodyParsed {
                    body_span,
                    source_kind,
                    values_span,
                    values_keyword_span,
                    values_rows_spans,
                    values_rows,
                    query_span,
                    query,
                    default_values_span,
                    set_clause_span: None,
                    set_assignments: Vec::new(),
                    values_row_constructor: false,
                });
            }
        }

        // MySQL: `VALUE` synonym lexes as an identifier; a clause head only
        // when directly followed by '('.
        let is_value_synonym = self.dialect.supports_insert_value_synonym()
            && matches!(
                tok.kind,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                }
            )
            && tok.lexeme(self.source).eq_ignore_ascii_case("VALUE")
            && self.peek_ahead(1).is_some_and(|n| {
                matches!(
                    n.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            });

        if matches!(tok.kind, TokenKind::Keyword(Keyword::Values)) || is_value_synonym {
            // VALUES-based INSERT
            source_kind = AstInsertSourceKind::Values;
            let values_tok = self.advance().expect_invariant("VALUES keyword after peek");
            values_keyword_span = Some(values_tok.span);
            body_start = values_tok.span.start;
            values_span = Some(Span {
                start: values_tok.span.start,
                end: values_tok.span.end,
            });

            // Parse VALUES rows naturally with column count validation
            let mut first_row_col_count: Option<usize> = None;
            let mut row_number = 0;

            while let Some(next) = self.peek() {
                // MySQL 8.0.19: VALUES ROW(...), ROW(...) — consume the ROW
                // keyword when directly followed by '('.
                let mut row_kw_start: Option<u32> = None;
                if matches!(next.kind, TokenKind::Keyword(Keyword::Row))
                    && self.peek_ahead(1).is_some_and(|n| {
                        matches!(
                            n.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        )
                    })
                {
                    let row_tok = self
                        .advance()
                        .expect_invariant("ROW keyword confirmed by peek");
                    row_kw_start = Some(row_tok.span.start);
                    values_row_constructor = true;
                }

                // Check if next token is opening paren (start of row)
                if !matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
                ) {
                    // Not a row, done with VALUES
                    break;
                }

                row_number += 1;

                // Parse this row naturally
                if let Some((exprs, row_span)) = self.parse_values_row()? {
                    let row_span = match row_kw_start {
                        Some(start) => Span {
                            start,
                            end: row_span.end,
                        },
                        None => row_span,
                    };
                    body_end = Some(row_span.end);
                    values_rows_spans.push(row_span);

                    // Store the parsed expressions
                    let col_count = exprs.len();
                    values_rows.push(exprs.clone());

                    // Track column count for first row (used by formatter, not validation)
                    if first_row_col_count.is_none() {
                        first_row_col_count = Some(col_count);
                    }

                    // Check for comma (more rows)
                    if let Some(comma) = self.peek() {
                        if matches!(
                            comma.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            let _ = self.advance(); // consume comma
                            continue;
                        }
                    }
                    // No comma, done with rows
                    break;
                } else {
                    // Failed to parse row
                    return Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidSyntax {
                            message: format!("Failed to parse VALUES row {}", row_number),
                        },
                    ));
                }
            }

            // Update values_span to cover all rows
            if let Some(end) = body_end {
                values_span = Some(Span {
                    start: values_tok.span.start,
                    end,
                });
            }
        } else if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Select) | TokenKind::Keyword(Keyword::With)
        ) || (matches!(tok.kind, TokenKind::Keyword(Keyword::Table))
            && self.dialect.supports_table_query_statement())
        {
            // Query-based INSERT (incl. MySQL `INSERT ... TABLE tbl`)
            source_kind = AstInsertSourceKind::Query;
            body_start = tok.span.start;

            // Parse the SELECT/WITH query naturally
            // Use try_parse_stmt_core to handle WITH...SELECT or plain SELECT
            match self.parse_statement() {
                Ok(stmt) => {
                    let stmt_span = stmt.span();
                    body_end = Some(stmt_span.end);
                    query_span = Some(stmt_span);
                    query = Some(Box::new(stmt));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        } else {
            // Unknown/unsupported
            return Ok(InsertBodyParsed {
                body_span: None,
                source_kind,
                values_span,
                values_keyword_span,
                values_rows_spans,
                values_rows,
                query_span,
                query,
                default_values_span,
                set_clause_span: None,
                set_assignments: Vec::new(),
                values_row_constructor: false,
            });
        }

        let body_span = body_end.map(|end| Span {
            start: body_start,
            end,
        });

        Ok(InsertBodyParsed {
            body_span,
            source_kind,
            values_span,
            values_keyword_span,
            values_rows_spans,
            values_rows,
            query_span,
            query,
            default_values_span,
            set_clause_span: None,
            set_assignments: Vec::new(),
            values_row_constructor,
        })
    }

    /// Parse MySQL `SET col = expr, ...` assignments (INSERT/REPLACE SET
    /// form). Returns the clause span (SET through last expression) and the
    /// parsed assignments. Caller has confirmed the SET keyword via peek.
    fn parse_insert_set_assignments(
        &mut self,
    ) -> crate::error::ParseResult<(Span, Vec<(String, AstExpr)>)> {
        use crate::error::ExpectInvariant;

        let set_tok = self
            .advance()
            .expect_invariant("SET keyword confirmed by peek");
        let mut end = set_tok.span.end;
        let mut assignments: Vec<(String, AstExpr)> = Vec::new();

        loop {
            // Column name (identifier or keyword used as identifier).
            let col_name = match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) =>
                {
                    let name = tok.lexeme(self.source).to_string();
                    self.advance();
                    name
                }
                _ => break,
            };

            // Expect '='
            match self.peek() {
                Some(tok)
                    if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) =>
                {
                    self.advance();
                }
                _ => {
                    return Err(ParseError::new(
                        self.current_span(),
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected '=' after column name '{}' in SET assignment",
                                col_name
                            ),
                        },
                    ));
                }
            }

            let expr = self.parse_expr()?;
            end = expr.span().end;
            assignments.push((col_name, expr));

            match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) =>
                {
                    self.advance();
                }
                _ => break,
            }
        }

        Ok((
            Span {
                start: set_tok.span.start,
                end,
            },
            assignments,
        ))
    }

    /// Parse MySQL `ON DUPLICATE KEY UPDATE col = expr, ...`. Rewinds and
    /// returns None when the lookahead is not exactly ON DUPLICATE KEY
    /// UPDATE (DUPLICATE lexes as an identifier between three keywords).
    fn try_parse_on_duplicate_key_update(
        &mut self,
    ) -> crate::error::ParseResult<Option<crate::ast::AstOnDuplicateKeyUpdate>> {
        use crate::error::ExpectInvariant;

        let saved_idx = self.idx;
        let on_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) => self
                .advance()
                .expect_invariant("ON keyword confirmed by peek"),
            _ => return Ok(None),
        };

        // DUPLICATE (identifier), KEY, UPDATE — rewind on any mismatch.
        match self.peek() {
            Some(tok)
                if matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("DUPLICATE") =>
            {
                self.advance();
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        }
        match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Key)) => {
                self.advance();
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        }
        let update_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Update)) => {
                self.advance().expect_invariant("UPDATE confirmed by peek")
            }
            _ => {
                self.idx = saved_idx;
                return Ok(None);
            }
        };

        let keywords_span = Span {
            start: on_tok.span.start,
            end: update_tok.span.end,
        };

        // Assignments: col = expr, ... (RHS may use VALUES(col) / alias.col).
        let mut assignments: Vec<(String, AstExpr)> = Vec::new();
        let mut end = keywords_span.end;
        loop {
            let col_name = match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) =>
                {
                    let name = tok.lexeme(self.source).to_string();
                    self.advance();
                    name
                }
                _ => break,
            };

            match self.peek() {
                Some(tok)
                    if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) =>
                {
                    self.advance();
                }
                _ => {
                    return Err(ParseError::new(
                        self.current_span(),
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected '=' after column name '{}' in ON DUPLICATE KEY UPDATE",
                                col_name
                            ),
                        },
                    ));
                }
            }

            let expr = self.parse_expr()?;
            end = expr.span().end;
            assignments.push((col_name, expr));

            match self.peek() {
                Some(tok)
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) =>
                {
                    self.advance();
                }
                _ => break,
            }
        }

        Ok(Some(crate::ast::AstOnDuplicateKeyUpdate {
            node_id: self.id_gen.next(),
            span: Span {
                start: keywords_span.start,
                end,
            },
            keywords_span,
            assignments,
        }))
    }

    /// Parse an INSERT statement with Result-based error handling.
    /// Automatically detects and routes to multi-insert parser if ALL/FIRST is present.
    pub(crate) fn try_parse_insert_stmt_in_mode(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

        let kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INSERT".to_string()])?; // INSERT
        let keyword_span = kw.span;
        let mut span = keyword_span;
        let mut overwrite_span: Option<Span> = None;
        let mut replace_span: Option<Span> = None;

        // MySQL: LOW_PRIORITY / HIGH_PRIORITY / IGNORE modifiers. These lex
        // as unquoted identifiers and are MySQL reserved words, so lexeme
        // matching cannot collide with a table name.
        let (priority, ignore_span) = if self.dialect.supports_insert_modifiers() {
            let (p, i, end) = self.parse_insert_modifiers(span.end);
            span.end = end;
            (p, i)
        } else {
            (None, None)
        };

        // Optional OVERWRITE keyword
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OVERWRITE") {
                let ow = self
                    .advance()
                    .expect_invariant("OVERWRITE keyword confirmed by peek");
                overwrite_span = Some(ow.span);
                span.end = ow.span.end;
            }
        }

        // Optional OR REPLACE (Databricks: INSERT OR REPLACE INTO ...)
        if overwrite_span.is_none() {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                    let saved_idx = self.idx;
                    let or_tok = self.advance().expect_invariant("OR confirmed by peek");
                    if let Some(next) = self.peek() {
                        if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                            let repl_tok =
                                self.advance().expect_invariant("REPLACE confirmed by peek");
                            replace_span = Some(Span {
                                start: or_tok.span.start,
                                end: repl_tok.span.end,
                            });
                            span.end = repl_tok.span.end;
                        } else {
                            self.idx = saved_idx; // Not OR REPLACE — restore
                        }
                    } else {
                        self.idx = saved_idx;
                    }
                }
            }
        }

        // DETECTION: Check if this is a multi-table INSERT (ALL/FIRST)
        if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::All) | TokenKind::Keyword(Keyword::First)
            ) {
                // This is a multi-insert. Rewind and delegate to multi-insert parser.
                self.idx = self.idx.saturating_sub(1); // Back up past INSERT
                if overwrite_span.is_some() {
                    self.idx = self.idx.saturating_sub(1); // Back up past OVERWRITE too
                }

                return self.try_parse_multi_insert_stmt();
            }
        }

        // Parse target table, optional PARTITION selection, optional table
        // hints, and optional column list
        let target = self.parse_insert_target_and_columns(span.end)?;
        let InsertTargetParsed {
            target_table_span,
            partition_span,
            columns_span,
            column_count: _column_count,
            end: updated_end,
            into_span: into_kw_span,
            table_hints,
        } = target;
        span.end = updated_end;

        // VALIDATION: INSERT statement requires INTO with target table
        if target_table_span.is_none() {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::MissingClause {
                    clause: "INSERT statement requires INTO clause with target table".to_string(),
                },
            ));
        }

        // PostgreSQL: Parse optional OVERRIDING { SYSTEM | USER } VALUE
        let mut overriding_value_span: Option<crate::Span> = None;
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OVERRIDING") {
                let ov_tok = self
                    .advance()
                    .expect_invariant("OVERRIDING confirmed by peek");
                let ov_start = ov_tok.span.start;
                // Expect SYSTEM or USER
                let _kind_tok = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["SYSTEM".to_string(), "USER".to_string()],
                )?;
                // Expect VALUE (singular, not VALUES)
                let value_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["VALUE".to_string()])?;
                let ov_span = crate::Span {
                    start: ov_start,
                    end: value_tok.span.end,
                };
                overriding_value_span = Some(ov_span);
                span.end = ov_span.end;
            }
        }

        // MSSQL: Parse optional OUTPUT clause before VALUES/SELECT body
        let output = self.try_parse_output_clause(&[
            Keyword::Values,
            Keyword::Select,
            Keyword::With,
            Keyword::Default,
            Keyword::Returning,
        ])?;
        if let Some(ref out) = output {
            span.end = out.span.end;
        }

        // Parse body naturally: VALUES or SELECT query
        let body_start = self.current_span().end;
        let body = self.parse_insert_body_natural()?;

        if let Some(ref bs) = body.body_span {
            span.end = bs.end;
        }

        // VALIDATION: INSERT requires VALUES, DEFAULT VALUES, or SELECT
        if body.body_span.is_none()
            && !matches!(body.source_kind, AstInsertSourceKind::DefaultValues)
        {
            return Err(ParseError::new(
                Span {
                    start: body_start,
                    end: body_start,
                },
                ParseErrorKind::MissingClause {
                    clause: "INSERT statement requires VALUES clause or SELECT query".to_string(),
                },
            ));
        }

        // Column list and VALUES counts tracked but not validated
        // Snowflake runtime will validate column count matching

        // MySQL 8.0.19 row alias: VALUES (...) AS alias [(col, ...)].
        // Only valid after a VALUES body; rewinds if AS is not followed by
        // an identifier.
        let mut row_alias_span: Option<Span> = None;
        if matches!(body.source_kind, AstInsertSourceKind::Values) {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                    let saved_idx = self.idx;
                    let as_tok = self.advance().expect_invariant("AS confirmed by peek");
                    match self.peek() {
                        Some(alias_tok)
                            if matches!(alias_tok.kind, TokenKind::Identifier { .. }) =>
                        {
                            let alias = self
                                .advance()
                                .expect_invariant("alias identifier confirmed by peek");
                            let mut alias_end = alias.span.end;
                            // Optional column-alias list: (x, y)
                            if let Some(lp) = self.peek() {
                                if matches!(
                                    lp.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    let mut depth: usize = 0;
                                    while let Some(t) = self.advance() {
                                        match t.kind {
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::LParen,
                                            ) => depth += 1,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::RParen,
                                            ) => {
                                                depth -= 1;
                                                if depth == 0 {
                                                    alias_end = t.span.end;
                                                    break;
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            row_alias_span = Some(Span {
                                start: as_tok.span.start,
                                end: alias_end,
                            });
                            span.end = alias_end;
                        }
                        _ => {
                            self.idx = saved_idx;
                        }
                    }
                }
            }
        }

        // Parse optional ON CONFLICT clause (PostgreSQL upsert)
        let on_conflict = self.try_parse_on_conflict()?;
        if let Some(ref oc) = on_conflict {
            span.end = oc.span.end;
        }

        // Parse optional ON DUPLICATE KEY UPDATE clause (MySQL upsert).
        // Disjoint from ON CONFLICT — both rewind cleanly on mismatch.
        let on_duplicate_key_update = self.try_parse_on_duplicate_key_update()?;
        if let Some(ref odku) = on_duplicate_key_update {
            span.end = odku.span.end;
        }

        // Parse optional RETURNING clause (PostgreSQL)
        let returning = self.try_parse_returning()?;
        if let Some(ref ret) = returning {
            span.end = ret.span.end;
        }

        let mut stmt = crate::parser::sql_stmt::build_insert(
            self.id_gen.next(),
            span,
            keyword_span,
            overwrite_span,
            target_table_span,
            columns_span,
            body.body_span,
            body.source_kind,
            body.values_span,
            body.values_rows_spans,
            body.values_rows,
            body.query_span,
            body.query,
        );
        stmt.into_span = into_kw_span;
        stmt.values_keyword_span = body.values_keyword_span;
        stmt.output = output;
        stmt.returning = returning;
        stmt.on_conflict = on_conflict;
        stmt.overriding_value_span = overriding_value_span;
        stmt.default_values_span = body.default_values_span;
        stmt.replace_span = replace_span;
        stmt.table_hints = table_hints;
        stmt.priority = priority;
        stmt.ignore_span = ignore_span;
        stmt.partition_span = partition_span;
        stmt.row_alias_span = row_alias_span;
        stmt.set_clause_span = body.set_clause_span;
        stmt.set_assignments = body.set_assignments;
        stmt.on_duplicate_key_update = on_duplicate_key_update;
        stmt.values_row_constructor = body.values_row_constructor;
        Ok(AstStmt::Insert(Box::new(stmt)))
    }

    /// Consume MySQL INSERT/REPLACE modifiers (LOW_PRIORITY / HIGH_PRIORITY /
    /// IGNORE). Returns (priority, ignore_span, updated_end). Caller has
    /// checked `supports_insert_modifiers()`.
    fn parse_insert_modifiers(
        &mut self,
        span_end: u32,
    ) -> (Option<crate::ast::AstInsertPriority>, Option<Span>, u32) {
        let mut priority: Option<crate::ast::AstInsertPriority> = None;
        let mut ignore_span: Option<Span> = None;
        let mut end = span_end;

        while let Some(tok) = self.peek() {
            if !matches!(
                tok.kind,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                }
            ) {
                break;
            }
            let lex = tok.lexeme(self.source);
            if priority.is_none() && lex.eq_ignore_ascii_case("LOW_PRIORITY") {
                let t = self
                    .advance()
                    .expect_invariant("LOW_PRIORITY confirmed by peek");
                priority = Some(crate::ast::AstInsertPriority::Low { span: t.span });
                end = t.span.end;
            } else if priority.is_none() && lex.eq_ignore_ascii_case("HIGH_PRIORITY") {
                let t = self
                    .advance()
                    .expect_invariant("HIGH_PRIORITY confirmed by peek");
                priority = Some(crate::ast::AstInsertPriority::High { span: t.span });
                end = t.span.end;
            } else if ignore_span.is_none() && lex.eq_ignore_ascii_case("IGNORE") {
                let t = self.advance().expect_invariant("IGNORE confirmed by peek");
                ignore_span = Some(t.span);
                end = t.span.end;
            } else {
                break;
            }
        }

        (priority, ignore_span, end)
    }

    /// Parse a MySQL REPLACE statement (row-level delete-then-insert).
    ///
    /// REPLACE [LOW_PRIORITY] [INTO] tbl [PARTITION (...)]
    ///     { [(cols)] {VALUES|VALUE} (...), ... | SET col = expr, ... | SELECT ... }
    ///
    /// No IGNORE, no ON DUPLICATE KEY UPDATE, no row alias.
    pub(crate) fn try_parse_replace_into_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ParseError, ParseErrorKind, ParseResultExt};

        let kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?; // REPLACE
        let keyword_span = kw.span;
        let mut span = keyword_span;

        let priority = if self.dialect.supports_insert_modifiers() {
            let (p, _ignore, end) = self.parse_insert_modifiers(span.end);
            span.end = end;
            p
        } else {
            None
        };

        let target = self.parse_insert_target_and_columns(span.end)?;
        let InsertTargetParsed {
            target_table_span,
            partition_span,
            columns_span,
            column_count: _column_count,
            end: updated_end,
            into_span,
            table_hints: _table_hints,
        } = target;
        span.end = updated_end;

        if target_table_span.is_none() {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::MissingClause {
                    clause: "REPLACE statement requires a target table".to_string(),
                },
            ));
        }

        let body_start = self.current_span().end;
        let body = self.parse_insert_body_natural()?;
        if let Some(ref bs) = body.body_span {
            span.end = bs.end;
        }

        if body.body_span.is_none() {
            return Err(ParseError::new(
                Span {
                    start: body_start,
                    end: body_start,
                },
                ParseErrorKind::MissingClause {
                    clause: "REPLACE statement requires VALUES, SET, or a SELECT query".to_string(),
                },
            ));
        }

        Ok(AstStmt::ReplaceInto(Box::new(crate::ast::AstReplaceInto {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            priority,
            into_span,
            target_table_span,
            partition_span,
            columns_span,
            body_span: body.body_span,
            source_kind: body.source_kind,
            values_span: body.values_span,
            values_keyword_span: body.values_keyword_span,
            values_rows_spans: body.values_rows_spans,
            values_rows: body.values_rows,
            values_row_constructor: body.values_row_constructor,
            query_span: body.query_span,
            query: body.query,
            set_clause_span: body.set_clause_span,
            set_assignments: body.set_assignments,
        })))
    }

    /// Helper to parse a WHEN clause in multi-insert.
    fn parse_multi_insert_when_clause(&mut self) -> Option<(AstMultiInsertWhenClause, u32)> {
        let when_tok = self.advance()?;
        let when_span = when_tok.span;

        // Parse condition until THEN
        let cond_start_idx = self.idx;
        while let Some(t) = self.peek() {
            if t.lexeme(self.source).eq_ignore_ascii_case("THEN") {
                break;
            }
            let _ = self.advance();
        }
        let cond_end_idx = self.idx;
        let mut condition_span: Option<Span> = None;
        if cond_end_idx > cond_start_idx {
            let first = &self.tokens[cond_start_idx];
            let last = &self.tokens[cond_end_idx - 1];
            condition_span = Some(Span {
                start: first.span.start,
                end: last.span.end,
            });
        }

        let then_tok = self.advance()?; // THEN
        let then_span = then_tok.span;
        let mut span_end = then_span.end;

        // Parse one or more INTO clauses
        let mut w_into = Vec::new();
        while let Some(next) = self.peek() {
            match &next.kind {
                TokenKind::Keyword(Keyword::Into) => {
                    let into = self.parse_multi_insert_into_clause()?;
                    span_end = into
                        .values_span
                        .or(into.columns_span)
                        .or(into.target_table_span)
                        .unwrap_or(into.into_span)
                        .end;
                    w_into.push(into);
                }
                _ => break,
            }
        }

        Some((
            AstMultiInsertWhenClause {
                node_id: self.id_gen.next(),
                when_span,
                condition_span,
                then_span,
                into_clauses: w_into,
            },
            span_end,
        ))
    }

    /// Helper to parse ELSE INTO clauses in multi-insert.
    fn parse_multi_insert_else_clauses(&mut self) -> (Vec<AstMultiInsertIntoClause>, u32) {
        let else_tok = self.advance().expect_invariant(
            "ELSE keyword confirmed before calling parse_multi_insert_else_clauses",
        );
        let mut span_end = else_tok.span.end;
        let mut else_into_clauses = Vec::new();

        while let Some(next) = self.peek() {
            match &next.kind {
                TokenKind::Keyword(Keyword::Into) => {
                    let into = match self.parse_multi_insert_into_clause() {
                        Some(i) => i,
                        None => break,
                    };
                    span_end = into
                        .values_span
                        .or(into.columns_span)
                        .or(into.target_table_span)
                        .unwrap_or(into.into_span)
                        .end;
                    else_into_clauses.push(into);
                }
                _ => break,
            }
        }

        (else_into_clauses, span_end)
    }

    /// Parse a multi-table INSERT statement with Result-based error handling.
    /// Handles: INSERT [OVERWRITE] {ALL|FIRST} INTO ... INTO ... SELECT ...
    pub(crate) fn try_parse_multi_insert_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

        let kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INSERT".to_string()])?; // INSERT
        let keyword_span = kw.span;
        let mut span = keyword_span;
        let mut overwrite_span: Option<Span> = None;

        // Optional OVERWRITE
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OVERWRITE") {
                let ow = self
                    .advance()
                    .expect_invariant("OVERWRITE keyword confirmed by peek");
                overwrite_span = Some(ow.span);
                span.end = ow.span.end;
            }
        }

        // Mode: ALL or FIRST (required)
        let mode_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALL or FIRST".to_string()])?;
        let mode_span = mode_tok.span;
        let _mode = match &mode_tok.kind {
            TokenKind::Keyword(Keyword::All) => AstMultiInsertMode::UnconditionalAll,
            TokenKind::Keyword(Keyword::First) => AstMultiInsertMode::ConditionalFirst,
            _ => {
                return Err(ParseError::new(
                    mode_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Expected ALL or FIRST after INSERT [OVERWRITE], found: {}",
                            mode_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
        };
        span.end = mode_span.end;

        let mut into_clauses = Vec::new();
        let mut when_clauses = Vec::new();
        let mut else_into_clauses = Vec::new();

        // Parse INTO/WHEN/ELSE blocks until we hit the subquery (SELECT)
        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Keyword(Keyword::Into) => {
                    let into = self.parse_multi_insert_into_clause().ok_or_else(|| {
                        ParseError::new(
                            self.current_span(),
                            ParseErrorKind::InvalidSyntax {
                                message: "Failed to parse INTO clause in multi-table INSERT"
                                    .to_string(),
                            },
                        )
                    })?;
                    span.end = into
                        .values_span
                        .or(into.columns_span)
                        .or(into.target_table_span)
                        .unwrap_or(into.into_span)
                        .end;
                    into_clauses.push(into);
                }
                TokenKind::Keyword(Keyword::When) => {
                    let (when_clause, end) =
                        self.parse_multi_insert_when_clause().ok_or_else(|| {
                            ParseError::new(
                                self.current_span(),
                                ParseErrorKind::InvalidSyntax {
                                    message: "Failed to parse WHEN clause in multi-table INSERT"
                                        .to_string(),
                                },
                            )
                        })?;
                    span.end = end;
                    when_clauses.push(when_clause);
                }
                TokenKind::Keyword(Keyword::Else) => {
                    let (else_clauses, end) = self.parse_multi_insert_else_clauses();
                    span.end = end;
                    else_into_clauses = else_clauses;
                }
                TokenKind::Keyword(Keyword::Select) => break,
                _ => {
                    let _ = self.advance();
                }
            }
        }

        // Parse trailing subquery (SELECT statement)
        let mut subquery: Option<Box<crate::ast::AstStmt>> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Select)) {
                if let Ok(select) = self.try_parse_set_or_select_stmt() {
                    span.end = select.span().end;
                    subquery = Some(Box::new(select));
                }
            }
        }

        let stmt = AstMultiInsert {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            overwrite_span,
            mode: crate::ast::AstMultiInsertMode::UnconditionalAll,
            mode_span: keyword_span,
            into_clauses,
            when_clauses,
            else_into_clauses,
            subquery,
        };
        Ok(AstStmt::MultiInsert(Box::new(stmt)))
    }

    fn parse_multi_insert_into_clause(&mut self) -> Option<AstMultiInsertIntoClause> {
        let into_tok = self.advance()?; // INTO
        let into_span = into_tok.span;
        let mut target_table_span: Option<Span> = None;
        let mut columns_span: Option<Span> = None;
        let mut values_span: Option<Span> = None;

        // Capture target table until we see '(', VALUES, WHEN/ELSE, or SELECT.
        let start_idx = self.idx;
        while let Some(t) = self.peek() {
            match &t.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                | TokenKind::Keyword(Keyword::Values)
                | TokenKind::Keyword(Keyword::When)
                | TokenKind::Keyword(Keyword::Else)
                | TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Into)
                | TokenKind::Eof
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                _ => {
                    let _ = self.advance();
                }
            }
        }
        let end_idx = self.idx;
        if end_idx > start_idx {
            let first = &self.tokens[start_idx];
            let last = &self.tokens[end_idx - 1];
            target_table_span = Some(Span {
                start: first.span.start,
                end: last.span.end,
            });
        }

        // Optional column list starting with '('.
        if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                let start = tok.span.start;
                let mut depth: usize = 0;
                while let Some(t) = self.advance() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            depth -= 1;
                            if depth == 0 {
                                columns_span = Some(Span {
                                    start,
                                    end: t.span.end,
                                });
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Optional VALUES clause.
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Values)) {
                let start = tok.span.start;
                let _ = self.advance(); // VALUES
                                        // Capture until next INTO/WHEN/ELSE/SELECT or end of statement.
                while let Some(t) = self.peek() {
                    match &t.kind {
                        TokenKind::Keyword(Keyword::Into)
                        | TokenKind::Keyword(Keyword::When)
                        | TokenKind::Keyword(Keyword::Else)
                        | TokenKind::Keyword(Keyword::Select)
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Eof => break,
                        _ => {
                            let _ = self.advance();
                        }
                    }
                }
                let end = match self.tokens.get(self.idx.saturating_sub(1)) {
                    Some(last) => last.span.end,
                    None => start,
                };
                values_span = Some(Span { start, end });
            }
        }

        Some(AstMultiInsertIntoClause {
            node_id: self.id_gen.next(),
            into_span,
            target_table_span,
            columns_span,
            values_span,
        })
    }

    /// Parse optional ON CONFLICT clause (PostgreSQL upsert).
    ///
    /// Syntax:
    ///   ON CONFLICT [ (column, ...) | ON CONSTRAINT constraint_name ]
    ///     DO NOTHING | DO UPDATE SET col = expr, ... [ WHERE condition ]
    ///
    /// Returns None if no ON CONFLICT clause is found.
    fn try_parse_on_conflict(&mut self) -> crate::error::ParseResult<Option<AstOnConflict>> {
        // Check for ON keyword followed by CONFLICT identifier
        let _on_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) => tok,
            _ => return Ok(None),
        };

        // Peek ahead to check if this is ON CONFLICT (not just ON something else)
        let saved_idx = self.idx;
        let on_tok_saved = self.advance().expect_invariant("ON keyword after peek");
        let on_start = on_tok_saved.span.start;

        match self.peek() {
            Some(tok)
                if matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("CONFLICT") =>
            {
                self.advance(); // consume CONFLICT
            }
            _ => {
                // Not ON CONFLICT — rewind
                self.idx = saved_idx;
                return Ok(None);
            }
        }

        let on_conflict_span = Span {
            start: on_start,
            end: self.tokens[self.idx - 1].span.end,
        };

        // Parse optional conflict target: (columns) or ON CONSTRAINT name
        let target = self.parse_conflict_target()?;

        // Parse DO NOTHING or DO UPDATE SET ...
        // Expect DO keyword
        let do_tok = match self.peek() {
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Do)) => {
                self.advance().expect_invariant("DO keyword")
            }
            _ => {
                return Err(ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected DO after ON CONFLICT target".to_string(),
                    },
                ));
            }
        };

        // Check for NOTHING or UPDATE
        let action = match self.peek() {
            Some(tok)
                if matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("NOTHING") =>
            {
                let nothing_tok = self.advance().expect_invariant("NOTHING");
                AstConflictAction::DoNothing(Span {
                    start: do_tok.span.start,
                    end: nothing_tok.span.end,
                })
            }
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Update)) => {
                let update_tok = self.advance().expect_invariant("UPDATE");

                // Expect SET
                match self.peek() {
                    Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) => {
                        self.advance(); // consume SET
                    }
                    _ => {
                        return Err(ParseError::new(
                            self.current_span(),
                            crate::error::ParseErrorKind::InvalidStatement {
                                message: "Expected SET after DO UPDATE".to_string(),
                            },
                        ));
                    }
                }

                // Parse SET items: col = expr, ...
                let mut set_items = Vec::new();
                loop {
                    // Parse column name
                    let col_name = match self.peek() {
                        Some(tok)
                            if matches!(
                                tok.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) =>
                        {
                            let name = tok.lexeme(self.source).to_string();
                            self.advance();
                            name
                        }
                        _ => break,
                    };

                    // Expect =
                    match self.peek() {
                        Some(tok)
                            if matches!(
                                tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Eq)
                            ) =>
                        {
                            self.advance(); // consume =
                        }
                        _ => {
                            return Err(ParseError::new(
                                self.current_span(),
                                crate::error::ParseErrorKind::InvalidStatement {
                                    message: format!(
                                        "Expected '=' after column name '{}'",
                                        col_name
                                    ),
                                },
                            ));
                        }
                    }

                    // Parse value expression
                    let expr = self.parse_expr()?;
                    set_items.push((col_name, expr));

                    // Check for comma or end
                    match self.peek() {
                        Some(tok)
                            if matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) =>
                        {
                            self.advance(); // consume comma
                        }
                        _ => break,
                    }
                }

                // Parse optional WHERE clause
                let where_clause = match self.peek() {
                    Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) => {
                        self.advance(); // consume WHERE
                        Some(Box::new(self.parse_expr()?))
                    }
                    _ => None,
                };

                let do_update_span = Span {
                    start: do_tok.span.start,
                    end: where_clause
                        .as_ref()
                        .map(|w| w.span().end)
                        .or_else(|| set_items.last().map(|(_, e)| e.span().end))
                        .unwrap_or(update_tok.span.end),
                };

                AstConflictAction::DoUpdate {
                    do_update_span,
                    set_items,
                    where_clause,
                }
            }
            _ => {
                return Err(ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected NOTHING or UPDATE after DO".to_string(),
                    },
                ));
            }
        };

        let span_end = match &action {
            AstConflictAction::DoNothing(s) => s.end,
            AstConflictAction::DoUpdate { do_update_span, .. } => do_update_span.end,
        };

        Ok(Some(AstOnConflict {
            node_id: self.id_gen.next(),
            on_conflict_span,
            target,
            action,
            span: Span {
                start: on_start,
                end: span_end,
            },
        }))
    }

    /// Parse conflict target: (column_or_expr_list) [WHERE predicate] or ON CONSTRAINT constraint_name
    ///
    /// PostgreSQL grammar:
    ///   conflict_target:
    ///       ( { index_column_name | ( index_expression ) } [ COLLATE collation ] [ opclass ] [, ...] ) [ WHERE index_predicate ]
    ///       ON CONSTRAINT constraint_name
    fn parse_conflict_target(&mut self) -> crate::error::ParseResult<Option<AstConflictTarget>> {
        match self.peek() {
            // (column_or_expr, ...)
            Some(tok)
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) =>
            {
                self.advance(); // consume (
                let mut items: Vec<AstConflictTargetItem> = Vec::new();
                loop {
                    match self.peek() {
                        Some(tok)
                            if matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) =>
                        {
                            self.advance(); // consume )
                            break;
                        }
                        Some(tok)
                            if matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) =>
                        {
                            self.advance(); // consume comma
                        }
                        Some(_) => {
                            let item = self.parse_conflict_target_item()?;
                            items.push(item);
                        }
                        None => {
                            return Err(ParseError::new(
                                self.current_span(),
                                crate::error::ParseErrorKind::InvalidStatement {
                                    message: "Unexpected end of input in ON CONFLICT target"
                                        .to_string(),
                                },
                            ));
                        }
                    }
                }

                // Parse optional WHERE predicate (for partial index inference)
                let where_predicate = match self.peek() {
                    Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) => {
                        self.advance(); // consume WHERE
                        Some(Box::new(self.parse_expr()?))
                    }
                    _ => None,
                };

                Ok(Some(AstConflictTarget::Columns {
                    items,
                    where_predicate,
                }))
            }
            // ON CONSTRAINT constraint_name
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) => {
                let saved = self.idx;
                self.advance(); // consume ON
                match self.peek() {
                    Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Constraint)) => {
                        self.advance(); // consume CONSTRAINT
                        match self.peek() {
                            Some(tok)
                                if matches!(
                                    tok.kind,
                                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                                ) =>
                            {
                                let name = tok.lexeme(self.source).to_string();
                                self.advance();
                                Ok(Some(AstConflictTarget::Constraint(name)))
                            }
                            _ => Err(ParseError::new(
                                self.current_span(),
                                crate::error::ParseErrorKind::InvalidStatement {
                                    message: "Expected constraint name after ON CONSTRAINT"
                                        .to_string(),
                                },
                            )),
                        }
                    }
                    _ => {
                        // Not ON CONSTRAINT — rewind
                        self.idx = saved;
                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
    }

    /// Parse a single item inside ON CONFLICT ( ... ).
    ///
    /// An item is one of:
    /// - A plain column name (identifier)
    /// - An expression: either a function call `LOWER(email)` or a parenthesized expression `(a + b)`
    ///
    /// Each item may optionally be followed by COLLATE collation_name and/or an opclass name.
    fn parse_conflict_target_item(&mut self) -> crate::error::ParseResult<AstConflictTargetItem> {
        let start_span = self.current_span();

        // Detect whether this is an expression item:
        // 1. LParen = parenthesized expression like (a + b)
        // 2. Identifier followed by LParen = function call like LOWER(email)
        // 3. Identifier NOT followed by LParen = plain column name
        let (kind, item_end) = match self.peek() {
            // Case 1: Parenthesized expression — (a + b)
            Some(tok)
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) =>
            {
                let expr = self.parse_expr()?;
                let end = expr.span().end;
                (AstConflictTargetItemKind::Expression(Box::new(expr)), end)
            }
            // Case 2/3: Identifier — could be column name or function call
            Some(tok)
                if matches!(
                    tok.kind,
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                ) =>
            {
                // Peek ahead to see if next is LParen (function call)
                let saved = self.idx;
                let ident_tok = self.advance().expect_invariant("identifier");
                let ident_name = ident_tok.lexeme(self.source).to_string();
                let ident_end = ident_tok.span.end;

                match self.peek() {
                    Some(next)
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) =>
                    {
                        // Function call — rewind and parse as expression
                        self.idx = saved;
                        let expr = self.parse_expr()?;
                        let end = expr.span().end;
                        (AstConflictTargetItemKind::Expression(Box::new(expr)), end)
                    }
                    _ => {
                        // Plain column name
                        (AstConflictTargetItemKind::Column(ident_name), ident_end)
                    }
                }
            }
            _ => {
                return Err(ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected column name or expression in ON CONFLICT target"
                            .to_string(),
                    },
                ));
            }
        };

        // Parse optional COLLATE collation_name
        let collation = match self.peek() {
            Some(tok)
                if matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(self.source).eq_ignore_ascii_case("COLLATE") =>
            {
                self.advance(); // consume COLLATE
                match self.peek() {
                    Some(tok)
                        if matches!(
                            tok.kind,
                            TokenKind::Identifier { .. }
                                | TokenKind::Keyword(_)
                                | TokenKind::Literal(_)
                        ) =>
                    {
                        let name = tok.lexeme(self.source).to_string();
                        self.advance();
                        Some(name)
                    }
                    _ => {
                        return Err(ParseError::new(
                            self.current_span(),
                            crate::error::ParseErrorKind::InvalidStatement {
                                message: "Expected collation name after COLLATE".to_string(),
                            },
                        ));
                    }
                }
            }
            _ => None,
        };

        // Opclass parsing is intentionally skipped — it's extremely rare in practice
        // and ambiguous to detect (just an identifier). The formatter is span-based
        // so opclass text is preserved in the output regardless.
        let opclass = None;

        let has_collation = collation.is_some();
        let span_end = self
            .tokens
            .get(self.idx.saturating_sub(1))
            .map(|t| t.span.end)
            .unwrap_or(item_end);

        Ok(AstConflictTargetItem {
            kind,
            collation,
            opclass,
            span: Span {
                start: start_span.start,
                end: if has_collation { span_end } else { item_end },
            },
        })
    }
}
