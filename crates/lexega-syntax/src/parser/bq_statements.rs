// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// BigQuery-specific statement parsers
//
// Statements handled:
//   EXPORT DATA, LOAD DATA, ASSERT,
//   CREATE/DROP SNAPSHOT TABLE,
//   CREATE/DROP SEARCH INDEX,
//   CREATE/DROP VECTOR INDEX,
//   ALTER VECTOR INDEX REBUILD,
//   CREATE EXTERNAL TABLE,
//   CREATE/ALTER/EXPORT/DROP MODEL (BQML)
//
// EXPORT DATA is parsed into a structured AST (AstBqExportData) with
// connection, options, and inner query fields.
//
// All others use span-passthrough (AstBqSimpleUtility): consume tokens
// until semicolon, preserve original source exactly.

use crate::ast::types::{
    AstBqAlterModel, AstBqCreateModel, AstBqDropModel, AstBqExportData, AstBqExportModel,
    AstBqSimpleUtility, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Operator, Punctuation, Span, Token, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    // ───────────────────────────────────────────────────────────────
    // Shared helper
    // ───────────────────────────────────────────────────────────────

    /// Consume all tokens until semicolon (or EOF), returning the end offset.
    fn bq_consume_until_semi(&mut self, start: u32) -> u32 {
        let mut end = start;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if let Some(t) = self.advance() {
                end = t.span.end;
            } else {
                break;
            }
        }
        end
    }

    /// Build a BQ simple-utility statement from consumed span.
    fn make_bq_simple(
        &mut self,
        start: u32,
        end: u32,
        constructor: fn(Box<AstBqSimpleUtility>) -> AstStmt,
    ) -> AstStmt {
        let span = Span { start, end };
        constructor(Box::new(AstBqSimpleUtility {
            node_id: self.id_gen.next(),
            span,
        }))
    }

    /// Parse a dot-separated qualified name (e.g., project.dataset.table).
    /// Returns the name string and its span.
    fn bq_parse_qualified_name(&mut self) -> ParseResult<(String, Span)> {
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
        let start = first.span.start;
        let mut end = first.span.end;
        let mut name = first.lexeme(self.source).to_string();

        // Consume additional .identifier parts
        while let Some(dot_tok) = self.peek_non_trivia() {
            if !matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            self.advance(); // consume dot
            let part = self.advance().ok_or_eof(
                self.current_span(),
                vec!["identifier after dot".to_string()],
            )?;
            name = format!("{}.{}", name, part.lexeme(self.source));
            end = part.span.end;
        }

        Ok((name, Span { start, end }))
    }

    /// Parse parenthesized content, returning span from '(' through ')'.
    fn bq_parse_paren_content(&mut self) -> ParseResult<Span> {
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::invalid_statement(
                lparen.span,
                "expected opening parenthesis".to_string(),
            ));
        }
        let start = lparen.span.start;
        let mut end = lparen.span.end;
        let mut depth = 1u32;

        while depth > 0 {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
            end = tok.span.end;
        }

        Ok(Span { start, end })
    }

    // ───────────────────────────────────────────────────────────────
    // EXPORT DATA
    //   EXPORT DATA [WITH CONNECTION conn] OPTIONS(...) AS query
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_export_data(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_export_data")?;
        // Current token is EXPORT (Identifier)
        let export_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXPORT".to_string()])?;
        let start = export_tok.span.start;

        // Expect DATA
        let data_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                export_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected DATA after EXPORT".to_string(),
                },
            )
        })?;
        if !data_tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
            return Err(ParseError::new(
                data_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATA after EXPORT, found '{}'",
                        data_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let data_tok = self.advance().unwrap();
        let keyword_span = Span {
            start,
            end: data_tok.span.end,
        };

        // Optional: WITH CONNECTION connection_name
        let connection_span = self.parse_bq_export_with_connection()?;

        // Required: OPTIONS(...)
        let options_span = self.parse_bq_export_options()?;

        // Required: AS keyword
        let as_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                options_span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected AS after OPTIONS(...)".to_string(),
                },
            )
        })?;
        if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
            return Err(ParseError::new(
                as_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected AS after OPTIONS(...), found '{}'",
                        as_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        self.advance(); // consume AS

        // Parse the inner query (SELECT, WITH CTE, etc.)
        let query = self.parse_flow_statement()?;
        let query_end = query.span().end;

        let span = Span {
            start,
            end: query_end,
        };
        let node_id = self.id_gen.next();

        let ast = AstBqExportData {
            node_id,
            span,
            keyword_span,
            connection_span,
            options_span,
            query: Box::new(query),
        };
        Ok(AstStmt::BqExportData(Box::new(ast)))
    }

    /// Parse optional `WITH CONNECTION project.dataset.connection_name` clause.
    /// Returns the span covering the entire clause if present, None otherwise.
    fn parse_bq_export_with_connection(&mut self) -> ParseResult<Option<Span>> {
        let next = match self.peek_non_trivia() {
            Some(tok) => tok,
            None => return Ok(None),
        };

        // Check for WITH keyword
        if !matches!(next.kind, TokenKind::Keyword(Keyword::With)) {
            return Ok(None);
        }

        let with_tok = self.advance().unwrap();
        let with_start = with_tok.span.start;

        // Expect CONNECTION
        let conn_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                with_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected CONNECTION after WITH".to_string(),
                },
            )
        })?;
        if !conn_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CONNECTION")
        {
            // Not a WITH CONNECTION clause — this is ambiguous.
            // Restore position and return None.
            // BUT we already consumed WITH. We need to handle this.
            return Err(ParseError::new(
                conn_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CONNECTION after WITH in EXPORT DATA, found '{}'",
                        conn_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        self.advance(); // consume CONNECTION

        // Parse qualified connection name: project.dataset.connection_name
        // Use dot-separated pattern: first ident, then dot+ident pairs
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["connection name".to_string()])?;
        let mut end = first.span.end;

        while let Some(dot_tok) = self.peek_non_trivia() {
            if !matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            self.advance(); // consume dot
            let part = self.advance().ok_or_eof(
                self.current_span(),
                vec!["connection name part".to_string()],
            )?;
            end = part.span.end;
        }

        Ok(Some(Span {
            start: with_start,
            end,
        }))
    }

    /// Parse required `OPTIONS(...)` clause.
    /// Returns span covering `OPTIONS(...)` including parentheses.
    fn parse_bq_export_options(&mut self) -> ParseResult<Span> {
        let options_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected OPTIONS in EXPORT DATA".to_string(),
                },
            )
        })?;
        if !options_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("OPTIONS")
        {
            return Err(ParseError::new(
                options_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected OPTIONS in EXPORT DATA, found '{}'",
                        options_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let options_tok = self.advance().unwrap();
        let start = options_tok.span.start;

        // Expect opening paren
        let lparen = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                options_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after OPTIONS".to_string(),
                },
            )
        })?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after OPTIONS".to_string(),
                },
            ));
        }
        self.advance(); // consume LParen

        // Consume balanced parens
        let mut depth: u32 = 1;
        let mut last_end = options_tok.span.end;
        while depth > 0 {
            let tok = self.advance().ok_or_else(|| {
                ParseError::new(
                    Span {
                        start,
                        end: last_end,
                    },
                    ParseErrorKind::InvalidStatement {
                        message: "Unterminated OPTIONS(...) — missing ')'".to_string(),
                    },
                )
            })?;
            last_end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
        }

        Ok(Span {
            start,
            end: last_end,
        })
    }

    // ───────────────────────────────────────────────────────────────
    // LOAD DATA
    //   LOAD DATA [INTO|OVERWRITE] [TEMP TABLE] target
    //     [(col_spec)] [PARTITION BY ...] [CLUSTER BY ...]
    //     FROM FILES(...)
    //     [WITH PARTITION COLUMNS [(...)]] [WITH CONNECTION conn]
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_load_data(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_load_data")?;
        let load_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOAD".to_string()])?;
        let start = load_tok.span.start;

        // Expect DATA
        let data_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                load_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected DATA after LOAD".to_string(),
                },
            )
        })?;
        if !data_tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
            return Err(ParseError::new(
                data_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATA after LOAD, found '{}'",
                        data_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let data_tok = self.advance().unwrap();
        let keyword_span = Span {
            start,
            end: data_tok.span.end,
        };

        // Skip optional INTO or OVERWRITE
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Into))
                || tok.lexeme(self.source).eq_ignore_ascii_case("OVERWRITE")
            {
                self.advance();
            }
        }

        // Skip optional TEMP/TEMPORARY TABLE
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Temp) | TokenKind::Keyword(Keyword::Temporary)
            ) {
                self.advance();
                // Expect TABLE keyword
                if let Some(t) = self.peek_non_trivia() {
                    if matches!(t.kind, TokenKind::Keyword(Keyword::Table)) {
                        self.advance();
                    }
                }
            }
        }

        // Parse target table name (dot-separated: project.dataset.table)
        let table_first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
        let table_start = table_first.span.start;
        let mut table_end = table_first.span.end;

        while let Some(dot_tok) = self.peek_non_trivia() {
            if !matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            self.advance(); // consume dot
            let part = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["table name part".to_string()])?;
            table_end = part.span.end;
        }
        let target_table_span = Span {
            start: table_start,
            end: table_end,
        };

        // Skip optional column spec: (col1 TYPE, col2 TYPE, ...)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                // Check this isn't a FROM FILES paren — peek for FROM keyword before it
                // Column spec parens come right after table name, before PARTITION/FROM
                self.bq_consume_balanced_parens();
            }
        }

        // Skip optional PARTITION BY ... [CLUSTER BY ...]
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Partition)) {
                self.advance(); // PARTITION
                if let Some(by) = self.peek_non_trivia() {
                    if matches!(by.kind, TokenKind::Keyword(Keyword::By)) {
                        self.advance(); // BY
                    }
                }
                // Consume partition column names until FROM or CLUSTER
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::From))
                        || matches!(tok.kind, TokenKind::Keyword(Keyword::Cluster))
                    {
                        break;
                    }
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    self.advance();
                }
            }
        }

        // Skip optional CLUSTER BY ...
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Cluster)) {
                self.advance(); // CLUSTER
                if let Some(by) = self.peek_non_trivia() {
                    if matches!(by.kind, TokenKind::Keyword(Keyword::By)) {
                        self.advance(); // BY
                    }
                }
                // Consume cluster column names until FROM
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
                        break;
                    }
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    self.advance();
                }
            }
        }

        // Required: FROM FILES(...)
        let from_files_span = self.parse_bq_load_from_files()?;

        // Optional trailing: WITH PARTITION COLUMNS [...] and/or WITH CONNECTION conn
        let trailing_start = self.peek_non_trivia().map(|t| t.span.start);
        let mut trailing_end: Option<u32> = None;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let t = self.advance().unwrap();
                if trailing_end.is_none() {
                    // trailing_start is already set from peek above
                }
                trailing_end = Some(t.span.end);
                // Consume the rest of the WITH clause until next WITH or semi
                while let Some(inner) = self.peek_non_trivia() {
                    if matches!(inner.kind, TokenKind::Punctuation(Punctuation::Semi))
                        || matches!(inner.kind, TokenKind::Keyword(Keyword::With))
                    {
                        break;
                    }
                    let consumed = self.advance().unwrap();
                    trailing_end = Some(consumed.span.end);
                    // Handle balanced parens inside WITH PARTITION COLUMNS (...)
                    if matches!(consumed.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let paren_end = self.bq_consume_balanced_parens_inner();
                        trailing_end = Some(paren_end);
                    }
                }
            } else {
                // Unknown token before semicolon — consume it
                let t = self.advance().unwrap();
                trailing_end = Some(t.span.end);
            }
        }

        let trailing_clauses_span = match (trailing_start, trailing_end) {
            (Some(s), Some(e)) => Some(Span { start: s, end: e }),
            _ => None,
        };

        let stmt_end = trailing_end.unwrap_or(from_files_span.end);
        let span = Span {
            start,
            end: stmt_end,
        };

        let node_id = self.id_gen.next();
        let ast = crate::ast::types::AstBqLoadData {
            node_id,
            span,
            keyword_span,
            target_table_span,
            from_files_span,
            trailing_clauses_span,
        };
        Ok(AstStmt::BqLoadData(Box::new(ast)))
    }

    /// Parse `FROM FILES(...)` clause. Returns span covering the entire clause.
    fn parse_bq_load_from_files(&mut self) -> ParseResult<Span> {
        // Expect FROM
        let from_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected FROM FILES(...) in LOAD DATA".to_string(),
                },
            )
        })?;
        if !matches!(from_tok.kind, TokenKind::Keyword(Keyword::From)) {
            return Err(ParseError::new(
                from_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected FROM in LOAD DATA, found '{}'",
                        from_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let from_tok = self.advance().unwrap();
        let start = from_tok.span.start;

        // Expect FILES
        let files_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                from_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FILES after FROM".to_string(),
                },
            )
        })?;
        if !files_tok.lexeme(self.source).eq_ignore_ascii_case("FILES") {
            return Err(ParseError::new(
                files_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected FILES after FROM, found '{}'",
                        files_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        self.advance(); // consume FILES

        // Expect (...)
        let lparen = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after FILES".to_string(),
                },
            )
        })?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after FILES".to_string(),
                },
            ));
        }
        self.advance(); // consume LParen

        // Consume balanced parens
        let mut depth: u32 = 1;
        let mut last_end = start;
        while depth > 0 {
            let tok = self.advance().ok_or_else(|| {
                ParseError::new(
                    Span {
                        start,
                        end: last_end,
                    },
                    ParseErrorKind::InvalidStatement {
                        message: "Unterminated FROM FILES(...) — missing ')'".to_string(),
                    },
                )
            })?;
            last_end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
        }

        Ok(Span {
            start,
            end: last_end,
        })
    }

    /// Consume a balanced parenthesized block (skipping LParen, consuming until matching RParen).
    /// Assumes the LParen has been peeked but NOT consumed.
    fn bq_consume_balanced_parens(&mut self) {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                self.advance(); // consume LParen
                self.bq_consume_balanced_parens_inner();
            }
        }
    }

    /// Consume tokens until the matching RParen (depth starts at 1).
    /// Returns the end offset of the closing RParen.
    fn bq_consume_balanced_parens_inner(&mut self) -> u32 {
        let mut depth: u32 = 1;
        let mut last_end = 0u32;
        while depth > 0 {
            if let Some(tok) = self.advance() {
                last_end = tok.span.end;
                match tok.kind {
                    TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                    _ => {}
                }
            } else {
                break;
            }
        }
        last_end
    }

    // ───────────────────────────────────────────────────────────────
    // ASSERT
    //   ASSERT expression [AS description]
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_assert(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqAssert;

        let _depth = self.track_depth("bq_assert")?;

        // Consume ASSERT keyword (it's an Identifier, not Keyword)
        let assert_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ASSERT".to_string()])?;
        let keyword_span = assert_tok.span;
        let start = keyword_span.start;

        // Parse the expression
        let expression = self.parse_expr()?;
        let mut end = expression.span().end;

        // Check for optional AS description
        let description_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = self.advance().unwrap();
                let as_start = as_tok.span.start;

                // Expect string literal for description
                let desc_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        as_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected string literal after AS in ASSERT".to_string(),
                        },
                    )
                })?;

                if !matches!(desc_tok.kind, TokenKind::Literal(LiteralKind::String)) {
                    return Err(ParseError::new(
                        desc_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected string literal for ASSERT description, found '{}'",
                                desc_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }

                let desc_tok = self.advance().unwrap();
                end = desc_tok.span.end;
                Some(Span {
                    start: as_start,
                    end,
                })
            } else {
                None
            }
        } else {
            None
        };

        let stmt_span = Span { start, end };

        let ast = AstBqAssert {
            node_id: self.id_gen.next(),
            span: stmt_span,
            keyword_span,
            expression: Box::new(expression),
            description_span,
        };
        Ok(AstStmt::BqAssert(Box::new(ast)))
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE SNAPSHOT TABLE name CLONE source FOR SYSTEM_TIME AS OF ...
    // ───────────────────────────────────────────────────────────────

    /// CREATE SNAPSHOT TABLE name CLONE source [FOR SYSTEM_TIME AS OF ...] [OPTIONS(...)]
    pub(crate) fn try_parse_bq_create_snapshot_table(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqCreateSnapshotTable;

        let _depth = self.track_depth("bq_create_snapshot_table")?;

        // Consume CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Skip optional OR REPLACE
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Or)) {
                self.advance(); // consume OR
                if let Some(replace_tok) = self.peek_non_trivia() {
                    if replace_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("REPLACE")
                    {
                        self.advance(); // consume REPLACE
                    }
                }
            }
        }

        // Consume SNAPSHOT (Identifier)
        let _snapshot_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SNAPSHOT".to_string()])?;

        // Consume TABLE (Keyword)
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        let mut keyword_end = table_tok.span.end;

        // Skip optional IF NOT EXISTS (comes AFTER SNAPSHOT TABLE per BigQuery syntax)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(crate::lexer::Keyword::If)) {
                self.advance(); // consume IF
                if let Some(not_tok) = self.peek_non_trivia() {
                    if matches!(not_tok.kind, TokenKind::Keyword(crate::lexer::Keyword::Not)) {
                        self.advance(); // consume NOT
                        if let Some(exists_tok) = self.peek_non_trivia() {
                            if matches!(
                                exists_tok.kind,
                                TokenKind::Keyword(crate::lexer::Keyword::Exists)
                            ) {
                                keyword_end = exists_tok.span.end;
                                self.advance(); // consume EXISTS
                            }
                        }
                    }
                }
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Parse snapshot name (qualified identifier)
        let (_, snapshot_name_span) = self.bq_parse_qualified_name()?;

        // Expect CLONE (Identifier)
        let clone_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CLONE".to_string()])?;
        if !clone_tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") {
            return Err(crate::error::ParseError::invalid_statement(
                clone_tok.span,
                "expected CLONE keyword".to_string(),
            ));
        }

        // Parse source table name
        let (_, source_table_span) = self.bq_parse_qualified_name()?;

        // Consume trailing clauses (FOR SYSTEM_TIME AS OF ..., OPTIONS) until semicolon
        let mut end = source_table_span.end;
        let trailing_start = end;
        let mut has_trailing = false;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                break;
            }
            if self.is_statement_keyword(tok) {
                break;
            }
            has_trailing = true;
            end = tok.span.end;
            self.advance();
        }

        let trailing_clauses_span = if has_trailing {
            Some(Span {
                start: trailing_start,
                end,
            })
        } else {
            None
        };

        let span = Span { start, end };
        Ok(AstStmt::BqCreateSnapshotTable(Box::new(
            AstBqCreateSnapshotTable {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                snapshot_name_span,
                source_table_span,
                trailing_clauses_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // DROP SNAPSHOT TABLE [IF EXISTS] name
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_drop_snapshot_table(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_drop_snapshot_table")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;
        let end = self.bq_consume_until_semi(start);
        Ok(self.make_bq_simple(start, end, AstStmt::BqDropSnapshotTable))
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE SEARCH INDEX [IF NOT EXISTS] name ON table(columns) [OPTIONS(...)]
    // ───────────────────────────────────────────────────────────────

    /// CREATE SEARCH INDEX [IF NOT EXISTS] name ON table(columns) [OPTIONS(...)]
    pub(crate) fn try_parse_bq_create_search_index(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqCreateSearchIndex;

        let _depth = self.track_depth("bq_create_search_index")?;

        // Consume CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Consume SEARCH (Identifier)
        self.advance(); // SEARCH

        // Consume INDEX (Identifier)
        let mut keyword_end_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;

        // Optional IF NOT EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance(); // NOT
                keyword_end_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                // EXISTS
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end_tok.span.end,
        };

        // Parse index name
        let (_, index_name_span) = self.bq_parse_qualified_name()?;

        // Expect ON (Keyword)
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::invalid_statement(
                on_tok.span,
                "expected ON keyword".to_string(),
            ));
        }

        // Parse table name
        let (_, table_span) = self.bq_parse_qualified_name()?;

        // Parse column list in parentheses
        let columns_span = self.bq_parse_paren_content()?;

        // Optional OPTIONS(...)
        let mut end = columns_span.end;
        let mut options_span = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
            {
                self.advance(); // OPTIONS
                let opts = self.bq_parse_paren_content()?;
                options_span = Some(Span {
                    start: tok.span.start,
                    end: opts.end,
                });
                end = opts.end;
            }
        }

        let span = Span { start, end };
        Ok(AstStmt::BqCreateSearchIndex(Box::new(
            AstBqCreateSearchIndex {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                index_name_span,
                table_span,
                columns_span,
                options_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // DROP SEARCH INDEX [IF EXISTS] name ON table
    // ───────────────────────────────────────────────────────────────

    /// DROP SEARCH INDEX [IF EXISTS] name ON table
    pub(crate) fn try_parse_bq_drop_search_index(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqDropSearchIndex;

        let _depth = self.track_depth("bq_drop_search_index")?;

        // Consume DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;

        // Consume SEARCH (Identifier)
        self.advance(); // SEARCH

        // Consume INDEX (Identifier)
        let mut keyword_end_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;

        // Optional IF EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                keyword_end_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                // EXISTS
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end_tok.span.end,
        };

        // Parse index name
        let (_, index_name_span) = self.bq_parse_qualified_name()?;

        // Expect ON (Keyword)
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::invalid_statement(
                on_tok.span,
                "expected ON keyword".to_string(),
            ));
        }

        // Parse table name
        let (_, table_span) = self.bq_parse_qualified_name()?;

        let span = Span {
            start,
            end: table_span.end,
        };
        Ok(AstStmt::BqDropSearchIndex(Box::new(AstBqDropSearchIndex {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            index_name_span,
            table_span,
        })))
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE [OR REPLACE] VECTOR INDEX [IF NOT EXISTS] name
    //   ON table(column) [STORING(cols)] OPTIONS(...)
    // ───────────────────────────────────────────────────────────────

    /// CREATE [OR REPLACE] VECTOR INDEX [IF NOT EXISTS] name ON table(column) [STORING(...)] [OPTIONS(...)]
    pub(crate) fn try_parse_bq_create_vector_index(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqCreateVectorIndex;

        let _depth = self.track_depth("bq_create_vector_index")?;

        // Consume CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Optional OR REPLACE
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // OR
                self.advance(); // REPLACE
            }
        }

        // Consume VECTOR (Identifier)
        self.advance(); // VECTOR

        // Consume INDEX (Identifier)
        let mut keyword_end_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;

        // Optional IF NOT EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance(); // NOT
                keyword_end_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                // EXISTS
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end_tok.span.end,
        };

        // Parse index name
        let (_, index_name_span) = self.bq_parse_qualified_name()?;

        // Expect ON (Keyword)
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::invalid_statement(
                on_tok.span,
                "expected ON keyword".to_string(),
            ));
        }

        // Parse table name
        let (_, table_span) = self.bq_parse_qualified_name()?;

        // Parse column list in parentheses
        let columns_span = self.bq_parse_paren_content()?;

        let mut end = columns_span.end;
        let mut storing_span = None;
        let mut options_span = None;

        // Optional STORING(...)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("STORING")
            {
                let storing_start = tok.span.start;
                self.advance(); // STORING
                let cols = self.bq_parse_paren_content()?;
                storing_span = Some(Span {
                    start: storing_start,
                    end: cols.end,
                });
                end = cols.end;
            }
        }

        // Optional OPTIONS(...)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
            {
                let opts_start = tok.span.start;
                self.advance(); // OPTIONS
                let opts = self.bq_parse_paren_content()?;
                options_span = Some(Span {
                    start: opts_start,
                    end: opts.end,
                });
                end = opts.end;
            }
        }

        let span = Span { start, end };
        Ok(AstStmt::BqCreateVectorIndex(Box::new(
            AstBqCreateVectorIndex {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                index_name_span,
                table_span,
                columns_span,
                storing_span,
                options_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // DROP VECTOR INDEX [IF EXISTS] name ON table
    // ───────────────────────────────────────────────────────────────

    /// DROP VECTOR INDEX [IF EXISTS] name ON table
    pub(crate) fn try_parse_bq_drop_vector_index(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstBqDropVectorIndex;

        let _depth = self.track_depth("bq_drop_vector_index")?;

        // Consume DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;

        // Consume VECTOR (Identifier)
        self.advance(); // VECTOR

        // Consume INDEX (Identifier)
        let mut keyword_end_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;

        // Optional IF EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                keyword_end_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                // EXISTS
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end_tok.span.end,
        };

        // Parse index name
        let (_, index_name_span) = self.bq_parse_qualified_name()?;

        // Expect ON (Keyword)
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::invalid_statement(
                on_tok.span,
                "expected ON keyword".to_string(),
            ));
        }

        // Parse table name
        let (_, table_span) = self.bq_parse_qualified_name()?;

        let span = Span {
            start,
            end: table_span.end,
        };
        Ok(AstStmt::BqDropVectorIndex(Box::new(AstBqDropVectorIndex {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            index_name_span,
            table_span,
        })))
    }

    // ───────────────────────────────────────────────────────────────
    // ALTER VECTOR INDEX [IF EXISTS] name REBUILD
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_alter_vector_index(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_alter_vector_index")?;
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        let end = self.bq_consume_until_semi(start);
        Ok(self.make_bq_simple(start, end, AstStmt::BqAlterVectorIndex))
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE [OR REPLACE] EXTERNAL TABLE [IF NOT EXISTS] table_name
    //
    // BigQuery syntax:
    //   [(column_name column_schema, ...)]
    //   [WITH CONNECTION {connection_name | DEFAULT}]
    //   [WITH PARTITION COLUMNS [(partition_column_name partition_column_type, ...)]]
    //   OPTIONS (external_table_option_list, ...);
    //
    // Snowflake syntax:
    //   (col_name type AS (expr), ...) | USING TEMPLATE (subquery)
    //   [cloudProviderParams: INTEGRATION = 'name']
    //   [PARTITION BY (col, ...)]
    //   [WITH] LOCATION = @stage/path/
    //   [REFRESH_ON_CREATE = TRUE|FALSE]
    //   [AUTO_REFRESH = TRUE|FALSE]
    //   [PATTERN = 'regex']
    //   FILE_FORMAT = (TYPE = ... | FORMAT_NAME = ...)
    //   [PARTITION_TYPE = USER_SPECIFIED]
    //   [TABLE_FORMAT = DELTA]
    //   [AWS_SNS_TOPIC = 'arn']
    //   [COPY GRANTS]
    //   [COMMENT = 'string']
    //   [[WITH] ROW ACCESS POLICY name ON (col)]
    //   [[WITH] TAG (name = 'value', ...)]
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_create_external_table(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstCreateExternalTable;

        let _depth = self.track_depth("create_external_table")?;

        // ── Shared prefix: CREATE [OR REPLACE] EXTERNAL TABLE [IF NOT EXISTS] name ──

        // Consume CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        let or_replace_span = self.parse_optional_or_replace()?;

        // Consume EXTERNAL (Identifier, NOT Keyword)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !external_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::invalid_statement(
                external_tok.span,
                "expected EXTERNAL keyword".to_string(),
            ));
        }

        // Consume TABLE (Keyword)
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::invalid_statement(
                table_tok.span,
                "expected TABLE keyword after EXTERNAL".to_string(),
            ));
        }
        let mut keyword_end = table_tok.span.end;

        // Skip optional IF NOT EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // consume IF
                if let Some(not_tok) = self.peek_non_trivia() {
                    if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                        self.advance(); // consume NOT
                        if let Some(exists_tok) = self.peek_non_trivia() {
                            if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                                let et = self.advance().unwrap(); // consume EXISTS
                                keyword_end = et.span.end;
                            }
                        }
                    }
                }
            }
        }

        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Parse table name (qualified: project.dataset.table or db.schema.table)
        let (_, table_name_span) = self.bq_parse_qualified_name()?;

        // Optional schema definition: (column_name type, ...)
        let schema_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                Some(self.bq_parse_paren_content()?)
            } else {
                None
            }
        } else {
            None
        };

        // ── T-SQL / PolyBase form: WITH ( LOCATION=, DATA_SOURCE=, FILE_FORMAT=, … ) ──
        // `WITH` immediately followed by `(` uniquely marks the PolyBase options
        // bag — BQ uses `WITH CONNECTION` / `WITH PARTITION`, Snowflake uses
        // `WITH LOCATION`/`ROW`/`TAG`, all keyword-led, never `(`. Capture the
        // whole bag (routed through the bq_options credential-literal harvest so
        // a hardcoded LOCATION/REJECTED_ROW_LOCATION leak no longer fragments
        // off unseen) and lift the DATA_SOURCE binding — the federated-access
        // discriminator. Once consumed, the dialect loops below see `;` and
        // no-op, so the rest of the parser is untouched.
        let mut tsql_with_options_span: Option<Span> = None;
        let mut data_source_span: Option<Span> = None;
        let mut as_query: Option<Result<Box<AstStmt>, Span>> = None;
        let mut as_query_end: Option<u32> = None;
        if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::With))
        ) {
            let saved = self.idx;
            let with_start = self.peek_non_trivia().map(|t| t.span.start);
            self.advance(); // tentatively consume WITH
            if matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Punctuation(Punctuation::LParen))
            ) {
                let with_start = with_start.unwrap_or(start);
                let lparen = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                let mut depth: u32 = 1;
                let mut end = lparen.span.end;
                while depth > 0 {
                    // Detect `DATA_SOURCE` at the top level of the bag before
                    // consuming it, so the following `= <name>` value is lifted.
                    let is_data_source = depth == 1
                        && self
                            .peek_non_trivia()
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("DATA_SOURCE")
                            })
                            .unwrap_or(false);
                    let tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    end = tok.span.end;
                    match tok.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => {
                            depth = depth.saturating_sub(1)
                        }
                        _ => {}
                    }
                    if is_data_source
                        && matches!(
                            self.peek_non_trivia().map(|t| &t.kind),
                            Some(TokenKind::Operator(Operator::Eq))
                        )
                    {
                        self.advance(); // consume `=`
                        if let Some(v) = self.peek_non_trivia() {
                            data_source_span = Some(v.span); // value consumed by the loop
                        }
                    }
                }
                tsql_with_options_span = Some(Span {
                    start: with_start,
                    end,
                });
            } else {
                self.idx = saved; // not the T-SQL form — restore for the dialect branches
            }
        }

        // ── T-SQL CETAS: `… WITH (…) AS <query>` ──
        // Only the PolyBase WITH-bag form takes an `AS <query>` (CETAS), which
        // writes the query's results out to the external location — a data
        // egress surface. Parse the query into a sub-statement so it doesn't
        // fragment off as a phantom second statement and so its reads are
        // visible as part of this statement. Read-only
        // external tables (BQ/Snowflake/Redshift) never carry `AS`.
        if tsql_with_options_span.is_some()
            && matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::As))
            )
        {
            let as_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
            let as_start = as_tok.span.start;
            let query_start_idx = self.idx;
            match self.parse_flow_statement() {
                Ok(query) => {
                    as_query_end = Some(query.span().end);
                    as_query = Some(Ok(Box::new(query)));
                }
                Err(_) => {
                    // Unparseable egress body — keep the external-table head
                    // recognized (mirror `ctas_query`): rewind and capture the
                    // body as a span up to the depth-0 statement boundary.
                    self.idx = query_start_idx;
                    let mut end = as_start;
                    while let Some(t) = self.peek_non_trivia() {
                        if matches!(
                            t.kind,
                            TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
                        ) {
                            break;
                        }
                        let consumed = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![";".to_string()])?;
                        end = consumed.span.end;
                    }
                    as_query_end = Some(end);
                    as_query = Some(Err(Span {
                        start: as_start,
                        end,
                    }));
                }
            }
        }

        // ── Dialect detection ──
        // Peek ahead (possibly past optional WITH) to determine which dialect's
        // clauses follow.
        //
        // BigQuery indicators: OPTIONS, WITH CONNECTION, WITH PARTITION COLUMNS
        // Snowflake indicators: everything else (LOCATION, FILE_FORMAT, USING, etc.)
        let is_bigquery = {
            let saved = self.idx;
            let result = match self.peek_non_trivia() {
                Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") => true,
                Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) => {
                    self.advance(); // skip WITH
                    self.skip_trivia();
                    let bq = match self.peek() {
                        Some(t) if t.lexeme(self.source).eq_ignore_ascii_case("CONNECTION") => true,
                        // WITH PARTITION COLUMNS → BQ (SF uses PARTITION BY, never WITH PARTITION)
                        Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Partition)) => {
                            // Peek one more: COLUMNS → BQ, BY → SF
                            let saved2 = self.idx;
                            self.advance(); // skip PARTITION
                            self.skip_trivia();
                            let is_columns = self
                                .peek()
                                .map(|t2| t2.lexeme(self.source).eq_ignore_ascii_case("COLUMNS"))
                                .unwrap_or(false);
                            self.idx = saved2;
                            is_columns
                        }
                        _ => false,
                    };
                    bq
                }
                _ => false,
            };
            self.idx = saved;
            result
        };

        // ── Initialize all clause spans ──
        // BigQuery
        let mut connection_span: Option<Span> = None;
        let mut options_span: Option<Span> = None;
        // Shared
        let mut partition_columns_span: Option<Span> = None;
        // Snowflake
        let mut using_template_span: Option<Span> = None;
        let mut location_span: Option<Span> = None;
        let mut integration_span: Option<Span> = None;
        let mut refresh_on_create_span: Option<Span> = None;
        let mut auto_refresh_span: Option<Span> = None;
        let mut pattern_span: Option<Span> = None;
        let mut file_format_span: Option<Span> = None;
        let mut partition_type_span: Option<Span> = None;
        let mut table_format_span: Option<Span> = None;
        let mut aws_sns_topic_span: Option<Span> = None;
        let mut copy_grants_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut row_access_policy_span: Option<Span> = None;
        let mut tag_span: Option<Span> = None;
        // Redshift Spectrum
        let mut stored_as_span: Option<Span> = None;
        let mut row_format_span: Option<Span> = None;
        let mut redshift_iam_role_span: Option<Span> = None;

        if is_bigquery {
            // ── BigQuery clause loop ──
            while let Some(tok) = self.peek_non_trivia() {
                // OPTIONS(...) — required in BQ, always last
                if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") {
                    let options_start = tok.span.start;
                    self.advance(); // consume OPTIONS
                    let paren_span = self.bq_parse_paren_content()?;
                    options_span = Some(Span {
                        start: options_start,
                        end: paren_span.end,
                    });
                    break;
                }

                // WITH CONNECTION ... or WITH PARTITION COLUMNS ...
                if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                    let with_start = tok.span.start;
                    self.advance(); // consume WITH

                    if let Some(next) = self.peek_non_trivia() {
                        if next.lexeme(self.source).eq_ignore_ascii_case("CONNECTION") {
                            self.advance(); // consume CONNECTION
                            if let Some(conn_tok) = self.peek_non_trivia() {
                                if matches!(conn_tok.kind, TokenKind::Keyword(Keyword::Default)) {
                                    let ct = self.advance().unwrap();
                                    connection_span = Some(Span {
                                        start: with_start,
                                        end: ct.span.end,
                                    });
                                } else {
                                    let (_, conn_name_span) = self.bq_parse_qualified_name()?;
                                    connection_span = Some(Span {
                                        start: with_start,
                                        end: conn_name_span.end,
                                    });
                                }
                            }
                        } else if matches!(next.kind, TokenKind::Keyword(Keyword::Partition)) {
                            self.advance(); // consume PARTITION
                            let columns_tok = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["COLUMNS".to_string()])?;
                            if !columns_tok
                                .lexeme(self.source)
                                .eq_ignore_ascii_case("COLUMNS")
                            {
                                return Err(ParseError::invalid_statement(
                                    columns_tok.span,
                                    "expected COLUMNS after PARTITION".to_string(),
                                ));
                            }
                            let mut part_end = columns_tok.span.end;
                            if let Some(paren_tok) = self.peek_non_trivia() {
                                if matches!(
                                    paren_tok.kind,
                                    TokenKind::Punctuation(Punctuation::LParen)
                                ) {
                                    let paren_span = self.bq_parse_paren_content()?;
                                    part_end = paren_span.end;
                                }
                            }
                            partition_columns_span = Some(Span {
                                start: with_start,
                                end: part_end,
                            });
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                    continue;
                }

                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    break;
                }
                if self.is_statement_keyword(tok) {
                    break;
                }
                self.advance(); // unknown — consume and continue
            }
        } else {
            // ── Snowflake clause loop ──
            while let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    break;
                }

                // ── Keyword-dispatched clauses ──
                match tok.kind {
                    TokenKind::Keyword(Keyword::Using) => {
                        // USING TEMPLATE (subquery)
                        let clause_start = tok.span.start;
                        self.advance(); // USING
                                        // Consume TEMPLATE (Identifier)
                        if let Some(t) = self.peek_non_trivia() {
                            if t.lexeme(self.source).eq_ignore_ascii_case("TEMPLATE") {
                                self.advance(); // TEMPLATE
                            }
                        }
                        // Consume parenthesized subquery
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                let paren = self.bq_parse_paren_content()?;
                                using_template_span = Some(Span {
                                    start: clause_start,
                                    end: paren.end,
                                });
                            }
                        }
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Partition) => {
                        // PARTITION BY (col, ...)
                        let clause_start = tok.span.start;
                        self.advance(); // PARTITION
                                        // Consume BY
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Keyword(Keyword::By)) {
                                self.advance(); // BY
                            }
                        }
                        // Consume parenthesized column list
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                let paren = self.bq_parse_paren_content()?;
                                partition_columns_span = Some(Span {
                                    start: clause_start,
                                    end: paren.end,
                                });
                            }
                        }
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Integration) => {
                        // INTEGRATION = 'name'
                        integration_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }

                    TokenKind::Keyword(Keyword::FileFormat) => {
                        // FILE_FORMAT = (TYPE = CSV ...) or FILE_FORMAT = format_name
                        let clause_start = tok.span.start;
                        self.advance(); // FILE_FORMAT
                                        // Consume =
                        if let Some(eq) = self.peek_non_trivia() {
                            if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                                self.advance(); // =
                            }
                        }
                        // Value: parenthesized or single token
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                let paren = self.bq_parse_paren_content()?;
                                file_format_span = Some(Span {
                                    start: clause_start,
                                    end: paren.end,
                                });
                            } else {
                                let val = self.advance().unwrap();
                                file_format_span = Some(Span {
                                    start: clause_start,
                                    end: val.span.end,
                                });
                            }
                        }
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Pattern) => {
                        // PATTERN = 'regex'
                        pattern_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Copy) => {
                        // COPY GRANTS
                        let clause_start = tok.span.start;
                        self.advance(); // COPY
                        let mut clause_end = tok.span.end;
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Keyword(Keyword::Grants)) {
                                let grants = self.advance().unwrap();
                                clause_end = grants.span.end;
                            }
                        }
                        copy_grants_span = Some(Span {
                            start: clause_start,
                            end: clause_end,
                        });
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Comment) => {
                        // COMMENT = 'string'
                        comment_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Row) => {
                        // Disambiguate Snowflake ROW ACCESS POLICY vs Redshift
                        // Spectrum ROW FORMAT. Both start with the ROW keyword;
                        // the following word (ACCESS vs FORMAT) decides.
                        let clause_start = tok.span.start;
                        let saved = self.idx;
                        self.advance(); // ROW
                        let is_row_format = self
                            .peek_non_trivia()
                            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Format)))
                            .unwrap_or(false);
                        if is_row_format {
                            // ROW FORMAT { DELIMITED [FIELDS TERMINATED BY '..'] | SERDE '..' }
                            let mut clause_end = tok.span.end;
                            if let Some(f) = self.advance() {
                                clause_end = f.span.end; // FORMAT
                            }
                            loop {
                                match self.peek_non_trivia() {
                                    None => break,
                                    Some(t) => {
                                        if self.is_ext_table_clause_boundary(t) {
                                            break;
                                        }
                                        if let Some(a) = self.advance() {
                                            clause_end = a.span.end;
                                        }
                                    }
                                }
                            }
                            row_format_span = Some(Span {
                                start: clause_start,
                                end: clause_end,
                            });
                        } else {
                            // ROW ACCESS POLICY — restore and reuse the helper.
                            self.idx = saved;
                            let clause_end = self.parse_ext_row_access_policy()?;
                            row_access_policy_span = Some(clause_end);
                        }
                        continue;
                    }

                    TokenKind::Keyword(Keyword::Tag) => {
                        // TAG (name = 'value', ...)
                        let clause_start = tok.span.start;
                        self.advance(); // TAG
                        if let Some(p) = self.peek_non_trivia() {
                            if matches!(p.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                let paren = self.bq_parse_paren_content()?;
                                tag_span = Some(Span {
                                    start: clause_start,
                                    end: paren.end,
                                });
                            }
                        }
                        continue;
                    }

                    TokenKind::Keyword(Keyword::With) => {
                        // WITH — optional prefix for LOCATION, ROW ACCESS POLICY, TAG
                        let with_start = tok.span.start;
                        let saved = self.idx;
                        self.advance(); // WITH
                        self.skip_trivia();

                        match self.peek() {
                            Some(next)
                                if next.lexeme(self.source).eq_ignore_ascii_case("LOCATION") =>
                            {
                                // WITH LOCATION = @stage/path/
                                self.advance(); // LOCATION
                                self.consume_ext_eq()?;
                                let val_end = self.parse_ext_location_value()?;
                                location_span = Some(Span {
                                    start: with_start,
                                    end: val_end,
                                });
                            }
                            Some(next) if matches!(next.kind, TokenKind::Keyword(Keyword::Row)) => {
                                // WITH ROW ACCESS POLICY name ON (col)
                                let rap = self.parse_ext_row_access_policy()?;
                                row_access_policy_span = Some(Span {
                                    start: with_start,
                                    end: rap.end,
                                });
                            }
                            Some(next) if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) => {
                                // WITH TAG (name = 'val', ...)
                                self.advance(); // TAG
                                if let Some(p) = self.peek_non_trivia() {
                                    if matches!(p.kind, TokenKind::Punctuation(Punctuation::LParen))
                                    {
                                        let paren = self.bq_parse_paren_content()?;
                                        tag_span = Some(Span {
                                            start: with_start,
                                            end: paren.end,
                                        });
                                    }
                                }
                            }
                            _ => {
                                // Unknown WITH clause — restore and stop
                                self.idx = saved;
                                break;
                            }
                        }
                        continue;
                    }

                    _ => {} // fall through to identifier-based checks below
                }

                // ── Identifier-dispatched clauses ──
                if self.can_be_identifier_token(tok) {
                    let lex = tok.lexeme(self.source);

                    if lex.eq_ignore_ascii_case("LOCATION") {
                        let clause_start = tok.span.start;
                        self.advance(); // LOCATION
                                        // Snowflake writes `LOCATION = …`; Redshift Spectrum
                                        // writes `LOCATION '…'` with no `=`. Accept both.
                        if let Some(eq) = self.peek_non_trivia() {
                            if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                                self.advance(); // =
                            }
                        }
                        let val_end = self.parse_ext_location_value()?;
                        location_span = Some(Span {
                            start: clause_start,
                            end: val_end,
                        });
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("STORED") {
                        // Redshift Spectrum: STORED AS <format>
                        let clause_start = tok.span.start;
                        let mut clause_end = tok.span.end;
                        self.advance(); // STORED
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Keyword(Keyword::As)) {
                                if let Some(a) = self.advance() {
                                    clause_end = a.span.end; // AS
                                }
                            }
                        }
                        // Format token(s): single ident (PARQUET/TEXTFILE/ORC) or
                        // INPUTFORMAT '..' OUTPUTFORMAT '..' — consume to boundary.
                        loop {
                            match self.peek_non_trivia() {
                                None => break,
                                Some(t) => {
                                    if self.is_ext_table_clause_boundary(t) {
                                        break;
                                    }
                                    if let Some(a) = self.advance() {
                                        clause_end = a.span.end;
                                    }
                                }
                            }
                        }
                        stored_as_span = Some(Span {
                            start: clause_start,
                            end: clause_end,
                        });
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("IAM_ROLE") {
                        // Redshift Spectrum: IAM_ROLE { default | '<arn>' }
                        let clause_start = tok.span.start;
                        let mut clause_end = tok.span.end;
                        self.advance(); // IAM_ROLE
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Literal(_)) {
                                if let Some(a) = self.advance() {
                                    clause_end = a.span.end;
                                }
                            }
                        }
                        redshift_iam_role_span = Some(Span {
                            start: clause_start,
                            end: clause_end,
                        });
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("REFRESH_ON_CREATE") {
                        refresh_on_create_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("AUTO_REFRESH") {
                        auto_refresh_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("PARTITION_TYPE") {
                        partition_type_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("TABLE_FORMAT") {
                        table_format_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }
                    if lex.eq_ignore_ascii_case("AWS_SNS_TOPIC") {
                        aws_sns_topic_span = Some(self.parse_ext_key_eq_value()?);
                        continue;
                    }
                }

                // ── Statement boundary ──
                if self.is_statement_keyword(tok) {
                    break;
                }

                // Unknown token — consume and continue (future-proofing)
                self.advance();
            }
        }

        // ── Compute final span from last set clause ──
        let end = [
            tsql_with_options_span,
            redshift_iam_role_span,
            stored_as_span,
            row_format_span,
            tag_span,
            row_access_policy_span,
            comment_span,
            copy_grants_span,
            aws_sns_topic_span,
            table_format_span,
            partition_type_span,
            file_format_span,
            pattern_span,
            auto_refresh_span,
            refresh_on_create_span,
            location_span,
            integration_span,
            using_template_span,
            options_span,
            partition_columns_span,
            connection_span,
            schema_span,
        ]
        .iter()
        .filter_map(|s| s.map(|sp| sp.end))
        .max()
        .unwrap_or(table_name_span.end);
        // CETAS `AS <query>` extends the statement past every clause span.
        let end = as_query_end.map(|e| e.max(end)).unwrap_or(end);

        let span = Span { start, end };
        Ok(AstStmt::CreateExternalTable(Box::new(
            AstCreateExternalTable {
                node_id: self.id_gen.next(),
                span,
                or_replace_span,
                keyword_span,
                table_name_span,
                schema_span,
                connection_span,
                options_span,
                partition_columns_span,
                using_template_span,
                location_span,
                integration_span,
                refresh_on_create_span,
                auto_refresh_span,
                pattern_span,
                file_format_span,
                partition_type_span,
                table_format_span,
                aws_sns_topic_span,
                copy_grants_span,
                comment_span,
                row_access_policy_span,
                tag_span,
                stored_as_span,
                row_format_span,
                redshift_iam_role_span,
                tsql_with_options_span,
                data_source_span,
                as_query,
            },
        )))
    }

    /// Parse `CREATE EXTERNAL SCHEMA [IF NOT EXISTS] <name> FROM <source> …`
    /// (Redshift Spectrum / federated query). Dispatched by lexeme from core.
    /// EXTERNAL and SCHEMA both lex as Identifier under Redshift.
    pub(crate) fn try_parse_create_external_schema(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::types::{AstCreateExternalSchema, AstExternalSchemaSource};

        let _depth = self.track_depth("create_external_schema")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // EXTERNAL (Identifier)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !external_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::invalid_statement(
                external_tok.span,
                "expected EXTERNAL keyword".to_string(),
            ));
        }

        // SCHEMA (Identifier)
        let schema_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;
        if !schema_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SCHEMA")
        {
            return Err(ParseError::invalid_statement(
                schema_tok.span,
                "expected SCHEMA after EXTERNAL".to_string(),
            ));
        }
        let mut keyword_end = schema_tok.span.end;

        // Optional IF NOT EXISTS
        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        if let Some(sp) = if_not_exists_span {
            keyword_end = sp.end;
        }
        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Schema name
        let (_, name_span) = self.bq_parse_qualified_name()?;
        let mut end = name_span.end;

        // FROM <source> [<source2>]
        let mut source_kind = AstExternalSchemaSource::Other;
        let mut source_span = name_span;
        if let Some(from_tok) = self.peek_non_trivia() {
            if matches!(from_tok.kind, TokenKind::Keyword(Keyword::From)) {
                self.advance(); // FROM
                if let Some(w1) = self.peek_non_trivia() {
                    let w1_start = w1.span.start;
                    let mut src_end = w1.span.end;
                    let lex1 = w1.lexeme(self.source).to_ascii_uppercase();
                    self.advance(); // first source word
                    let lex2 = self
                        .peek_non_trivia()
                        .map(|t| t.lexeme(self.source).to_ascii_uppercase());
                    source_kind = match (lex1.as_str(), lex2.as_deref()) {
                        ("DATA", Some("CATALOG")) => {
                            if let Some(t) = self.advance() {
                                src_end = t.span.end;
                            }
                            AstExternalSchemaSource::DataCatalog
                        }
                        ("HIVE", Some("METASTORE")) => {
                            if let Some(t) = self.advance() {
                                src_end = t.span.end;
                            }
                            AstExternalSchemaSource::HiveMetastore
                        }
                        ("POSTGRES", _) => AstExternalSchemaSource::Postgres,
                        ("MYSQL", _) => AstExternalSchemaSource::Mysql,
                        ("KINESIS", _) => AstExternalSchemaSource::Kinesis,
                        ("REDSHIFT", _) => AstExternalSchemaSource::Redshift,
                        _ => AstExternalSchemaSource::Other,
                    };
                    source_span = Span {
                        start: w1_start,
                        end: src_end,
                    };
                    end = src_end;
                }
            }
        }

        // Property loop: DATABASE '..' | SCHEMA '..' | URI '..' | PORT n |
        // IAM_ROLE '..' | CREATE EXTERNAL DATABASE [IF NOT EXISTS]
        let mut database_literal_span: Option<Span> = None;
        let mut uri_span: Option<Span> = None;
        let mut port_span: Option<Span> = None;
        let mut iam_role_span: Option<Span> = None;
        let mut create_external_database_span: Option<Span> = None;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            // Trailing CREATE EXTERNAL DATABASE [IF NOT EXISTS] — part of THIS
            // statement (consume so it is not re-parsed as a new statement).
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Create)) {
                let clause_start = tok.span.start;
                let clause_end = self.bq_consume_until_semi(clause_start);
                create_external_database_span = Some(Span {
                    start: clause_start,
                    end: clause_end,
                });
                end = clause_end;
                continue;
            }
            if self.is_statement_keyword(tok) {
                break;
            }
            if self.can_be_identifier_token(tok) {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("DATABASE") {
                    self.advance(); // DATABASE
                    if let Some(v) = self.peek_non_trivia() {
                        if matches!(v.kind, TokenKind::Literal(_)) {
                            if let Some(a) = self.advance() {
                                database_literal_span = Some(a.span);
                                end = a.span.end;
                            }
                        }
                    }
                    continue;
                }
                if lex.eq_ignore_ascii_case("URI") {
                    self.advance(); // URI
                    if let Some(v) = self.peek_non_trivia() {
                        if matches!(v.kind, TokenKind::Literal(_)) {
                            if let Some(a) = self.advance() {
                                uri_span = Some(a.span);
                                end = a.span.end;
                            }
                        }
                    }
                    continue;
                }
                if lex.eq_ignore_ascii_case("PORT") {
                    self.advance(); // PORT
                    if let Some(v) = self.peek_non_trivia() {
                        if matches!(v.kind, TokenKind::Literal(_)) {
                            if let Some(a) = self.advance() {
                                port_span = Some(a.span);
                                end = a.span.end;
                            }
                        }
                    }
                    continue;
                }
                if lex.eq_ignore_ascii_case("IAM_ROLE") {
                    self.advance(); // IAM_ROLE
                    if let Some(v) = self.peek_non_trivia() {
                        if matches!(v.kind, TokenKind::Literal(_)) {
                            if let Some(a) = self.advance() {
                                iam_role_span = Some(a.span);
                                end = a.span.end;
                            }
                        }
                    }
                    continue;
                }
                if lex.eq_ignore_ascii_case("SCHEMA") {
                    self.advance(); // SCHEMA
                    if let Some(v) = self.peek_non_trivia() {
                        if matches!(v.kind, TokenKind::Literal(_)) {
                            if let Some(a) = self.advance() {
                                end = a.span.end;
                            }
                        }
                    }
                    continue;
                }
            }
            // Unknown token — consume for forward-compat.
            if let Some(a) = self.advance() {
                end = a.span.end;
            }
        }

        let span = Span { start, end };
        Ok(AstStmt::CreateExternalSchema(Box::new(
            AstCreateExternalSchema {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                if_not_exists_span,
                name_span,
                source_kind,
                source_span,
                database_literal_span,
                uri_span,
                port_span,
                iam_role_span,
                create_external_database_span,
            },
        )))
    }

    // ── Helpers for CREATE EXTERNAL TABLE clause parsing ──

    /// Parse KEY = VALUE where VALUE is a single token (string, boolean, identifier).
    /// Cursor is at the KEY token. Returns span from KEY to VALUE.
    fn parse_ext_key_eq_value(&mut self) -> ParseResult<Span> {
        let key_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["property name".to_string()])?;
        let key_start = key_tok.span.start;

        // Consume =
        let eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::invalid_statement(
                eq_tok.span,
                format!("expected '=' after {}", key_tok.lexeme(self.source)),
            ));
        }

        // Consume value (single token: string literal, boolean, identifier, number)
        let val_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;

        Ok(Span {
            start: key_start,
            end: val_tok.span.end,
        })
    }

    /// Consume a `=` operator. Used when the key has already been consumed.
    fn consume_ext_eq(&mut self) -> ParseResult<()> {
        if let Some(eq) = self.peek_non_trivia() {
            if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
                return Ok(());
            }
        }
        Err(ParseError::invalid_statement(
            self.current_span(),
            "expected '='".to_string(),
        ))
    }

    /// Parse LOCATION value after `=` has been consumed.
    /// Handles both stage references (@namespace.stage/path/) and string literals ('url').
    /// Returns the end position of the consumed value.
    fn parse_ext_location_value(&mut self) -> ParseResult<u32> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => {
                return Err(ParseError::invalid_statement(
                    self.current_span(),
                    "expected stage reference or URL after LOCATION =".to_string(),
                ))
            }
        };

        // String literal: LOCATION = 's3://bucket/path/'
        if matches!(tok.kind, TokenKind::Literal(_)) {
            let val = self.advance().unwrap();
            return Ok(val.span.end);
        }

        // Stage reference: @namespace.stage/path/
        // Tokens: Unknown(@), Identifier(name), [Dot, Identifier]*, [Slash, Identifier|Slash]*
        // Consume until we hit a token that starts a new clause.
        let mut end = tok.span.start;
        loop {
            match self.peek_non_trivia() {
                None => break,
                Some(t) => {
                    if self.is_ext_table_clause_boundary(t) {
                        break;
                    }
                    end = self.advance().unwrap().span.end;
                }
            }
        }
        Ok(end)
    }

    /// Parse ROW ACCESS POLICY name ON (col_list).
    /// Cursor is at the ROW token. Returns the full clause span.
    fn parse_ext_row_access_policy(&mut self) -> ParseResult<Span> {
        let row_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ROW".to_string()])?;
        let clause_start = row_tok.span.start;

        // ACCESS
        if let Some(t) = self.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Keyword(Keyword::Access)) {
                self.advance();
            }
        }
        // POLICY
        if let Some(t) = self.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Keyword(Keyword::Policy)) {
                self.advance();
            }
        }
        // Policy name (possibly qualified: db.schema.policy_name)
        let (_, name_span) = self.bq_parse_qualified_name()?;
        let mut clause_end = name_span.end;

        // ON (col_list)
        if let Some(t) = self.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Keyword(Keyword::On)) {
                self.advance(); // ON
                if let Some(p) = self.peek_non_trivia() {
                    if matches!(p.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let paren = self.bq_parse_paren_content()?;
                        clause_end = paren.end;
                    }
                }
            }
        }

        Ok(Span {
            start: clause_start,
            end: clause_end,
        })
    }

    /// Check whether a token represents the start of a new CREATE EXTERNAL TABLE
    /// clause (Snowflake). Used to stop consuming multi-token values like stage paths.
    fn is_ext_table_clause_boundary(&self, tok: &Token) -> bool {
        // Keywords that start clauses
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Integration)
                | TokenKind::Keyword(Keyword::FileFormat)
                | TokenKind::Keyword(Keyword::Pattern)
                | TokenKind::Keyword(Keyword::Copy)
                | TokenKind::Keyword(Keyword::Comment)
                | TokenKind::Keyword(Keyword::With)
                | TokenKind::Keyword(Keyword::Row)
                | TokenKind::Keyword(Keyword::Tag)
                | TokenKind::Keyword(Keyword::Using)
                | TokenKind::Keyword(Keyword::Partition)
                | TokenKind::Punctuation(Punctuation::Semi)
        ) {
            return true;
        }
        // Identifiers that start clauses
        if self.can_be_identifier_token(tok) {
            let lex = tok.lexeme(self.source);
            if lex.eq_ignore_ascii_case("LOCATION")
                || lex.eq_ignore_ascii_case("REFRESH_ON_CREATE")
                || lex.eq_ignore_ascii_case("AUTO_REFRESH")
                || lex.eq_ignore_ascii_case("PARTITION_TYPE")
                || lex.eq_ignore_ascii_case("TABLE_FORMAT")
                || lex.eq_ignore_ascii_case("AWS_SNS_TOPIC")
                // Redshift Spectrum clause starters
                || lex.eq_ignore_ascii_case("STORED")
                || lex.eq_ignore_ascii_case("IAM_ROLE")
            {
                return true;
            }
        }
        // Statement-level keywords
        self.is_statement_keyword(tok)
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE [OR REPLACE] MODEL [IF NOT EXISTS] name
    //   [TRANSFORM (select_list)]
    //   [INPUT (field_name field_type, ...)]
    //   [OUTPUT (field_name field_type, ...)]
    //   [REMOTE WITH CONNECTION {connection_name | DEFAULT}]
    //   [OPTIONS(model_option_list)]
    //   [AS query_statement]
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_create_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_create_model")?;

        // Current position is at CREATE.
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Parse optional OR REPLACE
        let mut or_replace = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // consume OR
                                // Expect REPLACE
                let rep = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                if !rep.lexeme(self.source).eq_ignore_ascii_case("REPLACE") {
                    return Err(ParseError::invalid_statement(
                        rep.span,
                        format!(
                            "Expected REPLACE after OR, found '{}'",
                            rep.lexeme(self.source)
                        ),
                    ));
                }
                or_replace = true;
            }
        }

        // Consume MODEL (Identifier)
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        if !model_tok.lexeme(self.source).eq_ignore_ascii_case("MODEL") {
            return Err(ParseError::invalid_statement(
                model_tok.span,
                format!("Expected MODEL, found '{}'", model_tok.lexeme(self.source)),
            ));
        }

        // Parse optional IF NOT EXISTS
        let mut if_not_exists = false;
        let mut keyword_end = model_tok.span.end;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().unwrap();
                // Expect NOT
                let not_tok = self
                    .advance()
                    .ok_or_eof(if_tok.span, vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::invalid_statement(
                        not_tok.span,
                        "Expected NOT after IF".to_string(),
                    ));
                }
                // Expect EXISTS
                let exists_tok = self
                    .advance()
                    .ok_or_eof(not_tok.span, vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::invalid_statement(
                        exists_tok.span,
                        "Expected EXISTS after IF NOT".to_string(),
                    ));
                }
                if_not_exists = true;
                keyword_end = exists_tok.span.end;
            }
        }

        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Parse model name (qualified, may be backtick-quoted)
        let (_name, model_name_span) = self.bq_parse_qualified_name()?;

        // Parse optional clauses in order: TRANSFORM, INPUT, OUTPUT, REMOTE, OPTIONS, AS
        let mut transform_span: Option<Span> = None;
        let mut input_span: Option<Span> = None;
        let mut output_span: Option<Span> = None;
        let mut remote_connection_span: Option<Span> = None;
        let mut options_span: Option<Span> = None;
        let mut query: Option<Box<AstStmt>> = None;

        while let Some(tok) = self.peek_non_trivia() {
            // Semicolon or statement boundary → stop
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // AS query_statement — must be last clause
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                self.advance(); // consume AS
                let q = self.parse_flow_statement()?;
                query = Some(Box::new(q));
                break;
            }

            // TRANSFORM(...) clause
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("TRANSFORM")
            {
                let clause_start = tok.span.start;
                self.advance(); // consume TRANSFORM
                let paren = self.bq_parse_paren_content()?;
                transform_span = Some(Span {
                    start: clause_start,
                    end: paren.end,
                });
                continue;
            }

            // INPUT(...) clause
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Input)) {
                let clause_start = tok.span.start;
                self.advance(); // consume INPUT
                let paren = self.bq_parse_paren_content()?;
                input_span = Some(Span {
                    start: clause_start,
                    end: paren.end,
                });
                continue;
            }

            // OUTPUT(...) clause
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Output)) {
                let clause_start = tok.span.start;
                self.advance(); // consume OUTPUT
                let paren = self.bq_parse_paren_content()?;
                output_span = Some(Span {
                    start: clause_start,
                    end: paren.end,
                });
                continue;
            }

            // REMOTE WITH CONNECTION name/DEFAULT
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("REMOTE")
            {
                let clause_start = tok.span.start;
                self.advance(); // consume REMOTE
                                // Expect WITH
                let with_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                    return Err(ParseError::invalid_statement(
                        with_tok.span,
                        format!(
                            "Expected WITH after REMOTE, found '{}'",
                            with_tok.lexeme(self.source)
                        ),
                    ));
                }
                // Expect CONNECTION
                let conn_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CONNECTION".to_string()])?;
                if !conn_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("CONNECTION")
                {
                    return Err(ParseError::invalid_statement(
                        conn_tok.span,
                        format!(
                            "Expected CONNECTION after WITH, found '{}'",
                            conn_tok.lexeme(self.source)
                        ),
                    ));
                }
                // Parse connection name or DEFAULT
                let next = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::invalid_statement(
                        conn_tok.span,
                        "Expected connection name or DEFAULT after CONNECTION".to_string(),
                    )
                })?;
                let clause_end = if matches!(next.kind, TokenKind::Keyword(Keyword::Default)) {
                    let default_tok = self.advance().unwrap();
                    default_tok.span.end
                } else {
                    let (_conn_name, conn_span) = self.bq_parse_qualified_name()?;
                    conn_span.end
                };
                remote_connection_span = Some(Span {
                    start: clause_start,
                    end: clause_end,
                });
                continue;
            }

            // OPTIONS(...) clause
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
            {
                options_span = Some(self.parse_bq_export_options()?);
                continue;
            }

            // Unknown token — break (error recovery will handle)
            break;
        }

        // Calculate final span
        let end = query
            .as_ref()
            .map(|q| q.span().end)
            .or(options_span.map(|s| s.end))
            .or(remote_connection_span.map(|s| s.end))
            .or(output_span.map(|s| s.end))
            .or(input_span.map(|s| s.end))
            .or(transform_span.map(|s| s.end))
            .unwrap_or(model_name_span.end);
        let span = Span { start, end };

        let ast = AstBqCreateModel {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            or_replace,
            if_not_exists,
            model_name_span,
            transform_span,
            input_span,
            output_span,
            remote_connection_span,
            options_span,
            query,
        };
        Ok(AstStmt::BqCreateModel(Box::new(ast)))
    }

    // ───────────────────────────────────────────────────────────────
    // ALTER MODEL [IF EXISTS] model_name SET OPTIONS(option_list)
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_alter_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_alter_model")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;

        // Consume MODEL
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        if !model_tok.lexeme(self.source).eq_ignore_ascii_case("MODEL") {
            return Err(ParseError::invalid_statement(
                model_tok.span,
                format!(
                    "Expected MODEL after ALTER, found '{}'",
                    model_tok.lexeme(self.source)
                ),
            ));
        }

        // Optional IF EXISTS
        let mut if_exists = false;
        let mut keyword_end = model_tok.span.end;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // consume IF
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::invalid_statement(
                        exists_tok.span,
                        "Expected EXISTS after IF".to_string(),
                    ));
                }
                if_exists = true;
                keyword_end = exists_tok.span.end;
            }
        }

        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Parse model name
        let (_name, model_name_span) = self.bq_parse_qualified_name()?;

        // Expect SET OPTIONS(...)
        let set_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
        if !matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            return Err(ParseError::invalid_statement(
                set_tok.span,
                format!(
                    "Expected SET after model name, found '{}'",
                    set_tok.lexeme(self.source)
                ),
            ));
        }
        let set_start = set_tok.span.start;

        let options_paren = self.parse_bq_export_options()?;
        let set_options_span = Span {
            start: set_start,
            end: options_paren.end,
        };

        let span = Span {
            start,
            end: set_options_span.end,
        };

        let ast = AstBqAlterModel {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            if_exists,
            model_name_span,
            set_options_span,
        };
        Ok(AstStmt::BqAlterModel(Box::new(ast)))
    }

    // ───────────────────────────────────────────────────────────────
    // EXPORT MODEL model_name OPTIONS(URI = string [, ...])
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_export_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_export_model")?;

        // Current position is at EXPORT
        let export_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXPORT".to_string()])?;
        let start = export_tok.span.start;

        // Consume MODEL
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        if !model_tok.lexeme(self.source).eq_ignore_ascii_case("MODEL") {
            return Err(ParseError::invalid_statement(
                model_tok.span,
                format!(
                    "Expected MODEL after EXPORT, found '{}'",
                    model_tok.lexeme(self.source)
                ),
            ));
        }
        let keyword_span = Span {
            start,
            end: model_tok.span.end,
        };

        // Parse model name
        let (_name, model_name_span) = self.bq_parse_qualified_name()?;

        // Expect OPTIONS(...)
        let options_span = self.parse_bq_export_options()?;

        let span = Span {
            start,
            end: options_span.end,
        };

        let ast = AstBqExportModel {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            model_name_span,
            options_span,
        };
        Ok(AstStmt::BqExportModel(Box::new(ast)))
    }

    // ───────────────────────────────────────────────────────────────
    // DROP MODEL [IF EXISTS] model_name
    // ───────────────────────────────────────────────────────────────

    pub(crate) fn try_parse_bq_drop_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("bq_drop_model")?;

        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;

        // Consume MODEL
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        if !model_tok.lexeme(self.source).eq_ignore_ascii_case("MODEL") {
            return Err(ParseError::invalid_statement(
                model_tok.span,
                format!(
                    "Expected MODEL after DROP, found '{}'",
                    model_tok.lexeme(self.source)
                ),
            ));
        }

        // Optional IF EXISTS
        let mut if_exists = false;
        let mut keyword_end = model_tok.span.end;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // consume IF
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::invalid_statement(
                        exists_tok.span,
                        "Expected EXISTS after IF".to_string(),
                    ));
                }
                if_exists = true;
                keyword_end = exists_tok.span.end;
            }
        }

        let keyword_span = Span {
            start,
            end: keyword_end,
        };

        // Parse model name
        let (_name, model_name_span) = self.bq_parse_qualified_name()?;

        let span = Span {
            start,
            end: model_name_span.end,
        };

        let ast = AstBqDropModel {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            if_exists,
            model_name_span,
        };
        Ok(AstStmt::BqDropModel(Box::new(ast)))
    }
}
