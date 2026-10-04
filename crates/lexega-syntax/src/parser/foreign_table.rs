// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the SQL/MED `CREATE FOREIGN TABLE` statement (PostgreSQL FDW).
//!
//! `CREATE FOREIGN TABLE [IF NOT EXISTS] name
//!  ( [column_def [, …]] ) SERVER name [OPTIONS (…)]`
//! `CREATE FOREIGN TABLE [IF NOT EXISTS] name
//!  PARTITION OF parent { FOR VALUES … | DEFAULT } SERVER name [OPTIONS (…)]`
//!
//! Exposes a remote relation locally; queries against it reach the foreign
//! server across the instance boundary. Recognition lifts the server name,
//! whether the table is a partition, and whether an OPTIONS bag is present.
//! Column definitions are not governance-relevant — the reader scans past
//! them (and the partition clause) to the depth-0 `SERVER` operand, which
//! covers both forms uniformly.
//!
//! Dispatched from the `CREATE FOREIGN TABLE` arm in `core.rs` (gated on the
//! `TABLE` keyword so it wins over the Databricks `CREATE FOREIGN CATALOG`).
//!
//! Token reference (`--debug-tokens`, postgresql dialect):
//!   FOREIGN / TABLE / IF / NOT / EXISTS / PARTITION → Keyword
//!   SERVER / OPTIONS / column names                 → Identifier

use crate::ast::types::{AstCreateForeignTable, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_create_foreign_table(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_foreign_table")?;
        let result = (|| {
            let create_span = self.current_span();
            // 1. CREATE FOREIGN TABLE. The dispatch guard guarantees all three.
            let create_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
            let start = create_tok.span.start;
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FOREIGN".to_string()])?;
            self.advance()
                .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;

            // 2. Optional IF NOT EXISTS.
            let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

            // 3. Table name (possibly qualified).
            let name_span = self.parse_qualified_name_span()?;

            // 4. Scan to the depth-0 `SERVER` operand, tracking paren depth so
            //    the column list and a `FOR VALUES (…)` partition bound are
            //    skipped uniformly. Note whether a PARTITION clause appears.
            let mut is_partition = false;
            let mut depth: u32 = 0;
            let server_span;
            loop {
                let tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected SERVER in CREATE FOREIGN TABLE".to_string(),
                        },
                    )
                })?;
                match tok.kind {
                    TokenKind::Keyword(Keyword::Partition) if depth == 0 => {
                        is_partition = true;
                    }
                    TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof => {
                        return Err(ParseError::new(
                            tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "CREATE FOREIGN TABLE missing SERVER clause".to_string(),
                            },
                        ));
                    }
                    _ if depth == 0 && tok.lexeme(self.source).eq_ignore_ascii_case("SERVER") => {
                        // Consume SERVER, then read the server name.
                        self.advance()
                            .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;
                        server_span = self.parse_qualified_name_span()?;
                        break;
                    }
                    _ => {}
                }
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;
            }
            let mut end = server_span.end;

            // 5. Optional OPTIONS ( … ) — consume the balanced paren group,
            //    noting presence. Values can name remote schemas/tables but are
            //    not surfaced.
            let mut options_present = false;
            let has_options = self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("OPTIONS"))
                .unwrap_or(false);
            if has_options {
                options_present = true;
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIONS".to_string()])?;
                let lparen = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    return Err(ParseError::new(
                        lparen.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected ( after OPTIONS in CREATE FOREIGN TABLE".to_string(),
                        },
                    ));
                }
                end = lparen.span.end;
                let mut odepth: u32 = 1;
                while odepth > 0 {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    end = t.span.end;
                    match t.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => odepth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => {
                            odepth = odepth.saturating_sub(1)
                        }
                        _ => {}
                    }
                }
            }

            Ok(AstStmt::CreateForeignTable(Box::new(
                AstCreateForeignTable {
                    node_id: self.id_gen.next(),
                    span: Span { start, end },
                    create_span,
                    name_span,
                    if_not_exists,
                    is_partition,
                    server_span,
                    options_present,
                },
            )))
        })();
        result
    }
}
