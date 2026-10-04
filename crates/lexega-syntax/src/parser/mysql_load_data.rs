// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the MySQL `LOAD DATA … INFILE` statement (bulk file ingestion).
//!
//! `LOAD DATA [LOW_PRIORITY | CONCURRENT] [LOCAL] INFILE '<path>'
//!    [REPLACE | IGNORE] INTO TABLE tbl_name [PARTITION (...)]
//!    [CHARACTER SET cs] [{FIELDS|COLUMNS} ...] [LINES ...] [IGNORE n LINES]
//!    [(col, ...)] [SET col = expr, ...]`
//!
//! Distinct grammar from BigQuery's `LOAD DATA … FROM FILES(...)`. Recognition
//! lifts the `LOCAL` modifier (client-side vs server-side file read — the
//! security-relevant axis), the `INFILE` path, and the `INTO TABLE` target;
//! the framing clauses (FIELDS / LINES / etc.) are consumed but not modelled.
//! Dispatched from the `LOAD` arm in `core.rs` when `is_mysql_load_data_at`
//! sees an `INFILE` marker ahead — otherwise it is BigQuery's LOAD DATA.

use crate::ast::types::{AstMysqlLoadData, AstStmt};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `LOAD DATA` is the MySQL `INFILE`
/// form when an `INFILE` token appears (past the optional `LOW_PRIORITY` /
/// `CONCURRENT` / `LOCAL` modifiers) before the first depth-0 terminator —
/// otherwise it is BigQuery's `FROM FILES(...)` form. Scans significant tokens
/// from `idx` (the LOAD position).
pub(crate) fn is_mysql_load_data_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    // Skip LOAD, DATA, then the optional priority + LOCAL modifiers; the next
    // word must be INFILE. Stop at a depth-0 terminator / FROM (BQ marker).
    let mut i = idx;
    let mut seen_data = false;
    while i < tokens.len() {
        match tokens[i].kind {
            TokenKind::Eof => return false,
            TokenKind::Punctuation(Punctuation::Semi) => return false,
            TokenKind::Keyword(Keyword::From) => return false,
            TokenKind::LineComment | TokenKind::BlockComment => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let lx = tokens[i].lexeme(source);
        if lx.eq_ignore_ascii_case("INFILE") {
            return true;
        }
        if !seen_data {
            // Require the leading LOAD DATA before scanning modifiers.
            if lx.eq_ignore_ascii_case("DATA") {
                seen_data = true;
            }
            i += 1;
            continue;
        }
        // After DATA, only the priority / LOCAL modifiers may precede INFILE.
        if lx.eq_ignore_ascii_case("LOW_PRIORITY")
            || lx.eq_ignore_ascii_case("CONCURRENT")
            || lx.eq_ignore_ascii_case("LOCAL")
            || lx.eq_ignore_ascii_case("LOAD")
        {
            i += 1;
            continue;
        }
        return false;
    }
    false
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mysql_load_data(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_load_data")?;

        // LOAD DATA (the dispatch guard guarantees both).
        let load_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOAD".to_string()])?;
        let start = load_tok.span.start;
        let data_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
        let keyword_span = Span {
            start,
            end: data_tok.span.end,
        };

        // Optional LOW_PRIORITY | CONCURRENT.
        if self
            .peek_non_trivia()
            .map(|t| {
                let lx = t.lexeme(self.source);
                lx.eq_ignore_ascii_case("LOW_PRIORITY") || lx.eq_ignore_ascii_case("CONCURRENT")
            })
            .unwrap_or(false)
        {
            self.advance();
        }

        // Optional LOCAL.
        let mut local = false;
        if self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("LOCAL"))
            .unwrap_or(false)
        {
            local = true;
            self.advance();
        }

        // INFILE '<path>'.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["INFILE".to_string()])?;
        let path_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["file path".to_string()])?;
        let infile_path_span = path_tok.span;
        let mut end = path_tok.span.end;

        // Scan the remaining clauses to the depth-0 terminator, lifting the
        // `INTO TABLE <name>` target. REPLACE/IGNORE, PARTITION, CHARACTER SET,
        // FIELDS/LINES, IGNORE n LINES, (cols), SET … are consumed.
        let mut target_table_span: Option<Span> = None;
        let mut depth: u32 = 0;
        loop {
            let (is_semi, is_eof, is_lparen, is_rparen, is_into) = match self.peek_non_trivia() {
                None => break,
                Some(t) => (
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)),
                    matches!(t.kind, TokenKind::Eof),
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                    depth == 0 && matches!(t.kind, TokenKind::Keyword(Keyword::Into)),
                ),
            };
            if is_eof || (is_semi && depth == 0) {
                break;
            }
            if is_lparen {
                depth += 1;
            } else if is_rparen {
                depth = depth.saturating_sub(1);
            }
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = tok.span.end;

            // INTO TABLE <name> — lift the (optionally qualified) target.
            if is_into
                && self
                    .peek_non_trivia()
                    .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Table)))
                    .unwrap_or(false)
            {
                self.advance(); // TABLE
                if let Some(mut ts) = self.peek_non_trivia().map(|t| t.span) {
                    let nt = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
                    end = nt.span.end;
                    while self
                        .peek_non_trivia()
                        .map(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Dot)))
                        .unwrap_or(false)
                    {
                        self.advance(); // dot
                        if let Some(part) = self.peek_non_trivia() {
                            let pt_end = part.span.end;
                            self.advance();
                            ts = Span {
                                start: ts.start,
                                end: pt_end,
                            };
                            end = pt_end;
                        }
                    }
                    target_table_span = Some(ts);
                }
            }
        }

        let span = Span { start, end };
        let ast = AstMysqlLoadData {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            local,
            infile_path_span,
            target_table_span,
        };
        Ok(AstStmt::MysqlLoadData(Box::new(ast)))
    }
}
