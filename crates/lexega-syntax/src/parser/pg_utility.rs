// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for PostgreSQL utility statements.
//!
//! These are statements that don't exist in Snowflake SQL and are
//! specific to PostgreSQL dialects:
//!
//! - `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON ...`
//! - `COMMENT ON {TABLE|COLUMN|...} name IS 'text'`
//! - `DO [LANGUAGE lang] $$ body $$`
//! - `VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE] [table ...]`
//! - `ANALYZE [VERBOSE] [table [(column, ...)]]`
//! - `CREATE TYPE name AS ...`
//! - `ALTER TYPE name ...`
//! - `CREATE EXTENSION [IF NOT EXISTS] name ...`
//!
//! Each parser extracts real structural fields and builds both AST and CST
//! nodes so that the formatter can emit individual tokens with proper
//! keyword casing and spacing.

use crate::ast::types::{
    AstAlterPgTrigger, AstAlterSequence, AstAlterType, AstAnalyzeStmt, AstCommentOn,
    AstCreateExtension, AstCreateIndex, AstCreatePgTrigger, AstCreateSequence, AstCreateType,
    AstDoBlock, AstDropPgTrigger, AstStmt, AstVacuum, PgAlterTriggerAction, PgCascadeRestrict,
    PgDeferrableMode, PgForEachMode, PgReferencingEntry, PgTriggerEvent, PgTriggerEventKind,
    PgTriggerTiming,
};
use crate::cst::TokenId;
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON table
    //   [USING method] (columns) [INCLUDE (columns)] [WHERE predicate]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_index_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_index")?;
        let start_span = self.current_span();

        // CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;
        let mut end = create_tok.span.end;

        // Optional: UNIQUE
        let mut unique = false;
        let mut unique_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Unique)) {
                self.advance();
                unique = true;
                unique_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            }
        }

        // Optional: CLUSTERED | NONCLUSTERED (T-SQL index type; identifiers in our lexer)
        let mut clustered = None;
        let mut clustered_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            let lx = tok.lexeme(self.source);
            if lx.eq_ignore_ascii_case("CLUSTERED") {
                self.advance();
                clustered = Some(crate::ast::AstIndexClustering::Clustered);
                clustered_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            } else if lx.eq_ignore_ascii_case("NONCLUSTERED") {
                self.advance();
                clustered = Some(crate::ast::AstIndexClustering::NonClustered);
                clustered_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            }
        }

        // Optional: COLUMNSTORE (T-SQL columnstore index)
        let mut columnstore = false;
        let mut columnstore_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("COLUMNSTORE") {
                self.advance();
                columnstore = true;
                columnstore_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            }
        }

        // Optional: FULLTEXT | SPATIAL (MySQL index kinds; identifiers in our lexer)
        let mut mysql_index_kind = None;
        let mut mysql_index_kind_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            let lx = tok.lexeme(self.source);
            if lx.eq_ignore_ascii_case("FULLTEXT") {
                self.advance();
                mysql_index_kind = Some(crate::ast::AstMysqlIndexKind::Fulltext);
                mysql_index_kind_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            } else if lx.eq_ignore_ascii_case("SPATIAL") {
                self.advance();
                mysql_index_kind = Some(crate::ast::AstMysqlIndexKind::Spatial);
                mysql_index_kind_keyword = Some(self.last_token_id());
                end = self.tokens[self.idx - 1].span.end;
            }
        }

        // INDEX keyword (Identifier in our lexer)
        let mut index_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("INDEX") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;
                index_keyword = Some(self.last_token_id());
                end = t.span.end;
            }
        }
        let index_keyword = index_keyword.unwrap_or(create_keyword); // fallback

        // Optional: CONCURRENTLY
        let mut concurrently = false;
        let mut concurrently_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("CONCURRENTLY") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CONCURRENTLY".to_string()])?;
                concurrently = true;
                concurrently_keyword = Some(self.last_token_id());
                end = t.span.end;
            }
        }

        // Optional: IF NOT EXISTS
        let mut if_not_exists = false;
        let mut if_keyword = None;
        let mut not_keyword = None;
        let mut exists_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                if_keyword = Some(self.last_token_id());
                end = t.span.end;
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Not)) {
                        let t2 = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                        not_keyword = Some(self.last_token_id());
                        end = t2.span.end;
                        if let Some(tok3) = self.peek_non_trivia() {
                            if matches!(tok3.kind, TokenKind::Keyword(Keyword::Exists)) {
                                let t3 = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                                exists_keyword = Some(self.last_token_id());
                                end = t3.span.end;
                                if_not_exists = true;
                            }
                        }
                    }
                }
            }
        }

        // Index name (optional — PG allows omitting it, but it's typical)
        // The name comes before ON, so we peek to decide.
        let mut index_name = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) && !matches!(tok.kind, TokenKind::Keyword(Keyword::On))
            {
                let name_start = tok.span.start;
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                let mut name_end = t.span.end;
                // Handle qualified: schema.index_name
                while let Some(dot_tok) = self.peek_non_trivia() {
                    if matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                        self.advance(); // dot
                        if let Some(next) = self.peek_non_trivia() {
                            if matches!(
                                next.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                let n = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["identifier".to_string()],
                                )?;
                                name_end = n.span.end;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                index_name = Some(Span {
                    start: name_start,
                    end: name_end,
                });
                end = name_end;
            }
        }

        // ON keyword
        let mut on_keyword = create_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
                on_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Table name (qualified)
        let mut table_name = Span { start: end, end };
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                table_name = self.parse_qualified_name_span()?;
                end = table_name.end;
            }
        }

        // Optional: USING method
        let mut using_keyword = None;
        let mut using_method = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["USING".to_string()])?;
                using_keyword = Some(self.last_token_id());
                end = t.span.end;
                if let Some(method_tok) = self.peek_non_trivia() {
                    if matches!(
                        method_tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) {
                        let m = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["method".to_string()])?;
                        using_method = Some(Span {
                            start: m.span.start,
                            end: m.span.end,
                        });
                        end = m.span.end;
                    }
                }
            }
        }

        // Parenthesized column list
        let mut columns_l_paren = create_keyword; // fallback
        let mut columns_r_paren = create_keyword; // fallback
        let mut columns_span = Span { start: end, end };
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lp = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                columns_l_paren = self.last_token_id();
                let col_start = lp.span.start;
                end = lp.span.end;

                let mut depth = 1u32;
                while depth > 0 {
                    if let Some(inner) = self.peek_non_trivia() {
                        match inner.kind {
                            TokenKind::Punctuation(Punctuation::LParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                end = t.span.end;
                                depth += 1;
                            }
                            TokenKind::Punctuation(Punctuation::RParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                end = t.span.end;
                                depth -= 1;
                                if depth == 0 {
                                    columns_r_paren = self.last_token_id();
                                }
                            }
                            TokenKind::Eof => break,
                            _ => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                                end = t.span.end;
                            }
                        }
                    } else {
                        break;
                    }
                }
                columns_span = Span {
                    start: col_start,
                    end,
                };
            }
        }

        // MySQL index option: `(cols) USING {BTREE | HASH}` — the method
        // follows the column list in MySQL (it precedes it in PostgreSQL).
        // Consumed into the statement span so the tail doesn't orphan; the
        // formatter preserves it byte-exact via the trailing span.
        if using_keyword.is_none() {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["USING".to_string()])?;
                    end = t.span.end;
                    if let Some(method_tok) = self.peek_non_trivia() {
                        if matches!(
                            method_tok.kind,
                            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                        ) {
                            let m = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["method".to_string()])?;
                            using_method = Some(Span {
                                start: m.span.start,
                                end: m.span.end,
                            });
                            end = m.span.end;
                        }
                    }
                }
            }
        }

        // Optional: INCLUDE (columns)
        let mut include_keyword = None;
        let mut include_l_paren = None;
        let mut include_r_paren = None;
        let mut include_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("INCLUDE") {
                let inc_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["INCLUDE".to_string()])?;
                include_keyword = Some(self.last_token_id());
                let inc_start = inc_tok.span.start;
                end = inc_tok.span.end;

                if let Some(lp_tok) = self.peek_non_trivia() {
                    if matches!(lp_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let lp = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                        include_l_paren = Some(self.last_token_id());
                        end = lp.span.end;

                        let mut depth = 1u32;
                        while depth > 0 {
                            if let Some(inner) = self.peek_non_trivia() {
                                match inner.kind {
                                    TokenKind::Punctuation(Punctuation::LParen) => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["(".to_string()],
                                        )?;
                                        end = t.span.end;
                                        depth += 1;
                                    }
                                    TokenKind::Punctuation(Punctuation::RParen) => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec![")".to_string()],
                                        )?;
                                        end = t.span.end;
                                        depth -= 1;
                                        if depth == 0 {
                                            include_r_paren = Some(self.last_token_id());
                                        }
                                    }
                                    TokenKind::Eof => break,
                                    _ => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["token".to_string()],
                                        )?;
                                        end = t.span.end;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                        include_span = Some(Span {
                            start: inc_start,
                            end,
                        });
                    }
                }
            }
        }

        // Optional: WHERE predicate — use expression parser
        let mut where_keyword = None;
        let mut where_predicate: Option<Box<crate::ast::AstExpr>> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
                let w = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WHERE".to_string()])?;
                where_keyword = Some(self.last_token_id());
                end = w.span.end;
                // Delegate to the existing expression parser (same as UPDATE/DELETE WHERE)
                if let Ok(expr) = self.parse_expr() {
                    end = crate::parser::scripting::expr_span_end(&expr);
                    where_predicate = Some(Box::new(expr));
                }
            }
        }

        // Optional T-SQL tail: `WITH (options)`, storage `ON ...`, `FILESTREAM_ON ...`.
        // These carry no governance structure, so they are consumed permissively
        // (paren-balanced where present) and preserved byte-exact by the formatter
        // via a trailing span. Consuming them keeps the statement whole instead of
        // orphaning the tail into a separate unreadable statement.
        //
        // WITH (option = value, ...)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let saved = self.idx;
                let with_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let group = self.consume_balanced_parens()?;
                        end = group.end;
                    } else {
                        // Not an index-options WITH — leave it for the caller.
                        self.idx = saved;
                    }
                } else {
                    end = with_tok.span.end;
                }
            }
        }

        // Storage: `ON { filegroup | partition_scheme(col) | "default" }`
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                self.advance(); // ON
                end = self.tokens[self.idx - 1].span.end;
                if let Some(name_tok) = self.peek_non_trivia() {
                    if matches!(
                        name_tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) {
                        let name = self.parse_qualified_name_span()?;
                        end = name.end;
                        // Optional partition column: ps(col)
                        if let Some(lp) = self.peek_non_trivia() {
                            if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                let group = self.consume_balanced_parens()?;
                                end = group.end;
                            }
                        }
                    }
                }
            }
        }

        // FILESTREAM_ON { filegroup | "default" } (single identifier token in our lexer)
        if let Some(tok) = self.peek_non_trivia() {
            if tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("FILESTREAM_ON")
            {
                self.advance();
                end = self.tokens[self.idx - 1].span.end;
                if let Some(name_tok) = self.peek_non_trivia() {
                    if matches!(
                        name_tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) {
                        let name = self.parse_qualified_name_span()?;
                        end = name.end;
                    }
                }
            }
        }

        let stmt_span = Span { start, end };

        // Build CST
        let syntax_id =
            self.syntax_arena
                .alloc_create_index_stmt(crate::syntax::SyntaxCreateIndexStmt {
                    create_keyword,
                    unique_keyword,
                    clustered_keyword,
                    columnstore_keyword,
                    mysql_index_kind_keyword,
                    index_keyword,
                    concurrently_keyword,
                    if_keyword,
                    not_keyword,
                    exists_keyword,
                    name_span: index_name,
                    on_keyword,
                    table_name_span: table_name,
                    using_keyword,
                    using_method_span: using_method,
                    columns_l_paren,
                    columns_r_paren,
                    include_keyword,
                    include_l_paren,
                    include_r_paren,
                    where_keyword,
                    span: stmt_span,
                });
        Ok(AstStmt::CreateIndex(Box::new(AstCreateIndex {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            unique,
            clustered,
            columnstore,
            mysql_index_kind,
            concurrently,
            if_not_exists,
            index_name,
            table_name,
            using_method,
            columns_span,
            include_span,
            where_predicate,
        })))
    }

    // -----------------------------------------------------------------------
    // COMMENT ON {TABLE|COLUMN|INDEX|...} name IS 'text'
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_comment_on_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("comment_on")?;
        let start_span = self.current_span();

        // COMMENT keyword
        let comment_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["COMMENT".to_string()])?;
        let comment_keyword = self.last_token_id();
        let start = comment_tok.span.start;
        let mut end = comment_tok.span.end;

        // ON keyword
        let mut on_keyword = comment_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
                on_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Object kind — consume tokens until we see an identifier that looks
        // like the start of the object name. Object kinds can be multi-word
        // (e.g., FOREIGN TABLE, LARGE OBJECT, OPERATOR CLASS, etc.).
        // Strategy: consume identifiers/keywords until we hit a token that
        // is followed by IS or a dot-qualified name pattern.
        let kind_start = if let Some(tok) = self.peek_non_trivia() {
            tok.span.start
        } else {
            end
        };
        let mut kind_end = kind_start;

        // We need at least one word for the object kind
        let mut object_kind_tokens = Vec::new();
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                    // Check if this could be the start of the object name.
                    // The object kind consists of SQL keywords (TABLE, COLUMN, etc.)
                    // while the object name is typically an identifier possibly
                    // followed by dots. We use a heuristic: if we've consumed at
                    // least one kind token and the next-next token is IS or a dot,
                    // then the current token is the start of the object name.
                    if !object_kind_tokens.is_empty() {
                        // Peek further to see if this is object name
                        let saved = self.idx;
                        let candidate = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                        let _candidate_end = candidate.span.end;

                        // Check what follows: IS, dot, lparen (function sig), or another name part
                        let is_object_name = if let Some(next) = self.peek_non_trivia() {
                            matches!(next.kind, TokenKind::Keyword(Keyword::Is))
                                || matches!(next.kind, TokenKind::Punctuation(Punctuation::Dot))
                                || matches!(next.kind, TokenKind::Punctuation(Punctuation::LParen))
                        } else {
                            true // end of tokens, treat as name
                        };

                        // Restore position — we'll re-parse the name properly below
                        self.idx = saved;

                        if is_object_name {
                            break;
                        }
                    }
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["object kind".to_string()])?;
                    object_kind_tokens.push(self.last_token_id());
                    kind_end = t.span.end;
                    end = t.span.end;
                }
                _ => break,
            }
        }
        let object_kind = Span {
            start: kind_start,
            end: kind_end,
        };

        // Object name (qualified), possibly followed by a parenthesized
        // signature for FUNCTION/PROCEDURE/AGGREGATE types, e.g. my_func(integer)
        let mut signature_l_paren: Option<crate::cst::TokenId> = None;
        let mut signature_r_paren: Option<crate::cst::TokenId> = None;
        let object_name = if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                let name = self.parse_qualified_name_span()?;
                end = name.end;

                // Check for parenthesized signature: func_name(arg_types)
                if let Some(paren_tok) = self.peek_non_trivia() {
                    if matches!(paren_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let lp = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                        signature_l_paren = Some(self.last_token_id());
                        end = lp.span.end;
                        let mut depth = 1u32;
                        while depth > 0 {
                            if let Some(inner) = self.peek_non_trivia() {
                                match inner.kind {
                                    TokenKind::Punctuation(Punctuation::RParen) => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec![")".to_string()],
                                        )?;
                                        end = t.span.end;
                                        depth -= 1;
                                        if depth == 0 {
                                            signature_r_paren = Some(self.last_token_id());
                                        }
                                    }
                                    TokenKind::Punctuation(Punctuation::LParen) => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["(".to_string()],
                                        )?;
                                        end = t.span.end;
                                        depth += 1;
                                    }
                                    TokenKind::Eof => break,
                                    _ => {
                                        let t = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["token".to_string()],
                                        )?;
                                        end = t.span.end;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                name
            } else {
                Span { start: end, end }
            }
        } else {
            Span { start: end, end }
        };

        // IS keyword
        let mut is_keyword = comment_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Is)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IS".to_string()])?;
                is_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Comment value (string literal, dollar-quoted string, or NULL)
        let value_start = if let Some(tok) = self.peek_non_trivia() {
            tok.span.start
        } else {
            end
        };
        let mut value_end = value_start;
        // A PG/Redshift dollar-quoted value (`$$ … $$` / `$tag$ … $tag$`) is lexed
        // under the dollar-quote dialect gate as opener + inner SQL tokens +
        // closer; reassemble the whole run into one value span (shared with the
        // expression parser) so the inner tokens are not mis-parsed as a fresh
        // statement and dropped to OpaqueContent.
        let is_dollar_value = self.dialect.supports_dollar_quoted_strings()
            && self
                .peek_non_trivia()
                .map(|t| {
                    matches!(t.kind, TokenKind::Identifier { .. })
                        && crate::parser::core::is_dollar_quote_tag(t.lexeme(self.source))
                })
                .unwrap_or(false);
        if is_dollar_value {
            let span = self.reassemble_dollar_quoted_span();
            value_end = span.end;
            end = span.end;
        } else if self.peek_non_trivia().is_some() {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["comment value".to_string()])?;
            value_end = t.span.end;
            end = t.span.end;
        }
        let comment_value = Span {
            start: value_start,
            end: value_end,
        };

        let stmt_span = Span { start, end };

        let syntax_id =
            self.syntax_arena
                .alloc_comment_on_stmt(crate::syntax::SyntaxCommentOnStmt {
                    comment_keyword,
                    on_keyword,
                    object_kind_span: object_kind,
                    object_name_span: object_name,
                    signature_l_paren,
                    signature_r_paren,
                    is_keyword,
                    comment_value_span: comment_value,
                    span: stmt_span,
                });
        Ok(AstStmt::CommentOn(Box::new(AstCommentOn {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            object_kind,
            object_name,
            comment_value,
        })))
    }

    // -----------------------------------------------------------------------
    // DO [LANGUAGE lang] $$ body $$
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_do_block_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("do_block")?;
        let start_span = self.current_span();

        // DO keyword
        let do_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DO".to_string()])?;
        let do_keyword = self.last_token_id();
        let start = do_tok.span.start;
        let mut end = do_tok.span.end;

        // Optional: LANGUAGE lang (can appear before or after the body in PG,
        // but before is more common)
        let mut language_keyword = None;
        let mut language_name_span = None;
        let mut language = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["LANGUAGE".to_string()])?;
                language_keyword = Some(self.last_token_id());
                end = t.span.end;
                // Language name
                if let Some(name_tok) = self.peek_non_trivia() {
                    if matches!(
                        name_tok.kind,
                        TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                    ) {
                        let n = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["language name".to_string()])?;
                        let lang_span = n.span;
                        language_name_span = Some(lang_span);
                        language = Some(lang_span);
                        end = n.span.end;
                    }
                }
            }
        }

        // Body: a dollar-quoted block (`$$ … $$` / `$tag$ … $tag$`) or, rarely, a
        // plain string-literal body. Under the dollar-quote dialect gate the
        // lexer emits the region as opener + inner SQL tokens + closer; sub-parse
        // a closed BEGIN/DECLARE body into `body_stmt` (shared with CREATE
        // PROCEDURE via `parse_dollar_block_body`) so the anonymous block's
        // statements are analyzed, while keeping `body_span` over the whole
        // `$$ … $$` region (delimiters included) for byte-exact formatting.
        let mut body_token = do_keyword; // fallback
        let mut body_span = Span { start: end, end };
        let mut body_stmt: Option<Box<AstStmt>> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if crate::parser::core::is_dollar_quote_tag(tok.lexeme(self.source)) {
                let open_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["$$".to_string()])?;
                body_token = self.last_token_id();
                let open_start = open_tok.span.start;
                let open_tag_lo = open_tok.span.start as usize;
                let open_tag_hi = open_tok.span.end as usize;
                let body_content_start = open_tok.span.end;
                let parsed = crate::parser::scripting::parse_dollar_block_body(
                    self,
                    open_tag_lo,
                    open_tag_hi,
                    body_content_start,
                );
                body_stmt = parsed.body_stmt;
                end = parsed.delimiter_end.max(parsed.body_end);
                body_span = Span {
                    start: open_start,
                    end,
                };
            } else {
                // Not a dollar-quote — consume single token as body (e.g. a string literal)
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["body".to_string()])?;
                body_token = self.last_token_id();
                body_span = t.span;
                end = t.span.end;
            }
        }

        // Optional: LANGUAGE lang (can also appear after the body)
        if language_keyword.is_none() {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["LANGUAGE".to_string()])?;
                    language_keyword = Some(self.last_token_id());
                    end = t.span.end;
                    if let Some(name_tok) = self.peek_non_trivia() {
                        if matches!(
                            name_tok.kind,
                            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                        ) {
                            let n = self.advance().ok_or_eof(
                                self.current_span(),
                                vec!["language name".to_string()],
                            )?;
                            let lang_span = n.span;
                            language_name_span = Some(lang_span);
                            language = Some(lang_span);
                            end = n.span.end;
                        }
                    }
                }
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_do_block_stmt(crate::syntax::SyntaxDoBlockStmt {
                do_keyword,
                language_keyword,
                language_name_span,
                body_token,
                span: stmt_span,
            });
        Ok(AstStmt::DoBlock(Box::new(AstDoBlock {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            language,
            body_span,
            body_stmt,
        })))
    }

    // -----------------------------------------------------------------------
    // VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE] [table [(column, ...)]]
    // VACUUM (option [, ...]) [table [(column, ...)]]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_vacuum_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("vacuum")?;
        let start_span = self.current_span();

        // VACUUM keyword (Identifier in our lexer)
        let vacuum_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["VACUUM".to_string()])?;
        let vacuum_keyword = self.last_token_id();
        let start = vacuum_tok.span.start;
        let mut end = vacuum_tok.span.end;

        let mut options_l_paren = None;
        let mut options_r_paren = None;
        let mut options_span = None;
        let mut full = false;
        let mut freeze = false;
        let mut verbose = false;
        let mut analyze = false;
        let mut full_keyword = None;
        let mut freeze_keyword = None;
        let mut verbose_keyword = None;
        let mut analyze_keyword = None;

        // Redshift-specific VACUUM modes (mutually exclusive with each other and
        // with FULL): DELETE ONLY | SORT ONLY | REINDEX | RECLUSTER.
        let mut delete_only = false;
        let mut sort_only = false;
        let mut reindex = false;
        let mut recluster = false;
        let mut delete_keyword = None;
        let mut delete_only_keyword = None;
        let mut sort_keyword = None;
        let mut sort_only_keyword = None;
        let mut reindex_keyword = None;
        let mut recluster_keyword = None;

        // Databricks-specific variables
        let mut retain_hours: Option<u64> = None;
        let mut retain_span: Option<Span> = None;
        let mut retain_keyword_id: Option<TokenId> = None;
        let mut retain_value_token_id: Option<TokenId> = None;
        let mut hours_keyword_id: Option<TokenId> = None;
        let mut dry_run = false;
        let mut dry_keyword_id: Option<TokenId> = None;
        let mut run_keyword_id: Option<TokenId> = None;
        let mut lite = false;
        let mut lite_keyword_id: Option<TokenId> = None;

        // Check for parenthesized options form: VACUUM (VERBOSE, ANALYZE)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lp = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                options_l_paren = Some(self.last_token_id());
                let opt_start = lp.span.start;
                end = lp.span.end;

                let mut depth = 1u32;
                while depth > 0 {
                    if let Some(inner) = self.peek_non_trivia() {
                        match inner.kind {
                            TokenKind::Punctuation(Punctuation::RParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                end = t.span.end;
                                depth -= 1;
                                if depth == 0 {
                                    options_r_paren = Some(self.last_token_id());
                                }
                            }
                            TokenKind::Punctuation(Punctuation::LParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                end = t.span.end;
                                depth += 1;
                            }
                            TokenKind::Eof => break,
                            _ => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                                end = t.span.end;
                            }
                        }
                    } else {
                        break;
                    }
                }
                options_span = Some(Span {
                    start: opt_start,
                    end,
                });
            } else {
                // Non-parenthesized form: VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE]
                // These PG modifiers come BEFORE the table name
                while let Some(tok) = self.peek_non_trivia() {
                    let lex = tok.lexeme(self.source);
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::Full)) {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["FULL".to_string()])?;
                        full = true;
                        full_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else if lex.eq_ignore_ascii_case("FREEZE") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["FREEZE".to_string()])?;
                        freeze = true;
                        freeze_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else if lex.eq_ignore_ascii_case("VERBOSE") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["VERBOSE".to_string()])?;
                        verbose = true;
                        verbose_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else if lex.eq_ignore_ascii_case("ANALYZE") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["ANALYZE".to_string()])?;
                        analyze = true;
                        analyze_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Delete)) {
                        // Redshift: VACUUM DELETE ONLY
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["DELETE".to_string()])?;
                        delete_only = true;
                        delete_keyword = Some(self.last_token_id());
                        end = t.span.end;
                        if let Some(only) = self.peek_non_trivia() {
                            if matches!(only.kind, TokenKind::Keyword(Keyword::Only)) {
                                let o = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["ONLY".to_string()])?;
                                delete_only_keyword = Some(self.last_token_id());
                                end = o.span.end;
                            }
                        }
                    } else if lex.eq_ignore_ascii_case("SORT") {
                        // Redshift: VACUUM SORT ONLY
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["SORT".to_string()])?;
                        sort_only = true;
                        sort_keyword = Some(self.last_token_id());
                        end = t.span.end;
                        if let Some(only) = self.peek_non_trivia() {
                            if matches!(only.kind, TokenKind::Keyword(Keyword::Only)) {
                                let o = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["ONLY".to_string()])?;
                                sort_only_keyword = Some(self.last_token_id());
                                end = o.span.end;
                            }
                        }
                    } else if lex.eq_ignore_ascii_case("REINDEX") {
                        // Redshift: VACUUM REINDEX
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["REINDEX".to_string()])?;
                        reindex = true;
                        reindex_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else if lex.eq_ignore_ascii_case("RECLUSTER") {
                        // Redshift: VACUUM RECLUSTER
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["RECLUSTER".to_string()])?;
                        recluster = true;
                        recluster_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else {
                        break;
                    }
                }
            }
        }

        // Optional: table name
        let mut table_name = None;
        let mut table_name_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) && !matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                && !matches!(tok.kind, TokenKind::Eof)
            {
                let name = self.parse_qualified_name_span()?;
                table_name = Some(name);
                table_name_span = Some(name);
                end = name.end;
            }
        }

        // Optional: column list (col1, col2, ...) — PostgreSQL form
        let mut columns_span = None;
        let mut columns_l_paren = None;
        let mut columns_r_paren = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lp = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                columns_l_paren = Some(self.last_token_id());
                let col_start = lp.span.start;
                end = lp.span.end;

                let mut depth = 1u32;
                while depth > 0 {
                    if let Some(inner) = self.peek_non_trivia() {
                        match inner.kind {
                            TokenKind::Punctuation(Punctuation::RParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                end = t.span.end;
                                depth -= 1;
                                if depth == 0 {
                                    columns_r_paren = Some(self.last_token_id());
                                }
                            }
                            TokenKind::Punctuation(Punctuation::LParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                end = t.span.end;
                                depth += 1;
                            }
                            TokenKind::Eof => break,
                            _ => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                                end = t.span.end;
                            }
                        }
                    } else {
                        break;
                    }
                }
                columns_span = Some(Span {
                    start: col_start,
                    end,
                });
            }
        }

        // ---------------------------------------------------------------
        // Databricks-specific post-table modifiers:
        //   RETAIN num HOURS | FULL | LITE | DRY RUN
        // These come AFTER the table name in Databricks syntax.
        // We parse them in a loop to accept any order.
        // ---------------------------------------------------------------
        while let Some(tok) = self.peek_non_trivia() {
            let lex = tok.lexeme(self.source);
            if lex.eq_ignore_ascii_case("RETAIN") && retain_hours.is_none() {
                // RETAIN num HOURS
                let retain_start = tok.span.start;
                let retain_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RETAIN".to_string()])?;
                retain_keyword_id = Some(self.last_token_id());
                end = retain_tok.span.end;

                // Parse numeric value
                if let Some(num_tok) = self.peek_non_trivia() {
                    if matches!(
                        num_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::Number)
                    ) {
                        let n = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["number".to_string()])?;
                        retain_value_token_id = Some(self.last_token_id());
                        let num_text = n.lexeme(self.source);
                        retain_hours = Some(num_text.parse::<u64>().unwrap_or(0));
                        end = n.span.end;
                    }
                }

                // Parse HOURS keyword
                if let Some(hours_tok) = self.peek_non_trivia() {
                    let hours_lex = hours_tok.lexeme(self.source);
                    if hours_lex.eq_ignore_ascii_case("HOURS") {
                        let h = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["HOURS".to_string()])?;
                        hours_keyword_id = Some(self.last_token_id());
                        end = h.span.end;
                    }
                }

                retain_span = Some(Span {
                    start: retain_start,
                    end,
                });
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Full)) && !full {
                // FULL (Databricks Iceberg mode — after table name)
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["FULL".to_string()])?;
                full = true;
                full_keyword = Some(self.last_token_id());
                end = t.span.end;
            } else if lex.eq_ignore_ascii_case("LITE") && !lite {
                // LITE (Databricks Iceberg mode)
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["LITE".to_string()])?;
                lite = true;
                lite_keyword_id = Some(self.last_token_id());
                end = t.span.end;
            } else if lex.eq_ignore_ascii_case("DRY") && !dry_run {
                // DRY RUN (two-word modifier)
                let d = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["DRY".to_string()])?;
                dry_keyword_id = Some(self.last_token_id());
                end = d.span.end;

                // RUN keyword (required after DRY)
                if let Some(run_tok) = self.peek_non_trivia() {
                    let run_lex = run_tok.lexeme(self.source);
                    if run_lex.eq_ignore_ascii_case("RUN") {
                        let r = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["RUN".to_string()])?;
                        run_keyword_id = Some(self.last_token_id());
                        end = r.span.end;
                    }
                }
                dry_run = true;
            } else {
                break;
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_vacuum_stmt(crate::syntax::SyntaxVacuumStmt {
                vacuum_keyword,
                options_l_paren,
                options_r_paren,
                full_keyword,
                freeze_keyword,
                verbose_keyword,
                analyze_keyword,
                delete_keyword,
                delete_only_keyword,
                sort_keyword,
                sort_only_keyword,
                reindex_keyword,
                recluster_keyword,
                table_name_span,
                columns_l_paren,
                columns_r_paren,
                retain_keyword: retain_keyword_id,
                retain_value_token: retain_value_token_id,
                hours_keyword: hours_keyword_id,
                dry_keyword: dry_keyword_id,
                run_keyword: run_keyword_id,
                lite_keyword: lite_keyword_id,
                span: stmt_span,
            });
        Ok(AstStmt::Vacuum(Box::new(AstVacuum {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            options_span,
            full,
            freeze,
            verbose,
            analyze,
            delete_only,
            sort_only,
            reindex,
            recluster,
            table_name,
            columns_span,
            retain_hours,
            retain_span,
            dry_run,
            lite,
        })))
    }

    // -----------------------------------------------------------------------
    // ANALYZE [VERBOSE] [table [(column, ...)]]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_analyze_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("analyze")?;
        let start_span = self.current_span();

        // ANALYZE keyword (Identifier in our lexer)
        let analyze_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ANALYZE".to_string()])?;
        let analyze_keyword = self.last_token_id();
        let start = analyze_tok.span.start;
        let mut end = analyze_tok.span.end;

        // Optional: VERBOSE
        let mut verbose = false;
        let mut verbose_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("VERBOSE") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["VERBOSE".to_string()])?;
                verbose = true;
                verbose_keyword = Some(self.last_token_id());
                end = t.span.end;
            }
        }

        // Optional: COMPRESSION (Redshift `ANALYZE COMPRESSION [table]`) — must be
        // consumed here so it is not mis-parsed as the table name.
        let mut compression = false;
        let mut compression_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("COMPRESSION") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["COMPRESSION".to_string()])?;
                compression = true;
                compression_keyword = Some(self.last_token_id());
                end = t.span.end;
            }
        }

        // Optional: table name
        let mut table_name = None;
        let mut table_name_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) && !matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                && !matches!(tok.kind, TokenKind::Eof)
            {
                let name = self.parse_qualified_name_span()?;
                table_name = Some(name);
                table_name_span = Some(name);
                end = name.end;
            }
        }

        // Optional: column list (col1, col2, ...)
        let mut columns_span = None;
        let mut columns_l_paren = None;
        let mut columns_r_paren = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lp = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                columns_l_paren = Some(self.last_token_id());
                let col_start = lp.span.start;
                end = lp.span.end;

                let mut depth = 1u32;
                while depth > 0 {
                    if let Some(inner) = self.peek_non_trivia() {
                        match inner.kind {
                            TokenKind::Punctuation(Punctuation::RParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                                end = t.span.end;
                                depth -= 1;
                                if depth == 0 {
                                    columns_r_paren = Some(self.last_token_id());
                                }
                            }
                            TokenKind::Punctuation(Punctuation::LParen) => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                end = t.span.end;
                                depth += 1;
                            }
                            TokenKind::Eof => break,
                            _ => {
                                let t = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                                end = t.span.end;
                            }
                        }
                    } else {
                        break;
                    }
                }
                columns_span = Some(Span {
                    start: col_start,
                    end,
                });
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_analyze_stmt(crate::syntax::SyntaxAnalyzeStmt {
                analyze_keyword,
                verbose_keyword,
                compression_keyword,
                table_name_span,
                columns_l_paren,
                columns_r_paren,
                span: stmt_span,
            });
        Ok(AstStmt::AnalyzeStmt(Box::new(AstAnalyzeStmt {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            verbose,
            compression,
            table_name,
            columns_span,
        })))
    }

    // -----------------------------------------------------------------------
    // CREATE TYPE name AS ENUM (...) / AS (...) / AS RANGE (...)
    // Snowflake: CREATE [OR REPLACE] TYPE [IF NOT EXISTS] name AS <data_type> [COMMENT = '...']
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_type_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_type")?;
        let start_span = self.current_span();

        // CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;
        let mut end = create_tok.span.end;

        // Skip optional OR REPLACE
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OR".to_string()])?;
                end = t.span.end;
                if let Some(rep_tok) = self.peek_non_trivia() {
                    if matches!(rep_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                        end = t.span.end;
                    }
                }
            }
        }

        // TYPE keyword
        let mut type_keyword = create_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TYPE".to_string()])?;
                type_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Skip optional IF NOT EXISTS (Snowflake)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                end = t.span.end;
                if let Some(not_tok) = self.peek_non_trivia() {
                    if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                        end = t.span.end;
                    }
                }
                if let Some(exists_tok) = self.peek_non_trivia() {
                    if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                        end = t.span.end;
                    }
                }
            }
        }

        // Type name (qualified)
        let type_name = if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                let name = self.parse_qualified_name_span()?;
                end = name.end;
                name
            } else {
                Span { start: end, end }
            }
        } else {
            Span { start: end, end }
        };

        // Optional: AS ... (the body)
        let mut as_keyword = None;
        let mut sub_keyword: Option<crate::cst::TokenId> = None; // ENUM or RANGE keyword
        let mut body_l_paren: Option<crate::cst::TokenId> = None;
        let mut body_r_paren: Option<crate::cst::TokenId> = None;
        let mut body_inner_span: Option<Span> = None;
        let mut data_type_span: Option<Span> = None;
        let mut trailing_span: Option<Span> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
                as_keyword = Some(self.last_token_id());
                end = t.span.end;

                // Check for sub-keyword: ENUM or RANGE
                if let Some(next) = self.peek_non_trivia() {
                    let lex = next.lexeme(self.source);
                    if lex.eq_ignore_ascii_case("ENUM") || lex.eq_ignore_ascii_case("RANGE") {
                        let sk = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["ENUM or RANGE".to_string()])?;
                        sub_keyword = Some(self.last_token_id());
                        end = sk.span.end;
                    }
                }

                // Check what follows: parenthesized body OR data type identifier
                if let Some(next_tok) = self.peek_non_trivia() {
                    if matches!(next_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        // PostgreSQL composite type: AS (field type, ...)
                        // or PostgreSQL ENUM/RANGE body: AS ENUM (...) / AS RANGE (...)
                        let lp = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                        body_l_paren = Some(self.last_token_id());
                        let inner_start = lp.span.end;
                        end = lp.span.end;

                        let mut depth = 1u32;
                        while depth > 0 {
                            if let Some(inner) = self.peek_non_trivia() {
                                match inner.kind {
                                    TokenKind::Punctuation(Punctuation::LParen) => {
                                        let t2 = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["(".to_string()],
                                        )?;
                                        end = t2.span.end;
                                        depth += 1;
                                    }
                                    TokenKind::Punctuation(Punctuation::RParen) => {
                                        let t2 = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec![")".to_string()],
                                        )?;
                                        if depth == 1 {
                                            body_inner_span = Some(Span {
                                                start: inner_start,
                                                end: t2.span.start,
                                            });
                                        }
                                        end = t2.span.end;
                                        depth -= 1;
                                        if depth == 0 {
                                            body_r_paren = Some(self.last_token_id());
                                        }
                                    }
                                    TokenKind::Eof => break,
                                    _ => {
                                        let t2 = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["token".to_string()],
                                        )?;
                                        end = t2.span.end;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    } else if sub_keyword.is_none()
                        && matches!(
                            next_tok.kind,
                            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                        )
                    {
                        // Snowflake data type: AS NUMBER(3,0), AS VARCHAR, AS OBJECT(...)
                        // The data type name is an identifier (NUMBER, VARCHAR, OBJECT, etc.)
                        let dt_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["data type".to_string()])?;
                        let dt_start = dt_tok.span.start;
                        end = dt_tok.span.end;

                        // If followed by parenthesized content (e.g., NUMBER(3,0) or OBJECT(field TYPE, ...))
                        if let Some(paren_tok) = self.peek_non_trivia() {
                            if matches!(paren_tok.kind, TokenKind::Punctuation(Punctuation::LParen))
                            {
                                let lp = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                                body_l_paren = Some(self.last_token_id());
                                let inner_start = lp.span.end;
                                end = lp.span.end;

                                let mut depth = 1u32;
                                while depth > 0 {
                                    if let Some(inner) = self.peek_non_trivia() {
                                        match inner.kind {
                                            TokenKind::Punctuation(Punctuation::LParen) => {
                                                let t2 = self.advance().ok_or_eof(
                                                    self.current_span(),
                                                    vec!["(".to_string()],
                                                )?;
                                                end = t2.span.end;
                                                depth += 1;
                                            }
                                            TokenKind::Punctuation(Punctuation::RParen) => {
                                                let t2 = self.advance().ok_or_eof(
                                                    self.current_span(),
                                                    vec![")".to_string()],
                                                )?;
                                                if depth == 1 {
                                                    body_inner_span = Some(Span {
                                                        start: inner_start,
                                                        end: t2.span.start,
                                                    });
                                                }
                                                end = t2.span.end;
                                                depth -= 1;
                                                if depth == 0 {
                                                    body_r_paren = Some(self.last_token_id());
                                                }
                                            }
                                            TokenKind::Eof => break,
                                            _ => {
                                                let t2 = self.advance().ok_or_eof(
                                                    self.current_span(),
                                                    vec!["token".to_string()],
                                                )?;
                                                end = t2.span.end;
                                            }
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }

                        data_type_span = Some(Span {
                            start: dt_start,
                            end,
                        });
                    }
                }
            }
        }

        // Optional trailing clause: COMMENT = '...' (Snowflake)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let trailing_start = tok.span.start;
                // Consume until semicolon
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(
                        t.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) {
                        break;
                    }
                    let consumed = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                    end = consumed.span.end;
                }
                trailing_span = Some(Span {
                    start: trailing_start,
                    end,
                });
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id =
            self.syntax_arena
                .alloc_create_type_stmt(crate::syntax::SyntaxCreateTypeStmt {
                    create_keyword,
                    type_keyword,
                    type_name_span: type_name,
                    as_keyword,
                    sub_keyword,
                    body_l_paren,
                    body_r_paren,
                    data_type_span,
                    trailing_span,
                    span: stmt_span,
                });
        Ok(AstStmt::CreateType(Box::new(AstCreateType {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            type_name,
            body_inner_span,
        })))
    }

    // -----------------------------------------------------------------------
    // ALTER TYPE name {ADD VALUE | RENAME TO | ...}
    // Snowflake: ALTER TYPE [IF EXISTS] name {SET COMMENT = '...' | UNSET COMMENT}
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_alter_type_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_type")?;
        let start_span = self.current_span();

        // ALTER keyword
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;
        let mut end = alter_tok.span.end;

        // TYPE keyword
        let mut type_keyword = alter_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TYPE".to_string()])?;
                type_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Optional IF EXISTS (Snowflake)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                // Peek ahead to check for EXISTS (not IF NOT EXISTS — that's for type name "IF")
                let saved = self.idx;
                self.advance(); // consume IF
                if let Some(exists_tok) = self.peek_non_trivia() {
                    if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        // Confirmed IF EXISTS — consume both
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                        end = t.span.end;
                    } else {
                        // Not IF EXISTS — restore (IF is the type name)
                        self.idx = saved;
                    }
                } else {
                    self.idx = saved;
                }
            }
        }

        // Type name (qualified)
        let type_name = if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                let name = self.parse_qualified_name_span()?;
                end = name.end;
                name
            } else {
                Span { start: end, end }
            }
        } else {
            Span { start: end, end }
        };

        // Action clause — parse each action token individually
        // Variants:
        //   ADD VALUE [IF NOT EXISTS] 'value' [BEFORE|AFTER 'existing']
        //   RENAME TO new_name
        //   RENAME VALUE 'old' TO 'new'
        //   SET SCHEMA schema_name
        //   OWNER TO new_owner
        //   ADD ATTRIBUTE attr_name data_type [COLLATE collation] [CASCADE|RESTRICT]
        let mut action_keyword: Option<crate::cst::TokenId> = None; // ADD, RENAME, SET, OWNER
        let mut action_keyword2: Option<crate::cst::TokenId> = None; // VALUE, TO, SCHEMA, ATTRIBUTE
        let mut action_if_keyword: Option<crate::cst::TokenId> = None;
        let mut action_not_keyword: Option<crate::cst::TokenId> = None;
        let mut action_exists_keyword: Option<crate::cst::TokenId> = None;
        let mut action_value_span: Option<Span> = None; // Primary value/name
        let mut action_position_keyword: Option<crate::cst::TokenId> = None; // BEFORE|AFTER
        let mut action_position_value_span: Option<Span> = None; // Value after BEFORE/AFTER
        let mut action_to_keyword: Option<crate::cst::TokenId> = None;
        let mut action_target_span: Option<Span> = None; // Target name (RENAME TO x, etc.)
                                                         // Extra tokens for ADD ATTRIBUTE (data type, COLLATE, CASCADE/RESTRICT)
        let mut action_extra_span: Option<Span> = None;

        if let Some(tok) = self.peek_non_trivia() {
            let lex = tok.lexeme(self.source);

            if lex.eq_ignore_ascii_case("ADD") {
                // ADD VALUE or ADD ATTRIBUTE
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ADD".to_string()])?;
                action_keyword = Some(self.last_token_id());
                end = t.span.end;

                if let Some(next) = self.peek_non_trivia() {
                    let next_lex = next.lexeme(self.source);
                    if next_lex.eq_ignore_ascii_case("VALUE") {
                        // ADD VALUE [IF NOT EXISTS] 'val' [BEFORE|AFTER 'existing']
                        let vt = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["VALUE".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = vt.span.end;

                        // Optional: IF NOT EXISTS
                        if let Some(if_tok) = self.peek_non_trivia() {
                            if matches!(if_tok.kind, TokenKind::Keyword(Keyword::If)) {
                                let it = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                                action_if_keyword = Some(self.last_token_id());
                                end = it.span.end;
                                if let Some(nt) = self.peek_non_trivia() {
                                    if matches!(nt.kind, TokenKind::Keyword(Keyword::Not)) {
                                        let nt2 = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["NOT".to_string()],
                                        )?;
                                        action_not_keyword = Some(self.last_token_id());
                                        end = nt2.span.end;
                                    }
                                }
                                if let Some(et) = self.peek_non_trivia() {
                                    if matches!(et.kind, TokenKind::Keyword(Keyword::Exists)) {
                                        let et2 = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["EXISTS".to_string()],
                                        )?;
                                        action_exists_keyword = Some(self.last_token_id());
                                        end = et2.span.end;
                                    }
                                }
                            }
                        }

                        // The value (string literal)
                        if let Some(val_tok) = self.peek_non_trivia() {
                            if !matches!(
                                val_tok.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                let vt2 = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                                action_value_span = Some(vt2.span);
                                end = vt2.span.end;
                            }
                        }

                        // Optional: BEFORE|AFTER 'existing_value'
                        if let Some(pos_tok) = self.peek_non_trivia() {
                            let pos_lex = pos_tok.lexeme(self.source);
                            if pos_lex.eq_ignore_ascii_case("BEFORE")
                                || pos_lex.eq_ignore_ascii_case("AFTER")
                            {
                                let pt = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["BEFORE or AFTER".to_string()],
                                )?;
                                action_position_keyword = Some(self.last_token_id());
                                end = pt.span.end;
                                if let Some(pv) = self.peek_non_trivia() {
                                    if !matches!(
                                        pv.kind,
                                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                                    ) {
                                        let pvt = self.advance().ok_or_eof(
                                            self.current_span(),
                                            vec!["position value".to_string()],
                                        )?;
                                        action_position_value_span = Some(pvt.span);
                                        end = pvt.span.end;
                                    }
                                }
                            }
                        }
                    } else if next_lex.eq_ignore_ascii_case("ATTRIBUTE") {
                        // ADD ATTRIBUTE attr_name data_type [...]
                        let at = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["ATTRIBUTE".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = at.span.end;
                        // attr_name
                        if let Some(name_tok) = self.peek_non_trivia() {
                            if !matches!(
                                name_tok.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                let nt = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["attribute name".to_string()],
                                )?;
                                action_value_span = Some(nt.span);
                                end = nt.span.end;
                            }
                        }
                        // data_type + any trailing tokens (COLLATE, CASCADE, RESTRICT)
                        let extra_start = end;
                        while let Some(extra_tok) = self.peek_non_trivia() {
                            if matches!(
                                extra_tok.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                break;
                            }
                            let et = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                            end = et.span.end;
                        }
                        if end > extra_start {
                            action_extra_span = Some(Span {
                                start: extra_start,
                                end,
                            });
                        }
                    }
                }
            } else if lex.eq_ignore_ascii_case("RENAME") {
                // RENAME TO new_name  OR  RENAME VALUE 'old' TO 'new'
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
                action_keyword = Some(self.last_token_id());
                end = t.span.end;

                if let Some(next) = self.peek_non_trivia() {
                    let next_lex = next.lexeme(self.source);
                    if next_lex.eq_ignore_ascii_case("VALUE") {
                        // RENAME VALUE 'old' TO 'new'
                        let vt = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["VALUE".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = vt.span.end;
                        // 'old' value
                        if let Some(old_tok) = self.peek_non_trivia() {
                            if !matches!(
                                old_tok.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                let ot = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["old value".to_string()],
                                )?;
                                action_value_span = Some(ot.span);
                                end = ot.span.end;
                            }
                        }
                        // TO keyword
                        if let Some(to_tok) = self.peek_non_trivia() {
                            if matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                                let tt = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                                action_to_keyword = Some(self.last_token_id());
                                end = tt.span.end;
                            }
                        }
                        // 'new' value
                        if let Some(new_tok) = self.peek_non_trivia() {
                            if !matches!(
                                new_tok.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                let nt = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["new value".to_string()],
                                )?;
                                action_target_span = Some(nt.span);
                                end = nt.span.end;
                            }
                        }
                    } else if matches!(next.kind, TokenKind::Keyword(Keyword::To)) {
                        // RENAME TO new_name
                        let tt = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                        action_to_keyword = Some(self.last_token_id());
                        end = tt.span.end;
                        // new_name
                        if let Some(name_tok) = self.peek_non_trivia() {
                            if matches!(
                                name_tok.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                let nt = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["new name".to_string()])?;
                                action_target_span = Some(nt.span);
                                end = nt.span.end;
                            }
                        }
                    }
                }
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set))
                || lex.eq_ignore_ascii_case("SET")
            {
                // SET SCHEMA schema_name (PostgreSQL)
                // SET COMMENT = '...' (Snowflake)
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
                action_keyword = Some(self.last_token_id());
                end = t.span.end;

                if let Some(next) = self.peek_non_trivia() {
                    let next_lex = next.lexeme(self.source);
                    if next_lex.eq_ignore_ascii_case("SCHEMA") {
                        let st = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = st.span.end;
                        // schema_name
                        if let Some(name_tok) = self.peek_non_trivia() {
                            if matches!(
                                name_tok.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                let nt = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["schema name".to_string()],
                                )?;
                                action_target_span = Some(nt.span);
                                end = nt.span.end;
                            }
                        }
                    } else if matches!(next.kind, TokenKind::Keyword(Keyword::Comment)) {
                        // SET COMMENT = '...' (Snowflake)
                        let ct = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["COMMENT".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = ct.span.end;
                        // Capture = 'value' as action_extra_span
                        let extra_start = end;
                        while let Some(rest) = self.peek_non_trivia() {
                            if matches!(
                                rest.kind,
                                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                            ) {
                                break;
                            }
                            let rt = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                            end = rt.span.end;
                        }
                        if end > extra_start {
                            action_extra_span = Some(Span {
                                start: extra_start,
                                end,
                            });
                        }
                    }
                }
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset))
                || lex.eq_ignore_ascii_case("UNSET")
            {
                // UNSET COMMENT (Snowflake)
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["UNSET".to_string()])?;
                action_keyword = Some(self.last_token_id());
                end = t.span.end;

                if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Comment)) {
                        let ct = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["COMMENT".to_string()])?;
                        action_keyword2 = Some(self.last_token_id());
                        end = ct.span.end;
                    }
                }
            } else if lex.eq_ignore_ascii_case("OWNER") {
                // OWNER TO new_owner
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OWNER".to_string()])?;
                action_keyword = Some(self.last_token_id());
                end = t.span.end;

                if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::To)) {
                        let tt = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                        action_to_keyword = Some(self.last_token_id());
                        end = tt.span.end;
                        // new_owner
                        if let Some(name_tok) = self.peek_non_trivia() {
                            if matches!(
                                name_tok.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                let nt = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["owner name".to_string()],
                                )?;
                                action_target_span = Some(nt.span);
                                end = nt.span.end;
                            }
                        }
                    }
                }
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id =
            self.syntax_arena
                .alloc_alter_type_stmt(crate::syntax::SyntaxAlterTypeStmt {
                    alter_keyword,
                    type_keyword,
                    type_name_span: type_name,
                    action_keyword,
                    action_keyword2,
                    action_if_keyword,
                    action_not_keyword,
                    action_exists_keyword,
                    action_value_span,
                    action_position_keyword,
                    action_position_value_span,
                    action_to_keyword,
                    action_target_span,
                    action_extra_span,
                    span: stmt_span,
                });
        Ok(AstStmt::AlterType(Box::new(AstAlterType {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            type_name,
        })))
    }

    // -----------------------------------------------------------------------
    // UNDROP TYPE name (Snowflake)
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_undrop_type(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("undrop_type")?;

        // UNDROP - Identifier, not keyword
        let undrop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNDROP".to_string()])?;
        let undrop_span = undrop_tok.span;

        // TYPE keyword
        let type_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TYPE".to_string()])?;

        if !matches!(type_tok.kind, TokenKind::Keyword(Keyword::Type)) {
            return Err(ParseError::new(
                type_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected TYPE, found '{}'", type_tok.lexeme(self.source)),
                },
            ));
        }
        let type_span = type_tok.span;

        // Type name (may be qualified)
        let name_span = self.parse_qualified_name_span()?;

        let span = Span {
            start: undrop_span.start,
            end: name_span.end,
        };

        Ok(AstStmt::UndropType(Box::new(crate::ast::AstUndropType {
            node_id: self.id_gen.next(),
            span,
            undrop_span,
            type_span,
            name_span,
        })))
    }

    // -----------------------------------------------------------------------
    // CREATE EXTENSION [IF NOT EXISTS] name [WITH] [SCHEMA schema]
    //   [VERSION version] [CASCADE]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_extension_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_extension")?;
        let start_span = self.current_span();

        // CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;
        let mut end = create_tok.span.end;

        // EXTENSION keyword (Identifier in our lexer)
        let mut extension_keyword = create_keyword; // fallback
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("EXTENSION") {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXTENSION".to_string()])?;
                extension_keyword = self.last_token_id();
                end = t.span.end;
            }
        }

        // Optional: IF NOT EXISTS
        let mut if_not_exists = false;
        let mut if_keyword = None;
        let mut not_keyword = None;
        let mut exists_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                if_keyword = Some(self.last_token_id());
                end = t.span.end;
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Not)) {
                        let t2 = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                        not_keyword = Some(self.last_token_id());
                        end = t2.span.end;
                        if let Some(tok3) = self.peek_non_trivia() {
                            if matches!(tok3.kind, TokenKind::Keyword(Keyword::Exists)) {
                                let t3 = self
                                    .advance()
                                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                                exists_keyword = Some(self.last_token_id());
                                end = t3.span.end;
                                if_not_exists = true;
                            }
                        }
                    }
                }
            }
        }

        // Extension name
        let extension_name = if let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["extension name".to_string()])?;
                let name = t.span;
                end = t.span.end;
                name
            } else {
                Span { start: end, end }
            }
        } else {
            Span { start: end, end }
        };

        // Optional clauses: WITH, SCHEMA, VERSION, CASCADE
        let mut with_keyword = None;
        let mut schema_keyword = None;
        let mut schema_name = None;
        let mut schema_name_span = None;
        let mut version_keyword = None;
        let mut version = None;
        let mut version_span = None;
        let mut cascade = false;
        let mut cascade_keyword = None;

        // Parse optional trailing clauses
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Keyword(Keyword::With) => {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                    with_keyword = Some(self.last_token_id());
                    end = t.span.end;
                }
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof => break,
                _ => {
                    let lex = tok.lexeme(self.source);
                    if lex.eq_ignore_ascii_case("SCHEMA") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;
                        schema_keyword = Some(self.last_token_id());
                        end = t.span.end;
                        // Schema name
                        if let Some(name_tok) = self.peek_non_trivia() {
                            if matches!(
                                name_tok.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                let n = self.advance().ok_or_eof(
                                    self.current_span(),
                                    vec!["schema name".to_string()],
                                )?;
                                let s = n.span;
                                schema_name = Some(s);
                                schema_name_span = Some(s);
                                end = n.span.end;
                            }
                        }
                    } else if lex.eq_ignore_ascii_case("VERSION") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["VERSION".to_string()])?;
                        version_keyword = Some(self.last_token_id());
                        end = t.span.end;
                        // Version value
                        if self.peek_non_trivia().is_some() {
                            let v = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["version".to_string()])?;
                            let s = v.span;
                            version = Some(s);
                            version_span = Some(s);
                            end = v.span.end;
                        }
                    } else if lex.eq_ignore_ascii_case("CASCADE") {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                        cascade = true;
                        cascade_keyword = Some(self.last_token_id());
                        end = t.span.end;
                    } else {
                        // Unknown trailing token — consume it
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["token".to_string()])?;
                        end = t.span.end;
                    }
                }
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id = self.syntax_arena.alloc_create_extension_stmt(
            crate::syntax::SyntaxCreateExtensionStmt {
                create_keyword,
                extension_keyword,
                if_keyword,
                not_keyword,
                exists_keyword,
                extension_name_span: extension_name,
                with_keyword,
                schema_keyword,
                schema_name_span,
                version_keyword,
                version_span,
                cascade_keyword,
                span: stmt_span,
            },
        );
        Ok(AstStmt::CreateExtension(Box::new(AstCreateExtension {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            if_not_exists,
            extension_name,
            schema_name,
            version,
            cascade,
        })))
    }

    // -----------------------------------------------------------------------
    // CREATE [TEMPORARY | TEMP | UNLOGGED] SEQUENCE [IF NOT EXISTS] name
    //   [AS data_type] [INCREMENT [BY] n] [MINVALUE n | NO MINVALUE]
    //   [MAXVALUE n | NO MAXVALUE] [[NO] CYCLE] [START [WITH] n]
    //   [CACHE n] [OWNED BY table.column | NONE]
    // -----------------------------------------------------------------------
    pub(crate) fn try_parse_create_sequence_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_sequence")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;

        // Optional: OR REPLACE (Snowflake). Dialect-neutral recognition — the
        // dispatcher already routed here; the PG-shaped body just never
        // consumed it, so CREATE OR REPLACE SEQUENCE went opaque.
        let mut or_replace = false;
        let mut or_keyword: Option<crate::cst::TokenId> = None;
        let mut replace_keyword: Option<crate::cst::TokenId> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // OR
                or_keyword = Some(self.last_token_id());
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Replace)) {
                        self.advance(); // REPLACE
                        replace_keyword = Some(self.last_token_id());
                        or_replace = true;
                    }
                }
            }
        }

        // Optional: TEMPORARY | TEMP | UNLOGGED
        let mut temporary = false;
        let mut unlogged = false;
        let mut temp_keyword: Option<crate::cst::TokenId> = None;
        let mut unlogged_keyword: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Keyword(Keyword::Temporary) | TokenKind::Keyword(Keyword::Temp) => {
                    self.advance();
                    temporary = true;
                    temp_keyword = Some(self.last_token_id());
                }
                TokenKind::Identifier { .. }
                    if tok.lexeme(self.source).eq_ignore_ascii_case("UNLOGGED") =>
                {
                    self.advance();
                    unlogged = true;
                    unlogged_keyword = Some(self.last_token_id());
                }
                _ => {}
            }
        }

        // SEQUENCE (Identifier)
        let seq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SEQUENCE".to_string()])?;
        if !seq_tok.lexeme(self.source).eq_ignore_ascii_case("SEQUENCE") {
            return Err(crate::error::ParseError::new(
                seq_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!("Expected SEQUENCE, found '{}'", seq_tok.lexeme(self.source)),
                },
            ));
        }
        let sequence_keyword = self.last_token_id();

        // Optional: IF NOT EXISTS
        let mut if_not_exists = false;
        let mut if_keyword: Option<crate::cst::TokenId> = None;
        let mut not_keyword: Option<crate::cst::TokenId> = None;
        let mut exists_keyword: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance();
                if_keyword = Some(self.last_token_id());
                if let Some(t2) = self.peek_non_trivia() {
                    if matches!(t2.kind, TokenKind::Keyword(Keyword::Not)) {
                        self.advance();
                        not_keyword = Some(self.last_token_id());
                    }
                }
                if let Some(t3) = self.peek_non_trivia() {
                    if matches!(t3.kind, TokenKind::Keyword(Keyword::Exists)) {
                        self.advance();
                        exists_keyword = Some(self.last_token_id());
                        if_not_exists = true;
                    }
                }
            }
        }

        // Sequence name (optionally schema-qualified: schema.name)
        let name_start_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["sequence name".to_string()])?;
        let mut name_end = name_start_tok.span.end;

        // Check for schema.name (dot-qualified)
        if let Some(dot_tok) = self.peek_non_trivia() {
            if matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                let name_part = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["sequence name after dot".to_string()],
                )?;
                name_end = name_part.span.end;
            }
        }
        let name = Span {
            start: name_start_tok.span.start,
            end: name_end,
        };

        // Consume remaining options until semicolon or EOF
        let options_span = self.consume_sequence_options()?;

        let end = options_span.map(|s| s.end).unwrap_or(name_end);
        let stmt_span = Span { start, end };

        let syntax_id =
            self.syntax_arena
                .alloc_create_sequence_stmt(crate::syntax::SyntaxCreateSequenceStmt {
                    create_keyword,
                    or_keyword,
                    replace_keyword,
                    temp_keyword,
                    unlogged_keyword,
                    sequence_keyword,
                    if_keyword,
                    not_keyword,
                    exists_keyword,
                    name_span: name,
                    options_span,
                    span: stmt_span,
                });
        Ok(AstStmt::CreateSequence(Box::new(AstCreateSequence {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            or_replace,
            temporary,
            unlogged,
            if_not_exists,
            name,
            options_span,
        })))
    }

    // -----------------------------------------------------------------------
    // ALTER SEQUENCE [IF EXISTS] name
    //   [AS data_type] [INCREMENT [BY] n] [MINVALUE n | NO MINVALUE]
    //   [MAXVALUE n | NO MAXVALUE] [[NO] CYCLE] [START [WITH] n]
    //   [RESTART [[WITH] n]] [CACHE n] [OWNED BY table.column | NONE]
    //   [SET {LOGGED | UNLOGGED}] [OWNER TO owner]
    //   [RENAME TO new_name] [SET SCHEMA schema]
    // -----------------------------------------------------------------------
    pub(crate) fn try_parse_alter_sequence_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_sequence")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;

        // SEQUENCE (Identifier)
        let seq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SEQUENCE".to_string()])?;
        if !seq_tok.lexeme(self.source).eq_ignore_ascii_case("SEQUENCE") {
            return Err(crate::error::ParseError::new(
                seq_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!("Expected SEQUENCE, found '{}'", seq_tok.lexeme(self.source)),
                },
            ));
        }
        let sequence_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let mut if_exists = false;
        let mut if_keyword: Option<crate::cst::TokenId> = None;
        let mut exists_keyword: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance();
                if_keyword = Some(self.last_token_id());
                if let Some(t2) = self.peek_non_trivia() {
                    if matches!(t2.kind, TokenKind::Keyword(Keyword::Exists)) {
                        self.advance();
                        exists_keyword = Some(self.last_token_id());
                        if_exists = true;
                    }
                }
            }
        }

        // Sequence name (optionally schema-qualified)
        let name_start_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["sequence name".to_string()])?;
        let mut name_end = name_start_tok.span.end;

        // Check for schema.name
        if let Some(dot_tok) = self.peek_non_trivia() {
            if matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                let name_part = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["sequence name after dot".to_string()],
                )?;
                name_end = name_part.span.end;
            }
        }
        let name = Span {
            start: name_start_tok.span.start,
            end: name_end,
        };

        // Consume remaining options/clauses until semicolon or EOF
        let options_span = self.consume_sequence_options()?;

        let end = options_span.map(|s| s.end).unwrap_or(name_end);
        let stmt_span = Span { start, end };

        let syntax_id =
            self.syntax_arena
                .alloc_alter_sequence_stmt(crate::syntax::SyntaxAlterSequenceStmt {
                    alter_keyword,
                    sequence_keyword,
                    if_keyword,
                    exists_keyword,
                    name_span: name,
                    options_span,
                    span: stmt_span,
                });
        Ok(AstStmt::AlterSequence(Box::new(AstAlterSequence {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            if_exists,
            name,
            options_span,
        })))
    }

    // -----------------------------------------------------------------------
    // Shared helper: consume sequence options as a single span.
    //
    // Options are a flat list of KEY [VALUE] pairs. No parenthesized
    // sub-expressions except OWNED BY table.column, which is just
    // identifiers and dots. We consume everything until semicolon/EOF.
    // -----------------------------------------------------------------------
    fn consume_sequence_options(&mut self) -> ParseResult<Option<Span>> {
        let mut end: Option<u32> = None;
        let mut start: Option<u32> = None;

        while let Some(tok) = self.peek_non_trivia() {
            // Stop at semicolon or EOF
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            // Stop at any statement-starting keyword that isn't a sequence option
            if self.is_statement_start_keyword(tok) {
                break;
            }
            let consumed = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["option".to_string()])?;
            if start.is_none() {
                start = Some(consumed.span.start);
            }
            end = Some(consumed.span.end);
        }

        match (start, end) {
            (Some(s), Some(e)) => Ok(Some(Span { start: s, end: e })),
            _ => Ok(None),
        }
    }

    /// Check if a token looks like the start of a new statement (not a sequence option).
    fn is_statement_start_keyword(&self, tok: &crate::lexer::Token) -> bool {
        matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Create)
                | TokenKind::Keyword(Keyword::Alter)
                | TokenKind::Keyword(Keyword::Drop)
                | TokenKind::Keyword(Keyword::Insert)
                | TokenKind::Keyword(Keyword::Update)
                | TokenKind::Keyword(Keyword::Delete)
                | TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Grant)
                | TokenKind::Keyword(Keyword::Revoke)
                | TokenKind::Keyword(Keyword::Deny)
                | TokenKind::Keyword(Keyword::Truncate)
                | TokenKind::Keyword(Keyword::Merge)
                | TokenKind::Keyword(Keyword::Begin)
                | TokenKind::Keyword(Keyword::Commit)
                | TokenKind::Keyword(Keyword::Rollback)
        )
    }

    // -----------------------------------------------------------------------
    // CREATE [OR REPLACE] [CONSTRAINT] TRIGGER name
    //   {BEFORE | AFTER | INSTEAD OF} {event [OR ...]}
    //   ON table_name
    //   [FROM referenced_table_name]
    //   [NOT DEFERRABLE | DEFERRABLE [INITIALLY {DEFERRED | IMMEDIATE}]]
    //   [REFERENCING {OLD|NEW} TABLE AS alias ...]
    //   [FOR [EACH] {ROW | STATEMENT}]
    //   [WHEN (condition)]
    //   EXECUTE {FUNCTION | PROCEDURE} func_name(args)
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_pg_trigger_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_pg_trigger")?;
        let start_span = self.current_span();

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;

        // Optional: OR REPLACE
        let mut or_replace = false;
        let mut or_keyword = None;
        let mut replace_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // OR
                or_keyword = Some(self.last_token_id());
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Replace)) {
                        self.advance(); // REPLACE
                        replace_keyword = Some(self.last_token_id());
                        or_replace = true;
                    }
                }
            }
        }

        // Optional: CONSTRAINT
        let mut is_constraint = false;
        let mut constraint_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Constraint)) {
                self.advance(); // CONSTRAINT
                constraint_keyword = Some(self.last_token_id());
                is_constraint = true;
            }
        }

        // TRIGGER keyword
        let trigger_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            )
        })?;
        if !matches!(trigger_tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
            return Err(crate::error::ParseError::new(
                trigger_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TRIGGER keyword, found '{}'",
                        trigger_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        self.advance(); // TRIGGER
        let trigger_keyword = self.last_token_id();

        // Trigger name
        let trigger_name = self.parse_qualified_name_span()?;

        // Timing: BEFORE | AFTER | INSTEAD OF
        let (timing, timing_span) = self.parse_trigger_timing()?;

        // Events: event [OR event ...]
        let events = self.parse_trigger_events()?;

        // ON table_name
        let on_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ON keyword after trigger events".to_string(),
                },
            )
        })?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::new(
                on_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ON keyword, found '{}'",
                        on_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        self.advance(); // ON
        let on_keyword = self.last_token_id();

        let table_name = self.parse_qualified_name_span()?;

        // Optional: FROM referenced_table (constraint triggers only)
        let mut from_table = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
                self.advance(); // FROM
                let ref_table = self.parse_qualified_name_span()?;
                from_table = Some(ref_table);
            }
        }

        // Optional: [NOT] DEFERRABLE [INITIALLY {DEFERRED | IMMEDIATE}]
        let (deferrable, deferrable_span) = self.parse_trigger_deferrable()?;

        // Optional: REFERENCING {OLD|NEW} TABLE AS alias ...
        let referencing = self.parse_trigger_referencing()?;

        // Optional: FOR [EACH] {ROW | STATEMENT}
        let (for_each, for_each_span) = self.parse_trigger_for_each()?;

        // Optional: WHEN (condition)
        let when_condition = self.parse_trigger_when()?;

        // EXECUTE {FUNCTION | PROCEDURE} func_name(args)
        let (execute_span, function_name, function_args_span, function_call_parens) =
            self.parse_trigger_execute()?;

        let end = function_call_parens.end;
        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = crate::syntax::SyntaxCreatePgTriggerStmt {
            create_keyword,
            or_keyword,
            replace_keyword,
            constraint_keyword,
            trigger_keyword,
            trigger_name_span: trigger_name,
            timing_span,
            on_keyword,
            table_name_span: table_name,
            execute_keyword: self.last_token_id(), // placeholder, overridden below
            func_or_proc_keyword: self.last_token_id(), // placeholder
            function_name_span: function_name,
            function_call_parens_span: function_call_parens,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_create_pg_trigger_stmt(syntax_node);

        let ast = AstCreatePgTrigger {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            or_replace,
            is_constraint,
            trigger_name,
            timing,
            timing_span,
            events,
            table_name,
            from_table,
            deferrable,
            deferrable_span,
            referencing,
            for_each,
            for_each_span,
            when_condition,
            execute_span,
            function_name,
            function_args_span,
            function_call_parens,
        };
        Ok(AstStmt::CreatePgTrigger(Box::new(ast)))
    }

    /// Parse BEFORE | AFTER | INSTEAD OF
    fn parse_trigger_timing(&mut self) -> ParseResult<(PgTriggerTiming, Span)> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected trigger timing (BEFORE, AFTER, or INSTEAD OF)".to_string(),
                },
            )
        })?;

        // BEFORE is Identifier, not Keyword!
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("BEFORE")
        {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["BEFORE".to_string()])?;
            return Ok((PgTriggerTiming::Before, t.span));
        }

        // AFTER is a Keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::After)) {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["AFTER".to_string()])?;
            return Ok((PgTriggerTiming::After, t.span));
        }

        // INSTEAD OF — INSTEAD is Identifier, OF is Keyword
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("INSTEAD")
        {
            let instead_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["INSTEAD".to_string()])?;
            let start = instead_tok.span.start;
            // Expect OF
            let of_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected OF after INSTEAD".to_string(),
                    },
                )
            })?;
            if !matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
                return Err(crate::error::ParseError::new(
                    of_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected OF after INSTEAD, found '{}'",
                            of_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let of = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["OF".to_string()])?;
            return Ok((
                PgTriggerTiming::InsteadOf,
                Span {
                    start,
                    end: of.span.end,
                },
            ));
        }

        Err(crate::error::ParseError::new(
            tok.span,
            crate::error::ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected BEFORE, AFTER, or INSTEAD OF, found '{}'",
                    tok.lexeme(self.source)
                ),
            },
        ))
    }

    /// Parse event [OR event ...] where event = INSERT | UPDATE [OF col, ...] | DELETE | TRUNCATE
    fn parse_trigger_events(&mut self) -> ParseResult<Vec<PgTriggerEvent>> {
        let mut events = Vec::new();
        events.push(self.parse_single_trigger_event()?);

        // Additional events separated by OR
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // OR
                events.push(self.parse_single_trigger_event()?);
            } else {
                break;
            }
        }

        Ok(events)
    }

    /// Parse a single trigger event: INSERT | UPDATE [OF col, ...] | DELETE | TRUNCATE
    fn parse_single_trigger_event(&mut self) -> ParseResult<PgTriggerEvent> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected trigger event (INSERT, UPDATE, DELETE, or TRUNCATE)"
                        .to_string(),
                },
            )
        })?;

        match tok.kind {
            TokenKind::Keyword(Keyword::Insert) => {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["INSERT".to_string()])?;
                Ok(PgTriggerEvent {
                    span: t.span,
                    kind: PgTriggerEventKind::Insert,
                })
            }
            TokenKind::Keyword(Keyword::Update) => {
                let update_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["UPDATE".to_string()])?;
                let mut end = update_tok.span.end;
                let mut columns = Vec::new();

                // Check for OF col1, col2, ...
                if let Some(of_tok) = self.peek_non_trivia() {
                    if matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
                        self.advance(); // OF

                        // Parse column list
                        loop {
                            let col = self.parse_qualified_name_span()?;
                            end = col.end;
                            columns.push(col);

                            if let Some(comma) = self.peek_non_trivia() {
                                if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma))
                                {
                                    self.advance(); // comma
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }

                Ok(PgTriggerEvent {
                    span: Span {
                        start: update_tok.span.start,
                        end,
                    },
                    kind: PgTriggerEventKind::Update { columns },
                })
            }
            TokenKind::Keyword(Keyword::Delete) => {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["DELETE".to_string()])?;
                Ok(PgTriggerEvent {
                    span: t.span,
                    kind: PgTriggerEventKind::Delete,
                })
            }
            TokenKind::Keyword(Keyword::Truncate) => {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TRUNCATE".to_string()])?;
                Ok(PgTriggerEvent {
                    span: t.span,
                    kind: PgTriggerEventKind::Truncate,
                })
            }
            _ => Err(crate::error::ParseError::new(
                tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected trigger event (INSERT, UPDATE, DELETE, TRUNCATE), found '{}'",
                        tok.lexeme(self.source)
                    ),
                },
            )),
        }
    }

    /// Parse optional [NOT] DEFERRABLE [INITIALLY {DEFERRED | IMMEDIATE}]
    fn parse_trigger_deferrable(
        &mut self,
    ) -> ParseResult<(Option<PgDeferrableMode>, Option<Span>)> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok((None, None)),
        };

        // NOT DEFERRABLE
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
            let not_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
            let start = not_tok.span.start;
            // Check for DEFERRABLE
            if let Some(def_tok) = self.peek_non_trivia() {
                if matches!(def_tok.kind, TokenKind::Identifier { .. })
                    && def_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("DEFERRABLE")
                {
                    let d = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["DEFERRABLE".to_string()])?;
                    return Ok((
                        Some(PgDeferrableMode::NotDeferrable),
                        Some(Span {
                            start,
                            end: d.span.end,
                        }),
                    ));
                }
            }
            // NOT without DEFERRABLE — weird, but don't consume
            // Restore is hard here since we already consumed NOT.
            // In practice, NOT only appears before DEFERRABLE in this context.
            return Ok((None, None));
        }

        // DEFERRABLE [INITIALLY {DEFERRED | IMMEDIATE}]
        // DEFERRABLE is Identifier, not Keyword!
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("DEFERRABLE")
        {
            let def_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["DEFERRABLE".to_string()])?;
            let start = def_tok.span.start;
            let mut end = def_tok.span.end;
            let mut mode = PgDeferrableMode::DeferrableInitiallyImmediate; // default

            // Check for INITIALLY
            if let Some(init_tok) = self.peek_non_trivia() {
                if matches!(init_tok.kind, TokenKind::Identifier { .. })
                    && init_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("INITIALLY")
                {
                    self.advance(); // INITIALLY
                    end = self.tokens[self.idx - 1].span.end;

                    // DEFERRED or IMMEDIATE
                    if let Some(mode_tok) = self.peek_non_trivia() {
                        if matches!(mode_tok.kind, TokenKind::Identifier { .. })
                            && mode_tok
                                .lexeme(self.source)
                                .eq_ignore_ascii_case("DEFERRED")
                        {
                            let m = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["DEFERRED".to_string()])?;
                            end = m.span.end;
                            mode = PgDeferrableMode::DeferrableInitiallyDeferred;
                        } else if matches!(mode_tok.kind, TokenKind::Keyword(Keyword::Immediate)) {
                            let m = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["IMMEDIATE".to_string()])?;
                            end = m.span.end;
                            mode = PgDeferrableMode::DeferrableInitiallyImmediate;
                        }
                    }
                }
            }

            return Ok((Some(mode), Some(Span { start, end })));
        }

        Ok((None, None))
    }

    /// Parse optional REFERENCING {OLD|NEW} TABLE AS alias ...
    fn parse_trigger_referencing(&mut self) -> ParseResult<Vec<PgReferencingEntry>> {
        let mut entries = Vec::new();
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(entries),
        };

        // REFERENCING is Identifier
        if !(matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("REFERENCING"))
        {
            return Ok(entries);
        }
        self.advance(); // REFERENCING

        // Parse {OLD|NEW} TABLE AS alias entries
        while let Some(entry_tok) = self.peek_non_trivia() {
            // OLD or NEW (both are Identifiers)
            let is_new = if matches!(entry_tok.kind, TokenKind::Identifier { .. })
                && entry_tok.lexeme(self.source).eq_ignore_ascii_case("OLD")
            {
                false
            } else if matches!(entry_tok.kind, TokenKind::Identifier { .. })
                && entry_tok.lexeme(self.source).eq_ignore_ascii_case("NEW")
            {
                true
            } else {
                break;
            };
            let old_new_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["OLD or NEW".to_string()])?;
            let entry_start = old_new_tok.span.start;

            // TABLE (Keyword)
            let table_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected TABLE after OLD/NEW in REFERENCING clause".to_string(),
                    },
                )
            })?;
            if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
                return Err(crate::error::ParseError::new(
                    table_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TABLE after OLD/NEW, found '{}'",
                            table_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            self.advance(); // TABLE

            // AS (Keyword)
            let as_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected AS after TABLE in REFERENCING clause".to_string(),
                    },
                )
            })?;
            if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                return Err(crate::error::ParseError::new(
                    as_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected AS after TABLE, found '{}'",
                            as_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            self.advance(); // AS

            // Alias name
            let alias = self.parse_qualified_name_span()?;

            entries.push(PgReferencingEntry {
                span: Span {
                    start: entry_start,
                    end: alias.end,
                },
                is_new,
                alias,
            });
        }

        Ok(entries)
    }

    /// Parse optional FOR [EACH] {ROW | STATEMENT}
    fn parse_trigger_for_each(&mut self) -> ParseResult<(Option<PgForEachMode>, Option<Span>)> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok((None, None)),
        };

        if !matches!(tok.kind, TokenKind::Keyword(Keyword::For)) {
            return Ok((None, None));
        }
        let for_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?;
        let start = for_tok.span.start;

        // Optional: EACH (Identifier, not Keyword!)
        if let Some(each_tok) = self.peek_non_trivia() {
            if matches!(each_tok.kind, TokenKind::Identifier { .. })
                && each_tok.lexeme(self.source).eq_ignore_ascii_case("EACH")
            {
                self.advance(); // EACH
            }
        }

        // ROW (Keyword) or STATEMENT (Identifier)
        let mode_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ROW or STATEMENT after FOR [EACH]".to_string(),
                },
            )
        })?;

        if matches!(mode_tok.kind, TokenKind::Keyword(Keyword::Row)) {
            let m = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["ROW".to_string()])?;
            Ok((
                Some(PgForEachMode::Row),
                Some(Span {
                    start,
                    end: m.span.end,
                }),
            ))
        } else if matches!(mode_tok.kind, TokenKind::Identifier { .. })
            && mode_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("STATEMENT")
        {
            let m = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["STATEMENT".to_string()])?;
            Ok((
                Some(PgForEachMode::Statement),
                Some(Span {
                    start,
                    end: m.span.end,
                }),
            ))
        } else {
            Err(crate::error::ParseError::new(
                mode_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ROW or STATEMENT, found '{}'",
                        mode_tok.lexeme(self.source)
                    ),
                },
            ))
        }
    }

    /// Parse optional WHEN (condition)
    fn parse_trigger_when(&mut self) -> ParseResult<Option<Span>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };

        if !matches!(tok.kind, TokenKind::Keyword(Keyword::When)) {
            return Ok(None);
        }
        let when_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WHEN".to_string()])?;
        let start = when_tok.span.start;

        // Expect opening paren
        let lparen_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after WHEN".to_string(),
                },
            )
        })?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(crate::error::ParseError::new(
                lparen_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after WHEN".to_string(),
                },
            ));
        }
        self.advance(); // (

        // Consume until matching closing paren, tracking nesting
        let mut depth: u32 = 1;
        let mut end = self.tokens[self.idx - 1].span.end;
        while depth > 0 {
            let next = self.advance().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Unterminated WHEN condition — missing ')'".to_string(),
                    },
                )
            })?;
            match next.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                TokenKind::Eof => {
                    return Err(crate::error::ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: "Unterminated WHEN condition — missing ')'".to_string(),
                        },
                    ));
                }
                _ => {}
            }
            end = next.span.end;
        }

        Ok(Some(Span { start, end }))
    }

    /// Parse EXECUTE {FUNCTION | PROCEDURE} func_name(args)
    /// Returns (execute_span, function_name, args_span, call_parens_span)
    fn parse_trigger_execute(&mut self) -> ParseResult<(Span, Span, Option<Span>, Span)> {
        // EXECUTE keyword
        let exec_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected EXECUTE keyword".to_string(),
                },
            )
        })?;
        if !matches!(exec_tok.kind, TokenKind::Keyword(Keyword::Execute)) {
            return Err(crate::error::ParseError::new(
                exec_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected EXECUTE keyword, found '{}'",
                        exec_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let execute_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXECUTE".to_string()])?;
        let exec_start = execute_tok.span.start;

        // FUNCTION or PROCEDURE
        let func_proc_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected FUNCTION or PROCEDURE after EXECUTE".to_string(),
                },
            )
        })?;
        if !matches!(
            func_proc_tok.kind,
            TokenKind::Keyword(Keyword::Function) | TokenKind::Keyword(Keyword::Procedure)
        ) {
            return Err(crate::error::ParseError::new(
                func_proc_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected FUNCTION or PROCEDURE, found '{}'",
                        func_proc_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let fp = self.advance().ok_or_eof(
            self.current_span(),
            vec!["FUNCTION or PROCEDURE".to_string()],
        )?;
        let execute_span = Span {
            start: exec_start,
            end: fp.span.end,
        };

        // Function name (may be schema-qualified)
        let function_name = self.parse_qualified_name_span()?;

        // Function arguments: ( args )
        let lparen_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after function name".to_string(),
                },
            )
        })?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(crate::error::ParseError::new(
                lparen_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after function name".to_string(),
                },
            ));
        }
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        let parens_start = lparen.span.start;

        // Consume until matching RParen
        let mut depth: u32 = 1;
        let mut args_start: Option<u32> = None;
        let mut args_end: Option<u32> = None;

        while depth > 0 {
            let next = self.advance().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Unterminated function call — missing ')'".to_string(),
                    },
                )
            })?;
            match next.kind {
                TokenKind::Punctuation(Punctuation::LParen) => {
                    if args_start.is_none() {
                        args_start = Some(next.span.start);
                    }
                    depth += 1;
                }
                TokenKind::Punctuation(Punctuation::RParen) => {
                    depth -= 1;
                    if depth > 0 {
                        args_end = Some(next.span.end);
                    }
                }
                TokenKind::Eof => {
                    return Err(crate::error::ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: "Unterminated function call — missing ')'".to_string(),
                        },
                    ));
                }
                _ => {
                    if args_start.is_none() {
                        args_start = Some(next.span.start);
                    }
                    args_end = Some(next.span.end);
                }
            }
        }

        let rparen_end = self.tokens[self.idx - 1].span.end;
        let function_call_parens = Span {
            start: parens_start,
            end: rparen_end,
        };

        let function_args_span = match (args_start, args_end) {
            (Some(s), Some(e)) => Some(Span { start: s, end: e }),
            _ => None,
        };

        Ok((
            execute_span,
            function_name,
            function_args_span,
            function_call_parens,
        ))
    }

    // -----------------------------------------------------------------------
    // ALTER TRIGGER name ON table_name
    //   {RENAME TO new_name | [NO] DEPENDS ON EXTENSION ext_name}
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_alter_pg_trigger_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_pg_trigger")?;
        let start_span = self.current_span();

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;

        // TRIGGER
        let trigger_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            )
        })?;
        if !matches!(trigger_tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
            return Err(crate::error::ParseError::new(
                trigger_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            ));
        }
        self.advance(); // TRIGGER
        let trigger_keyword = self.last_token_id();

        // Trigger name
        let trigger_name = self.parse_qualified_name_span()?;

        // ON
        let on_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ON keyword".to_string(),
                },
            )
        })?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::new(
                on_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ON keyword".to_string(),
                },
            ));
        }
        self.advance(); // ON
        let on_keyword = self.last_token_id();

        // Table name
        let table_name = self.parse_qualified_name_span()?;

        // Action: RENAME TO | [NO] DEPENDS ON EXTENSION
        let action_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected RENAME or [NO] DEPENDS".to_string(),
                },
            )
        })?;

        let end;

        let action = if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            let rename_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
            let action_start = rename_tok.span.start;

            // TO
            let to_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected TO after RENAME".to_string(),
                    },
                )
            })?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(crate::error::ParseError::new(
                    to_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected TO after RENAME".to_string(),
                    },
                ));
            }
            self.advance(); // TO

            let new_name = self.parse_qualified_name_span()?;
            end = new_name.end;
            PgAlterTriggerAction::RenameTo {
                span: Span {
                    start: action_start,
                    end,
                },
                new_name,
            }
        } else {
            // [NO] DEPENDS ON EXTENSION ext_name
            let mut no = false;
            let action_start;

            if matches!(action_tok.kind, TokenKind::Identifier { .. })
                && action_tok.lexeme(self.source).eq_ignore_ascii_case("NO")
            {
                self.advance(); // NO
                no = true;
                action_start = self.tokens[self.idx - 1].span.start;
            } else {
                action_start = action_tok.span.start;
            }

            // DEPENDS (Identifier)
            let depends_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected DEPENDS".to_string(),
                    },
                )
            })?;
            if !(matches!(depends_tok.kind, TokenKind::Identifier { .. })
                && depends_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("DEPENDS"))
            {
                return Err(crate::error::ParseError::new(
                    depends_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected DEPENDS, found '{}'",
                            depends_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            self.advance(); // DEPENDS

            // ON
            let on2 = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected ON after DEPENDS".to_string(),
                    },
                )
            })?;
            if !matches!(on2.kind, TokenKind::Keyword(Keyword::On)) {
                return Err(crate::error::ParseError::new(
                    on2.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected ON after DEPENDS".to_string(),
                    },
                ));
            }
            self.advance(); // ON

            // EXTENSION (Identifier)
            let ext_tok = self.peek_non_trivia().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected EXTENSION".to_string(),
                    },
                )
            })?;
            if !(matches!(ext_tok.kind, TokenKind::Identifier { .. })
                && ext_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("EXTENSION"))
            {
                return Err(crate::error::ParseError::new(
                    ext_tok.span,
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected EXTENSION".to_string(),
                    },
                ));
            }
            self.advance(); // EXTENSION

            // Extension name
            let extension_name = self.parse_qualified_name_span()?;
            end = extension_name.end;

            PgAlterTriggerAction::DependsOnExtension {
                span: Span {
                    start: action_start,
                    end,
                },
                no,
                extension_name,
            }
        };

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = crate::syntax::SyntaxAlterPgTriggerStmt {
            alter_keyword,
            trigger_keyword,
            trigger_name_span: trigger_name,
            on_keyword,
            table_name_span: table_name,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_alter_pg_trigger_stmt(syntax_node);

        let ast = AstAlterPgTrigger {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            trigger_name,
            table_name,
            action,
        };
        Ok(AstStmt::AlterPgTrigger(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DROP TRIGGER [IF EXISTS] name ON table_name [CASCADE | RESTRICT]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_drop_pg_trigger_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_pg_trigger")?;
        let start_span = self.current_span();

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DROP".to_string()])?;
        let drop_keyword = self.last_token_id();
        let start = drop_tok.span.start;

        // TRIGGER
        let trigger_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            )
        })?;
        if !matches!(trigger_tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
            return Err(crate::error::ParseError::new(
                trigger_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            ));
        }
        self.advance(); // TRIGGER
        let trigger_keyword = self.last_token_id();

        // Optional: IF EXISTS
        let mut if_exists = false;
        let mut if_keyword = None;
        let mut exists_keyword = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                if_keyword = Some(self.last_token_id());
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Exists)) {
                        self.advance(); // EXISTS
                        exists_keyword = Some(self.last_token_id());
                        if_exists = true;
                    }
                }
            }
        }

        // Trigger name
        let trigger_name = self.parse_qualified_name_span()?;

        // ON table_name
        let on_tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ON keyword after trigger name".to_string(),
                },
            )
        })?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(crate::error::ParseError::new(
                on_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: "Expected ON keyword after trigger name".to_string(),
                },
            ));
        }
        self.advance(); // ON
        let on_keyword = self.last_token_id();

        let table_name = self.parse_qualified_name_span()?;
        let mut end = table_name.end;

        // Optional: CASCADE | RESTRICT (both are Identifiers, not Keywords!)
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("CASCADE")
            {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                cascade_restrict = Some(PgCascadeRestrict::Cascade);
                end = t.span.end;
            } else if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("RESTRICT")
            {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                cascade_restrict = Some(PgCascadeRestrict::Restrict);
                end = t.span.end;
            }
        }

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = crate::syntax::SyntaxDropPgTriggerStmt {
            drop_keyword,
            trigger_keyword,
            if_keyword,
            exists_keyword,
            trigger_name_span: trigger_name,
            on_keyword,
            table_name_span: table_name,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_drop_pg_trigger_stmt(syntax_node);

        let ast = AstDropPgTrigger {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            if_exists,
            trigger_name,
            table_name,
            cascade_restrict,
        };
        Ok(AstStmt::DropPgTrigger(Box::new(ast)))
    }
}
