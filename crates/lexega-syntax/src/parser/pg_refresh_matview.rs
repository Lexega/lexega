// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::ast::types::{AstPgRefreshMatview, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxPgRefreshMatviewStmt;

impl<'a> Parser<'a> {
    /// Parse: REFRESH MATERIALIZED VIEW [ CONCURRENTLY ] name [ WITH [ NO ] DATA ]
    pub(crate) fn try_parse_pg_refresh_matview_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_refresh_matview")?;
        let start_span = self.current_span();

        // Consume REFRESH keyword
        let refresh_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["REFRESH".to_string()])?;
        let refresh_token_id = self.last_token_id();
        let start = refresh_tok.span.start;

        // Consume MATERIALIZED (Identifier, not Keyword)
        let mat_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MATERIALIZED".to_string()])?;
        if !mat_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("MATERIALIZED")
        {
            return Err(ParseError::new(
                mat_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected MATERIALIZED, found '{}'",
                        mat_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Consume VIEW keyword
        let view_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VIEW".to_string()])?;
        if !matches!(view_tok.kind, TokenKind::Keyword(Keyword::View)) {
            return Err(ParseError::new(
                view_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected VIEW, found '{}'", view_tok.lexeme(self.source)),
                },
            ));
        }
        let materialized_view_span = Span {
            start: mat_tok.span.start,
            end: view_tok.span.end,
        };

        // Check for optional CONCURRENTLY (Identifier)
        let mut concurrently = false;
        let mut concurrently_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("CONCURRENTLY")
            {
                let conc_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CONCURRENTLY".to_string()])?;
                concurrently = true;
                concurrently_span = Some(conc_tok.span);
            }
        }

        // Parse view name (possibly schema-qualified: schema.name or catalog.schema.name)
        let name_span = self.parse_pg_refresh_matview_name()?;
        let mut end = name_span.end;

        // Check for optional WITH [ NO ] DATA
        let mut with_data: Option<bool> = None;
        let mut with_data_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let with_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                let with_start = with_tok.span.start;

                // Peek for NO or DATA
                if let Some(next) = self.peek_non_trivia() {
                    let next_lexeme = next.lexeme(self.source).to_ascii_uppercase();
                    if next_lexeme == "NO" {
                        // WITH NO DATA
                        let _no_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["NO".to_string()])?;

                        // Expect DATA
                        let data_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
                        if !data_tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
                            return Err(ParseError::new(
                                data_tok.span,
                                ParseErrorKind::InvalidSyntax {
                                    message: format!(
                                        "Expected DATA after WITH NO, found '{}'",
                                        data_tok.lexeme(self.source)
                                    ),
                                },
                            ));
                        }
                        end = data_tok.span.end;
                        with_data = Some(false);
                        with_data_span = Some(Span {
                            start: with_start,
                            end: data_tok.span.end,
                        });
                    } else if next_lexeme == "DATA" {
                        // WITH DATA
                        let data_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
                        end = data_tok.span.end;
                        with_data = Some(true);
                        with_data_span = Some(Span {
                            start: with_start,
                            end: data_tok.span.end,
                        });
                    } else {
                        // Just WITH with no DATA/NO DATA — error
                        return Err(ParseError::new(
                            next.span,
                            ParseErrorKind::InvalidSyntax {
                                message: format!(
                                    "Expected DATA or NO DATA after WITH, found '{}'",
                                    next.lexeme(self.source)
                                ),
                            },
                        ));
                    }
                }
            }
        }

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_node = SyntaxPgRefreshMatviewStmt {
            refresh_keyword: refresh_token_id,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_pg_refresh_matview_stmt(syntax_node);

        let node_id = self.id_gen.next();

        let ast = AstPgRefreshMatview {
            node_id,
            span: stmt_span,
            syntax_id: Some(syntax_id),
            materialized_view_span,
            concurrently,
            concurrently_span,
            name_span,
            with_data,
            with_data_span,
        };

        Ok(AstStmt::PgRefreshMatview(Box::new(ast)))
    }

    /// Parse a possibly schema-qualified view name (dotted identifiers)
    fn parse_pg_refresh_matview_name(&mut self) -> ParseResult<Span> {
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["view name".to_string()])?;

        if !matches!(
            first.kind,
            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
        ) {
            return Err(ParseError::new(
                first.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected view name, found '{}'", first.lexeme(self.source)),
                },
            ));
        }

        let start = first.span.start;
        let mut end = first.span.end;

        // Check for dot-separated qualifiers
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                let _dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![".".to_string()])?;
                let part = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["identifier after '.'".to_string()],
                )?;
                end = part.span.end;
            } else {
                break;
            }
        }

        Ok(Span { start, end })
    }
}
