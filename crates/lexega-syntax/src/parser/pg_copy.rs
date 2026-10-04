// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PostgreSQL COPY statement.
//!
//! ```text
//! COPY table_name [ ( column_name [, ...] ) ]
//!     FROM { 'filename' | PROGRAM 'command' | STDIN }
//!     [ [ WITH ] ( option [, ...] ) ]
//!     [ WHERE condition ]
//!
//! COPY { table_name [ ( column_name [, ...] ) ] | ( query ) }
//!     TO { 'filename' | PROGRAM 'command' | STDOUT }
//!     [ [ WITH ] ( option [, ...] ) ]
//! ```
//!
//! Token shapes:
//! - COPY → Keyword(Copy)
//! - FROM/TO/WITH/WHERE → Keywords
//! - STDIN/STDOUT/PROGRAM → Identifier (must use lexeme comparison)
//! - HEADER/FREEZE/DELIMITER/QUOTE → Identifier
//! - NULL → Literal(Null)  ⚠️
//! - ESCAPE → Keyword(Escape) ⚠️
//! - FORMAT → Keyword(Format) ⚠️
//! - DEFAULT → Keyword(Default) ⚠️
//! - FORCE_QUOTE/FORCE_NOT_NULL/FORCE_NULL → single Identifier tokens
//! - ON_ERROR/ENCODING/LOG_VERBOSITY/REJECT_LIMIT → single Identifier tokens

use crate::ast::types::{AstPgCopy, AstStmt, PgCopyDirection, PgCopySubject, PgCopyTarget};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxPgCopyStmt;

impl<'a> Parser<'a> {
    /// Parse PostgreSQL COPY statement.
    ///
    /// Dispatched when dialect is PostgreSQL and COPY keyword is seen.
    pub(crate) fn try_parse_pg_copy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_copy")?;
        let start_span = self.current_span();

        // COPY keyword
        let copy_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["COPY".to_string()])?;
        let copy_keyword = self.last_token_id();
        let start = copy_tok.span.start;

        // Next: either '(' for a query, or a table name
        let next = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected table name or (query) after COPY".to_string(),
                },
            )
        })?;

        let (subject, columns_span) =
            if matches!(next.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                // COPY (query) TO ... — parse inner query as real AST
                let lparen_tok = self
                    .advance()
                    .ok_or_eof(start_span, vec!["(".to_string()])?;
                let lparen_start = lparen_tok.span.start;

                // Parse the inner SELECT/WITH/VALUES query
                let inner_stmt = self.try_parse_set_or_select_stmt()?;

                // Consume closing paren
                let rparen_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::UnexpectedEof {
                            expected: vec![")".to_string()],
                        },
                    )
                })?;
                if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    return Err(ParseError::unexpected_token(
                        rparen_tok.span,
                        vec![")".to_string()],
                        Parser::token_description(rparen_tok, self.source),
                    ));
                }

                let query_span = Span {
                    start: lparen_start,
                    end: rparen_tok.span.end,
                };
                (PgCopySubject::Query(query_span, Box::new(inner_stmt)), None)
            } else {
                // COPY table_name [ (col, ...) ] ...
                let table_span = self.parse_pg_copy_table_name()?;

                // Optional column list
                let cols = if let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        // Check it's not the WITH options paren — peek if the token
                        // after opening paren looks like FROM/TO keyword, which means
                        // these aren't columns. Actually, columns always come BEFORE
                        // FROM/TO, so if we see '(' here and haven't yet seen FROM/TO,
                        // it's a column list.
                        let cols_span = self.consume_balanced_parens()?;
                        Some(cols_span)
                    } else {
                        None
                    }
                } else {
                    None
                };

                (PgCopySubject::Table(table_span), cols)
            };

        // FROM or TO keyword (required)
        let dir_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected FROM or TO after COPY subject".to_string(),
                },
            )
        })?;

        let direction = match dir_tok.kind {
            TokenKind::Keyword(Keyword::From) => PgCopyDirection::From,
            TokenKind::Keyword(Keyword::To) => PgCopyDirection::To,
            _ => {
                return Err(ParseError::new(
                    dir_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Expected FROM or TO, found '{}'",
                            dir_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
        };

        // Consume the FROM/TO keyword
        let _dir_consumed = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FROM or TO".to_string()])?;

        // Target: 'filename' | PROGRAM 'command' | STDIN | STDOUT
        let target = self.parse_pg_copy_target(direction)?;
        let mut end = match &target {
            PgCopyTarget::File(s)
            | PgCopyTarget::Program(s)
            | PgCopyTarget::Stdin(s)
            | PgCopyTarget::Stdout(s)
            | PgCopyTarget::Placeholder(s) => s.end,
        };

        // Optional: [ WITH ] ( option [, ...] )
        let options_span = self.parse_pg_copy_options()?;
        if let Some(ref opts) = options_span {
            end = opts.end;
        }

        // Optional: WHERE condition (COPY FROM only)
        let where_span = if direction == PgCopyDirection::From {
            self.parse_pg_copy_where()?
        } else {
            None
        };
        if let Some(ref ws) = where_span {
            end = ws.end;
        }

        // Build CST node
        let syntax_id = {
            let syntax_node = SyntaxPgCopyStmt {
                copy_keyword,
                span: Span { start, end },
            };
            self.syntax_arena.alloc_pg_copy_stmt(syntax_node)
        };

        let ast = AstPgCopy {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            syntax_id: Some(syntax_id),
            direction,
            subject,
            columns_span,
            target,
            options_span,
            where_span,
        };
        Ok(AstStmt::PgCopy(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Parse a possibly schema-qualified table name for COPY.
    /// Returns a span covering the whole name (e.g., `public.my_table`).
    fn parse_pg_copy_table_name(&mut self) -> ParseResult<Span> {
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
        let start = first.span.start;
        let mut end = first.span.end;

        // Check for dot-qualified: schema.table or catalog.schema.table
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                let _dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![".".to_string()])?;
                let next_part = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["identifier after '.'".to_string()],
                )?;
                end = next_part.span.end;
            } else {
                break;
            }
        }

        Ok(Span { start, end })
    }

    /// Parse the target/source of a COPY: 'file', PROGRAM 'cmd', STDIN, STDOUT.
    fn parse_pg_copy_target(&mut self, direction: PgCopyDirection) -> ParseResult<PgCopyTarget> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected filename, PROGRAM, STDIN, or STDOUT after FROM/TO"
                        .to_string(),
                },
            )
        })?;

        let lexeme = tok.lexeme(self.source);

        // STDIN
        if lexeme.eq_ignore_ascii_case("STDIN") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["STDIN".to_string()])?;
            return Ok(PgCopyTarget::Stdin(t.span));
        }

        // STDOUT
        if lexeme.eq_ignore_ascii_case("STDOUT") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["STDOUT".to_string()])?;
            return Ok(PgCopyTarget::Stdout(t.span));
        }

        // PROGRAM 'command'
        if lexeme.eq_ignore_ascii_case("PROGRAM") {
            let program_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["PROGRAM".to_string()])?;
            let start = program_tok.span.start;

            let cmd_tok = self.advance().ok_or_eof(
                self.current_span(),
                vec!["command string after PROGRAM".to_string()],
            )?;
            let end = cmd_tok.span.end;

            return Ok(PgCopyTarget::Program(Span { start, end }));
        }

        // 'filename' (string literal)
        if matches!(tok.kind, TokenKind::Literal(_)) {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["filename".to_string()])?;
            return Ok(PgCopyTarget::File(t.span));
        }

        // psql client variable placeholder, e.g. `:source` or `:'source'`.
        // The colon is lexed separately from the following name token.
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Colon)) {
            let colon = self
                .advance()
                .ok_or_eof(self.current_span(), vec![":".to_string()])?;
            let start = colon.span.start;
            let name = self.advance().ok_or_eof(
                self.current_span(),
                vec!["psql variable name after ':'".to_string()],
            )?;
            // Only an identifier (`:var`/`:"var"`) or a string (`:'var'`)
            // forms a psql variable; anything else is a genuine syntax error.
            if matches!(
                name.kind,
                TokenKind::Identifier { .. }
                    | TokenKind::Literal(crate::lexer::token::LiteralKind::String)
            ) {
                return Ok(PgCopyTarget::Placeholder(Span {
                    start,
                    end: name.span.end,
                }));
            }
            return Err(ParseError::new(
                name.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected a psql variable name after ':', found '{}'",
                        name.lexeme(self.source)
                    ),
                },
            ));
        }

        let direction_str = match direction {
            PgCopyDirection::From => "FROM",
            PgCopyDirection::To => "TO",
        };
        Err(ParseError::new(
            tok.span,
            ParseErrorKind::InvalidSyntax {
                message: format!(
                    "Expected filename, PROGRAM, STDIN, or STDOUT after {}, found '{}'",
                    direction_str, lexeme
                ),
            },
        ))
    }

    /// Parse optional WITH (options) clause.
    /// Returns span covering everything from WITH (or just '(') through ')'.
    fn parse_pg_copy_options(&mut self) -> ParseResult<Option<Span>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };

        // Check for WITH keyword or direct '('
        let has_with = matches!(tok.kind, TokenKind::Keyword(Keyword::With));
        let has_lparen = matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen));

        if !has_with && !has_lparen {
            return Ok(None);
        }

        let start;
        if has_with {
            let with_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
            start = with_tok.span.start;

            // After WITH, expect '(' for the modern form. Without it, this is
            // the legacy pre-9.0 option list (e.g. `WITH DELIMITER 'x' CSV
            // HEADER QUOTE 'y'`): consume those tokens up to ';', EOF, or a
            // WHERE clause so the whole clause is captured in the options span
            // rather than mis-parsed as the start of a new statement.
            //
            // INVARIANT: span-capture is safe only because PostgreSQL (the sole
            // dialect gated into this parser via supports_copy_to_from_table)
            // has no credential-bearing COPY option. A credential-bearing
            // COPY dialect (e.g. Redshift CREDENTIALS / IAM_ROLE /
            // ACCESS_KEY_ID / SECRET_ACCESS_KEY) MUST type these options
            // instead of swallowing the span, so secrets stay visible.
            let next = self.peek_non_trivia();
            if !matches!(
                next.map(|t| &t.kind),
                Some(TokenKind::Punctuation(Punctuation::LParen))
            ) {
                let mut end = with_tok.span.end;
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(
                        t.kind,
                        TokenKind::Punctuation(Punctuation::Semi)
                            | TokenKind::Eof
                            | TokenKind::Keyword(Keyword::Where)
                    ) {
                        break;
                    }
                    let consumed = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["COPY option".to_string()])?;
                    end = consumed.span.end;
                }
                return Ok(Some(Span { start, end }));
            }
        } else {
            // Direct '(' — peek ahead to check if this looks like options.
            // For COPY FROM, after the target, '(' could be options.
            // We use start from the upcoming paren.
            start = tok.span.start;
        }

        // Consume balanced parens
        let paren_span = self.consume_balanced_parens()?;

        Ok(Some(Span {
            start,
            end: paren_span.end,
        }))
    }

    /// Parse optional WHERE clause for COPY FROM.
    /// Returns span covering WHERE keyword + condition up to statement end.
    fn parse_pg_copy_where(&mut self) -> ParseResult<Option<Span>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };

        if !matches!(tok.kind, TokenKind::Keyword(Keyword::Where)) {
            return Ok(None);
        }

        let where_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WHERE".to_string()])?;
        let start = where_tok.span.start;
        let mut end = where_tok.span.end;

        // Consume everything until semicolon or EOF
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                || matches!(tok.kind, TokenKind::Eof)
            {
                break;
            }
            // Stop if we hit another top-level keyword that starts a new statement
            // In practice, WHERE consumes everything until ';' or EOF
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["condition".to_string()])?;
            end = t.span.end;
        }

        Ok(Some(Span { start, end }))
    }
}
