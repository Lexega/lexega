// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the SQL/MED `CREATE SERVER … FOREIGN DATA WRAPPER` statement
//! (PostgreSQL foreign-data-wrapper federation).
//!
//! `CREATE SERVER [IF NOT EXISTS] name [TYPE '…'] [VERSION '…']
//!  FOREIGN DATA WRAPPER fdw_name [OPTIONS (key 'value' [, …])]`
//!
//! Registers a federated endpoint reached through a foreign-data wrapper.
//! Recognition lifts the wrapper name (the discriminator — `postgres_fdw`
//! reaches the network, `file_fdw` reads server-side files), whether a TYPE
//! clause and an OPTIONS bag are present. OPTION values are never surfaced.
//!
//! Dispatched from the `CREATE SERVER` arm in `core.rs` when
//! `is_foreign_server_at` sees a `FOREIGN DATA` clause ahead — otherwise
//! the bare `CREATE SERVER` form belongs to the Databricks Unity-Catalog
//! connection parser.
//!
//! Token reference (`--debug-tokens`, postgresql dialect):
//!   SERVER / DATA / WRAPPER / VERSION / OPTIONS / fdw_name → Identifier
//!   FOREIGN / TYPE / IF / NOT / EXISTS                     → Keyword

use crate::ast::types::{AstAlterForeignServer, AstCreateForeignServer, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Disambiguation guard: a statement-leading `CREATE SERVER` introduces a
/// SQL/MED foreign server only when a `FOREIGN DATA` clause appears before the
/// first statement terminator. Otherwise it is the Databricks Unity-Catalog
/// `CREATE SERVER` form. Scans significant tokens from `idx` (the CREATE
/// position), stopping at a depth-0 semicolon or EOF.
pub(crate) fn is_foreign_server_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    let mut i = idx;
    let mut depth: u32 = 0;
    while i < tokens.len() {
        match tokens[i].kind {
            TokenKind::Eof => return false,
            TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => return false,
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
            TokenKind::Keyword(Keyword::Foreign) if depth == 0 => {
                // FOREIGN must be followed by the identifier DATA.
                let mut j = i + 1;
                while j < tokens.len()
                    && matches!(
                        tokens[j].kind,
                        TokenKind::LineComment | TokenKind::BlockComment
                    )
                {
                    j += 1;
                }
                if j < tokens.len() && tokens[j].lexeme(source).eq_ignore_ascii_case("DATA") {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_create_foreign_server(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_foreign_server")?;
        let start_span = self.current_span();

        // 1. CREATE SERVER. The dispatch guard guarantees both.
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let start = create_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;

        // 2. Optional IF NOT EXISTS.
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // 3. Server name.
        let name_span = self.parse_qualified_name_span()?;

        // 4. Optional TYPE '…' and VERSION '…' (either order, both optional).
        //    Walk forward until the FOREIGN keyword, recording TYPE presence.
        let mut type_present = false;
        loop {
            let tok = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Unexpected end of CREATE SERVER statement".to_string(),
                    },
                )
            })?;
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Foreign)) {
                break;
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                type_present = true;
            }
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FOREIGN".to_string()])?;
        }

        // 5. FOREIGN DATA WRAPPER fdw_name.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["FOREIGN".to_string()])?;
        let data_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
        if !data_tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
            return Err(ParseError::new(
                data_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected DATA after FOREIGN in CREATE SERVER".to_string(),
                },
            ));
        }
        let wrapper_kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WRAPPER".to_string()])?;
        if !wrapper_kw
            .lexeme(self.source)
            .eq_ignore_ascii_case("WRAPPER")
        {
            return Err(ParseError::new(
                wrapper_kw.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected WRAPPER after FOREIGN DATA in CREATE SERVER".to_string(),
                },
            ));
        }
        let fdw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["fdw_name".to_string()])?;
        let wrapper = Some(fdw_tok.lexeme(self.source).to_ascii_lowercase());
        let mut end = fdw_tok.span.end;

        // 6. Optional OPTIONS ( … ) — consume the balanced paren group, noting
        //    presence only. Values can name hosts but never surface here.
        let mut options_present = false;
        if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Identifier { .. })
        ) {
            if let Some(tok) = self.peek_non_trivia() {
                if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") {
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
                                message: "Expected ( after OPTIONS in CREATE SERVER".to_string(),
                            },
                        ));
                    }
                    end = lparen.span.end;
                    let mut depth: u32 = 1;
                    while depth > 0 {
                        let t = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        end = t.span.end;
                        match t.kind {
                            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                            TokenKind::Punctuation(Punctuation::RParen) => {
                                depth = depth.saturating_sub(1)
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let stmt_span = Span { start, end };
        let ast = AstCreateForeignServer {
            node_id: self.id_gen.next(),
            span: stmt_span,
            create_span,
            name_span,
            if_not_exists,
            type_present,
            wrapper,
            options_present,
        };
        Ok(AstStmt::CreateForeignServer(Box::new(ast)))
    }

    /// `ALTER SERVER name [VERSION '…'] [OPTIONS (…)] | OWNER TO … | RENAME TO …`
    /// (SQL/MED foreign-server reconfiguration). Dispatched from the bare
    /// `ALTER SERVER` arm in `core.rs` — `SERVER AUDIT` / `SERVER ROLE` are
    /// matched earlier and T-SQL `SERVER CONFIGURATION` is excluded there.
    ///
    /// The reconfiguration tail is consumed to the depth-0 terminator; the only
    /// governance axis lifted is whether an `OPTIONS (…)` bag is modified (it
    /// can repoint the remote endpoint). Option values never surface.
    pub(crate) fn try_parse_alter_foreign_server(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_foreign_server")?;
        let start_span = self.current_span();

        // ALTER SERVER (the dispatch guard guarantees both).
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;

        // Server name.
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Recognize the reconfiguration tail to the depth-0 statement
        // terminator, noting only whether OPTIONS (…) is touched.
        let mut options_present = false;
        let mut depth: u32 = 0;
        loop {
            let (is_semi, is_eof, is_lparen, is_rparen, is_options) = match self.peek_non_trivia() {
                None => break,
                Some(t) => (
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)),
                    matches!(t.kind, TokenKind::Eof),
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                    matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                    matches!(t.kind, TokenKind::Identifier { .. })
                        && t.lexeme(self.source).eq_ignore_ascii_case("OPTIONS"),
                ),
            };
            if is_eof || (is_semi && depth == 0) {
                break;
            }
            if depth == 0 && is_options {
                options_present = true;
            }
            if is_lparen {
                depth += 1;
            } else if is_rparen {
                depth = depth.saturating_sub(1);
            }
            let consumed = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = consumed.span.end;
        }

        let stmt_span = Span { start, end };
        let ast = AstAlterForeignServer {
            node_id: self.id_gen.next(),
            span: stmt_span,
            name_span,
            options_present,
        };
        Ok(AstStmt::AlterForeignServer(Box::new(ast)))
    }
}
