// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Databricks Unity Catalog `CREATE/ALTER/DROP CONNECTION` statements.
//!
//! Syntax:
//!   `CREATE CONNECTION [IF NOT EXISTS] name TYPE type OPTIONS (...) [COMMENT '...']`
//!   `CREATE SERVER [IF NOT EXISTS] name TYPE type OPTIONS (...) [COMMENT '...']`
//!   `ALTER CONNECTION name { [SET] OWNER TO principal | RENAME TO new_name | OPTIONS (...) }`
//!   `DROP CONNECTION [IF EXISTS] name`
//!
//! Token reference (--debug-tokens --dialect databricks):
//!   CREATE     → Keyword(Create)
//!   ALTER      → Keyword(Alter)
//!   DROP       → Keyword(Drop)
//!   CONNECTION → Identifier (NOT Keyword)
//!   SERVER     → Identifier (NOT Keyword)
//!   IF         → Keyword(If)
//!   NOT        → Keyword(Not)
//!   EXISTS     → Keyword(Exists)
//!   TYPE       → Keyword(Type)
//!   POSTGRESQL → Identifier (NOT Keyword)
//!   OPTIONS    → Identifier (NOT Keyword)
//!   COMMENT    → Keyword(Comment)
//!   SET        → Keyword(Set)
//!   OWNER      → Keyword(Owner)
//!   TO         → Keyword(To)
//!   RENAME     → Keyword(Rename)
//!   secret     → Identifier (NOT Keyword)

use crate::ast::types::{
    AlterConnectionAction, AstAlterConnection, AstCreateConnection, AstDropConnection, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE CONNECTION|SERVER [IF NOT EXISTS] name TYPE type OPTIONS (...) [COMMENT '...']`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies CREATE CONNECTION|SERVER.
    /// Position: at CREATE token (idx reset to saved_idx pointing to CREATE).
    pub(crate) fn try_parse_create_connection(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_connection")?;
        let start = self.current_span().start;

        // CREATE
        let _create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;

        let or_replace_span = self.parse_optional_or_replace()?;

        // CONNECTION or SERVER (both are Identifiers)
        let conn_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CONNECTION".to_string()])?;
        let conn_lex = conn_kw_tok.lexeme(self.source);
        if !conn_lex.eq_ignore_ascii_case("CONNECTION") && !conn_lex.eq_ignore_ascii_case("SERVER")
        {
            return Err(ParseError::new(
                conn_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected CONNECTION or SERVER, found '{}'", conn_lex),
                },
            ));
        }

        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // Connection name (required — possibly backtick-quoted, possibly qualified)
        let connection_name_span = self.parse_qualified_name_span()?;
        let mut end = connection_name_span.end;

        // Snowflake: AS REPLICA OF <org>.<account>.<connection>. Guarded on
        // the next-next token being REPLICA so a bare AS is never consumed
        // (the statement span must stay whole for the formatter).
        let mut replica_of_span = None;
        let is_replica = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::As))
        ) && self
            .tokens
            .get(self.idx + 1)
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("REPLICA"));
        if is_replica {
            self.advance(); // AS
            self.advance(); // REPLICA
            if let Some(of) = self.peek_non_trivia() {
                if of.lexeme(self.source).eq_ignore_ascii_case("OF") {
                    self.advance(); // OF
                }
            }
            let src = self.parse_qualified_name_span()?;
            replica_of_span = Some(src);
            end = src.end;
        }

        // TYPE connection_type (TYPE is a Keyword, type value is Identifier)
        let mut type_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                let type_kw_tok = self.advance().unwrap();
                let type_start = type_kw_tok.span.start;
                // Type value (POSTGRESQL, MYSQL, SNOWFLAKE, DATABRICKS, etc. — all Identifiers)
                let type_val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["connection type".to_string()])?;
                type_span = Some(Span {
                    start: type_start,
                    end: type_val_tok.span.end,
                });
                end = type_val_tok.span.end;
            }
        }

        // OPTIONS (...) (OPTIONS is an Identifier)
        let mut options_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
            {
                let opts_start = tok.span.start;
                self.advance(); // consume OPTIONS

                // Expect LParen
                let lparen = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
                if !matches!(
                    lparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    return Err(ParseError::new(
                        lparen.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected '(' after OPTIONS, found '{}'",
                                lparen.lexeme(self.source)
                            ),
                        },
                    ));
                }

                // Consume everything until matching RParen (handling nested parens for secret() calls)
                let mut depth: u32 = 1;
                let mut last_end = lparen.span.end;
                while depth > 0 {
                    let tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    last_end = tok.span.end;
                    match tok.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                        _ => {}
                    }
                }
                options_span = Some(Span {
                    start: opts_start,
                    end: last_end,
                });
                end = last_end;
            }
        }

        // Optional COMMENT 'string'
        let mut comment_keyword_span = None;
        let mut comment_value_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_kw = self.advance().unwrap();
                comment_keyword_span = Some(comment_kw.span);

                // Snowflake writes `COMMENT = '...'`; Databricks `COMMENT '...'`.
                // Skip an optional `=` before the value.
                if matches!(
                    self.peek_non_trivia(),
                    Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq))
                ) {
                    self.advance();
                }

                let comment_val = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                comment_value_span = Some(comment_val.span);
                end = comment_val.span.end;
            }
        }

        let span = Span { start, end };

        let ast = AstCreateConnection {
            node_id: self.id_gen.next(),
            span,
            if_not_exists,
            or_replace_span,
            connection_name_span,
            type_span,
            options_span,
            comment_keyword_span,
            comment_value_span,
            replica_of_span,
        };
        Ok(AstStmt::CreateConnection(Box::new(ast)))
    }

    /// Parse `ALTER CONNECTION name { [SET] OWNER TO principal | RENAME TO new_name | OPTIONS (...) }`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies ALTER CONNECTION.
    /// Position: at ALTER token (idx reset to saved_idx pointing to ALTER).
    pub(crate) fn try_parse_alter_connection(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_connection")?;
        let start = self.current_span().start;

        // ALTER
        let _alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;

        // CONNECTION (Identifier, NOT Keyword)
        let conn_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CONNECTION".to_string()])?;
        if !conn_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CONNECTION")
        {
            return Err(ParseError::new(
                conn_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CONNECTION, found '{}'",
                        conn_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Connection name (required)
        let connection_name_span = self.parse_qualified_name_span()?;

        // Parse action: [SET] OWNER TO | RENAME TO | OPTIONS (...)
        let action = self.parse_alter_connection_action()?;
        let end = match &action {
            AlterConnectionAction::OwnerTo {
                owner_name_span, ..
            } => owner_name_span.end,
            AlterConnectionAction::RenameTo { new_name_span, .. } => new_name_span.end,
            AlterConnectionAction::Options { options_span } => options_span.end,
            AlterConnectionAction::EnableFailover {
                failover_span,
                accounts_span,
            }
            | AlterConnectionAction::DisableFailover {
                failover_span,
                accounts_span,
            } => accounts_span.map_or(failover_span.end, |s| s.end),
            AlterConnectionAction::Primary { primary_span } => primary_span.end,
        };

        let span = Span { start, end };

        let ast = AstAlterConnection {
            node_id: self.id_gen.next(),
            span,
            connection_name_span,
            action,
        };
        Ok(AstStmt::AlterConnection(Box::new(ast)))
    }

    /// Parse `DROP CONNECTION [IF EXISTS] name`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies DROP CONNECTION.
    /// Position: at DROP token (idx reset to saved_idx - 1, pointing to DROP).
    pub(crate) fn try_parse_drop_connection(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_connection")?;
        let start = self.current_span().start;

        // DROP
        let _drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;

        // CONNECTION (Identifier, NOT Keyword)
        let conn_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CONNECTION".to_string()])?;
        if !conn_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CONNECTION")
        {
            return Err(ParseError::new(
                conn_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CONNECTION, found '{}'",
                        conn_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF EXISTS
        let if_exists = self.parse_optional_if_exists()?.is_some();

        // Connection name (required)
        let connection_name_span = self.parse_qualified_name_span()?;
        let end = connection_name_span.end;

        let span = Span { start, end };

        let ast = AstDropConnection {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            connection_name_span,
        };
        Ok(AstStmt::DropConnection(Box::new(ast)))
    }

    // ─── Helpers ────────────────────────────────────────────────────────────────

    /// Parse the action clause of an ALTER CONNECTION statement.
    /// Parse an optional `TO ACCOUNTS <account>[, <account>]*` tail after
    /// ENABLE / DISABLE FAILOVER, returning the span covering the account list.
    fn parse_optional_failover_accounts(&mut self) -> Option<Span> {
        let has_to = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::To))
        );
        if !has_to {
            return None;
        }
        self.advance(); // TO
        if let Some(t) = self.peek_non_trivia() {
            if t.lexeme(self.source).eq_ignore_ascii_case("ACCOUNTS") {
                self.advance(); // ACCOUNTS
            }
        }
        let mut start = None;
        let mut end = None;
        while let Some(t) = self.peek_non_trivia() {
            if matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            if let Some(tok) = self.advance() {
                if start.is_none() {
                    start = Some(tok.span.start);
                }
                end = Some(tok.span.end);
            } else {
                break;
            }
        }
        match (start, end) {
            (Some(s), Some(e)) => Some(Span { start: s, end: e }),
            _ => None,
        }
    }

    /// Expects: [SET] OWNER TO principal | RENAME TO new_name | OPTIONS (...)
    fn parse_alter_connection_action(&mut self) -> ParseResult<AlterConnectionAction> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected OWNER TO, RENAME TO, or OPTIONS after connection name"
                        .to_string(),
                },
            )
        })?;

        if matches!(tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            let rename_tok = self.advance().unwrap();
            let rename_span = rename_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after RENAME, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let new_name_span = self.parse_qualified_name_span()?;

            Ok(AlterConnectionAction::RenameTo {
                rename_span,
                to_span,
                new_name_span,
            })
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
            // SET OWNER TO principal
            let set_tok = self.advance().unwrap();
            let set_span = Some(set_tok.span);

            let owner_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["OWNER".to_string()])?;
            if !matches!(owner_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
                return Err(ParseError::new(
                    owner_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected OWNER after SET, found '{}'",
                            owner_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let owner_span = owner_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after OWNER, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let owner_name_span = self.parse_qualified_name_span()?;

            Ok(AlterConnectionAction::OwnerTo {
                set_span,
                owner_span,
                to_span,
                owner_name_span,
            })
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Owner)) {
            // OWNER TO principal (without SET)
            let owner_tok = self.advance().unwrap();
            let owner_span = owner_tok.span;

            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TO after OWNER, found '{}'",
                            to_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let to_span = to_tok.span;

            let owner_name_span = self.parse_qualified_name_span()?;

            Ok(AlterConnectionAction::OwnerTo {
                set_span: None,
                owner_span,
                to_span,
                owner_name_span,
            })
        } else if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS")
        {
            // OPTIONS (...)
            let opts_start = tok.span.start;
            self.advance(); // consume OPTIONS

            // Expect LParen
            let lparen = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
            if !matches!(
                lparen.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::new(
                    lparen.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected '(' after OPTIONS, found '{}'",
                            lparen.lexeme(self.source)
                        ),
                    },
                ));
            }

            // Consume everything until matching RParen (handles nested parens for secret() calls)
            let mut depth: u32 = 1;
            let mut last_end = lparen.span.end;
            while depth > 0 {
                let tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                last_end = tok.span.end;
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                    _ => {}
                }
            }

            let options_span = Span {
                start: opts_start,
                end: last_end,
            };

            Ok(AlterConnectionAction::Options { options_span })
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("ENABLE")
            || tok.lexeme(self.source).eq_ignore_ascii_case("DISABLE")
        {
            // ENABLE / DISABLE may lex as a keyword or identifier — match by lexeme.
            // Snowflake: ENABLE | DISABLE FAILOVER [TO ACCOUNTS <list>]
            let is_enable = tok.lexeme(self.source).eq_ignore_ascii_case("ENABLE");
            self.advance(); // ENABLE | DISABLE
            let fo = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["FAILOVER".to_string()])?;
            if !fo.lexeme(self.source).eq_ignore_ascii_case("FAILOVER") {
                return Err(ParseError::new(
                    fo.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected FAILOVER after {}, found '{}'",
                            if is_enable { "ENABLE" } else { "DISABLE" },
                            fo.lexeme(self.source)
                        ),
                    },
                ));
            }
            let failover_span = fo.span;
            let accounts_span = self.parse_optional_failover_accounts();
            if is_enable {
                Ok(AlterConnectionAction::EnableFailover {
                    failover_span,
                    accounts_span,
                })
            } else {
                Ok(AlterConnectionAction::DisableFailover {
                    failover_span,
                    accounts_span,
                })
            }
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("PRIMARY") {
            // Snowflake: PRIMARY — promote a replica connection to primary.
            let primary_span = tok.span;
            self.advance(); // consume PRIMARY
            Ok(AlterConnectionAction::Primary { primary_span })
        } else {
            Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected [SET] OWNER TO, RENAME TO, OPTIONS, ENABLE/DISABLE FAILOVER, or PRIMARY, found '{}'",
                        tok.lexeme(self.source)
                    ),
                },
            ))
        }
    }
}
