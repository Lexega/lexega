// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake FILE FORMAT statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] [{TEMP | TEMPORARY | VOLATILE}] FILE FORMAT`
//!   `[IF NOT EXISTS] <name> [TYPE = <type>] [<formatTypeOptions>] [COMMENT = '<s>']`
//! - `ALTER FILE FORMAT [IF EXISTS] <name> { RENAME TO <new> | SET <formatTypeOptions> }`
//!
//! DROP FILE FORMAT routes through the generic `AstStmt::Drop` parser
//! (the `FILE FORMAT` compound is registered in `sql_stmt.rs`).
//!
//! Token reference:
//! - FILE / FORMAT / TYPE / COMMENT / COMPRESSION / TEMP / TEMPORARY /
//!   VOLATILE / RENAME / TO / SET are Keywords; underscored option names
//!   (FIELD_DELIMITER, NULL_IF, …) and bare enum values (CSV, GZIP) are
//!   Identifiers
//! - property pairs are space-separated (no comma between pairs); commas
//!   appear only inside `( … )` value lists — handled by the shared walker

use crate::ast::AstStmt;
use crate::ast::{AstAlterFileFormat, AstAlterFileFormatActionKind, AstCreateFileFormat};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::snowflake_account_ddl::walk_object_properties;

impl<'a> Parser<'a> {
    /// Parse CREATE FILE FORMAT statement.
    pub(crate) fn try_parse_create_file_format(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_file_format")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        // Optional OR REPLACE
        let or_replace_span = self.parse_optional_or_replace()?;

        // Optional { TEMP | TEMPORARY | VOLATILE }
        let (transient_span, volatile) = match self.peek_non_trivia() {
            Some(tok)
                if matches!(
                    tok.kind,
                    TokenKind::Keyword(Keyword::Temp)
                        | TokenKind::Keyword(Keyword::Temporary)
                        | TokenKind::Keyword(Keyword::Volatile)
                ) =>
            {
                let t = self
                    .advance()
                    .expect_invariant("transience keyword after peek");
                let is_volatile = matches!(t.kind, TokenKind::Keyword(Keyword::Volatile));
                (Some(t.span), is_volatile)
            }
            _ => (None, false),
        };

        // FILE FORMAT (both Keywords)
        let file_format_span = self.expect_file_format_keywords()?;

        // Optional IF NOT EXISTS
        let if_not_exists_span = self.parse_optional_if_not_exists()?;

        // Name (may be qualified)
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Property bag: TYPE / COMPRESSION / format options / COMMENT
        let properties = walk_object_properties(self);
        if let Some(last) = properties.last() {
            end = last.value_span.map(|v| v.end).unwrap_or(last.name_span.end);
        }

        let stmt_span = Span {
            start: create_span.start,
            end,
        };

        let ast = AstCreateFileFormat {
            node_id: self.id_gen.next(),
            span: stmt_span,
            create_span,
            or_replace_span,
            transient_span,
            volatile,
            file_format_span,
            if_not_exists_span,
            name_span,
            properties,
        };
        Ok(AstStmt::CreateFileFormat(Box::new(ast)))
    }

    /// Parse ALTER FILE FORMAT statement.
    pub(crate) fn try_parse_alter_file_format(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_file_format")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // FILE FORMAT
        let file_format_span = self.expect_file_format_keywords()?;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Name
        let name_span = self.parse_qualified_name_span()?;

        // Action
        let action = match self.parse_alter_file_format_action() {
            Ok(a) => a,
            Err(e) => {
                return Err(e);
            }
        };
        let action_span = match &action {
            AstAlterFileFormatActionKind::RenameTo {
                rename_span,
                new_name_span,
                ..
            } => Span {
                start: rename_span.start,
                end: new_name_span.end,
            },
            AstAlterFileFormatActionKind::Set {
                set_span,
                properties,
            } => Span {
                start: set_span.start,
                end: properties
                    .last()
                    .map(|p| p.value_span.map(|v| v.end).unwrap_or(p.name_span.end))
                    .unwrap_or(set_span.end),
            },
        };

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        let ast = AstAlterFileFormat {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            file_format_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterFileFormat(Box::new(ast)))
    }

    // ───────────────────────── helpers ─────────────────────────

    /// Consume the `FILE FORMAT` keyword pair, returning the covering span.
    fn expect_file_format_keywords(&mut self) -> ParseResult<Span> {
        let file_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FILE".to_string()])?;
        if !matches!(file_tok.kind, TokenKind::Keyword(Keyword::File)) {
            return Err(ParseError::new(
                file_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FILE keyword".to_string(),
                },
            ));
        }
        let format_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FORMAT".to_string()])?;
        if !matches!(format_tok.kind, TokenKind::Keyword(Keyword::Format)) {
            return Err(ParseError::new(
                format_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected FORMAT after FILE".to_string(),
                },
            ));
        }
        Ok(Span {
            start: file_tok.span.start,
            end: format_tok.span.end,
        })
    }

    /// Parse the ALTER FILE FORMAT action: `RENAME TO <new>` or `SET <props>`.
    fn parse_alter_file_format_action(&mut self) -> ParseResult<AstAlterFileFormatActionKind> {
        let action_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["RENAME or SET".to_string()])?;

        match &action_tok.kind {
            TokenKind::Keyword(Keyword::Rename) => {
                self.advance(); // consume RENAME
                let rename_span = action_tok.span;
                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TO after RENAME".to_string(),
                        },
                    ));
                }
                let new_name_span = self.parse_qualified_name_span()?;
                Ok(AstAlterFileFormatActionKind::RenameTo {
                    rename_span,
                    to_span: Some(to_tok.span),
                    new_name_span,
                })
            }
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = action_tok.span;
                let properties = walk_object_properties(self);
                if properties.is_empty() {
                    return Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected format options after SET".to_string(),
                        },
                    ));
                }
                Ok(AstAlterFileFormatActionKind::Set {
                    set_span,
                    properties,
                })
            }
            _ => Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected RENAME or SET".to_string(),
                },
            )),
        }
    }
}
