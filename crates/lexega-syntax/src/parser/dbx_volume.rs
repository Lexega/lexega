// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for Databricks Unity Catalog VOLUME DDL statements.
//!
//! - `CREATE [EXTERNAL] VOLUME [IF NOT EXISTS] name [LOCATION path] [COMMENT comment]`
//! - `ALTER VOLUME name { RENAME TO new | [SET] OWNER TO principal | SET TAGS (...) | UNSET TAGS (...) }`
//! - `DROP VOLUME [IF EXISTS] name`
//!
//! Token reference (--debug-tokens --dialect bigquery):
//!   VOLUME   → Identifier (NOT Keyword)
//!   EXTERNAL → Identifier
//!   LOCATION → Identifier
//!   TAGS     → Identifier
//!   COMMENT  → Keyword(Comment)
//!   SET      → Keyword(Set)
//!   UNSET    → Keyword(Unset)
//!   OWNER    → Keyword(Owner)
//!   TO       → Keyword(To)
//!   RENAME   → Keyword(Rename)
//!   IF       → Keyword(If)
//!   NOT      → Keyword(Not)
//!   EXISTS   → Keyword(Exists)

use crate::ast::types::{
    AlterVolumeActionKind, AstAlterVolume, AstCreateVolume, AstDropVolume, AstStmt,
    AstStorageLocation,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // CREATE [EXTERNAL] VOLUME [IF NOT EXISTS] name [LOCATION path] [COMMENT comment]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_volume(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_volume")?;
        let start = self.current_span().start;

        // CREATE (already peeked by dispatcher, consume it)
        let _create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;

        let or_replace_span = self.parse_optional_or_replace()?;

        // Check for optional EXTERNAL
        let mut is_external = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("EXTERNAL")
            {
                self.advance(); // consume EXTERNAL
                is_external = true;
            }
        }

        // VOLUME (Identifier, NOT Keyword)
        let volume_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VOLUME".to_string()])?;
        if !volume_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("VOLUME")
        {
            return Err(ParseError::new(
                volume_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected VOLUME, found '{}'",
                        volume_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // Volume name (required, possibly qualified: catalog.schema.volume)
        let volume_name_span = self.parse_qualified_name_span()?;
        let mut end = volume_name_span.end;

        // Parse optional clauses: LOCATION (Databricks), STORAGE_LOCATIONS (Snowflake),
        // ALLOW_WRITES (Snowflake), COMMENT (both).
        let mut location_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut storage_locations_span: Option<Span> = None;
        let mut storage_locations: Vec<AstStorageLocation> = Vec::new();
        let mut allow_writes: Option<bool> = None;

        while let Some(tok) = self.peek_non_trivia() {
            // Check for statement boundary
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            let lex = tok.lexeme(self.source);

            if matches!(tok.kind, TokenKind::Identifier { .. })
                && lex.eq_ignore_ascii_case("LOCATION")
            {
                let loc_start = tok.span.start;
                self.advance(); // consume LOCATION
                                // Eat the string literal
                let val_tok = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["location path string".to_string()],
                )?;
                let loc_end = val_tok.span.end;
                location_span = Some(Span {
                    start: loc_start,
                    end: loc_end,
                });
                end = loc_end;
            } else if matches!(tok.kind, TokenKind::Identifier { .. })
                && lex.eq_ignore_ascii_case("STORAGE_LOCATIONS")
            {
                // Snowflake: STORAGE_LOCATIONS = ( (<loc>) [, (<loc>)]* )
                let storage_start = tok.span.start;
                self.advance(); // consume STORAGE_LOCATIONS
                                // Expect '='
                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    return Err(ParseError::new(
                        eq_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected '=' after STORAGE_LOCATIONS".to_string(),
                        },
                    ));
                }
                let (body_span, locations) = self.parse_storage_locations()?;
                storage_locations = locations;
                storage_locations_span = Some(Span {
                    start: storage_start,
                    end: body_span.end,
                });
                end = body_span.end;
            } else if matches!(tok.kind, TokenKind::Identifier { .. })
                && lex.eq_ignore_ascii_case("ALLOW_WRITES")
            {
                // Snowflake: ALLOW_WRITES = TRUE | FALSE.
                self.advance(); // consume ALLOW_WRITES
                let eq_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    return Err(ParseError::new(
                        eq_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected '=' after ALLOW_WRITES".to_string(),
                        },
                    ));
                }
                let val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                let val_lex = val_tok.lexeme(self.source);
                if val_lex.eq_ignore_ascii_case("TRUE") {
                    allow_writes = Some(true);
                } else if val_lex.eq_ignore_ascii_case("FALSE") {
                    allow_writes = Some(false);
                }
                end = val_tok.span.end;
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let com_start = tok.span.start;
                self.advance(); // consume COMMENT
                let val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                let com_end = val_tok.span.end;
                comment_span = Some(Span {
                    start: com_start,
                    end: com_end,
                });
                end = com_end;
            } else {
                // Unknown clause — stop parsing
                break;
            }
        }

        let span = Span { start, end };

        let ast = AstCreateVolume {
            node_id: self.id_gen.next(),
            span,
            is_external,
            if_not_exists,
            or_replace_span,
            volume_name_span,
            location_span,
            comment_span,
            storage_locations_span,
            storage_locations,
            allow_writes,
        };
        Ok(AstStmt::CreateVolume(Box::new(ast)))
    }

    /// Parse a Snowflake `STORAGE_LOCATIONS` body `( (<loc>) [, (<loc>)]* )`.
    /// Cursor must be at the outer `(`. Returns the body span and the typed
    /// per-location entries. Permissive: unexpected tokens are consumed.
    fn parse_storage_locations(&mut self) -> ParseResult<(Span, Vec<AstStorageLocation>)> {
        let open = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(open.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                open.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '(' after STORAGE_LOCATIONS =".to_string(),
                },
            ));
        }
        let start = open.span.start;
        let mut end = open.span.end;
        let mut locations = Vec::new();
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                if let Some(t) = self.advance() {
                    end = t.span.end;
                }
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let loc = self.parse_one_storage_location()?;
                end = loc.full_span.end;
                locations.push(loc);
                continue;
            }
            // Unexpected token inside the list — consume to make progress.
            if let Some(t) = self.advance() {
                end = t.span.end;
            }
        }
        Ok((Span { start, end }, locations))
    }

    /// Parse one `( NAME = … STORAGE_PROVIDER = … )` storage-location bag.
    /// Cursor must be at the location's opening `(`. Each property value is a
    /// single token except `ENCRYPTION`, whose `TYPE` is pulled out.
    fn parse_one_storage_location(&mut self) -> ParseResult<AstStorageLocation> {
        let open = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        let start = open.span.start;
        let mut loc = AstStorageLocation {
            full_span: open.span,
            name_span: None,
            provider_span: None,
            base_url_span: None,
            role_arn_span: None,
            external_id_span: None,
            encryption_type_span: None,
        };
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                if let Some(t) = self.advance() {
                    loc.full_span = Span {
                        start,
                        end: t.span.end,
                    };
                }
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }
            // Property: <name> [= <value>].
            let Some(name_tok) = self.advance() else {
                break;
            };
            let name_upper = self
                .source
                .get(name_tok.span.start as usize..name_tok.span.end as usize)
                .unwrap_or("")
                .to_ascii_uppercase();
            let has_eq = matches!(
                self.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq))
            );
            if !has_eq {
                continue; // value-less keyword — tolerate
            }
            self.advance(); // consume '='
            let is_paren_value = matches!(
                self.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
            );
            if is_paren_value {
                // `ENCRYPTION = (TYPE = '…' …)` — pull out TYPE.
                let enc_type = self.parse_encryption_type()?;
                if name_upper == "ENCRYPTION" {
                    loc.encryption_type_span = enc_type;
                }
            } else if let Some(val_tok) = self.advance() {
                let v = val_tok.span;
                match name_upper.as_str() {
                    "NAME" => loc.name_span = Some(v),
                    "STORAGE_PROVIDER" => loc.provider_span = Some(v),
                    "STORAGE_BASE_URL" => loc.base_url_span = Some(v),
                    "STORAGE_AWS_ROLE_ARN" => loc.role_arn_span = Some(v),
                    "STORAGE_AWS_EXTERNAL_ID" => loc.external_id_span = Some(v),
                    _ => {}
                }
            }
        }
        Ok(loc)
    }

    /// Parse `( TYPE = '…' [KMS_KEY_ID = '…'] )` after `ENCRYPTION =`.
    /// Cursor must be at the opening `(`. Returns the `TYPE` value span.
    fn parse_encryption_type(&mut self) -> ParseResult<Option<Span>> {
        let _open = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        let mut type_span = None;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                self.advance();
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }
            let Some(name_tok) = self.advance() else {
                break;
            };
            let name_upper = self
                .source
                .get(name_tok.span.start as usize..name_tok.span.end as usize)
                .unwrap_or("")
                .to_ascii_uppercase();
            let has_eq = matches!(
                self.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq))
            );
            if !has_eq {
                continue;
            }
            self.advance(); // consume '='
            let is_paren_value = matches!(
                self.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
            );
            if is_paren_value {
                let _ = self.consume_balanced_parens()?;
            } else if let Some(val_tok) = self.advance() {
                if name_upper == "TYPE" {
                    type_span = Some(val_tok.span);
                }
            }
        }
        Ok(type_span)
    }

    // -----------------------------------------------------------------------
    // ALTER VOLUME name { RENAME TO new | [SET] OWNER TO principal | SET TAGS (...) | UNSET TAGS (...) }
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_alter_volume(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_volume")?;
        let start = self.current_span().start;

        // ALTER
        let _alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;

        // VOLUME (Identifier)
        let volume_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VOLUME".to_string()])?;
        if !volume_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("VOLUME")
        {
            return Err(ParseError::new(
                volume_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected VOLUME, found '{}'",
                        volume_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Volume name (required, possibly qualified)
        let volume_name_span = self.parse_qualified_name_span()?;

        // Parse the action
        let action_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ALTER VOLUME action (RENAME, SET, UNSET, OWNER)".to_string(),
                },
            )
        })?;

        let action_start = action_tok.span.start;
        let action_lex = action_tok.lexeme(self.source);
        let (action_kind, end) = if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            self.advance(); // consume RENAME
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
            let new_name_span = self.parse_qualified_name_span()?;
            (AlterVolumeActionKind::RenameTo, new_name_span.end)
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
            // OWNER TO principal (without SET)
            self.advance(); // consume OWNER
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
            let principal_span = self.parse_qualified_name_span()?;
            (AlterVolumeActionKind::OwnerTo, principal_span.end)
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            // SET OWNER TO principal | SET TAGS (...)
            self.advance(); // consume SET

            let next_tok = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected OWNER or TAGS after SET".to_string(),
                    },
                )
            })?;

            let next_lex = next_tok.lexeme(self.source);

            if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
                // SET OWNER TO principal
                self.advance(); // consume OWNER
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
                let principal_span = self.parse_qualified_name_span()?;
                (AlterVolumeActionKind::OwnerTo, principal_span.end)
            } else if matches!(next_tok.kind, TokenKind::Identifier { .. })
                && next_lex.eq_ignore_ascii_case("TAGS")
            {
                // SET TAGS ('key' = 'val', ...)
                self.advance(); // consume TAGS
                let action_end = self.consume_parenthesized_block()?;
                (AlterVolumeActionKind::SetTags, action_end)
            } else {
                return Err(ParseError::new(
                    next_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!("Expected OWNER or TAGS after SET, found '{}'", next_lex),
                    },
                ));
            }
        } else if matches!(action_tok.kind, TokenKind::Keyword(Keyword::Unset)) {
            // UNSET TAGS ('key', ...)
            self.advance(); // consume UNSET

            let tags_tok = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected TAGS after UNSET".to_string(),
                    },
                )
            })?;

            if matches!(tags_tok.kind, TokenKind::Identifier { .. })
                && tags_tok.lexeme(self.source).eq_ignore_ascii_case("TAGS")
            {
                self.advance(); // consume TAGS
                let action_end = self.consume_parenthesized_block()?;
                (AlterVolumeActionKind::UnsetTags, action_end)
            } else {
                return Err(ParseError::new(
                    tags_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected TAGS after UNSET, found '{}'",
                            tags_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Unexpected ALTER VOLUME action: '{}'", action_lex),
                },
            ));
        };

        let action_span = Span {
            start: action_start,
            end,
        };

        let span = Span { start, end };

        let ast = AstAlterVolume {
            node_id: self.id_gen.next(),
            span,
            volume_name_span,
            action_kind,
            action_span,
        };
        Ok(AstStmt::AlterVolume(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DROP VOLUME [IF EXISTS] name
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_drop_volume(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_volume")?;
        let start = self.current_span().start;

        // DROP
        let _drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;

        // VOLUME (Identifier)
        let volume_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VOLUME".to_string()])?;
        if !volume_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("VOLUME")
        {
            return Err(ParseError::new(
                volume_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected VOLUME, found '{}'",
                        volume_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF EXISTS
        let if_exists = self.parse_optional_if_exists()?.is_some();

        // Volume name (required, possibly qualified)
        let volume_name_span = self.parse_qualified_name_span()?;
        let end = volume_name_span.end;

        let span = Span { start, end };

        let ast = AstDropVolume {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            volume_name_span,
        };
        Ok(AstStmt::DropVolume(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // Helper: consume balanced parenthesized block, return the end position.
    // -----------------------------------------------------------------------

    fn consume_parenthesized_block(&mut self) -> ParseResult<u32> {
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected '(', found '{}'", lparen.lexeme(self.source)),
                },
            ));
        }

        let mut depth: u32 = 1;
        loop {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(tok.span.end);
                    }
                }
                TokenKind::Eof => {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Unexpected EOF inside parenthesized block".to_string(),
                        },
                    ));
                }
                _ => {} // consume everything inside
            }
        }
    }
}
