// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Databricks Unity Catalog `CREATE EXTERNAL LOCATION` statement.
//!
//! Syntax:
//!   `CREATE EXTERNAL LOCATION [IF NOT EXISTS] location_name`
//!   `  URL url_str`
//!   `  WITH (STORAGE CREDENTIAL credential_name)`
//!   `  [COMMENT comment]`
//!
//! Token reference (--debug-tokens --dialect databricks):
//!   CREATE     → Keyword(Create)
//!   EXTERNAL   → Identifier (NOT Keyword)
//!   LOCATION   → Identifier (NOT Keyword)
//!   IF         → Keyword(If)
//!   NOT        → Keyword(Not)
//!   EXISTS     → Keyword(Exists)
//!   URL        → Keyword(Url)
//!   url_str    → Literal(String)
//!   WITH       → Keyword(With)
//!   (          → Punctuation(LParen)
//!   STORAGE    → Keyword(Storage)
//!   CREDENTIAL → Identifier (NOT Keyword — singular, not Credentials)
//!   cred_name  → Identifier (unquoted or backtick-quoted)
//!   )          → Punctuation(RParen)
//!   COMMENT    → Keyword(Comment)
//!   comment    → Literal(String)

use crate::ast::types::{
    AlterExternalLocationAction, AstAlterExternalLocation, AstCreateExternalLocation,
    AstDropExternalLocation, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse `CREATE EXTERNAL LOCATION [IF NOT EXISTS] name URL '...' WITH (STORAGE CREDENTIAL cred) [COMMENT '...']`
    ///
    /// Called from `try_parse_stmt()` after dispatcher identifies `CREATE EXTERNAL LOCATION`.
    /// Position: at CREATE token (saved_idx points here).
    pub(crate) fn try_parse_create_external_location(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_external_location")?;
        let start = self.current_span().start;

        // CREATE
        let _create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;

        // EXTERNAL (Identifier)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !external_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected EXTERNAL, found '{}'",
                        external_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // LOCATION (Identifier)
        let location_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOCATION".to_string()])?;
        if !location_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("LOCATION")
        {
            return Err(ParseError::new(
                location_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected LOCATION, found '{}'",
                        location_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // Location name (required — possibly backtick-quoted, possibly qualified)
        let location_name_span = self.parse_qualified_name_span()?;

        // URL keyword (required)
        let url_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["URL".to_string()])?;
        if !matches!(url_kw_tok.kind, TokenKind::Keyword(Keyword::Url)) {
            return Err(ParseError::new(
                url_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected URL keyword, found '{}'",
                        url_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let url_keyword_span = url_kw_tok.span;

        // URL string literal (required)
        let url_val_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["URL string literal".to_string()])?;
        let url_value_span = url_val_tok.span;

        // WITH keyword (required)
        let with_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
        if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
            return Err(ParseError::new(
                with_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected WITH keyword, found '{}'",
                        with_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let with_keyword_span = with_tok.span;

        // ( — opening paren
        let lparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected '(' after WITH, found '{}'",
                        lparen_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let clause_start = lparen_tok.span.start;

        // STORAGE keyword
        let storage_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["STORAGE".to_string()])?;
        if !matches!(storage_tok.kind, TokenKind::Keyword(Keyword::Storage)) {
            return Err(ParseError::new(
                storage_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected STORAGE keyword, found '{}'",
                        storage_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // CREDENTIAL (Identifier, NOT Keyword)
        let cred_kw_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
        if !cred_kw_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CREDENTIAL")
        {
            return Err(ParseError::new(
                cred_kw_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CREDENTIAL, found '{}'",
                        cred_kw_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // credential_name (required — Identifier, possibly backtick-quoted or qualified)
        let credential_name_span = self.parse_qualified_name_span()?;

        // ) — closing paren
        let rparen_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ')' after credential name, found '{}'",
                        rparen_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let storage_credential_clause_span = Span {
            start: clause_start,
            end: rparen_tok.span.end,
        };
        let mut end = rparen_tok.span.end;

        // Optional COMMENT clause
        let mut comment_keyword_span: Option<Span> = None;
        let mut comment_value_span: Option<Span> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let com_kw = self.advance().unwrap();
                comment_keyword_span = Some(com_kw.span);

                let com_val = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["comment string".to_string()])?;
                comment_value_span = Some(com_val.span);
                end = com_val.span.end;
            }
        }

        let span = Span { start, end };

        let ast = AstCreateExternalLocation {
            node_id: self.id_gen.next(),
            span,
            if_not_exists,
            location_name_span,
            url_keyword_span,
            url_value_span,
            with_keyword_span,
            storage_credential_clause_span,
            credential_name_span,
            comment_keyword_span,
            comment_value_span,
        };
        Ok(AstStmt::CreateExternalLocation(Box::new(ast)))
    }

    // =========================================================================
    // ALTER EXTERNAL LOCATION
    // =========================================================================
    //
    // Syntax (Databricks docs):
    //   ALTER EXTERNAL LOCATION location_name
    //     { RENAME TO to_location_name
    //     | SET URL url_str [ FORCE ]
    //     | SET STORAGE CREDENTIAL credential_name
    //     | [ SET ] OWNER TO principal }
    //
    // Token reference (--debug-tokens --dialect databricks):
    //   ALTER      → Keyword(Alter)
    //   EXTERNAL   → Identifier (NOT Keyword)
    //   LOCATION   → Identifier (NOT Keyword)
    //   RENAME     → Keyword(Rename)
    //   TO         → Keyword(To)
    //   SET        → Keyword(Set)
    //   URL        → Keyword(Url)
    //   STORAGE    → Keyword(Storage)
    //   CREDENTIAL → Identifier (NOT Keyword)
    //   OWNER      → Keyword(Owner)
    //   FORCE      → Identifier (NOT Keyword)

    pub(crate) fn try_parse_alter_external_location(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_external_location")?;
        let start = self.current_span().start;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // EXTERNAL (Identifier)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !external_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected EXTERNAL, found '{}'",
                        external_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let external_span = external_tok.span;

        // LOCATION (Identifier)
        let location_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOCATION".to_string()])?;
        if !location_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("LOCATION")
        {
            return Err(ParseError::new(
                location_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected LOCATION, found '{}'",
                        location_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let location_kw_span = location_tok.span;

        // Location name (required — possibly backtick-quoted, possibly qualified)
        let location_name_span = self.parse_qualified_name_span()?;

        // Parse action clause
        let next_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::unexpected_eof(
                self.current_span(),
                vec!["RENAME".to_string(), "SET".to_string(), "OWNER".to_string()],
            )
        })?;

        let (action, end) = if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            // RENAME TO new_name
            let rename_tok = self.advance().unwrap(); // consume RENAME
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
            (
                AlterExternalLocationAction::RenameTo {
                    rename_span: rename_tok.span,
                    to_span: to_tok.span,
                    new_name_span,
                },
                new_name_span.end,
            )
        } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
            // OWNER TO principal (without SET prefix)
            let owner_tok = self.advance().unwrap(); // consume OWNER
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
            let owner_name_span = self.parse_qualified_name_span()?;
            (
                AlterExternalLocationAction::OwnerTo {
                    set_span: None,
                    owner_span: owner_tok.span,
                    to_span: to_tok.span,
                    owner_name_span,
                },
                owner_name_span.end,
            )
        } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            // SET URL | SET STORAGE CREDENTIAL | SET OWNER TO
            let set_tok = self.advance().unwrap(); // consume SET
            let set_span = set_tok.span;

            let set_target = self.peek_non_trivia().ok_or_else(|| {
                ParseError::unexpected_eof(
                    self.current_span(),
                    vec![
                        "URL".to_string(),
                        "STORAGE".to_string(),
                        "OWNER".to_string(),
                    ],
                )
            })?;

            if matches!(set_target.kind, TokenKind::Keyword(Keyword::Url)) {
                // SET URL 'url' [FORCE]
                let url_kw_tok = self.advance().unwrap(); // consume URL
                let url_val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["URL string literal".to_string()])?;
                let url_value_span = url_val_tok.span;
                let mut end = url_val_tok.span.end;

                // Optional FORCE (Identifier, NOT Keyword)
                let force_span = if let Some(force_tok) = self.peek_non_trivia() {
                    if matches!(force_tok.kind, TokenKind::Identifier { .. })
                        && force_tok.lexeme(self.source).eq_ignore_ascii_case("FORCE")
                    {
                        let f = self.advance().unwrap();
                        end = f.span.end;
                        Some(f.span)
                    } else {
                        None
                    }
                } else {
                    None
                };
                (
                    AlterExternalLocationAction::SetUrl {
                        set_span,
                        url_kw_span: url_kw_tok.span,
                        url_value_span,
                        force_span,
                    },
                    end,
                )
            } else if matches!(set_target.kind, TokenKind::Keyword(Keyword::Storage)) {
                // SET STORAGE CREDENTIAL credential_name
                let storage_tok = self.advance().unwrap(); // consume STORAGE

                // CREDENTIAL (Identifier)
                let cred_kw_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CREDENTIAL".to_string()])?;
                if !cred_kw_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("CREDENTIAL")
                {
                    return Err(ParseError::new(
                        cred_kw_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected CREDENTIAL, found '{}'",
                                cred_kw_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                let credential_name_span = self.parse_qualified_name_span()?;
                (
                    AlterExternalLocationAction::SetStorageCredential {
                        set_span,
                        storage_span: storage_tok.span,
                        credential_kw_span: cred_kw_tok.span,
                        credential_name_span,
                    },
                    credential_name_span.end,
                )
            } else if matches!(set_target.kind, TokenKind::Keyword(Keyword::Owner)) {
                // SET OWNER TO principal
                let owner_tok = self.advance().unwrap(); // consume OWNER
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
                let owner_name_span = self.parse_qualified_name_span()?;
                (
                    AlterExternalLocationAction::OwnerTo {
                        set_span: Some(set_span),
                        owner_span: owner_tok.span,
                        to_span: to_tok.span,
                        owner_name_span,
                    },
                    owner_name_span.end,
                )
            } else {
                return Err(ParseError::new(
                    set_target.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected URL, STORAGE, or OWNER after SET, found '{}'",
                            set_target.lexeme(self.source)
                        ),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                next_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected RENAME, SET, or OWNER in ALTER EXTERNAL LOCATION, found '{}'",
                        next_tok.lexeme(self.source)
                    ),
                },
            ));
        };

        let span = Span { start, end };
        let ast = AstAlterExternalLocation {
            node_id: self.id_gen.next(),
            span,
            alter_span,
            external_span,
            location_kw_span,
            location_name_span,
            action,
        };
        Ok(AstStmt::AlterExternalLocation(Box::new(ast)))
    }

    // =========================================================================
    // DROP EXTERNAL LOCATION
    // =========================================================================
    //
    // Syntax (Databricks docs):
    //   DROP EXTERNAL LOCATION [ IF EXISTS ] location_name
    //
    // Token reference (--debug-tokens --dialect databricks):
    //   DROP       → Keyword(Drop)
    //   EXTERNAL   → Identifier (NOT Keyword)
    //   LOCATION   → Identifier (NOT Keyword)
    //   IF         → Keyword(If)
    //   EXISTS     → Keyword(Exists)

    pub(crate) fn try_parse_drop_external_location(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_external_location")?;
        let start = self.current_span().start;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;

        // EXTERNAL (Identifier)
        let external_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        if !external_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("EXTERNAL")
        {
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected EXTERNAL, found '{}'",
                        external_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let external_span = external_tok.span;

        // LOCATION (Identifier)
        let location_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOCATION".to_string()])?;
        if !location_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("LOCATION")
        {
            return Err(ParseError::new(
                location_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected LOCATION, found '{}'",
                        location_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let location_kw_span = location_tok.span;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Location name (required)
        let location_name_span = self.parse_qualified_name_span()?;
        let end = location_name_span.end;

        let span = Span { start, end };
        let ast = AstDropExternalLocation {
            node_id: self.id_gen.next(),
            span,
            drop_span,
            external_span,
            location_kw_span,
            if_exists_span,
            location_name_span,
        };
        Ok(AstStmt::DropExternalLocation(Box::new(ast)))
    }
}
