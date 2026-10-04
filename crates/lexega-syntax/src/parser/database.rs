// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DATABASE statement parsing (CREATE, ALTER, DROP, UNDROP)
//!
//! DATABASE is Identifier, NOT Keyword.
//! Must use lexeme matching with eq_ignore_ascii_case().

use crate::ast::{
    AstAlterDatabase, AstAlterDatabaseAction, AstAlterDatabaseActionKind, AstCreateDatabase,
    AstCreateDatabaseVariant, AstDropDatabase, AstStmt, AstUndropDatabase, AstUnknownClause,
    UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse CREATE DATABASE statement.
    ///
    /// Dispatcher resets idx before calling - we MUST consume CREATE.
    pub(crate) fn try_parse_create_database(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_database")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        // Optional OR REPLACE
        let or_replace_span = self.parse_optional_or_replace()?;

        // Optional TRANSIENT
        let transient_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Transient)) {
                let t = self
                    .advance()
                    .expect_invariant("TRANSIENT keyword consumed after match");
                Some(t.span)
            } else {
                None
            }
        } else {
            None
        };

        // DATABASE (Identifier, NOT Keyword!)
        let database_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DATABASE".to_string()])?;

        if !matches!(database_tok.kind, TokenKind::Identifier { .. })
            || !database_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("DATABASE")
        {
            return Err(ParseError::new(
                database_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATABASE, found '{}'",
                        database_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let database_span = database_tok.span;

        // Optional IF NOT EXISTS
        let if_not_exists_span = self.parse_optional_if_not_exists()?;

        // Database name (required) - handles qualified names
        let name_span = self.parse_qualified_name_span()?;

        // Parse variant and remaining clauses
        let mut extras: Vec<AstUnknownClause> = Vec::new();
        let mut comment_span: Option<Span> = None;
        let mut tag_span: Option<Span> = None;

        let variant = self.parse_create_database_variant(&mut extras)?;

        // Parse properties AFTER variant (CLONE and AS REPLICA allow properties)
        // FROM SHARE/FROM LISTING/FROM BACKUP do NOT allow properties
        let properties_span = match &variant {
            AstCreateDatabaseVariant::Standard
            | AstCreateDatabaseVariant::Clone { .. }
            | AstCreateDatabaseVariant::AsReplica { .. } => {
                self.parse_database_properties(&mut extras)?
            }
            _ => None,
        };

        // Parse trailing COMMENT and TAG
        self.parse_database_trailing_clauses(&mut comment_span, &mut tag_span)?;

        // Calculate final span
        let mut span_end = name_span.end;
        if let Some(s) = &properties_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &comment_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &tag_span {
            span_end = span_end.max(s.end);
        }
        for extra in &extras {
            span_end = span_end.max(extra.span.end);
        }
        // Check variant spans
        match &variant {
            AstCreateDatabaseVariant::Standard => {}
            AstCreateDatabaseVariant::Clone {
                source_span,
                time_travel,
                ignore_tables_span,
                ..
            } => {
                span_end = span_end.max(source_span.end);
                if let Some(tt) = time_travel {
                    let tt_end = match tt.as_ref() {
                        crate::ast::AstTimeTravelClause::SnowflakeAtBefore(at) => at.span.end,
                        crate::ast::AstTimeTravelClause::ForSystemTime(fst) => fst.span.end,
                        crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx) => dbx.span.end,
                    };
                    span_end = span_end.max(tt_end);
                }
                if let Some(s) = ignore_tables_span {
                    span_end = span_end.max(s.end);
                }
            }
            AstCreateDatabaseVariant::FromShare {
                share_name_span, ..
            } => {
                span_end = span_end.max(share_name_span.end);
            }
            AstCreateDatabaseVariant::FromListing {
                listing_name_span, ..
            } => {
                span_end = span_end.max(listing_name_span.end);
            }
            AstCreateDatabaseVariant::AsReplica { source_db_span, .. } => {
                span_end = span_end.max(source_db_span.end);
            }
            AstCreateDatabaseVariant::FromBackup {
                backup_spec_span, ..
            } => {
                span_end = span_end.max(backup_spec_span.end);
            }
        }

        let span = Span {
            start: create_span.start,
            end: span_end,
        };

        Ok(AstStmt::CreateDatabase(Box::new(AstCreateDatabase {
            node_id: self.id_gen.next(),
            span,
            create_span,
            or_replace_span,
            transient_span,
            database_span,
            if_not_exists_span,
            name_span,
            variant,
            properties_span,
            comment_span,
            tag_span,
            extras,
        })))
    }

    /// Parse the CREATE DATABASE variant (CLONE, FROM SHARE, etc.)
    fn parse_create_database_variant(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<AstCreateDatabaseVariant> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => {
                return Ok(AstCreateDatabaseVariant::Standard);
            }
        };

        // CLONE variant
        if tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") {
            let clone_tok = self
                .advance()
                .expect_invariant("CLONE identifier consumed after lexeme match");
            let clone_span = clone_tok.span;

            let source_span = self.parse_qualified_name_span()?;

            // Optional AT/BEFORE time travel
            let time_travel = self
                .parse_time_travel()?
                .map(|tt| Box::new(crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt)));

            // Optional IGNORE TABLES WITH INSUFFICIENT DATA RETENTION
            let ignore_tables_span = self.parse_ignore_tables_clause()?;

            return Ok(AstCreateDatabaseVariant::Clone {
                clone_span,
                source_span,
                time_travel,
                ignore_tables_span,
            });
        }

        // FROM SHARE / FROM LISTING / FROM BACKUP
        if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
            let from_tok = self
                .advance()
                .expect_invariant("FROM keyword consumed after match");
            let from_start = from_tok.span.start;

            let next = self.peek_non_trivia().ok_or_eof(
                self.current_span(),
                vec!["SHARE, LISTING, or BACKUP".to_string()],
            )?;

            if next.lexeme(self.source).eq_ignore_ascii_case("SHARE") {
                let share_tok = self
                    .advance()
                    .expect_invariant("SHARE identifier consumed after lexeme match");
                let from_share_span = Span {
                    start: from_start,
                    end: share_tok.span.end,
                };
                let share_name_span = self.parse_qualified_name_span()?;

                return Ok(AstCreateDatabaseVariant::FromShare {
                    from_share_span,
                    share_name_span,
                });
            }

            if next.lexeme(self.source).eq_ignore_ascii_case("LISTING") {
                let listing_tok = self
                    .advance()
                    .expect_invariant("LISTING identifier consumed after lexeme match");
                let from_listing_span = Span {
                    start: from_start,
                    end: listing_tok.span.end,
                };
                // Listing name (string literal)
                let listing_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["listing_name".to_string()])?;
                let listing_name_span = listing_tok.span;

                return Ok(AstCreateDatabaseVariant::FromListing {
                    from_listing_span,
                    listing_name_span,
                });
            }

            if next.lexeme(self.source).eq_ignore_ascii_case("BACKUP") {
                let backup_tok = self
                    .advance()
                    .expect_invariant("BACKUP identifier consumed after lexeme match");
                let from_backup_span = Span {
                    start: from_start,
                    end: backup_tok.span.end,
                };
                // Consume remaining backup specification until statement end
                let backup_end = self.consume_until_semi_or_eof()?;
                let backup_spec_span = Span {
                    start: backup_tok.span.end,
                    end: backup_end,
                };

                return Ok(AstCreateDatabaseVariant::FromBackup {
                    from_backup_span,
                    backup_spec_span,
                });
            }

            // Unknown FROM variant - add as extra
            extras.push(AstUnknownClause {
                introducer: Some(from_tok.span),
                span: Span {
                    start: from_start,
                    end: next.span.end,
                },
                kind: UnknownKind::Clause,
                node_id: self.id_gen.next(),
            });
        }

        // AS REPLICA OF
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_tok = self
                .advance()
                .expect_invariant("AS keyword consumed after match");
            let as_start = as_tok.span.start;

            if let Some(next) = self.peek_non_trivia() {
                if next.lexeme(self.source).eq_ignore_ascii_case("REPLICA") {
                    #[allow(unused_variables)]
                    let replica_tok = self
                        .advance()
                        .expect_invariant("REPLICA identifier consumed after lexeme match");

                    // Expect OF
                    let of_tok = self
                        .peek_non_trivia()
                        .ok_or_eof(self.current_span(), vec!["OF".to_string()])?;
                    if matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
                        self.advance();
                    }

                    let as_replica_span = Span {
                        start: as_start,
                        end: self.previous_span_end(),
                    };

                    let source_db_span = self.parse_qualified_name_span()?;

                    return Ok(AstCreateDatabaseVariant::AsReplica {
                        as_replica_span,
                        source_db_span,
                    });
                }
            }
        }

        // Standard variant - no special clause
        Ok(AstCreateDatabaseVariant::Standard)
    }

    /// Parse DROP DATABASE statement.
    pub(crate) fn try_parse_drop_database(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_database")?;

        // DROP already peeked but not consumed - consume it
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;

        // DATABASE
        let database_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DATABASE".to_string()])?;

        if !matches!(database_tok.kind, TokenKind::Identifier { .. })
            || !database_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("DATABASE")
        {
            return Err(ParseError::new(
                database_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATABASE, found '{}'",
                        database_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let database_span = database_tok.span;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Database name
        let name_span = self.parse_qualified_name_span()?;

        // Optional CASCADE or RESTRICT
        let cascade_restrict_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("CASCADE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("RESTRICT")
            {
                let t = self
                    .advance()
                    .expect_invariant("CASCADE/RESTRICT consumed after lexeme match");
                Some(t.span)
            } else {
                None
            }
        } else {
            None
        };

        let mut span_end = name_span.end;
        if let Some(s) = &cascade_restrict_span {
            span_end = s.end;
        }

        let span = Span {
            start: drop_span.start,
            end: span_end,
        };

        Ok(AstStmt::DropDatabase(Box::new(AstDropDatabase {
            node_id: self.id_gen.next(),
            span,
            drop_span,
            database_span,
            if_exists_span,
            name_span,
            cascade_restrict_span,
        })))
    }

    /// Parse UNDROP DATABASE statement.
    pub(crate) fn try_parse_undrop_database(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("undrop_database")?;

        // UNDROP (Identifier, not Keyword)
        let undrop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNDROP".to_string()])?;

        if !matches!(undrop_tok.kind, TokenKind::Identifier { .. })
            || !undrop_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("UNDROP")
        {
            return Err(ParseError::new(
                undrop_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected UNDROP, found '{}'",
                        undrop_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let undrop_span = undrop_tok.span;

        // DATABASE
        let database_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DATABASE".to_string()])?;

        if !matches!(database_tok.kind, TokenKind::Identifier { .. })
            || !database_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("DATABASE")
        {
            return Err(ParseError::new(
                database_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATABASE, found '{}'",
                        database_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let database_span = database_tok.span;

        // Database name
        let name_span = self.parse_qualified_name_span()?;

        let span = Span {
            start: undrop_span.start,
            end: name_span.end,
        };

        Ok(AstStmt::UndropDatabase(Box::new(AstUndropDatabase {
            node_id: self.id_gen.next(),
            span,
            undrop_span,
            database_span,
            name_span,
        })))
    }

    // ========== Helper functions for DATABASE/SCHEMA parsing ==========

    /// Parse OR REPLACE
    pub(crate) fn parse_optional_or_replace(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword consumed after match");
                let replace_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                if !matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    return Err(ParseError::new(
                        replace_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE after OR".to_string(),
                        },
                    ));
                }
                return Ok(Some(Span {
                    start: or_tok.span.start,
                    end: replace_tok.span.end,
                }));
            }
        }
        Ok(None)
    }

    /// Parse IF NOT EXISTS
    pub(crate) fn parse_optional_if_not_exists(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword consumed after match");
                let not_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::new(
                        not_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected NOT after IF".to_string(),
                        },
                    ));
                }
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF NOT".to_string(),
                        },
                    ));
                }
                return Ok(Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                }));
            }
        }
        Ok(None)
    }

    /// Parse IF EXISTS
    pub(crate) fn parse_optional_if_exists(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword consumed after match");
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF".to_string(),
                        },
                    ));
                }
                return Ok(Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                }));
            }
        }
        Ok(None)
    }

    /// Parse IGNORE TABLES WITH INSUFFICIENT DATA RETENTION clause
    pub(crate) fn parse_ignore_tables_clause(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("IGNORE") {
                let start = tok.span.start;
                self.advance(); // IGNORE

                // Consume: TABLES WITH INSUFFICIENT DATA RETENTION
                let mut end = tok.span.end;
                for expected in &["TABLES", "WITH", "INSUFFICIENT", "DATA", "RETENTION"] {
                    if let Some(t) = self.peek_non_trivia() {
                        if t.lexeme(self.source).eq_ignore_ascii_case(expected) {
                            end = t.span.end;
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                return Ok(Some(Span { start, end }));
            }
        }
        Ok(None)
    }

    /// MySQL CREATE DATABASE / CREATE SCHEMA tail:
    /// `[DEFAULT] {CHARACTER SET | CHARSET | COLLATE | ENCRYPTION} [=] value`.
    /// Consumes one such clause and returns its (start, end) byte bounds, or
    /// `None` (consuming nothing) when the cursor isn't at one.
    pub(crate) fn try_consume_mysql_charset_property(&mut self) -> ParseResult<Option<(u32, u32)>> {
        let Some(tok) = self.peek_non_trivia() else {
            return Ok(None);
        };
        let prop_start = tok.span.start;
        let lex_up_head = tok.lexeme(self.source).to_uppercase();
        let head_after_default = if lex_up_head == "DEFAULT" {
            self.peek_ahead(1)
                .map(|t| t.lexeme(self.source).to_uppercase())
        } else {
            None
        };
        let head = head_after_default
            .as_deref()
            .unwrap_or(lex_up_head.as_str());
        if !matches!(head, "CHARACTER" | "CHARSET" | "COLLATE" | "ENCRYPTION") {
            return Ok(None);
        }
        if lex_up_head == "DEFAULT" {
            self.advance(); // DEFAULT
        }
        let head_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![head.to_string()])?;
        let mut last_end = head_tok.span.end;
        if head == "CHARACTER" {
            if let Some(next) = self.peek_non_trivia() {
                if next.lexeme(self.source).eq_ignore_ascii_case("SET") {
                    let t = self
                        .advance()
                        .expect_invariant("SET consumed after CHARACTER peek");
                    last_end = t.span.end;
                }
            }
        }
        if let Some(next) = self.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                let t = self.advance().expect_invariant("= consumed after peek");
                last_end = t.span.end;
            }
        }
        // Charset/collation names are identifiers; ENCRYPTION takes 'Y'/'N'.
        if let Some(next) = self.peek_non_trivia() {
            if matches!(
                next.kind,
                TokenKind::Identifier { .. } | TokenKind::Literal(_)
            ) {
                let t = self.advance().expect_invariant("value consumed after peek");
                last_end = t.span.end;
            }
        }
        Ok(Some((prop_start, last_end)))
    }

    /// Parse database properties (DATA_RETENTION_TIME_IN_DAYS = value, etc.)
    fn parse_database_properties(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<Option<Span>> {
        let mut props_start: Option<u32> = None;
        let mut props_end: u32 = 0;

        while let Some(tok) = self.peek_non_trivia() {
            // Stop conditions
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment))
                || matches!(tok.kind, TokenKind::Keyword(Keyword::Tag))
                || tok.lexeme(self.source).eq_ignore_ascii_case("WITH")
            {
                break;
            }

            let prop_start = tok.span.start;

            if let Some((s, e)) = self.try_consume_mysql_charset_property()? {
                if props_start.is_none() {
                    props_start = Some(s);
                }
                props_end = e;
                continue;
            }

            // Check if this is a known property (match lexeme like session_policy.rs)
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex_up = tok.lexeme(self.source).to_uppercase();
                match lex_up.as_str() {
                    "DATA_RETENTION_TIME_IN_DAYS"
                    | "MAX_DATA_EXTENSION_TIME_IN_DAYS"
                    | "EXTERNAL_VOLUME"
                    | "CATALOG"
                    | "REPLACE_INVALID_CHARACTERS"
                    | "DEFAULT_DDL_COLLATION"
                    | "STORAGE_SERIALIZATION_POLICY"
                    | "LOG_LEVEL"
                    | "TRACE_LEVEL"
                    | "CATALOG_SYNC" => {
                        self.advance(); // consume property name
                        let _eq_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        let value_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                        if props_start.is_none() {
                            props_start = Some(prop_start);
                        }
                        props_end = value_tok.span.end;
                    }
                    _ => {
                        // Unknown property - defensive design
                        let unknown_tok = self
                            .advance()
                            .expect_invariant("unknown property consumed after identifier match");
                        // Consume until next known property or semicolon
                        while let Some(next) = self.peek_non_trivia() {
                            if matches!(next.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            if matches!(
                                next.kind,
                                TokenKind::Keyword(Keyword::Comment | Keyword::Tag)
                            ) {
                                break;
                            }
                            if matches!(next.kind, TokenKind::Identifier { .. }) {
                                let next_up = next.lexeme(self.source).to_uppercase();
                                if next_up == "DATA_RETENTION_TIME_IN_DAYS"
                                    || next_up == "MAX_DATA_EXTENSION_TIME_IN_DAYS"
                                    || next_up == "EXTERNAL_VOLUME"
                                    || next_up == "CATALOG"
                                    || next_up == "WITH"
                                {
                                    break;
                                }
                            }
                            self.advance();
                        }
                        let end_pos = if self.idx > 0 {
                            self.tokens[self.idx - 1].span.end
                        } else {
                            unknown_tok.span.end
                        };
                        extras.push(AstUnknownClause {
                            introducer: Some(unknown_tok.span),
                            span: Span {
                                start: prop_start,
                                end: end_pos,
                            },
                            kind: UnknownKind::Property,
                            node_id: self.id_gen.next(),
                        });
                    }
                }
            } else {
                // Unexpected token type - stop
                break;
            }
        }

        if let Some(start) = props_start {
            Ok(Some(Span {
                start,
                end: props_end,
            }))
        } else {
            Ok(None)
        }
    }

    /// Parse trailing COMMENT and TAG clauses
    fn parse_database_trailing_clauses(
        &mut self,
        comment_span: &mut Option<Span>,
        tag_span: &mut Option<Span>,
    ) -> ParseResult<()> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // COMMENT = '...'
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let start = tok.span.start;
                self.advance();
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance();
                        if let Some(val) = self.peek_non_trivia() {
                            *comment_span = Some(Span {
                                start,
                                end: val.span.end,
                            });
                            self.advance();
                        }
                    }
                }
                continue;
            }

            // [WITH] TAG (...)
            if tok.lexeme(self.source).eq_ignore_ascii_case("WITH")
                || matches!(tok.kind, TokenKind::Keyword(Keyword::Tag))
            {
                let start = tok.span.start;
                if tok.lexeme(self.source).eq_ignore_ascii_case("WITH") {
                    self.advance(); // WITH
                }

                if let Some(tag_tok) = self.peek_non_trivia() {
                    if matches!(tag_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        self.advance(); // TAG
                    }
                }

                // Consume until closing paren or statement end
                let mut end = self.current_span().end;
                let mut paren_depth = 0;
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        paren_depth += 1;
                    }
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        paren_depth -= 1;
                        if paren_depth <= 0 {
                            end = t.span.end;
                            self.advance();
                            break;
                        }
                    }
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    end = t.span.end;
                    self.advance();
                }

                *tag_span = Some(Span { start, end });
                continue;
            }

            // Unknown - stop
            break;
        }
        Ok(())
    }

    /// True when the current `SET` clause is a multi-property list (a
    /// top-level comma before `;`/EOF), paren-aware so a `TAG (a=1, b=2)`
    /// value list is not counted. Trivia never enters the token stream, so
    /// `peek_ahead` index scanning is safe. Routes a multi-property SET —
    /// which may lead with COMMENT/TAG yet still set DATA_RETENTION — to
    /// SetProperties, whose span the retention resolver scans.
    fn alter_db_set_is_multi_property(&self) -> bool {
        let mut depth: i32 = 0;
        let mut n = 0usize;
        while let Some(tok) = self.peek_ahead(n) {
            if matches!(tok.kind, TokenKind::Eof)
                || matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
            {
                break;
            }
            if let TokenKind::Punctuation(p) = &tok.kind {
                match p {
                    Punctuation::LParen => depth += 1,
                    Punctuation::RParen => depth -= 1,
                    Punctuation::Comma if depth <= 0 => return true,
                    _ => {}
                }
            }
            n += 1;
        }
        false
    }

    /// Consume tokens until semicolon or EOF, return end position
    pub(crate) fn consume_until_semi_or_eof(&mut self) -> ParseResult<u32> {
        let mut end = self.current_span().end;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            end = tok.span.end;
            self.advance();
        }
        Ok(end)
    }

    /// Get previous token's span end
    fn previous_span_end(&self) -> u32 {
        if self.idx > 0 {
            self.tokens[self.idx - 1].span.end
        } else {
            0
        }
    }

    //==========================================================================
    // ALTER DATABASE
    //==========================================================================

    /// Parse ALTER DATABASE statement.
    ///
    /// ALTER DATABASE [ IF EXISTS ] <name> <action>
    pub(crate) fn try_parse_alter_database(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_database")?;

        let stmt_start = self.current_span().start;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // DATABASE (Identifier, NOT Keyword)
        let database_tok = self
            .advance()
            .ok_or_eof(alter_span, vec!["DATABASE".to_string()])?;
        if !matches!(database_tok.kind, TokenKind::Identifier { .. })
            || !database_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("DATABASE")
        {
            return Err(ParseError::new(
                database_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DATABASE, found '{}'",
                        database_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let database_span = database_tok.span;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Database name (can be qualified: db_name or account.db_name)
        let name_span = self.parse_qualified_name_span()?;

        // Parse action
        let mut extras = Vec::new();
        let (action, stmt_end) = self.parse_alter_database_action(&mut extras)?;

        let stmt = AstAlterDatabase {
            node_id: self.id_gen.next(),
            span: Span {
                start: stmt_start,
                end: stmt_end,
            },
            alter_span,
            database_span,
            if_exists_span,
            name_span,
            action,
            extras,
        };
        Ok(AstStmt::AlterDatabase(Box::new(stmt)))
    }

    /// Parse ALTER DATABASE action.
    ///
    /// Returns (action, end_position)
    fn parse_alter_database_action(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<(AstAlterDatabaseAction, u32)> {
        let action_start = self.current_span().start;

        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ALTER DATABASE action".to_string(),
                },
            )
        })?;
        let tok_upper = tok.lexeme(self.source).to_uppercase();

        let kind: AstAlterDatabaseActionKind;
        let mut action_end: u32;

        match tok_upper.as_str() {
            "RENAME" => {
                let rename_tok = self
                    .advance()
                    .expect_invariant("RENAME consumed after lexeme match");
                let rename_span = rename_tok.span;

                // TO
                let to_tok = self
                    .advance()
                    .ok_or_eof(rename_span, vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To))
                    && !to_tok.lexeme(self.source).eq_ignore_ascii_case("TO")
                {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!("Expected TO, found '{}'", to_tok.lexeme(self.source)),
                        },
                    ));
                }
                let to_span = to_tok.span;

                // New name
                let new_name_span = self.parse_qualified_name_span()?;
                action_end = new_name_span.end;

                kind = AstAlterDatabaseActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                };
            }

            "SWAP" => {
                let swap_tok = self
                    .advance()
                    .expect_invariant("SWAP consumed after lexeme match");
                let swap_span = swap_tok.span;

                // WITH
                let with_tok = self
                    .advance()
                    .ok_or_eof(swap_span, vec!["WITH".to_string()])?;
                if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With))
                    && !with_tok.lexeme(self.source).eq_ignore_ascii_case("WITH")
                {
                    return Err(ParseError::new(
                        with_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected WITH, found '{}'",
                                with_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                let with_span = with_tok.span;

                // Other database name
                let other_db_span = self.parse_qualified_name_span()?;
                action_end = other_db_span.end;

                kind = AstAlterDatabaseActionKind::SwapWith {
                    swap_span,
                    with_span,
                    other_db_span,
                };
            }

            "SET" => {
                let set_tok = self
                    .advance()
                    .expect_invariant("SET consumed after lexeme match");
                let set_span = set_tok.span;

                // Check what follows SET: TAG or properties?
                if let Some(next_tok) = self.peek_non_trivia() {
                    // SET TAG always takes the tag action — its assignments are
                    // comma-separated. A multi-property list led by COMMENT, though,
                    // still carries DATA_RETENTION etc.; route that to SetProperties
                    // so the retention resolver sees the whole clause, reserving
                    // SetComment for the sole-COMMENT form.
                    let multi = self.alter_db_set_is_multi_property();
                    if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // SET TAG
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword consumed after match");
                        let tag_span = tag_tok.span;

                        // Parse tag assignments until statement end
                        let assignments_start = self.current_span().start;
                        action_end = self.consume_until_semi_or_eof()?;

                        kind = AstAlterDatabaseActionKind::SetTag {
                            set_span,
                            tag_span,
                            assignments_span: Span {
                                start: assignments_start,
                                end: action_end,
                            },
                        };
                    } else if !multi && next_tok.lexeme(self.source).eq_ignore_ascii_case("COMMENT")
                    {
                        // SET COMMENT = '...'
                        let comment_tok = self
                            .advance()
                            .expect_invariant("COMMENT consumed after lexeme match");
                        let comment_start = comment_tok.span.start;

                        // = 'value'
                        action_end = self.consume_until_semi_or_eof()?;

                        kind = AstAlterDatabaseActionKind::SetComment {
                            set_span,
                            comment_span: Span {
                                start: comment_start,
                                end: action_end,
                            },
                        };
                    } else {
                        // SET properties
                        let props_start = self.current_span().start;
                        action_end = self.consume_until_semi_or_eof()?;

                        kind = AstAlterDatabaseActionKind::SetProperties {
                            set_span,
                            properties_span: Span {
                                start: props_start,
                                end: action_end,
                            },
                        };
                    }
                } else {
                    action_end = set_span.end;
                    kind = AstAlterDatabaseActionKind::SetProperties {
                        set_span,
                        properties_span: set_span,
                    };
                }
            }

            "UNSET" => {
                let unset_tok = self
                    .advance()
                    .expect_invariant("UNSET consumed after lexeme match");
                let unset_span = unset_tok.span;

                // Check what follows UNSET: TAG, COMMENT, or properties?
                if let Some(next_tok) = self.peek_non_trivia() {
                    if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // UNSET TAG
                        let tag_tok = self
                            .advance()
                            .expect_invariant("TAG keyword consumed after match");
                        let tag_span = tag_tok.span;

                        // Parse tag names until statement end
                        let tags_start = self.current_span().start;
                        action_end = self.consume_until_semi_or_eof()?;

                        kind = AstAlterDatabaseActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            tags_span: Span {
                                start: tags_start,
                                end: action_end,
                            },
                        };
                    } else if next_tok.lexeme(self.source).eq_ignore_ascii_case("COMMENT") {
                        // UNSET COMMENT
                        let comment_tok = self
                            .advance()
                            .expect_invariant("COMMENT consumed after lexeme match");
                        action_end = comment_tok.span.end;

                        kind = AstAlterDatabaseActionKind::UnsetComment {
                            unset_span,
                            comment_span: comment_tok.span,
                        };
                    } else {
                        // UNSET properties
                        let props_start = self.current_span().start;
                        action_end = self.consume_until_semi_or_eof()?;

                        kind = AstAlterDatabaseActionKind::UnsetProperties {
                            unset_span,
                            properties_span: Span {
                                start: props_start,
                                end: action_end,
                            },
                        };
                    }
                } else {
                    action_end = unset_span.end;
                    kind = AstAlterDatabaseActionKind::UnsetProperties {
                        unset_span,
                        properties_span: unset_span,
                    };
                }
            }

            "ENABLE" => {
                let enable_tok = self
                    .advance()
                    .expect_invariant("ENABLE consumed after lexeme match");
                let enable_span = enable_tok.span;

                // REPLICATION or FAILOVER?
                let next_tok = self
                    .advance()
                    .ok_or_eof(enable_span, vec!["REPLICATION or FAILOVER".to_string()])?;
                let next_upper = next_tok.lexeme(self.source).to_uppercase();

                if next_upper == "REPLICATION" {
                    // ENABLE REPLICATION TO ACCOUNTS ...
                    let replication_span = next_tok.span;

                    // TO
                    let _to_tok = self
                        .advance()
                        .ok_or_eof(replication_span, vec!["TO".to_string()])?;

                    // ACCOUNTS
                    let _accounts_tok = self
                        .advance()
                        .ok_or_eof(replication_span, vec!["ACCOUNTS".to_string()])?;

                    // Parse account list and optional IGNORE EDITION CHECK
                    let to_accounts_start = self.current_span().start;
                    let mut ignore_edition_span: Option<Span> = None;
                    action_end = to_accounts_start;

                    while let Some(t) = self.peek_non_trivia() {
                        if matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                            break;
                        }
                        if t.lexeme(self.source).eq_ignore_ascii_case("IGNORE") {
                            // IGNORE EDITION CHECK
                            let ignore_start = t.span.start;
                            self.advance(); // IGNORE
                            if let Some(edition) = self.peek_non_trivia() {
                                if edition.lexeme(self.source).eq_ignore_ascii_case("EDITION") {
                                    self.advance();
                                    if let Some(check) = self.peek_non_trivia() {
                                        if check.lexeme(self.source).eq_ignore_ascii_case("CHECK") {
                                            action_end = check.span.end;
                                            self.advance();
                                            ignore_edition_span = Some(Span {
                                                start: ignore_start,
                                                end: action_end,
                                            });
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        action_end = t.span.end;
                        self.advance();
                    }

                    kind = AstAlterDatabaseActionKind::EnableReplication {
                        enable_span,
                        replication_span,
                        to_accounts_span: Span {
                            start: to_accounts_start,
                            end: action_end,
                        },
                        ignore_edition_span,
                    };
                } else if next_upper == "FAILOVER" {
                    // ENABLE FAILOVER TO ACCOUNTS ...
                    let failover_span = next_tok.span;

                    // TO
                    let _to_tok = self
                        .advance()
                        .ok_or_eof(failover_span, vec!["TO".to_string()])?;

                    // ACCOUNTS
                    let _accounts_tok = self
                        .advance()
                        .ok_or_eof(failover_span, vec!["ACCOUNTS".to_string()])?;

                    let to_accounts_start = self.current_span().start;
                    action_end = self.consume_until_semi_or_eof()?;

                    kind = AstAlterDatabaseActionKind::EnableFailover {
                        enable_span,
                        failover_span,
                        to_accounts_span: Span {
                            start: to_accounts_start,
                            end: action_end,
                        },
                    };
                } else {
                    // Unknown ENABLE action
                    action_end = self.consume_until_semi_or_eof()?;
                    let unknown_span = Span {
                        start: enable_span.start,
                        end: action_end,
                    };
                    extras.push(AstUnknownClause {
                        node_id: self.id_gen.next(),
                        introducer: Some(enable_span),
                        span: unknown_span,
                        kind: UnknownKind::Clause,
                    });
                    kind = AstAlterDatabaseActionKind::Unknown(AstUnknownClause {
                        node_id: self.id_gen.next(),
                        introducer: Some(enable_span),
                        span: unknown_span,
                        kind: UnknownKind::Clause,
                    });
                }
            }

            "DISABLE" => {
                let disable_tok = self
                    .advance()
                    .expect_invariant("DISABLE consumed after lexeme match");
                let disable_span = disable_tok.span;

                // REPLICATION or FAILOVER?
                let next_tok = self
                    .advance()
                    .ok_or_eof(disable_span, vec!["REPLICATION or FAILOVER".to_string()])?;
                let next_upper = next_tok.lexeme(self.source).to_uppercase();

                if next_upper == "REPLICATION" {
                    // DISABLE REPLICATION [TO ACCOUNTS ...]
                    let replication_span = next_tok.span;

                    // Optional TO ACCOUNTS
                    let to_accounts_span: Option<Span>;
                    if let Some(to) = self.peek_non_trivia() {
                        if matches!(to.kind, TokenKind::Keyword(Keyword::To))
                            || to.lexeme(self.source).eq_ignore_ascii_case("TO")
                        {
                            let to_start = to.span.start;
                            self.advance(); // TO

                            if let Some(accts) = self.peek_non_trivia() {
                                if accts.lexeme(self.source).eq_ignore_ascii_case("ACCOUNTS") {
                                    self.advance(); // ACCOUNTS
                                    action_end = self.consume_until_semi_or_eof()?;
                                    to_accounts_span = Some(Span {
                                        start: to_start,
                                        end: action_end,
                                    });
                                } else {
                                    action_end = replication_span.end;
                                    to_accounts_span = None;
                                }
                            } else {
                                action_end = replication_span.end;
                                to_accounts_span = None;
                            }
                        } else {
                            action_end = replication_span.end;
                            to_accounts_span = None;
                        }
                    } else {
                        action_end = replication_span.end;
                        to_accounts_span = None;
                    }

                    kind = AstAlterDatabaseActionKind::DisableReplication {
                        disable_span,
                        replication_span,
                        to_accounts_span,
                    };
                } else if next_upper == "FAILOVER" {
                    // DISABLE FAILOVER [TO ACCOUNTS ...]
                    let failover_span = next_tok.span;

                    // Optional TO ACCOUNTS
                    let to_accounts_span: Option<Span>;
                    if let Some(to) = self.peek_non_trivia() {
                        if matches!(to.kind, TokenKind::Keyword(Keyword::To))
                            || to.lexeme(self.source).eq_ignore_ascii_case("TO")
                        {
                            let to_start = to.span.start;
                            self.advance(); // TO

                            if let Some(accts) = self.peek_non_trivia() {
                                if accts.lexeme(self.source).eq_ignore_ascii_case("ACCOUNTS") {
                                    self.advance(); // ACCOUNTS
                                    action_end = self.consume_until_semi_or_eof()?;
                                    to_accounts_span = Some(Span {
                                        start: to_start,
                                        end: action_end,
                                    });
                                } else {
                                    action_end = failover_span.end;
                                    to_accounts_span = None;
                                }
                            } else {
                                action_end = failover_span.end;
                                to_accounts_span = None;
                            }
                        } else {
                            action_end = failover_span.end;
                            to_accounts_span = None;
                        }
                    } else {
                        action_end = failover_span.end;
                        to_accounts_span = None;
                    }

                    kind = AstAlterDatabaseActionKind::DisableFailover {
                        disable_span,
                        failover_span,
                        to_accounts_span,
                    };
                } else {
                    // Unknown DISABLE action
                    action_end = self.consume_until_semi_or_eof()?;
                    kind = AstAlterDatabaseActionKind::Unknown(AstUnknownClause {
                        node_id: self.id_gen.next(),
                        introducer: Some(disable_span),
                        span: Span {
                            start: disable_span.start,
                            end: action_end,
                        },
                        kind: UnknownKind::Clause,
                    });
                }
            }

            "REFRESH" => {
                let refresh_tok = self
                    .advance()
                    .expect_invariant("REFRESH consumed after lexeme match");
                let refresh_span = refresh_tok.span;
                action_end = refresh_span.end;

                kind = AstAlterDatabaseActionKind::Refresh { refresh_span };
            }

            "PRIMARY" => {
                let primary_tok = self
                    .advance()
                    .expect_invariant("PRIMARY consumed after lexeme match");
                let primary_span = primary_tok.span;
                action_end = primary_span.end;

                kind = AstAlterDatabaseActionKind::Primary { primary_span };
            }

            _ => {
                // Unknown action - capture as unknown clause
                let introducer_span = tok.span;
                action_end = self.consume_until_semi_or_eof()?;

                kind = AstAlterDatabaseActionKind::Unknown(AstUnknownClause {
                    node_id: self.id_gen.next(),
                    introducer: Some(introducer_span),
                    span: Span {
                        start: introducer_span.start,
                        end: action_end,
                    },
                    kind: UnknownKind::Clause,
                });
            }
        }

        let action = AstAlterDatabaseAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end: action_end,
            },
            kind,
        };

        Ok((action, action_end))
    }
}
