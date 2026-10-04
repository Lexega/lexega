// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SCHEMA statement parsing (CREATE, ALTER, DROP, UNDROP)
//!
//! SCHEMA is Identifier, NOT Keyword.
//! Must use lexeme matching with eq_ignore_ascii_case().

use crate::ast::{
    AstAlterSchema, AstAlterSchemaAction, AstAlterSchemaActionKind, AstCreateSchema,
    AstCreateSchemaVariant, AstDropSchema, AstStmt, AstUndropSchema, AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse CREATE SCHEMA statement.
    ///
    /// Dispatcher resets idx before calling - we MUST consume CREATE.
    pub(crate) fn try_parse_create_schema(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_schema")?;

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
                    .expect_invariant("TRANSIENT: consumed after Keyword::Transient match");
                Some(t.span)
            } else {
                None
            }
        } else {
            None
        };

        // SCHEMA (Identifier, NOT Keyword!)
        let schema_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;

        if !matches!(schema_tok.kind, TokenKind::Identifier { .. })
            || !schema_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SCHEMA")
        {
            return Err(ParseError::new(
                schema_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SCHEMA, found '{}'",
                        schema_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let schema_span = schema_tok.span;

        // Optional IF NOT EXISTS
        let if_not_exists_span = self.parse_optional_if_not_exists()?;

        // Schema name (required) - handles qualified names (db.schema)
        let name_span = self.parse_qualified_name_span()?;

        // Parse variant and remaining clauses
        let mut extras: Vec<AstUnknownClause> = Vec::new();
        let mut with_managed_access_span: Option<Span> = None;
        let mut comment_span: Option<Span> = None;
        let mut tag_span: Option<Span> = None;
        let mut managed_location_span: Option<Span> = None;
        let mut location_span: Option<Span> = None;
        let mut default_collation_span: Option<Span> = None;
        let mut dbproperties_span: Option<Span> = None;

        let variant = self.parse_create_schema_variant(&mut extras)?;

        // Parse properties AFTER variant (CLONE allows trailing properties)
        let properties_span = match &variant {
            AstCreateSchemaVariant::Standard | AstCreateSchemaVariant::Clone { .. } => {
                self.parse_schema_properties(&mut extras)?
            }
        };

        // Parse optional trailing clauses (Snowflake + Databricks):
        //  - MANAGED LOCATION 'path' (Databricks Unity Catalog)
        //  - LOCATION 'path' (Databricks Hive metastore)
        //  - DEFAULT COLLATION name (Databricks)
        //  - WITH DBPROPERTIES (key=val, ...) (Databricks)
        //  - WITH MANAGED ACCESS (Snowflake)
        //  - COMMENT '...' (both)
        //  - [WITH] TAG (...) (Snowflake)
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                || matches!(tok.kind, TokenKind::Eof)
            {
                break;
            }

            let lex = tok.lexeme(self.source);

            // MANAGED LOCATION 'path' (Databricks)
            if lex.eq_ignore_ascii_case("MANAGED") {
                // Peek ahead to distinguish MANAGED LOCATION from WITH MANAGED ACCESS
                // (WITH MANAGED ACCESS is handled separately below via WITH)
                let save_idx = self.idx;
                let managed_tok = self
                    .advance()
                    .expect_invariant("MANAGED: consumed after lexeme check");
                if let Some(next) = self.peek_non_trivia() {
                    if next.lexeme(self.source).eq_ignore_ascii_case("LOCATION") {
                        self.advance(); // LOCATION
                        let path_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["path string".to_string()])?;
                        managed_location_span = Some(Span {
                            start: managed_tok.span.start,
                            end: path_tok.span.end,
                        });
                        continue;
                    } else if next.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                        // Part of WITH MANAGED ACCESS without WITH prefix - handle as Snowflake
                        let access_tok = self
                            .advance()
                            .expect_invariant("ACCESS: consumed after lexeme check");
                        with_managed_access_span = Some(Span {
                            start: managed_tok.span.start,
                            end: access_tok.span.end,
                        });
                        continue;
                    }
                }
                // Not LOCATION or ACCESS after MANAGED - revert
                self.idx = save_idx;
                break;
            }

            // LOCATION 'path' (Databricks Hive metastore)
            if lex.eq_ignore_ascii_case("LOCATION") {
                let loc_tok = self
                    .advance()
                    .expect_invariant("LOCATION: consumed after lexeme check");
                let path_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["path string".to_string()])?;
                location_span = Some(Span {
                    start: loc_tok.span.start,
                    end: path_tok.span.end,
                });
                continue;
            }

            // DEFAULT COLLATION name (Databricks)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                let save_idx = self.idx;
                let default_tok = self
                    .advance()
                    .expect_invariant("DEFAULT: consumed after Keyword::Default match");
                if let Some(next) = self.peek_non_trivia() {
                    if next.lexeme(self.source).eq_ignore_ascii_case("COLLATION") {
                        self.advance(); // COLLATION
                        let name_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["collation name".to_string()])?;
                        default_collation_span = Some(Span {
                            start: default_tok.span.start,
                            end: name_tok.span.end,
                        });
                        continue;
                    }
                }
                // Not COLLATION after DEFAULT - revert
                self.idx = save_idx;
                break;
            }

            // WITH ... (MANAGED ACCESS, DBPROPERTIES, or TAG)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let save_idx = self.idx;
                let with_start = tok.span.start;
                self.advance(); // WITH

                if let Some(next) = self.peek_non_trivia() {
                    let next_lex = next.lexeme(self.source);

                    // WITH MANAGED ACCESS (Snowflake)
                    if next_lex.eq_ignore_ascii_case("MANAGED") {
                        self.advance(); // MANAGED
                        if let Some(access) = self.peek_non_trivia() {
                            if access.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                                let access_tok = self
                                    .advance()
                                    .expect_invariant("ACCESS: consumed after lexeme check");
                                with_managed_access_span = Some(Span {
                                    start: with_start,
                                    end: access_tok.span.end,
                                });
                                continue;
                            }
                        }
                        // MANAGED without ACCESS after WITH - revert
                        self.idx = save_idx;
                        break;
                    }

                    // WITH DBPROPERTIES (key=val, ...) (Databricks)
                    if next_lex.eq_ignore_ascii_case("DBPROPERTIES") {
                        self.advance(); // DBPROPERTIES
                        let paren_span = self.consume_balanced_parens()?;
                        dbproperties_span = Some(Span {
                            start: with_start,
                            end: paren_span.end,
                        });
                        continue;
                    }

                    // WITH TAG (...) (Snowflake)
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                        self.idx = save_idx; // revert, let trailing clause handler deal with it
                        break;
                    }
                }
                // Unknown WITH clause - revert
                self.idx = save_idx;
                break;
            }

            // COMMENT '...' (both Snowflake and Databricks)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                break; // let parse_schema_trailing_clauses handle it
            }

            // TAG (...) (Snowflake without WITH prefix)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                break; // let parse_schema_trailing_clauses handle it
            }

            // Unknown clause - stop this loop
            break;
        }

        // Parse trailing COMMENT and TAG (Snowflake-specific handling)
        self.parse_schema_trailing_clauses(&mut comment_span, &mut tag_span, &mut extras)?;

        // Calculate final span
        let mut span_end = name_span.end;
        if let Some(s) = &properties_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &with_managed_access_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &managed_location_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &location_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &default_collation_span {
            span_end = span_end.max(s.end);
        }
        if let Some(s) = &dbproperties_span {
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
            AstCreateSchemaVariant::Standard => {}
            AstCreateSchemaVariant::Clone {
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
        }

        let span = Span {
            start: create_span.start,
            end: span_end,
        };

        Ok(AstStmt::CreateSchema(Box::new(AstCreateSchema {
            node_id: self.id_gen.next(),
            span,
            create_span,
            or_replace_span,
            transient_span,
            schema_span,
            if_not_exists_span,
            name_span,
            variant,
            properties_span,
            with_managed_access_span,
            managed_location_span,
            location_span,
            default_collation_span,
            dbproperties_span,
            comment_span,
            tag_span,
            extras,
        })))
    }

    /// Parse the CREATE SCHEMA variant (CLONE, FROM BACKUP, etc.)
    fn parse_create_schema_variant(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<AstCreateSchemaVariant> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => {
                return Ok(AstCreateSchemaVariant::Standard);
            }
        };

        // CLONE variant
        if tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") {
            let clone_tok = self
                .advance()
                .expect_invariant("CLONE: consumed after lexeme eq_ignore_ascii_case check");
            let clone_span = clone_tok.span;

            let source_span = self.parse_qualified_name_span()?;

            // Optional AT/BEFORE time travel
            let time_travel = self
                .parse_time_travel()?
                .map(|tt| Box::new(crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt)));

            // Optional IGNORE TABLES WITH INSUFFICIENT DATA RETENTION
            let ignore_tables_span = self.parse_ignore_tables_clause()?;

            return Ok(AstCreateSchemaVariant::Clone {
                clone_span,
                source_span,
                time_travel,
                ignore_tables_span,
            });
        }

        // FROM BACKUP SET variant
        if matches!(tok.kind, TokenKind::Keyword(Keyword::From)) {
            let from_tok = self
                .advance()
                .expect_invariant("FROM: consumed after Keyword::From match");
            let from_start = from_tok.span.start;

            if let Some(next) = self.peek_non_trivia() {
                if next.lexeme(self.source).eq_ignore_ascii_case("BACKUP") {
                    // Consume rest of FROM BACKUP SET ... as unknown
                    let end = self.consume_until_semi_or_eof()?;
                    extras.push(AstUnknownClause {
                        introducer: Some(from_tok.span),
                        span: Span {
                            start: from_start,
                            end,
                        },
                        kind: UnknownKind::Clause,
                        node_id: self.id_gen.next(),
                    });
                }
            }
        }

        // Standard variant
        Ok(AstCreateSchemaVariant::Standard)
    }

    /// Parse DROP SCHEMA statement.
    pub(crate) fn try_parse_drop_schema(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_schema")?;

        // DROP already peeked but not consumed - consume it
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;

        // SCHEMA
        let schema_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;

        if !matches!(schema_tok.kind, TokenKind::Identifier { .. })
            || !schema_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SCHEMA")
        {
            return Err(ParseError::new(
                schema_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SCHEMA, found '{}'",
                        schema_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let schema_span = schema_tok.span;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Schema name
        let name_span = self.parse_qualified_name_span()?;

        // Optional CASCADE or RESTRICT
        let cascade_restrict_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("CASCADE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("RESTRICT")
            {
                let t = self
                    .advance()
                    .expect_invariant("CASCADE/RESTRICT: consumed after lexeme check");
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

        Ok(AstStmt::DropSchema(Box::new(AstDropSchema {
            node_id: self.id_gen.next(),
            span,
            drop_span,
            schema_span,
            if_exists_span,
            name_span,
            cascade_restrict_span,
        })))
    }

    /// Parse UNDROP SCHEMA statement.
    pub(crate) fn try_parse_undrop_schema(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("undrop_schema")?;

        // UNDROP - Identifier, not keyword!
        let undrop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNDROP".to_string()])?;
        let undrop_span = undrop_tok.span;

        // SCHEMA
        let schema_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;

        if !matches!(schema_tok.kind, TokenKind::Identifier { .. })
            || !schema_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SCHEMA")
        {
            return Err(ParseError::new(
                schema_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SCHEMA, found '{}'",
                        schema_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let schema_span = schema_tok.span;

        // Schema name
        let name_span = self.parse_qualified_name_span()?;

        let span = Span {
            start: undrop_span.start,
            end: name_span.end,
        };

        Ok(AstStmt::UndropSchema(Box::new(AstUndropSchema {
            node_id: self.id_gen.next(),
            span,
            undrop_span,
            schema_span,
            name_span,
        })))
    }

    /// Parse ALTER SCHEMA statement.
    pub(crate) fn try_parse_alter_schema(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_schema")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // SCHEMA
        let schema_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;

        if !matches!(schema_tok.kind, TokenKind::Identifier { .. })
            || !schema_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("SCHEMA")
        {
            return Err(ParseError::new(
                schema_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SCHEMA, found '{}'",
                        schema_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let schema_span = schema_tok.span;

        // Optional IF EXISTS
        let if_exists_span = self.parse_optional_if_exists()?;

        // Schema name
        let name_span = self.parse_qualified_name_span()?;

        // Parse the action
        let mut extras: Vec<AstUnknownClause> = Vec::new();
        let action = self.parse_alter_schema_action(&mut extras)?;

        let span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        Ok(AstStmt::AlterSchema(Box::new(AstAlterSchema {
            node_id: self.id_gen.next(),
            span,
            alter_span,
            schema_span,
            if_exists_span,
            name_span,
            action,
            extras,
        })))
    }

    /// Parse ALTER SCHEMA action
    fn parse_alter_schema_action(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<AstAlterSchemaAction> {
        let tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, SWAP, SET, UNSET, or ENABLE/DISABLE".to_string()],
        )?;

        let action_start = tok.span.start;

        // RENAME TO new_name
        if tok.lexeme(self.source).eq_ignore_ascii_case("RENAME") {
            let rename_tok = self
                .advance()
                .expect_invariant("RENAME: consumed after lexeme eq_ignore_ascii_case check");
            let rename_span = rename_tok.span;

            let to_tok = self
                .peek_non_trivia()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                return Err(ParseError::new(
                    to_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!("Expected TO, found '{}'", to_tok.lexeme(self.source)),
                    },
                ));
            }
            let to_tok = self
                .advance()
                .expect_invariant("TO: consumed after Keyword::To validation above");
            let to_span = to_tok.span;

            let new_name_span = self.parse_qualified_name_span()?;

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end: new_name_span.end,
                },
                kind: AstAlterSchemaActionKind::RenameTo {
                    rename_span,
                    to_span,
                    new_name_span,
                },
            });
        }

        // SWAP WITH other_schema
        if tok.lexeme(self.source).eq_ignore_ascii_case("SWAP") {
            let swap_tok = self
                .advance()
                .expect_invariant("SWAP: consumed after lexeme eq_ignore_ascii_case check");
            let swap_span = swap_tok.span;

            let with_tok = self
                .peek_non_trivia()
                .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
            if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                return Err(ParseError::new(
                    with_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!("Expected WITH, found '{}'", with_tok.lexeme(self.source)),
                    },
                ));
            }
            let with_tok = self
                .advance()
                .expect_invariant("WITH: consumed after Keyword::With validation above");
            let with_span = with_tok.span;

            let other_schema_span = self.parse_qualified_name_span()?;

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end: other_schema_span.end,
                },
                kind: AstAlterSchemaActionKind::SwapWith {
                    swap_span,
                    with_span,
                    other_schema_span,
                },
            });
        }

        // SET property = value OR SET TAG OR SET DBPROPERTIES OR SET OWNER TO OR SET TAGS
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
            let set_tok = self
                .advance()
                .expect_invariant("SET: consumed after Keyword::Set match");
            let set_span = set_tok.span;

            if let Some(next_tok) = self.peek_non_trivia() {
                // SET TAG (Snowflake)
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    let tag_tok = self
                        .advance()
                        .expect_invariant("TAG: consumed after Keyword::Tag match in SET TAG");
                    let tag_span = tag_tok.span;

                    let assignments_start = self.current_span().start;
                    let end = self.consume_until_semi_or_eof_schema()?;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end,
                        },
                        kind: AstAlterSchemaActionKind::SetTag {
                            set_span,
                            tag_span,
                            assignments_span: Span {
                                start: assignments_start,
                                end,
                            },
                        },
                    });
                }

                // SET TAGS (...) (Databricks - TAGS is Identifier, not Keyword)
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("TAGS")
                {
                    let tags_tok = self
                        .advance()
                        .expect_invariant("TAGS: consumed after lexeme check");
                    let tags_span = tags_tok.span;
                    let end = self.consume_balanced_parens()?.end;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end,
                        },
                        kind: AstAlterSchemaActionKind::SetTags {
                            set_span,
                            tags_span,
                            assignments_span: Span {
                                start: tags_span.end,
                                end,
                            },
                        },
                    });
                }

                // SET DBPROPERTIES (...) (Databricks)
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("DBPROPERTIES")
                {
                    self.advance(); // DBPROPERTIES
                    let end = self.consume_balanced_parens()?.end;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end,
                        },
                        kind: AstAlterSchemaActionKind::SetDbProperties {
                            set_span: Some(set_span),
                            dbproperties_span: Span {
                                start: action_start,
                                end,
                            },
                        },
                    });
                }

                // SET MANAGED ACCESS (Snowflake — alternate spelling to ENABLE MANAGED ACCESS)
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("MANAGED")
                {
                    let managed_tok = self
                        .advance()
                        .expect_invariant("MANAGED: consumed after lexeme check");
                    let managed_start = managed_tok.span.start;
                    let mut managed_end = managed_tok.span.end;
                    if let Some(access) = self.peek_non_trivia() {
                        if access.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                            managed_end = self
                                .advance()
                                .expect_invariant("ACCESS: consumed after lexeme check")
                                .span
                                .end;
                        }
                    }
                    let managed_access_span = Span {
                        start: managed_start,
                        end: managed_end,
                    };
                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: managed_end,
                        },
                        kind: AstAlterSchemaActionKind::SetManagedAccess {
                            set_span,
                            managed_access_span,
                        },
                    });
                }

                // SET OWNER TO principal (Databricks, with SET prefix)
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
                    let owner_tok = self
                        .advance()
                        .expect_invariant("OWNER: consumed after Keyword::Owner match");
                    let owner_span = owner_tok.span;
                    let to_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                    let to_span = to_tok.span;
                    let principal_span = self.parse_qualified_name_span()?;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: principal_span.end,
                        },
                        kind: AstAlterSchemaActionKind::OwnerTo {
                            set_span: Some(set_span),
                            owner_span,
                            to_span,
                            principal_span,
                        },
                    });
                }
            }

            // Not a special SET action, parse properties (Snowflake SET property = value)
            let props_span = self.parse_schema_properties(extras)?;
            let mut properties_span = props_span.unwrap_or(Span {
                start: set_span.end,
                end: set_span.end,
            });
            // parse_schema_properties stops at a COMMENT keyword, but a retention
            // (or other) property may follow it — Snowflake allows any property
            // order. Extend the span over the rest of the clause so the retention
            // resolver (a text scan over properties_span) sees it regardless of
            // COMMENT position.
            if matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::Comment))
            ) {
                let clause_end = self.consume_until_semi_or_eof_schema()?;
                if props_span.is_none() {
                    properties_span.start = set_span.end;
                }
                properties_span.end = properties_span.end.max(clause_end);
            }
            let span_end = properties_span.end;

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end: span_end,
                },
                kind: AstAlterSchemaActionKind::SetProperties {
                    set_span,
                    properties_span,
                },
            });
        }

        // UNSET property [, property ...] OR UNSET TAG OR UNSET TAGS
        if tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
            let unset_tok = self
                .advance()
                .expect_invariant("UNSET: consumed after lexeme eq_ignore_ascii_case check");
            let unset_span = unset_tok.span;

            if let Some(next_tok) = self.peek_non_trivia() {
                // UNSET TAG (Snowflake)
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    let tag_tok = self
                        .advance()
                        .expect_invariant("TAG: consumed after Keyword::Tag match in UNSET TAG");
                    let tag_span = tag_tok.span;

                    let tags_start = self.current_span().start;
                    let end = self.consume_until_semi_or_eof_schema()?;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end,
                        },
                        kind: AstAlterSchemaActionKind::UnsetTag {
                            unset_span,
                            tag_span,
                            tags_span: Span {
                                start: tags_start,
                                end,
                            },
                        },
                    });
                }

                // UNSET MANAGED ACCESS (Snowflake — alternate spelling to DISABLE MANAGED ACCESS)
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("MANAGED")
                {
                    let managed_tok = self
                        .advance()
                        .expect_invariant("MANAGED: consumed after lexeme check");
                    let managed_start = managed_tok.span.start;
                    let mut managed_end = managed_tok.span.end;
                    if let Some(access) = self.peek_non_trivia() {
                        if access.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                            managed_end = self
                                .advance()
                                .expect_invariant("ACCESS: consumed after lexeme check")
                                .span
                                .end;
                        }
                    }
                    let managed_access_span = Span {
                        start: managed_start,
                        end: managed_end,
                    };
                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: managed_end,
                        },
                        kind: AstAlterSchemaActionKind::UnsetManagedAccess {
                            unset_span,
                            managed_access_span,
                        },
                    });
                }

                // UNSET TAGS (...) (Databricks - TAGS is Identifier, not Keyword)
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("TAGS")
                {
                    let tags_tok = self
                        .advance()
                        .expect_invariant("TAGS: consumed after lexeme check");
                    let tags_span = tags_tok.span;
                    let end = self.consume_balanced_parens()?.end;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end,
                        },
                        kind: AstAlterSchemaActionKind::UnsetTags {
                            unset_span,
                            tags_span,
                            tag_list_span: Span {
                                start: tags_span.end,
                                end,
                            },
                        },
                    });
                }
            }

            // Not TAG, parse property list until semi or EOF
            let mut end = unset_span.end;
            while let Some(next) = self.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    break;
                }
                end = next.span.end;
                self.advance();
            }
            let properties_span = Span {
                start: unset_span.end,
                end,
            };

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterSchemaActionKind::UnsetProperties {
                    unset_span,
                    properties_span,
                },
            });
        }

        // ENABLE / DISABLE: MANAGED ACCESS (Snowflake) or PREDICTIVE OPTIMIZATION (Databricks)
        if tok.lexeme(self.source).eq_ignore_ascii_case("ENABLE")
            || tok.lexeme(self.source).eq_ignore_ascii_case("DISABLE")
        {
            let enable_disable_tok = self
                .advance()
                .expect_invariant("ENABLE/DISABLE: consumed after lexeme check");
            let is_enable = enable_disable_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("ENABLE");
            let start = enable_disable_tok.span.start;
            let mut end = enable_disable_tok.span.end;

            if let Some(next) = self.peek_non_trivia() {
                // PREDICTIVE OPTIMIZATION (Databricks)
                if next.lexeme(self.source).eq_ignore_ascii_case("PREDICTIVE") {
                    let pred_tok = self
                        .advance()
                        .expect_invariant("PREDICTIVE: consumed after lexeme check");
                    let mut pred_end = pred_tok.span.end;
                    if let Some(opt) = self.peek_non_trivia() {
                        if opt.lexeme(self.source).eq_ignore_ascii_case("OPTIMIZATION") {
                            pred_end = self
                                .advance()
                                .expect_invariant("OPTIMIZATION: consumed after lexeme check")
                                .span
                                .end;
                        }
                    }
                    end = pred_end;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span { start, end },
                        kind: AstAlterSchemaActionKind::PredictiveOptimization {
                            action_span: enable_disable_tok.span,
                            predictive_optimization_span: Span {
                                start: pred_tok.span.start,
                                end: pred_end,
                            },
                        },
                    });
                }

                // MANAGED ACCESS (Snowflake)
                if next.lexeme(self.source).eq_ignore_ascii_case("MANAGED") {
                    self.advance();
                    if let Some(access) = self.peek_non_trivia() {
                        if access.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                            end = self
                                .advance()
                                .expect_invariant("ACCESS: consumed after lexeme check")
                                .span
                                .end;
                        }
                    }
                }
            }

            let managed_access_span = Span {
                start: enable_disable_tok.span.end,
                end,
            };

            let kind = if is_enable {
                AstAlterSchemaActionKind::EnableManagedAccess {
                    enable_span: enable_disable_tok.span,
                    managed_access_span,
                }
            } else {
                AstAlterSchemaActionKind::DisableManagedAccess {
                    disable_span: enable_disable_tok.span,
                    managed_access_span,
                }
            };

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                kind,
            });
        }

        // INHERIT PREDICTIVE OPTIMIZATION (Databricks)
        if tok.lexeme(self.source).eq_ignore_ascii_case("INHERIT") {
            let inherit_tok = self
                .advance()
                .expect_invariant("INHERIT: consumed after lexeme check");
            let start = inherit_tok.span.start;
            let mut end = inherit_tok.span.end;
            let mut pred_start = end;

            if let Some(pred) = self.peek_non_trivia() {
                if pred.lexeme(self.source).eq_ignore_ascii_case("PREDICTIVE") {
                    pred_start = pred.span.start;
                    end = self
                        .advance()
                        .expect_invariant("PREDICTIVE: consumed after lexeme check")
                        .span
                        .end;
                    if let Some(opt) = self.peek_non_trivia() {
                        if opt.lexeme(self.source).eq_ignore_ascii_case("OPTIMIZATION") {
                            end = self
                                .advance()
                                .expect_invariant("OPTIMIZATION: consumed after lexeme check")
                                .span
                                .end;
                        }
                    }
                }
            }

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                kind: AstAlterSchemaActionKind::PredictiveOptimization {
                    action_span: inherit_tok.span,
                    predictive_optimization_span: Span {
                        start: pred_start,
                        end,
                    },
                },
            });
        }

        // OWNER TO principal (Databricks, without SET prefix)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Owner)) {
            let owner_tok = self
                .advance()
                .expect_invariant("OWNER: consumed after Keyword::Owner match");
            let owner_span = owner_tok.span;
            let to_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
            let to_span = to_tok.span;
            let principal_span = self.parse_qualified_name_span()?;

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end: principal_span.end,
                },
                kind: AstAlterSchemaActionKind::OwnerTo {
                    set_span: None,
                    owner_span,
                    to_span,
                    principal_span,
                },
            });
        }

        // DEFAULT COLLATION name (Databricks)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
            let default_tok = self
                .advance()
                .expect_invariant("DEFAULT: consumed after Keyword::Default match");
            if let Some(next) = self.peek_non_trivia() {
                if next.lexeme(self.source).eq_ignore_ascii_case("COLLATION") {
                    let collation_tok = self
                        .advance()
                        .expect_invariant("COLLATION: consumed after lexeme check");
                    let name_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["collation name".to_string()])?;

                    return Ok(AstAlterSchemaAction {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: action_start,
                            end: name_tok.span.end,
                        },
                        kind: AstAlterSchemaActionKind::DefaultCollation {
                            default_span: default_tok.span,
                            collation_span: collation_tok.span,
                            collation_name_span: name_tok.span,
                        },
                    });
                }
            }
            // DEFAULT without COLLATION - fall through to unknown
        }

        // SET TAG / UNSET TAG
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            // Consume until statement end
            let end = self.consume_until_semi_or_eof()?;
            extras.push(AstUnknownClause {
                introducer: Some(tok.span),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: UnknownKind::Clause,
                node_id: self.id_gen.next(),
            });

            return Ok(AstAlterSchemaAction {
                node_id: self.id_gen.next(),
                span: Span {
                    start: action_start,
                    end,
                },
                kind: AstAlterSchemaActionKind::Unknown(AstUnknownClause {
                    introducer: Some(tok.span),
                    span: Span {
                        start: action_start,
                        end,
                    },
                    kind: UnknownKind::Clause,
                    node_id: self.id_gen.next(),
                }),
            });
        }

        // Unknown action - consume rest as extra
        let end = self.consume_until_semi_or_eof()?;
        let unknown_clause = AstUnknownClause {
            introducer: Some(tok.span),
            span: Span {
                start: action_start,
                end,
            },
            kind: UnknownKind::Clause,
            node_id: self.id_gen.next(),
        };
        extras.push(unknown_clause.clone());

        Ok(AstAlterSchemaAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end,
            },
            kind: AstAlterSchemaActionKind::Unknown(unknown_clause),
        })
    }

    /// Parse schema properties (DATA_RETENTION_TIME_IN_DAYS = value, etc.)
    fn parse_schema_properties(
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
            {
                break;
            }
            // Stop at WITH (for WITH MANAGED ACCESS or WITH TAG)
            if tok.lexeme(self.source).eq_ignore_ascii_case("WITH") {
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

            // Check if this is a known property
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex_up = tok.lexeme(self.source).to_uppercase();

                // Stop at Databricks clause keywords (handled by the post-properties loop)
                if matches!(
                    lex_up.as_str(),
                    "MANAGED" | "LOCATION" | "COLLATION" | "DBPROPERTIES"
                ) {
                    break;
                }

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
                    | "CATALOG_SYNC"
                    | "CLASSIFICATION_PROFILE" => {
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
                        let unknown_tok = self.advance().expect_invariant(
                            "unknown property: consumed after Identifier match in outer if",
                        );
                        // Consume until next known property or stop condition
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
                            if next.lexeme(self.source).eq_ignore_ascii_case("WITH") {
                                break;
                            }
                            if matches!(next.kind, TokenKind::Identifier { .. }) {
                                let next_up = next.lexeme(self.source).to_uppercase();
                                if next_up == "DATA_RETENTION_TIME_IN_DAYS"
                                    || next_up == "MAX_DATA_EXTENSION_TIME_IN_DAYS"
                                    || next_up == "EXTERNAL_VOLUME"
                                    || next_up == "CATALOG"
                                    || next_up == "CLASSIFICATION_PROFILE"
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

    /// Parse trailing COMMENT and TAG clauses for SCHEMA
    fn parse_schema_trailing_clauses(
        &mut self,
        comment_span: &mut Option<Span>,
        tag_span: &mut Option<Span>,
        _extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<()> {
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }

            // COMMENT [=] '...' (Snowflake uses =, Databricks omits =)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let start = tok.span.start;
                self.advance(); // COMMENT
                                // Optional = sign (Snowflake has it, Databricks may omit it)
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance(); // =
                    }
                }
                // String literal value
                if let Some(val) = self.peek_non_trivia() {
                    if matches!(val.kind, TokenKind::Literal(_)) {
                        *comment_span = Some(Span {
                            start,
                            end: val.span.end,
                        });
                        self.advance();
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

    /// Consume tokens until semicolon or EOF for schema, return end position
    fn consume_until_semi_or_eof_schema(&mut self) -> ParseResult<u32> {
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
}
