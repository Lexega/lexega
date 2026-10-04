// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PostgreSQL ALTER INDEX and REINDEX statements.
//!
//! ALTER INDEX forms:
//! - `ALTER INDEX [ IF EXISTS ] name RENAME TO new_name`
//! - `ALTER INDEX [ IF EXISTS ] name SET TABLESPACE tablespace_name`
//! - `ALTER INDEX [ IF EXISTS ] name ATTACH PARTITION index_name`
//! - `ALTER INDEX [ IF EXISTS ] name [NO] DEPENDS ON EXTENSION extension_name`
//! - `ALTER INDEX [ IF EXISTS ] name SET ( param = value [, ...] )`
//! - `ALTER INDEX [ IF EXISTS ] name RESET ( param [, ...] )`
//! - `ALTER INDEX [ IF EXISTS ] name ALTER [ COLUMN ] column_number SET STATISTICS integer`
//! - `ALTER INDEX ALL IN TABLESPACE name [ OWNED BY ... ] SET TABLESPACE new_ts [ NOWAIT ]`
//!
//! REINDEX forms:
//! - `REINDEX [ ( option [, ...] ) ] { INDEX | TABLE | SCHEMA } [ CONCURRENTLY ] name`
//! - `REINDEX [ ( option [, ...] ) ] { DATABASE | SYSTEM } [ CONCURRENTLY ] [ name ]`
//!
//! Token gotchas (verified via --debug-tokens):
//!   INDEX, REINDEX, TABLESPACE, ATTACH, DEPENDS, RESET, OWNED, NOWAIT,
//!   STATISTICS, SCHEMA, DATABASE, SYSTEM, CONCURRENTLY, VERBOSE, NO,
//!   EXTENSION → all Identifier
//!   TABLE → Keyword(Table)
//!   ALL → Keyword(All)
//!   IF, EXISTS, RENAME, TO, SET, ON, COLUMN, IN, BY → Keywords
//!   column_number → Literal(Number)
//!   true/false in REINDEX options → Literal(Boolean)

use crate::ast::types::{
    AlterIndexAction, AlterIndexMaintenance, AlterIndexSubAction, AstAlterIndex, AstReindex,
    AstStmt, ReindexTargetType,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxAlterIndexStmt, SyntaxReindexStmt};

impl<'a> Parser<'a> {
    // =========================================================================
    // ALTER INDEX
    // =========================================================================

    /// Parse: ALTER INDEX ...
    ///
    /// Dispatched from core.rs after ALTER detected + next token is Identifier "INDEX".
    /// Parser index is reset to ALTER token before calling this.
    pub(crate) fn try_parse_alter_index_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_index")?;
        let start_span = self.current_span();

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;

        // INDEX (Identifier)
        let _index_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;
        let index_keyword = self.last_token_id();

        // Check for ALL IN TABLESPACE form vs named form
        let action = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::All)) {
                // T-SQL `ALTER INDEX ALL ON <object> …` vs PG `ALL IN TABLESPACE …`
                if matches!(
                    self.peek_ahead(1).map(|t| &t.kind),
                    Some(TokenKind::Keyword(Keyword::On))
                ) {
                    let all_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["ALL".to_string()])?;
                    self.parse_alter_index_on_object(None, Some(all_tok.span))?
                } else {
                    self.parse_alter_index_all_in_tablespace()?
                }
            } else {
                self.parse_alter_index_named()?
            }
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected index name or ALL after ALTER INDEX".to_string(),
                },
            ));
        };

        let end = match &action {
            AlterIndexAction::Named { sub_action, .. } => match sub_action {
                AlterIndexSubAction::RenameTo { new_name, .. } => new_name.end,
                AlterIndexSubAction::SetTablespace {
                    tablespace_name, ..
                } => tablespace_name.end,
                AlterIndexSubAction::AttachPartition { index_name, .. } => index_name.end,
                AlterIndexSubAction::DependsOnExtension { extension_name, .. } => {
                    extension_name.end
                }
                AlterIndexSubAction::SetParams { params_span, .. } => params_span.end,
                AlterIndexSubAction::ResetParams { params_span, .. } => params_span.end,
                AlterIndexSubAction::AlterColumnStatistics {
                    statistics_value, ..
                } => statistics_value.end,
            },
            AlterIndexAction::AllInTablespace { end_pos, .. } => *end_pos,
            AlterIndexAction::OnObject {
                maintenance_span,
                tail_span,
                ..
            } => tail_span.map(|t| t.end).unwrap_or(maintenance_span.end),
        };

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_index_stmt(SyntaxAlterIndexStmt {
                alter_keyword,
                index_keyword,
                span: stmt_span,
            });

        let ast = AstAlterIndex {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            action,
        };
        Ok(AstStmt::AlterIndex(Box::new(ast)))
    }

    /// Parse ALTER INDEX [IF EXISTS] name <sub-action>
    fn parse_alter_index_named(&mut self) -> ParseResult<AlterIndexAction> {
        // Optional IF EXISTS
        let (if_span, exists_span) = self.try_parse_if_exists();

        // Index name (possibly schema-qualified)
        let name = self.parse_schema_qualified_name()?;

        // T-SQL: `ALTER INDEX name ON <object> <maintenance>` (PG has no ON here)
        if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::On))
        ) {
            return self.parse_alter_index_on_object(Some(name), None);
        }

        // Parse sub-action
        let sub_action = self.parse_alter_index_sub_action()?;

        Ok(AlterIndexAction::Named {
            if_span,
            exists_span,
            name,
            sub_action,
        })
    }

    /// Parse T-SQL `ON <object> { REBUILD | REORGANIZE | DISABLE | SET (...) } [tail]`.
    /// `name`/`all_span` carry the already-parsed target index designator.
    fn parse_alter_index_on_object(
        &mut self,
        name: Option<Span>,
        all_span: Option<Span>,
    ) -> ParseResult<AlterIndexAction> {
        // ON
        let on_span = self.expect_keyword(Keyword::On)?;

        // Target object (possibly schema-qualified)
        let object = self.parse_schema_qualified_name()?;

        // Maintenance keyword: REBUILD | REORGANIZE | DISABLE | SET
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message:
                        "Expected REBUILD, REORGANIZE, DISABLE, or SET after ALTER INDEX ON object"
                            .to_string(),
                },
            )
        })?;
        let lx = tok.lexeme(self.source);
        let (maintenance, maintenance_span) = if lx.eq_ignore_ascii_case("REBUILD") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["REBUILD".to_string()])?;
            (AlterIndexMaintenance::Rebuild, t.span)
        } else if lx.eq_ignore_ascii_case("REORGANIZE") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["REORGANIZE".to_string()])?;
            (AlterIndexMaintenance::Reorganize, t.span)
        } else if lx.eq_ignore_ascii_case("DISABLE") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["DISABLE".to_string()])?;
            (AlterIndexMaintenance::Disable, t.span)
        } else if lx.eq_ignore_ascii_case("SET") {
            let t = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
            (AlterIndexMaintenance::Set, t.span)
        } else {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Unknown ALTER INDEX action: '{}'", tok.lexeme(self.source)),
                },
            ));
        };

        // Trailing options, preserved verbatim: `PARTITION = …`, `WITH (…)`, or `SET (…)`.
        // Consumed permissively (paren-balanced) so the statement stays whole.
        let mut tail_start: Option<u32> = None;
        let mut tail_end = maintenance_span.end;

        // PARTITION = { ALL | number }
        if let Some(t) = self.peek_non_trivia() {
            if t.lexeme(self.source).eq_ignore_ascii_case("PARTITION") {
                let p = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["PARTITION".to_string()])?;
                tail_start.get_or_insert(p.span.start);
                tail_end = p.span.end;
                // `=` and the value token (ALL or a number)
                if let Some(eq) = self.peek_non_trivia() {
                    if matches!(eq.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                        let e = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                        tail_end = e.span.end;
                        if self.peek_non_trivia().is_some() {
                            let v = self
                                .advance()
                                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                            tail_end = v.span.end;
                        }
                    }
                }
            }
        }

        // WITH ( options ) — or SET ( options ) where the maintenance keyword is SET
        if let Some(t) = self.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Keyword(Keyword::With)) {
                let w = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
                tail_start.get_or_insert(w.span.start);
                tail_end = w.span.end;
                if let Some(lp) = self.peek_non_trivia() {
                    if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let group = self.consume_balanced_parens()?;
                        tail_end = group.end;
                    }
                }
            }
        }
        // SET ( ... ) body (the `(` directly follows the SET keyword)
        if let Some(lp) = self.peek_non_trivia() {
            if matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let group = self.consume_balanced_parens()?;
                tail_start.get_or_insert(group.start);
                tail_end = group.end;
            }
        }

        let tail_span = tail_start.map(|start| Span {
            start,
            end: tail_end,
        });

        Ok(AlterIndexAction::OnObject {
            name,
            all_span,
            on_span,
            object,
            maintenance,
            maintenance_span,
            tail_span,
        })
    }

    /// Parse the sub-action after ALTER INDEX name ...
    fn parse_alter_index_sub_action(&mut self) -> ParseResult<AlterIndexSubAction> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected action after ALTER INDEX name".to_string(),
                },
            )
        })?;

        match tok.kind {
            // RENAME TO new_name
            TokenKind::Keyword(Keyword::Rename) => {
                let rename_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
                let to_span = self.expect_keyword(Keyword::To)?;
                let new_name = self.parse_schema_qualified_name()?;
                Ok(AlterIndexSubAction::RenameTo {
                    rename_span: rename_tok.span,
                    to_span,
                    new_name,
                })
            }

            // SET — could be SET TABLESPACE, SET ( params ), or via ALTER COLUMN ... SET STATISTICS
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
                let next = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TABLESPACE or '(' after SET".to_string(),
                        },
                    )
                })?;

                if matches!(next.kind, TokenKind::Identifier { .. })
                    && next.lexeme(self.source).eq_ignore_ascii_case("TABLESPACE")
                {
                    // SET TABLESPACE tablespace_name
                    let tablespace_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["TABLESPACE".to_string()])?;
                    let tablespace_name = self.parse_schema_qualified_name()?;
                    Ok(AlterIndexSubAction::SetTablespace {
                        set_span: set_tok.span,
                        tablespace_span: tablespace_tok.span,
                        tablespace_name,
                    })
                } else if matches!(next.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    // SET ( param = value [, ...] )
                    let params_span = self.consume_balanced_parens()?;
                    Ok(AlterIndexSubAction::SetParams {
                        set_span: set_tok.span,
                        params_span,
                    })
                } else {
                    Err(ParseError::new(
                        next.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TABLESPACE or '(' after SET in ALTER INDEX"
                                .to_string(),
                        },
                    ))
                }
            }

            // ATTACH PARTITION
            TokenKind::Identifier { .. }
                if tok.lexeme(self.source).eq_ignore_ascii_case("ATTACH") =>
            {
                let attach_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ATTACH".to_string()])?;
                // PARTITION keyword
                let mut partition_span: Option<Span> = None;
                if let Some(ptok) = self.peek_non_trivia() {
                    if matches!(ptok.kind, TokenKind::Keyword(Keyword::Partition)) {
                        let p = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["PARTITION".to_string()])?;
                        partition_span = Some(p.span);
                    }
                }
                let index_name = self.parse_schema_qualified_name()?;
                Ok(AlterIndexSubAction::AttachPartition {
                    attach_span: attach_tok.span,
                    partition_span,
                    index_name,
                })
            }

            // DEPENDS ON EXTENSION
            TokenKind::Identifier { .. }
                if tok.lexeme(self.source).eq_ignore_ascii_case("DEPENDS") =>
            {
                let depends_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["DEPENDS".to_string()])?;
                let on_span = self.expect_keyword(Keyword::On)?;
                // EXTENSION (Identifier)
                let ext_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXTENSION".to_string()])?;
                let extension_name = self.parse_schema_qualified_name()?;
                Ok(AlterIndexSubAction::DependsOnExtension {
                    no_span: None,
                    depends_span: depends_tok.span,
                    on_span,
                    extension_span: ext_tok.span,
                    extension_name,
                })
            }

            // NO DEPENDS ON EXTENSION
            TokenKind::Identifier { .. } if tok.lexeme(self.source).eq_ignore_ascii_case("NO") => {
                let no_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NO".to_string()])?;
                // DEPENDS (Identifier)
                let depends_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected DEPENDS after NO".to_string(),
                        },
                    )
                })?;
                if matches!(depends_tok.kind, TokenKind::Identifier { .. })
                    && depends_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("DEPENDS")
                {
                    self.advance(); // consume DEPENDS
                } else {
                    return Err(ParseError::new(
                        depends_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected DEPENDS after NO".to_string(),
                        },
                    ));
                }
                let on_span = self.expect_keyword(Keyword::On)?;
                // EXTENSION (Identifier)
                let ext_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXTENSION".to_string()])?;
                let extension_name = self.parse_schema_qualified_name()?;
                Ok(AlterIndexSubAction::DependsOnExtension {
                    no_span: Some(no_tok.span),
                    depends_span: depends_tok.span,
                    on_span,
                    extension_span: ext_tok.span,
                    extension_name,
                })
            }

            // RESET ( param [, ...] )
            TokenKind::Identifier { .. }
                if tok.lexeme(self.source).eq_ignore_ascii_case("RESET") =>
            {
                let reset_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RESET".to_string()])?;
                let params_span = self.consume_balanced_parens()?;
                Ok(AlterIndexSubAction::ResetParams {
                    reset_span: reset_tok.span,
                    params_span,
                })
            }

            // ALTER [ COLUMN ] column_number SET STATISTICS integer
            TokenKind::Keyword(Keyword::Alter) => {
                let alter_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
                // Optional COLUMN keyword
                let column_span = if let Some(col_tok) = self.peek_non_trivia() {
                    if matches!(col_tok.kind, TokenKind::Keyword(Keyword::Column)) {
                        let col = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["COLUMN".to_string()])?;
                        Some(col.span)
                    } else {
                        None
                    }
                } else {
                    None
                };
                // column_number (Literal(Number))
                let col_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["column number".to_string()])?;
                let column_number = col_tok.span;

                // SET
                let set_span = self.expect_keyword(Keyword::Set)?;

                // STATISTICS (Identifier)
                let stats_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected STATISTICS after SET".to_string(),
                        },
                    )
                })?;
                if matches!(stats_tok.kind, TokenKind::Identifier { .. })
                    && stats_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("STATISTICS")
                {
                    self.advance(); // consume STATISTICS
                } else {
                    return Err(ParseError::new(
                        stats_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected STATISTICS after SET".to_string(),
                        },
                    ));
                }

                // integer value
                let val_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["integer value".to_string()])?;
                let statistics_value = val_tok.span;

                Ok(AlterIndexSubAction::AlterColumnStatistics {
                    alter_span: alter_tok.span,
                    column_span,
                    column_number,
                    set_span,
                    statistics_span: stats_tok.span,
                    statistics_value,
                })
            }

            _ => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Unknown ALTER INDEX action: '{}'", tok.lexeme(self.source)),
                },
            )),
        }
    }

    /// Parse ALTER INDEX ALL IN TABLESPACE name [OWNED BY role [, ...]] SET TABLESPACE new_ts [NOWAIT]
    fn parse_alter_index_all_in_tablespace(&mut self) -> ParseResult<AlterIndexAction> {
        // ALL
        let all_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALL".to_string()])?;
        // IN
        let in_span = self.expect_keyword(Keyword::In)?;
        // TABLESPACE (Identifier)
        let ts_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLESPACE".to_string()])?;
        if !(matches!(ts_tok.kind, TokenKind::Identifier { .. })
            && ts_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("TABLESPACE"))
        {
            return Err(ParseError::new(
                ts_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLESPACE after ALL IN".to_string(),
                },
            ));
        }
        // tablespace name
        let tablespace_name = self.parse_schema_qualified_name()?;

        // Optional OWNED BY role_name [, ...]
        let mut owned_by_roles = Vec::new();
        let mut owned_span: Option<Span> = None;
        let mut by_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("OWNED")
            {
                let owned_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OWNED".to_string()])?;
                owned_span = Some(owned_tok.span);
                by_span = Some(self.expect_keyword(Keyword::By)?);
                // Parse role list
                let role_name = self.parse_schema_qualified_name()?;
                owned_by_roles.push(role_name);
                // Additional roles separated by commas
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                        self.advance(); // consume comma
                        let role_name = self.parse_schema_qualified_name()?;
                        owned_by_roles.push(role_name);
                    } else {
                        break;
                    }
                }
            }
        }

        // SET TABLESPACE new_tablespace_name
        let set_span = self.expect_keyword(Keyword::Set)?;
        let ts_tok2 = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLESPACE".to_string()])?;
        if !(matches!(ts_tok2.kind, TokenKind::Identifier { .. })
            && ts_tok2
                .lexeme(self.source)
                .eq_ignore_ascii_case("TABLESPACE"))
        {
            return Err(ParseError::new(
                ts_tok2.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLESPACE after SET".to_string(),
                },
            ));
        }
        let new_tablespace_name = self.parse_schema_qualified_name()?;
        let mut end_pos = new_tablespace_name.end;

        // Optional NOWAIT
        let mut nowait_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("NOWAIT")
            {
                let nw = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NOWAIT".to_string()])?; // consume NOWAIT
                end_pos = nw.span.end;
                nowait_span = Some(nw.span);
            }
        }

        Ok(AlterIndexAction::AllInTablespace {
            all_span: all_tok.span,
            in_span,
            tablespace_span: ts_tok.span,
            tablespace_name,
            owned_span,
            by_span,
            owned_by_roles,
            set_span,
            set_tablespace_span: ts_tok2.span,
            new_tablespace_name,
            nowait_span,
            end_pos,
        })
    }

    // =========================================================================
    // REINDEX
    // =========================================================================

    /// Parse: REINDEX [ ( option [, ...] ) ] target_type [ CONCURRENTLY ] [ name ]
    ///
    /// Dispatched from core.rs Identifier catch-all (REINDEX is Identifier).
    pub(crate) fn try_parse_reindex_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("reindex")?;
        let start_span = self.current_span();

        // REINDEX (Identifier)
        let reindex_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["REINDEX".to_string()])?;
        let reindex_keyword = self.last_token_id();
        let start = reindex_tok.span.start;

        // Optional parenthesized options: ( CONCURRENTLY [bool], TABLESPACE name, VERBOSE [bool] )
        let options_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                Some(self.consume_balanced_parens()?)
            } else {
                None
            }
        } else {
            None
        };

        // Target type: INDEX | TABLE | SCHEMA | DATABASE | SYSTEM
        let (target_type, target_type_span) = self.parse_reindex_target_type()?;
        let mut end = target_type_span.end;

        // Optional CONCURRENTLY
        let mut concurrently_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("CONCURRENTLY")
            {
                let conc_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["CONCURRENTLY".to_string()])?;
                end = tok.span.end;
                concurrently_span = Some(conc_tok.span);
            }
        }

        // Name: required for INDEX/TABLE/SCHEMA, optional for DATABASE/SYSTEM
        let name = match target_type {
            ReindexTargetType::Index | ReindexTargetType::Table | ReindexTargetType::Schema => {
                let name_span = self.parse_schema_qualified_name()?;
                end = name_span.end;
                Some(name_span)
            }
            ReindexTargetType::Database | ReindexTargetType::System => {
                // Name is optional
                if let Some(tok) = self.peek_non_trivia() {
                    if !matches!(
                        tok.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) && !self.is_statement_start_token(tok)
                    {
                        let name_span = self.parse_schema_qualified_name()?;
                        end = name_span.end;
                        Some(name_span)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        let stmt_span = Span { start, end };

        let syntax_id = self.syntax_arena.alloc_reindex_stmt(SyntaxReindexStmt {
            reindex_keyword,
            span: stmt_span,
        });

        let ast = AstReindex {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            options_span,
            target_type,
            target_type_span,
            concurrently_span,
            name,
        };
        Ok(AstStmt::Reindex(Box::new(ast)))
    }

    /// Parse the target type for REINDEX: INDEX | TABLE | SCHEMA | DATABASE | SYSTEM
    fn parse_reindex_target_type(&mut self) -> ParseResult<(ReindexTargetType, Span)> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected target type (INDEX, TABLE, SCHEMA, DATABASE, SYSTEM) after REINDEX".to_string(),
                },
            )
        })?;

        match tok.kind {
            // TABLE is the only Keyword target type
            TokenKind::Keyword(Keyword::Table) => {
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
                Ok((ReindexTargetType::Table, t.span))
            }
            // All others are Identifiers
            TokenKind::Identifier { .. } => {
                let lexeme = tok.lexeme(self.source);
                if lexeme.eq_ignore_ascii_case("INDEX") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;
                    Ok((ReindexTargetType::Index, t.span))
                } else if lexeme.eq_ignore_ascii_case("SCHEMA") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["SCHEMA".to_string()])?;
                    Ok((ReindexTargetType::Schema, t.span))
                } else if lexeme.eq_ignore_ascii_case("DATABASE") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["DATABASE".to_string()])?;
                    Ok((ReindexTargetType::Database, t.span))
                } else if lexeme.eq_ignore_ascii_case("SYSTEM") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["SYSTEM".to_string()])?;
                    Ok((ReindexTargetType::System, t.span))
                } else {
                    Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected INDEX, TABLE, SCHEMA, DATABASE, or SYSTEM; got '{}'",
                                lexeme
                            ),
                        },
                    ))
                }
            }
            _ => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected target type after REINDEX".to_string(),
                },
            )),
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Parse a possibly schema-qualified name (e.g., `schema.name` or just `name`).
    /// Returns the full span covering the entire qualified name.
    fn parse_schema_qualified_name(&mut self) -> ParseResult<Span> {
        let first_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["name".to_string()])?;
        let start = first_tok.span.start;
        let mut end = first_tok.span.end;

        // Check for dot-separated qualification
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                let part = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["qualified name part".to_string()])?;
                end = part.span.end;
            } else {
                break;
            }
        }

        Ok(Span { start, end })
    }

    /// Try to parse IF EXISTS. Returns true if found.
    fn try_parse_if_exists(&mut self) -> (Option<Span>, Option<Span>) {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let saved = self.idx;
                let if_tok = self.advance().expect_invariant("IF token after peek"); // consume IF
                if let Some(tok2) = self.peek_non_trivia() {
                    if matches!(tok2.kind, TokenKind::Keyword(Keyword::Exists)) {
                        let exists_tok = self.advance().expect_invariant("EXISTS token after peek"); // consume EXISTS
                        return (Some(if_tok.span), Some(exists_tok.span));
                    }
                }
                // Not IF EXISTS, rollback
                self.idx = saved;
            }
        }
        (None, None)
    }

    /// Check if a token could start a new statement (used for optional name detection).
    fn is_statement_start_token(&self, tok: &crate::lexer::Token) -> bool {
        matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Select)
                | TokenKind::Keyword(Keyword::Insert)
                | TokenKind::Keyword(Keyword::Update)
                | TokenKind::Keyword(Keyword::Delete)
                | TokenKind::Keyword(Keyword::Create)
                | TokenKind::Keyword(Keyword::Alter)
                | TokenKind::Keyword(Keyword::Drop)
                | TokenKind::Keyword(Keyword::Grant)
                | TokenKind::Keyword(Keyword::Revoke)
                | TokenKind::Keyword(Keyword::Deny)
                | TokenKind::Keyword(Keyword::Truncate)
                | TokenKind::Keyword(Keyword::Begin)
                | TokenKind::Keyword(Keyword::Commit)
                | TokenKind::Keyword(Keyword::Rollback)
        )
    }
}
