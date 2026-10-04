// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// ALTER TABLE statement parsing
//
// Follows the standard parser infrastructure patterns:
// - Uses Parser methods (peek_non_trivia, advance, etc.) instead of manual token scanning
// - Integrates parse_expr() for expressions (CLUSTER BY, DEFAULT values)
// - Parses column definitions properly for ADD COLUMN
// - Has recursion protection
// - Consistent error handling with ParseResult<T>

use crate::ast::{
    AstAlterTable, AstAlterTableAction, AstAlterTableActionKind, AstRowLevelSecurityMode, AstStmt,
};
use crate::ast::{AstAlterTableColumnDef, AstDataType};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_table::{is_column_tail_clause_lexeme, is_generated_storage_lexeme};

/// `ALTER TABLE ... ADD <X>` starters that introduce something other than a
/// column definition: anonymous constraints, indexes, partitions, system
/// periods, search optimization, old-style MSSQL `ADD DEFAULT ... FOR`,
/// PG `ADD IF NOT EXISTS`, row policies. These keep the Unknown path.
fn is_non_column_add_starter(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("PRIMARY")
        || lexeme.eq_ignore_ascii_case("UNIQUE")
        || lexeme.eq_ignore_ascii_case("FOREIGN")
        || lexeme.eq_ignore_ascii_case("CHECK")
        || lexeme.eq_ignore_ascii_case("INDEX")
        || lexeme.eq_ignore_ascii_case("KEY")
        || lexeme.eq_ignore_ascii_case("FULLTEXT")
        || lexeme.eq_ignore_ascii_case("SPATIAL")
        || lexeme.eq_ignore_ascii_case("PARTITION")
        || lexeme.eq_ignore_ascii_case("SEARCH")
        || lexeme.eq_ignore_ascii_case("PERIOD")
        || lexeme.eq_ignore_ascii_case("ROW")
        || lexeme.eq_ignore_ascii_case("IF")
        || lexeme.eq_ignore_ascii_case("DEFAULT")
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_alter_table_stmt_with_parser(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_table")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_keyword = self.last_token_id();

        // TABLE
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;
        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table))
            && !table_tok.lexeme(self.source).eq_ignore_ascii_case("TABLE")
        {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "ALTER currently only supports ALTER TABLE".to_string(),
                },
            ));
        }
        let table_span = table_tok.span;
        let table_keyword = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_keyword, exists_keyword) = self.parse_if_exists_clause()?;

        // Table name
        let name_span = self.parse_table_name()?;

        // Parse actions
        let actions_start = self.current_span().start;
        let (actions, action_ids, commas) = self.parse_alter_table_actions()?;
        let actions_end = if let Some(last) = actions.last() {
            last.span.end
        } else {
            name_span.end
        };

        let actions_span = Span {
            start: actions_start,
            end: actions_end,
        };
        let stmt_span = Span {
            start: alter_span.start,
            end: actions_end,
        };

        // Build CST
        let syntax_action_list = crate::syntax::SyntaxAlterTableActionList {
            actions: action_ids,
            commas,
            span: actions_span,
        };
        let syntax_action_list_id = self
            .syntax_arena
            .alloc_alter_table_action_list(syntax_action_list);

        let syntax_stmt = crate::syntax::SyntaxAlterTableStmt {
            alter_keyword,
            table_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            actions: syntax_action_list_id,
            span: stmt_span,
        };
        let syntax_stmt_id = self.syntax_arena.alloc_alter_table_stmt(syntax_stmt);

        Ok(AstStmt::AlterTable(Box::new(AstAlterTable {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_stmt_id),
            alter_span,
            table_span,
            if_exists_span,
            name_span,
            actions_span,
            actions,
        })))
    }

    fn parse_if_exists_clause(
        &mut self,
    ) -> ParseResult<(
        Option<Span>,
        Option<crate::cst::TokenId>,
        Option<crate::cst::TokenId>,
    )> {
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("IF") {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword consumed after match");
                let if_keyword = Some(self.last_token_id());

                if let Some(exists_tok) = self.peek_non_trivia() {
                    if exists_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("EXISTS")
                    {
                        let e = self
                            .advance()
                            .expect_invariant("EXISTS keyword consumed after match");
                        let exists_keyword = Some(self.last_token_id());
                        let if_exists_span = Some(Span {
                            start: if_tok.span.start,
                            end: e.span.end,
                        });
                        return Ok((if_exists_span, if_keyword, exists_keyword));
                    }
                }

                return Err(ParseError::new(
                    if_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "ALTER TABLE IF requires EXISTS".to_string(),
                    },
                ));
            }
        }
        Ok((None, None, None))
    }

    fn parse_table_name(&mut self) -> ParseResult<Span> {
        let start_pos = self.current_span().start;
        let mut end_pos = start_pos;
        let mut has_name = false;

        while let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("ADD")
                || tok.lexeme(self.source).eq_ignore_ascii_case("DROP")
                || tok.lexeme(self.source).eq_ignore_ascii_case("RENAME")
                || tok.lexeme(self.source).eq_ignore_ascii_case("SWAP")
                || tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                || tok.lexeme(self.source).eq_ignore_ascii_case("MODIFY")  // MODIFY COLUMN is an alias for ALTER COLUMN
                || tok.lexeme(self.source).eq_ignore_ascii_case("CLUSTER")
                || tok.lexeme(self.source).eq_ignore_ascii_case("SET")
                || tok.lexeme(self.source).eq_ignore_ascii_case("UNSET")
                || tok.lexeme(self.source).eq_ignore_ascii_case("SUSPEND")
                || tok.lexeme(self.source).eq_ignore_ascii_case("RESUME")
                // ROW LEVEL SECURITY toggle starters.
                || tok.lexeme(self.source).eq_ignore_ascii_case("ENABLE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("DISABLE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("FORCE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("NO")
                || matches!(tok.kind, TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi))
            {
                break;
            }
            let t = self
                .advance()
                .expect_invariant("table name token consumed after peek in parse_table_name");
            end_pos = t.span.end;
            has_name = true;
        }

        if !has_name {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "ALTER TABLE requires a table name".to_string(),
                },
            ));
        }

        Ok(Span {
            start: start_pos,
            end: end_pos,
        })
    }

    fn parse_alter_table_actions(
        &mut self,
    ) -> ParseResult<(
        Vec<AstAlterTableAction>,
        Vec<crate::syntax::SyntaxAlterTableActionId>,
        Vec<crate::cst::TokenId>,
    )> {
        let mut actions = Vec::new();
        let mut action_ids = Vec::new();
        let mut commas = Vec::new();

        if self.peek_non_trivia().is_none()
            || matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Eof) | Some(TokenKind::Punctuation(Punctuation::Semi))
            )
        {
            return Ok((actions, action_ids, commas));
        }

        loop {
            let action = self.parse_single_alter_action()?;
            let syntax_action = crate::syntax::SyntaxAlterTableAction {
                leading_keyword: None,
                span: action.span,
            };
            let syntax_id = self.syntax_arena.alloc_alter_table_action(syntax_action);
            action_ids.push(syntax_id);
            actions.push(action);

            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    let _ = self.advance();
                    commas.push(self.last_token_id());
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok((actions, action_ids, commas))
    }

    fn parse_single_alter_action(&mut self) -> ParseResult<AstAlterTableAction> {
        let start_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ALTER TABLE action".to_string(),
                },
            )
        })?;

        let action_start = start_tok.span.start;
        let kind: AstAlterTableActionKind;

        // Check for governance actions first (they start with ADD/DROP but have specific patterns)
        if start_tok.lexeme(self.source).eq_ignore_ascii_case("ADD")
            && self.is_row_access_policy_pattern(1)
        {
            kind = self.parse_governance_action()?;
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("DROP") {
            // Check for DROP ALL ROW ACCESS POLICIES or DROP ROW ACCESS POLICY
            if self.is_drop_all_row_access_policies_pattern()
                || self.is_row_access_policy_pattern(1)
            {
                kind = self.parse_governance_action()?;
            } else {
                kind = self.parse_drop_action()?;
            }
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("ADD") {
            kind = self.parse_add_action()?;
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("RENAME") {
            kind = self.parse_rename_action()?;
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
            || start_tok.lexeme(self.source).eq_ignore_ascii_case("MODIFY")
        {
            // MODIFY COLUMN is an alias for ALTER COLUMN in Snowflake
            kind = self.parse_alter_column_action()?;
        } else if start_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CLUSTER")
        {
            kind = self.parse_cluster_by_action()?;
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
            // Check for table-level policies: SET AGGREGATION POLICY or SET JOIN POLICY
            if self.is_table_level_policy_pattern() {
                kind = self.parse_governance_action()?;
            } else {
                kind = self.parse_set_action()?;
            }
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
            // Check for table-level policies: UNSET AGGREGATION POLICY or UNSET JOIN POLICY
            if self.is_table_level_policy_pattern() {
                kind = self.parse_governance_action()?;
            } else {
                kind = self.parse_unset_action()?;
            }
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("SWAP") {
            kind = self.parse_swap_action()?;
        } else if start_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SUSPEND")
            || start_tok.lexeme(self.source).eq_ignore_ascii_case("RESUME")
        {
            kind = self.parse_suspend_resume_action()?;
        } else if self.is_row_level_security_at() {
            kind = self.parse_row_level_security_action()?;
        } else {
            kind = self.parse_governance_action()?;
        }

        let action_end = self.peek().map(|t| t.span.start).unwrap_or(action_start);
        let span = Span {
            start: action_start,
            end: action_end,
        };

        Ok(AstAlterTableAction {
            node_id: self.id_gen.next(),
            span,
            syntax_id: None,
            kind,
        })
    }

    fn parse_add_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let add_tok = self
            .advance()
            .expect_invariant("ADD keyword consumed after caller match");
        let add_span = Some(add_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("COLUMN")
                || tok.lexeme(self.source).eq_ignore_ascii_case("COLUMNS")
            {
                let col_tok = self
                    .advance()
                    .expect_invariant("COLUMN keyword consumed after match in parse_add_action");
                let column_span = Some(col_tok.span);
                let columns = self.parse_column_definitions()?;
                let col_defs_start = col_tok.span.end;
                let columns_span = if let Some(last_col) = columns.last() {
                    Span {
                        start: col_defs_start,
                        end: last_col.full_span.end,
                    }
                } else {
                    Span {
                        start: col_defs_start,
                        end: col_tok.span.end,
                    }
                };

                return Ok(AstAlterTableActionKind::AddColumn {
                    add_span,
                    column_span,
                    columns_span,
                    columns,
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT") {
                let constraint_tok = self.advance().expect_invariant(
                    "CONSTRAINT keyword consumed after match in parse_add_action",
                );
                let details_start = constraint_tok.span.end;
                let end = self.consume_until_comma_or_end()?;

                return Ok(AstAlterTableActionKind::AddConstraint {
                    add_span,
                    constraint_span: Some(constraint_tok.span),
                    details_span: Span {
                        start: details_start,
                        end,
                    },
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("DATA")
                && self
                    .peek_at(self.idx + 1)
                    .is_some_and(|t2| t2.lexeme(self.source).eq_ignore_ascii_case("METRIC"))
            {
                // ADD DATA METRIC FUNCTION <name> ON (<cols>)
                return self.parse_add_data_metric_function(add_span);
            } else if self.can_be_identifier_token(tok)
                && !is_non_column_add_starter(tok.lexeme(self.source))
                && self.peek_at(self.idx + 1).is_some_and(|t2| {
                    self.can_be_identifier_token(t2)
                        || matches!(t2.kind, TokenKind::Keyword(Keyword::As))
                })
            {
                // Bare `ADD <column-def>` (T-SQL idiom; accepted by most
                // dialects). Guard requires name + plausible type start or
                // AS (computed column); anything else stays Unknown.
                let col_defs_start = add_tok.span.end;
                let columns = self.parse_column_definitions()?;
                let columns_span = if let Some(last_col) = columns.last() {
                    Span {
                        start: col_defs_start,
                        end: last_col.full_span.end,
                    }
                } else {
                    Span {
                        start: col_defs_start,
                        end: add_tok.span.end,
                    }
                };

                return Ok(AstAlterTableActionKind::AddColumn {
                    add_span,
                    column_span: None,
                    columns_span,
                    columns,
                });
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span {
                start: add_tok.span.start,
                end,
            },
        })
    }

    fn parse_drop_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let drop_tok = self
            .advance()
            .expect_invariant("DROP keyword consumed after caller match");
        let drop_span = Some(drop_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            if self.is_row_filter_pattern(0) {
                let row_tok = self
                    .advance()
                    .expect_invariant("ROW consumed after DROP for row filter");
                let filter_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        row_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected FILTER after ROW".to_string(),
                        },
                    )
                })?;

                return Ok(AstAlterTableActionKind::DropRowFilter {
                    drop_span,
                    row_span: Some(row_tok.span),
                    filter_span: Some(filter_tok.span),
                });
            }

            if tok.lexeme(self.source).eq_ignore_ascii_case("DATA")
                && self
                    .peek_at(self.idx + 1)
                    .is_some_and(|t2| t2.lexeme(self.source).eq_ignore_ascii_case("METRIC"))
            {
                // DROP DATA METRIC FUNCTION <name> ON (<cols>)
                return self.parse_drop_data_metric_function(drop_span);
            }

            if tok.lexeme(self.source).eq_ignore_ascii_case("COLUMN")
                || tok.lexeme(self.source).eq_ignore_ascii_case("COLUMNS")
            {
                let col_tok = self
                    .advance()
                    .expect_invariant("COLUMN keyword consumed after match in parse_drop_action");
                let column_span = Some(col_tok.span);
                let col_names_start = col_tok.span.end;
                let end = self.consume_until_comma_or_end()?;

                return Ok(AstAlterTableActionKind::DropColumn {
                    drop_span,
                    column_span,
                    columns_span: Span {
                        start: col_names_start,
                        end,
                    },
                    columns: Vec::new(),
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT") {
                let constraint_tok = self.advance().expect_invariant(
                    "CONSTRAINT keyword consumed after match in parse_drop_action",
                );
                let name_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        constraint_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected constraint name after CONSTRAINT".to_string(),
                        },
                    )
                })?;
                let name_span = name_tok.span;
                let _ = self.advance();

                return Ok(AstAlterTableActionKind::DropConstraint {
                    drop_span,
                    constraint_span: Some(constraint_tok.span),
                    name_span,
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CLUSTERING") {
                let clustering_tok = self
                    .advance()
                    .expect_invariant("CLUSTERING keyword consumed after match");
                let key_span = if let Some(k) = self.peek_non_trivia() {
                    if k.lexeme(self.source).eq_ignore_ascii_case("KEY") {
                        let kt = self
                            .advance()
                            .expect_invariant("KEY keyword consumed after match");
                        Some(kt.span)
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(AstAlterTableActionKind::DropClusteringKey {
                    drop_span,
                    clustering_span: Some(clustering_tok.span),
                    key_span,
                });
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Primary)) {
                // BigQuery: DROP PRIMARY KEY [IF EXISTS]
                let primary_tok = self
                    .advance()
                    .expect_invariant("PRIMARY keyword consumed after match");
                let primary_span = Some(primary_tok.span);
                let key_span = if let Some(k) = self.peek_non_trivia() {
                    if matches!(k.kind, TokenKind::Keyword(Keyword::Key)) {
                        let kt = self
                            .advance()
                            .expect_invariant("KEY keyword consumed after match");
                        Some(kt.span)
                    } else {
                        None
                    }
                } else {
                    None
                };
                // Optional IF EXISTS
                let if_exists_span = if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::If)) {
                        let if_tok = self.advance().expect_invariant("IF consumed");
                        if let Some(exists_tok) = self.peek_non_trivia() {
                            if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                                let et = self.advance().expect_invariant("EXISTS consumed");
                                Some(Span {
                                    start: if_tok.span.start,
                                    end: et.span.end,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                return Ok(AstAlterTableActionKind::DropPrimaryKey {
                    drop_span,
                    primary_span,
                    key_span,
                    if_exists_span,
                });
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span {
                start: drop_tok.span.start,
                end,
            },
        })
    }

    fn parse_rename_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let rename_tok = self
            .advance()
            .expect_invariant("RENAME keyword consumed after caller match");
        let rename_span = Some(rename_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("COLUMN") {
                let col_tok = self
                    .advance()
                    .expect_invariant("COLUMN keyword consumed after match in parse_rename_action");
                let old_name_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        col_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected old column name after RENAME COLUMN".to_string(),
                        },
                    )
                })?;
                let old_name_span = old_name_tok.span;

                let to_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        old_name_span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected TO after old column name".to_string(),
                        },
                    )
                })?;

                let to_span = if to_tok.lexeme(self.source).eq_ignore_ascii_case("TO") {
                    let t = self
                        .advance()
                        .expect_invariant("TO keyword consumed after match");
                    Some(t.span)
                } else {
                    None
                };

                let new_name_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected new column name after TO".to_string(),
                        },
                    )
                })?;
                let new_name_span = new_name_tok.span;

                return Ok(AstAlterTableActionKind::RenameColumn {
                    rename_span,
                    column_span: Some(col_tok.span),
                    old_name_span,
                    to_span,
                    new_name_span,
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("TO") {
                let to_tok = self
                    .advance()
                    .expect_invariant("TO keyword consumed after match in parse_rename_action");
                // Qualified targets (schema.y) are valid; dot-aware like SWAP WITH below.
                let new_name_span = self.parse_qualified_name_span()?;

                return Ok(AstAlterTableActionKind::RenameTo {
                    rename_span,
                    to_span: Some(to_tok.span),
                    new_name_span,
                });
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span {
                start: rename_tok.span.start,
                end,
            },
        })
    }

    fn parse_alter_column_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let alter_tok = self
            .advance()
            .expect_invariant("ALTER keyword consumed after caller match");
        let alter_span = Some(alter_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("COLUMN") {
                let col_tok = self.advance().expect_invariant(
                    "COLUMN keyword consumed after match in parse_alter_column_action",
                );
                let name_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        col_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected column name after ALTER/MODIFY COLUMN".to_string(),
                        },
                    )
                })?;
                let column_name_span = name_tok.span;

                // Check for masking/projection policy patterns
                if let Some(next_tok) = self.peek_non_trivia() {
                    if next_tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
                        if self.is_set_mask_pattern() {
                            return self.parse_set_column_mask(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        }
                        // Look ahead for MASKING POLICY or PROJECTION POLICY
                        if self.is_masking_policy_pattern() {
                            return self.parse_set_column_masking_policy(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        } else if self.is_projection_policy_pattern() {
                            return self.parse_set_column_projection_policy(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        }
                        // BigQuery: ALTER COLUMN <col> SET ...
                        return self.parse_bq_alter_column_set(
                            alter_span,
                            Some(col_tok.span),
                            column_name_span,
                        );
                    } else if next_tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
                        // Look ahead for MASKING POLICY or PROJECTION POLICY
                        if self.is_masking_policy_pattern() {
                            return self.parse_unset_column_masking_policy(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        } else if self.is_projection_policy_pattern() {
                            return self.parse_unset_column_projection_policy(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        }
                    } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Drop)) {
                        if self.is_drop_mask_pattern() {
                            return self.parse_drop_column_mask(
                                alter_span,
                                Some(col_tok.span),
                                column_name_span,
                            );
                        }
                        // BigQuery: ALTER COLUMN <col> DROP ...
                        return self.parse_bq_alter_column_drop(
                            alter_span,
                            Some(col_tok.span),
                            column_name_span,
                        );
                    }
                }

                // Default: generic ALTER COLUMN
                let op_start = column_name_span.end;
                let end = self.consume_until_comma_or_end()?;

                return Ok(AstAlterTableActionKind::AlterColumn {
                    alter_span,
                    column_span: Some(col_tok.span),
                    column_name_span,
                    operation_span: Span {
                        start: op_start,
                        end,
                    },
                });
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span {
                start: alter_tok.span.start,
                end,
            },
        })
    }

    fn parse_cluster_by_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let cluster_tok = self
            .advance()
            .expect_invariant("CLUSTER keyword consumed after caller match");
        let cluster_span = Some(cluster_tok.span);

        let by_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
                let by_tok = self
                    .advance()
                    .expect_invariant("BY keyword consumed after match");
                Some(by_tok.span)
            } else {
                None
            }
        } else {
            None
        };

        let start = by_span.map(|s| s.end).unwrap_or(cluster_tok.span.end);

        // Check for CLUSTER BY NONE or CLUSTER BY AUTO (Databricks)
        if let Some(tok) = self.peek_non_trivia() {
            let lex = tok.lexeme(self.source);
            if lex.eq_ignore_ascii_case("NONE") || lex.eq_ignore_ascii_case("AUTO") {
                let is_none = lex.eq_ignore_ascii_case("NONE");
                let kw_tok = self
                    .advance()
                    .expect_invariant("NONE/AUTO consumed after match");
                return Ok(AstAlterTableActionKind::ClusterBy {
                    cluster_span,
                    by_span,
                    exprs_span: Span {
                        start: kw_tok.span.start,
                        end: kw_tok.span.end,
                    },
                    exprs: None,
                    is_none,
                });
            }
        }

        let exprs = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let _ = self.advance(); // consume '('
                let mut expr_list = Vec::new();

                loop {
                    if let Some(t) = self.peek_non_trivia() {
                        if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                            let _ = self.advance();
                            break;
                        }
                    }

                    match self.parse_expr() {
                        Ok(expr) => expr_list.push(expr),
                        Err(_) => break,
                    }

                    if let Some(t) = self.peek_non_trivia() {
                        if matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            let _ = self.advance();
                        } else if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                            let _ = self.advance();
                            break;
                        } else {
                            break;
                        }
                    }
                }

                Some(expr_list)
            } else {
                None
            }
        } else {
            None
        };

        let end = self
            .peek()
            .map(|t| t.span.start)
            .unwrap_or(cluster_tok.span.end);

        Ok(AstAlterTableActionKind::ClusterBy {
            cluster_span,
            by_span,
            exprs_span: Span { start, end },
            exprs,
            is_none: false,
        })
    }

    fn parse_set_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let set_tok = self
            .advance()
            .expect_invariant("SET keyword consumed after caller match");
        let set_span = Some(set_tok.span);
        let start = set_tok.span.end;

        if let Some(tok) = self.peek_non_trivia() {
            if self.is_row_filter_pattern(0) {
                let row_tok = self
                    .advance()
                    .expect_invariant("ROW consumed after SET for row filter");
                let filter_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        row_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected FILTER after ROW".to_string(),
                        },
                    )
                })?;

                let function_name_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        filter_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected function name after ROW FILTER".to_string(),
                        },
                    )
                })?;

                let on_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        function_name_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected ON after row filter function name".to_string(),
                        },
                    )
                })?;

                let on_span = if on_tok.lexeme(self.source).eq_ignore_ascii_case("ON") {
                    let t = self
                        .advance()
                        .expect_invariant("ON consumed after row filter function name");
                    Some(t.span)
                } else {
                    return Err(ParseError::new(
                        function_name_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected ON after row filter function name".to_string(),
                        },
                    ));
                };

                let lparen_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        on_span.expect_invariant("on span exists"),
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected '(' after ON".to_string(),
                        },
                    )
                })?;

                if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    return Err(ParseError::new(
                        on_span.expect_invariant("on span exists"),
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected '(' after ON".to_string(),
                        },
                    ));
                }

                let columns_start = lparen_tok.span.start;
                self.advance(); // consume (

                let mut depth = 1;
                let mut last_end = lparen_tok.span.end;
                while depth > 0 {
                    let next = self.advance().ok_or_else(|| {
                        ParseError::new(
                            Span {
                                start: columns_start,
                                end: columns_start,
                            },
                            ParseErrorKind::InvalidSyntax {
                                message: "Unterminated column list in SET ROW FILTER".to_string(),
                            },
                        )
                    })?;
                    last_end = next.span.end;
                    if matches!(next.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        depth += 1;
                    } else if matches!(next.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        depth -= 1;
                    }
                }

                return Ok(AstAlterTableActionKind::SetRowFilter {
                    set_span,
                    row_span: Some(row_tok.span),
                    filter_span: Some(filter_tok.span),
                    function_name_span: function_name_tok.span,
                    on_span,
                    columns_span: Span {
                        start: columns_start,
                        end: last_end,
                    },
                });
            }

            // SET TAG tag = 'value' (Snowflake)
            if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
                let tag_tok = self
                    .advance()
                    .expect_invariant("TAG keyword consumed after match in parse_set_action");
                let tag_span = Some(tag_tok.span);
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::SetTag {
                    set_span,
                    tag_span,
                    assignments_span: Span {
                        start: tag_tok.span.end,
                        end,
                    },
                });
            }
            // Databricks: SET TBLPROPERTIES ('key' = 'value', ...)
            if tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("TBLPROPERTIES")
            {
                let tblproperties_tok = self.advance().expect_invariant("TBLPROPERTIES consumed");
                let tblproperties_span = Some(tblproperties_tok.span);
                let list_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::SetTblProperties {
                    set_span,
                    tblproperties_span,
                    properties_span: Span {
                        start: list_start,
                        end,
                    },
                });
            }
            // BigQuery: SET OPTIONS (key=value, ...)
            if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") {
                let options_tok = self.advance().expect_invariant("OPTIONS consumed");
                let options_span = Some(options_tok.span);
                // Consume the parenthesized options list
                let list_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::SetOptions {
                    set_span,
                    options_span,
                    options_list_span: Span {
                        start: list_start,
                        end,
                    },
                });
            }
            // BigQuery: SET DEFAULT COLLATE 'collation'
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                // Peek further to see if COLLATE follows
                let saved_idx = self.idx;
                let default_tok = self.advance().expect_invariant("DEFAULT consumed");
                if let Some(collate_tok) = self.peek_non_trivia() {
                    if collate_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("COLLATE")
                    {
                        let ct = self.advance().expect_invariant("COLLATE consumed");
                        let collate_span = Some(ct.span);
                        // Consume the collation spec (string literal or identifier)
                        let collation_start = self.current_span().start;
                        let end = self.consume_until_comma_or_end()?;
                        return Ok(AstAlterTableActionKind::SetDefaultCollate {
                            set_span,
                            default_span: Some(default_tok.span),
                            collate_span,
                            collation_span: Span {
                                start: collation_start,
                                end,
                            },
                        });
                    }
                }
                // Not COLLATE — backtrack and fall through to generic SET
                self.idx = saved_idx;
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Set {
            set_span,
            parameters_span: Span { start, end },
        })
    }

    fn parse_unset_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let unset_tok = self
            .advance()
            .expect_invariant("UNSET keyword consumed after caller match");
        let unset_span = Some(unset_tok.span);
        let start = unset_tok.span.end;

        // Check for UNSET TAG or UNSET TBLPROPERTIES
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
                let tag_tok = self
                    .advance()
                    .expect_invariant("TAG keyword consumed after match in parse_unset_action");
                let tag_span = Some(tag_tok.span);
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::UnsetTag {
                    unset_span,
                    tag_span,
                    tags_span: Span {
                        start: tag_tok.span.end,
                        end,
                    },
                });
            }
            // Databricks: UNSET TBLPROPERTIES [IF EXISTS] ('key', ...)
            if tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("TBLPROPERTIES")
            {
                let tblproperties_tok = self.advance().expect_invariant("TBLPROPERTIES consumed");
                let tblproperties_span = Some(tblproperties_tok.span);
                // Check for optional IF EXISTS
                let if_exists_span = if let Some(if_tok) = self.peek_non_trivia() {
                    if matches!(if_tok.kind, TokenKind::Keyword(Keyword::If)) {
                        let if_start = if_tok.span.start;
                        self.advance(); // consume IF
                        if let Some(exists_tok) = self.peek_non_trivia() {
                            if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                                let exists_end = exists_tok.span.end;
                                self.advance(); // consume EXISTS
                                Some(Span {
                                    start: if_start,
                                    end: exists_end,
                                })
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                let list_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::UnsetTblProperties {
                    unset_span,
                    tblproperties_span,
                    if_exists_span,
                    keys_span: Span {
                        start: list_start,
                        end,
                    },
                });
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unset {
            unset_span,
            parameters_span: Span { start, end },
        })
    }

    fn parse_swap_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let swap_tok = self
            .advance()
            .expect_invariant("SWAP keyword consumed after caller match");
        let swap_span = Some(swap_tok.span);

        let with_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("WITH") {
                let with_tok = self
                    .advance()
                    .expect_invariant("WITH keyword consumed after match");
                Some(with_tok.span)
            } else {
                None
            }
        } else {
            None
        };

        // The swap target is a (possibly qualified) table name —
        // `SWAP WITH db.schema.table` — so parse the full dotted name
        // rather than a single token, which would leave `.schema.table`
        // dangling as an unparsed fragment.
        let other_table_span = self.parse_qualified_name_span()?;

        Ok(AstAlterTableActionKind::SwapWith {
            swap_span,
            with_span,
            other_table_span,
        })
    }

    fn parse_suspend_resume_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let first_tok = self
            .advance()
            .expect_invariant("SUSPEND or RESUME keyword consumed after caller match");
        let is_suspend = first_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SUSPEND");

        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("RECLUSTER") {
                let recluster_tok = self
                    .advance()
                    .expect_invariant("RECLUSTER keyword consumed after match");
                return if is_suspend {
                    Ok(AstAlterTableActionKind::SuspendRecluster {
                        suspend_span: Some(first_tok.span),
                        recluster_span: Some(recluster_tok.span),
                    })
                } else {
                    Ok(AstAlterTableActionKind::ResumeRecluster {
                        resume_span: Some(first_tok.span),
                        recluster_span: Some(recluster_tok.span),
                    })
                };
            }
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::GovernanceSpan {
            span: Span {
                start: first_tok.span.start,
                end,
            },
        })
    }

    fn parse_governance_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        // Check for row access policy patterns: ADD ROW ACCESS POLICY, DROP ROW ACCESS POLICY, DROP ALL ROW ACCESS POLICIES
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("ADD") {
                // Look ahead for ROW ACCESS POLICY
                if self.is_row_access_policy_pattern(1) {
                    return self.parse_add_row_access_policy();
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("DROP") {
                // Look ahead for ROW ACCESS POLICY or ALL ROW ACCESS POLICIES
                if self.is_drop_all_row_access_policies_pattern() {
                    return self.parse_drop_all_row_access_policies();
                } else if self.is_row_access_policy_pattern(1) {
                    return self.parse_drop_row_access_policy();
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
                // Look ahead for AGGREGATION POLICY or JOIN POLICY
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("AGGREGATION") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            if tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY") {
                                return self.parse_set_aggregation_policy();
                            }
                        }
                    } else if tok2.lexeme(self.source).eq_ignore_ascii_case("JOIN") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            if tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY") {
                                return self.parse_set_join_policy();
                            }
                        }
                    }
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
                // Look ahead for AGGREGATION POLICY or JOIN POLICY
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("AGGREGATION") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            if tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY") {
                                return self.parse_unset_aggregation_policy();
                            }
                        }
                    } else if tok2.lexeme(self.source).eq_ignore_ascii_case("JOIN") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            if tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY") {
                                return self.parse_unset_join_policy();
                            }
                        }
                    }
                }
            }
        }

        // Fallback for unrecognized governance syntax
        let start_tok = self
            .advance()
            .expect_invariant("governance token consumed in fallback path");
        let start = start_tok.span.start;
        let end = self.consume_until_comma_or_end()?;

        Ok(AstAlterTableActionKind::GovernanceSpan {
            span: Span { start, end },
        })
    }

    fn is_row_access_policy_pattern(&self, offset: usize) -> bool {
        // Check for: ROW ACCESS POLICY
        if let Some(tok1) = self.peek_at(self.idx + offset) {
            if tok1.lexeme(self.source).eq_ignore_ascii_case("ROW") {
                if let Some(tok2) = self.peek_at(self.idx + offset + 1) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                        if let Some(tok3) = self.peek_at(self.idx + offset + 2) {
                            return tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY");
                        }
                    }
                }
            }
        }
        false
    }

    fn is_row_filter_pattern(&self, offset: usize) -> bool {
        // Check for: ROW FILTER
        if let Some(tok1) = self.peek_at(self.idx + offset) {
            if tok1.lexeme(self.source).eq_ignore_ascii_case("ROW") {
                if let Some(tok2) = self.peek_at(self.idx + offset + 1) {
                    return tok2.lexeme(self.source).eq_ignore_ascii_case("FILTER");
                }
            }
        }
        false
    }

    fn is_drop_all_row_access_policies_pattern(&self) -> bool {
        // Check for: DROP ALL ROW ACCESS POLICIES
        if let Some(tok1) = self.peek_at(self.idx + 1) {
            if tok1.lexeme(self.source).eq_ignore_ascii_case("ALL") {
                if let Some(tok2) = self.peek_at(self.idx + 2) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("ROW") {
                        if let Some(tok3) = self.peek_at(self.idx + 3) {
                            if tok3.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                                if let Some(tok4) = self.peek_at(self.idx + 4) {
                                    return tok4
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("POLICIES");
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn is_table_level_policy_pattern(&self) -> bool {
        // Check for: SET/UNSET AGGREGATION POLICY or SET/UNSET JOIN POLICY
        if let Some(tok2) = self.peek_at(self.idx + 1) {
            if tok2.lexeme(self.source).eq_ignore_ascii_case("AGGREGATION")
                || tok2.lexeme(self.source).eq_ignore_ascii_case("JOIN")
            {
                if let Some(tok3) = self.peek_at(self.idx + 2) {
                    return tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY");
                }
            }
        }
        false
    }

    fn parse_add_row_access_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        use crate::ast::AddRowAccessPolicyAction;

        let _action_start = self.current_span().start;

        // ADD
        let add_tok = self.advance().expect_invariant(
            "ADD keyword consumed after caller match in parse_add_row_access_policy",
        );
        let add_span = Some(add_tok.span);

        // ROW
        let row_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                add_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ROW after ADD".to_string(),
                },
            )
        })?;
        let row_span = Some(row_tok.span);

        // ACCESS
        let access_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ACCESS after ROW".to_string(),
                },
            )
        })?;
        let access_span = Some(access_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after ACCESS".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // Policy name (identifier)
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name = policy_name_tok.span;

        // ON (column1, column2, ...)
        let on_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                policy_name,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ON after policy name".to_string(),
                },
            )
        })?;

        let on_span = if on_tok.lexeme(self.source).eq_ignore_ascii_case("ON") {
            let t = self
                .advance()
                .expect_invariant("ON keyword consumed after match");
            Some(t.span)
        } else {
            return Err(ParseError::new(
                policy_name,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ON after policy name".to_string(),
                },
            ));
        };

        // Parse column list: (col1, col2, ...)
        let lparen_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                on_span.unwrap(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected '(' after ON".to_string(),
                },
            )
        })?;

        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                on_span.unwrap(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected '(' after ON".to_string(),
                },
            ));
        }

        let columns_start = lparen_tok.span.start;
        let _ = self.advance(); // consume '('

        let mut columns = Vec::new();
        loop {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    break;
                }

                let col_tok = self.advance().expect_invariant(
                    "column name token consumed after peek in parse_add_row_access_policy",
                );
                columns.push(col_tok.span);

                // Check for comma
                if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                        let _ = self.advance();
                    } else if !matches!(next.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        return Err(ParseError::new(
                            col_tok.span,
                            ParseErrorKind::InvalidSyntax {
                                message: "Expected ',' or ')' after column name".to_string(),
                            },
                        ));
                    }
                }
            } else {
                return Err(ParseError::new(
                    Span {
                        start: columns_start,
                        end: columns_start,
                    },
                    ParseErrorKind::InvalidSyntax {
                        message: "Unexpected end of input in column list".to_string(),
                    },
                ));
            }
        }

        let rparen_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                Span {
                    start: columns_start,
                    end: columns_start,
                },
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ')' after column list".to_string(),
                },
            )
        })?;
        let columns_end = rparen_tok.span.end;
        let columns_span = Span {
            start: columns_start,
            end: columns_end,
        };

        Ok(AstAlterTableActionKind::AddRowAccessPolicy(Box::new(
            AddRowAccessPolicyAction {
                add_span,
                row_span,
                access_span,
                policy_span,
                policy_name_span: policy_name,
                on_span,
                columns_span,
                columns,
            },
        )))
    }

    fn parse_drop_row_access_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let _action_start = self.current_span().start;

        // DROP
        let drop_tok = self.advance().expect_invariant(
            "DROP keyword consumed after caller match in parse_drop_row_access_policy",
        );
        let drop_span = Some(drop_tok.span);

        // ROW
        let row_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                drop_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ROW after DROP".to_string(),
                },
            )
        })?;
        let row_span = Some(row_tok.span);

        // ACCESS
        let access_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ACCESS after ROW".to_string(),
                },
            )
        })?;
        let access_span = Some(access_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after ACCESS".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // Optional IF EXISTS
        let (if_exists_span, _if_kw, _exists_kw) = self.parse_if_exists_clause()?;

        // Policy name (identifier)
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name_span = policy_name_tok.span;

        Ok(AstAlterTableActionKind::DropRowAccessPolicy {
            drop_span,
            row_span,
            access_span,
            policy_span,
            policy_name_span,
            if_exists_span,
        })
    }

    fn parse_drop_all_row_access_policies(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let _action_start = self.current_span().start;

        // DROP
        let drop_tok = self.advance().expect_invariant(
            "DROP keyword consumed after caller match in parse_drop_all_row_access_policies",
        );
        let drop_span = Some(drop_tok.span);

        // ALL
        let all_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                drop_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ALL after DROP".to_string(),
                },
            )
        })?;
        let all_span = Some(all_tok.span);

        // ROW
        let row_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                all_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ROW after ALL".to_string(),
                },
            )
        })?;
        let row_span = Some(row_tok.span);

        // ACCESS
        let access_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ACCESS after ROW".to_string(),
                },
            )
        })?;
        let access_span = Some(access_tok.span);

        // POLICIES
        let policies_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICIES after ACCESS".to_string(),
                },
            )
        })?;
        let policies_span = Some(policies_tok.span);

        Ok(AstAlterTableActionKind::DropAllRowAccessPolicies {
            drop_span,
            all_span,
            row_span,
            access_span,
            policies_span,
        })
    }

    fn is_masking_policy_pattern(&mut self) -> bool {
        // Check for: SET/UNSET MASKING POLICY
        if let Some(tok1) = self.peek_non_trivia() {
            let is_set_or_unset = tok1.lexeme(self.source).eq_ignore_ascii_case("SET")
                || tok1.lexeme(self.source).eq_ignore_ascii_case("UNSET");

            if is_set_or_unset {
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("MASKING") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            return tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY");
                        }
                    }
                }
            }
        }
        false
    }

    fn is_set_mask_pattern(&self) -> bool {
        // Check for: SET MASK
        if let Some(tok1) = self.peek_at(self.idx) {
            if tok1.lexeme(self.source).eq_ignore_ascii_case("SET") {
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    return tok2.lexeme(self.source).eq_ignore_ascii_case("MASK");
                }
            }
        }
        false
    }

    fn is_drop_mask_pattern(&self) -> bool {
        // Check for: DROP MASK
        if let Some(tok1) = self.peek_at(self.idx) {
            if tok1.lexeme(self.source).eq_ignore_ascii_case("DROP") {
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    return tok2.lexeme(self.source).eq_ignore_ascii_case("MASK");
                }
            }
        }
        false
    }

    fn parse_set_column_mask(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let set_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected SET after column name".to_string(),
                },
            )
        })?;
        let set_span = Some(set_tok.span);

        let mask_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected MASK after SET".to_string(),
                },
            )
        })?;
        let mask_span = Some(mask_tok.span);

        let function_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                mask_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected mask function name after MASK".to_string(),
                },
            )
        })?;

        Ok(AstAlterTableActionKind::SetColumnMask {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            mask_span,
            function_name_span: function_name_tok.span,
        })
    }

    fn parse_drop_column_mask(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let drop_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected DROP after column name".to_string(),
                },
            )
        })?;
        let drop_span = Some(drop_tok.span);

        let mask_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                drop_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected MASK after DROP".to_string(),
                },
            )
        })?;
        let mask_span = Some(mask_tok.span);

        Ok(AstAlterTableActionKind::DropColumnMask {
            alter_span,
            column_span,
            column_name_span,
            drop_span,
            mask_span,
        })
    }

    fn is_projection_policy_pattern(&mut self) -> bool {
        // Check for: SET/UNSET PROJECTION POLICY
        if let Some(tok1) = self.peek_non_trivia() {
            let is_set_or_unset = tok1.lexeme(self.source).eq_ignore_ascii_case("SET")
                || tok1.lexeme(self.source).eq_ignore_ascii_case("UNSET");

            if is_set_or_unset {
                if let Some(tok2) = self.peek_at(self.idx + 1) {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("PROJECTION") {
                        if let Some(tok3) = self.peek_at(self.idx + 2) {
                            return tok3.lexeme(self.source).eq_ignore_ascii_case("POLICY");
                        }
                    }
                }
            }
        }
        false
    }

    fn parse_set_column_masking_policy(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        use crate::ast::SetColumnMaskingPolicyAction;

        // SET
        let set_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected SET after column name".to_string(),
                },
            )
        })?;
        let set_span = Some(set_tok.span);

        // MASKING
        let masking_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected MASKING after SET".to_string(),
                },
            )
        })?;
        let masking_span = Some(masking_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                masking_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after MASKING".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // Policy name
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name_span = policy_name_tok.span;

        // Optional USING (col1, col2, ...)
        let using_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("USING") {
                let using_tok = self
                    .advance()
                    .expect_invariant("USING keyword consumed after match");

                // Consume USING clause (typically parenthesized column list)
                if let Some(lparen) = self.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let _ = self.advance();
                        let mut depth = 1;

                        while depth > 0 && self.peek().is_some() {
                            if let Some(tok) = self.advance() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                                    depth += 1;
                                } else if matches!(
                                    tok.kind,
                                    TokenKind::Punctuation(Punctuation::RParen)
                                ) {
                                    depth -= 1;
                                }
                            }
                        }
                    }
                }

                Some(using_tok.span)
            } else {
                None
            }
        } else {
            None
        };

        // Optional FORCE
        let force_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("FORCE") {
                let t = self.advance().expect_invariant(
                    "FORCE keyword consumed after match in parse_set_column_masking_policy",
                );
                Some(t.span)
            } else {
                None
            }
        } else {
            None
        };

        Ok(AstAlterTableActionKind::SetColumnMaskingPolicy(Box::new(
            SetColumnMaskingPolicyAction {
                alter_span,
                column_span,
                column_name_span,
                set_span,
                masking_span,
                policy_span,
                policy_name_span,
                using_span,
                force_span,
            },
        )))
    }

    fn parse_unset_column_masking_policy(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        // UNSET
        let unset_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected UNSET after column name".to_string(),
                },
            )
        })?;
        let unset_span = Some(unset_tok.span);

        // MASKING
        let masking_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                unset_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected MASKING after UNSET".to_string(),
                },
            )
        })?;
        let masking_span = Some(masking_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                masking_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after MASKING".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        Ok(AstAlterTableActionKind::UnsetColumnMaskingPolicy {
            alter_span,
            column_span,
            column_name_span,
            unset_span,
            masking_span,
            policy_span,
        })
    }

    fn parse_set_column_projection_policy(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        use crate::ast::SetColumnProjectionPolicyAction;

        // SET
        let set_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected SET after column name".to_string(),
                },
            )
        })?;
        let set_span = Some(set_tok.span);

        // PROJECTION
        let projection_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected PROJECTION after SET".to_string(),
                },
            )
        })?;
        let projection_span = Some(projection_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                projection_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after PROJECTION".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // Policy name
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name_span = policy_name_tok.span;

        // Optional FORCE
        let force_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("FORCE") {
                let t = self.advance().expect_invariant(
                    "FORCE keyword consumed after match in parse_set_column_projection_policy",
                );
                Some(t.span)
            } else {
                None
            }
        } else {
            None
        };

        Ok(AstAlterTableActionKind::SetColumnProjectionPolicy(
            Box::new(SetColumnProjectionPolicyAction {
                alter_span,
                column_span,
                column_name_span,
                set_span,
                projection_span,
                policy_span,
                policy_name_span,
                force_span,
            }),
        ))
    }

    fn parse_unset_column_projection_policy(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        // UNSET
        let unset_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                column_name_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected UNSET after column name".to_string(),
                },
            )
        })?;
        let unset_span = Some(unset_tok.span);

        // PROJECTION
        let projection_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                unset_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected PROJECTION after UNSET".to_string(),
                },
            )
        })?;
        let projection_span = Some(projection_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                projection_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after PROJECTION".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        Ok(AstAlterTableActionKind::UnsetColumnProjectionPolicy {
            alter_span,
            column_span,
            column_name_span,
            unset_span,
            projection_span,
            policy_span,
        })
    }

    fn parse_column_definitions(&mut self) -> ParseResult<Vec<AstAlterTableColumnDef>> {
        let mut columns = Vec::new();

        loop {
            let col = self.parse_column_definition()?;
            columns.push(col);

            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    let next_is_action = if let Some(next) = self.peek_at(self.idx + 1) {
                        next.lexeme(self.source).eq_ignore_ascii_case("ADD")
                            || next.lexeme(self.source).eq_ignore_ascii_case("DROP")
                            || next.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                            || next.lexeme(self.source).eq_ignore_ascii_case("RENAME")
                            || next.lexeme(self.source).eq_ignore_ascii_case("CLUSTER")
                            || next.lexeme(self.source).eq_ignore_ascii_case("SWAP")
                            || next.lexeme(self.source).eq_ignore_ascii_case("SET")
                            || next.lexeme(self.source).eq_ignore_ascii_case("UNSET")
                            || next.lexeme(self.source).eq_ignore_ascii_case("SUSPEND")
                            || next.lexeme(self.source).eq_ignore_ascii_case("RESUME")
                    } else {
                        false
                    };

                    if next_is_action {
                        break;
                    }

                    // Consume the comma
                    let _ = self.advance();

                    // Check if there's a valid column definition next (not EOF, semicolon, or action)
                    if let Some(next_tok) = self.peek_non_trivia() {
                        if matches!(
                            next_tok.kind,
                            TokenKind::Eof
                                | TokenKind::Punctuation(Punctuation::Semi | Punctuation::Comma)
                        ) {
                            // Trailing comma, EOF, or another comma - stop here
                            break;
                        }
                    } else {
                        // No more tokens - stop
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(columns)
    }

    /// Case-insensitive lexeme check at a raw token index (trivia-safe:
    /// the token stream is significant-only).
    fn lexeme_at_is(&self, idx: usize, s: &str) -> bool {
        self.tokens
            .get(idx)
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case(s))
    }

    /// `[ENABLE | DISABLE | FORCE | NO FORCE] ROW LEVEL SECURITY` lookahead.
    fn is_row_level_security_at(&self) -> bool {
        let i = self.idx;
        let row_idx = if self.lexeme_at_is(i, "NO") {
            if !self.lexeme_at_is(i + 1, "FORCE") {
                return false;
            }
            i + 2
        } else if self.lexeme_at_is(i, "ENABLE")
            || self.lexeme_at_is(i, "DISABLE")
            || self.lexeme_at_is(i, "FORCE")
        {
            i + 1
        } else {
            return false;
        };
        self.lexeme_at_is(row_idx, "ROW")
            && self.lexeme_at_is(row_idx + 1, "LEVEL")
            && self.lexeme_at_is(row_idx + 2, "SECURITY")
    }

    /// Parse `[ENABLE | DISABLE | FORCE | NO FORCE] ROW LEVEL SECURITY`.
    /// Caller guards with [`Self::is_row_level_security_at`].
    fn parse_row_level_security_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let mode_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["ENABLE|DISABLE|FORCE|NO".to_string()],
        )?;
        let start = mode_tok.span.start;
        let mode = if mode_tok.lexeme(self.source).eq_ignore_ascii_case("ENABLE") {
            AstRowLevelSecurityMode::Enable
        } else if mode_tok.lexeme(self.source).eq_ignore_ascii_case("DISABLE") {
            AstRowLevelSecurityMode::Disable
        } else if mode_tok.lexeme(self.source).eq_ignore_ascii_case("FORCE") {
            AstRowLevelSecurityMode::Force
        } else {
            // NO FORCE — consume FORCE.
            self.advance()
                .ok_or_eof(self.current_span(), vec!["FORCE".to_string()])?;
            AstRowLevelSecurityMode::NoForce
        };
        // ROW LEVEL SECURITY.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["ROW".to_string()])?;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["LEVEL".to_string()])?;
        let security_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SECURITY".to_string()])?;
        let keyword_span = Span {
            start,
            end: security_tok.span.end,
        };
        Ok(AstAlterTableActionKind::RowLevelSecurity { mode, keyword_span })
    }

    fn parse_column_definition(&mut self) -> ParseResult<AstAlterTableColumnDef> {
        let name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected column name".to_string(),
                },
            )
        })?;

        let name_span = Some(name_tok.span);

        // MSSQL typeless computed column: `name AS expr` — no data type.
        let mut type_end = name_tok.span.end;
        let type_span = if matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::As))
        ) {
            None
        } else {
            let type_start = self.current_span().start;
            let _data_type = self.parse_data_type_simple()?;

            // MySQL numeric-type modifiers belong to the type: UNSIGNED / ZEROFILL
            // / SIGNED (all lex as identifiers). Fold them into the type span,
            // mirroring CREATE TABLE which keeps them inside the type token run.
            while let Some(tok) = self.peek_non_trivia() {
                let is_num_modifier = matches!(tok.kind, TokenKind::Identifier { .. })
                    && (tok.lexeme(self.source).eq_ignore_ascii_case("UNSIGNED")
                        || tok.lexeme(self.source).eq_ignore_ascii_case("ZEROFILL")
                        || tok.lexeme(self.source).eq_ignore_ascii_case("SIGNED"));
                if is_num_modifier {
                    let _ = self.advance();
                } else {
                    break;
                }
            }
            type_end = self.peek().map(|t| t.span.start).unwrap_or(type_start);
            Some(Span {
                start: type_start,
                end: type_end,
            })
        };

        // Generated-column carve, mirroring CREATE TABLE's
        // build_create_table_item: GENERATED prefix, AS-expression,
        // storage keyword. Tokens stay inside full_span (the AddColumn
        // formatter re-emits full_span verbatim), so a conservative miss
        // here degrades to unset spans, never lost output.
        let mut generated_always_span: Option<Span> = None;
        let mut virtual_expr_span: Option<Span> = None;
        let mut storage_keyword_span: Option<Span> = None;

        // GENERATED ALWAYS | GENERATED BY DEFAULT prefix; fold the trailing
        // AS when followed by IDENTITY (identity column, not an expression).
        let gen_token_count = if self.lexeme_at_is(self.idx, "GENERATED") {
            if self.lexeme_at_is(self.idx + 1, "ALWAYS") {
                Some(2)
            } else if self.lexeme_at_is(self.idx + 1, "BY")
                && self.lexeme_at_is(self.idx + 2, "DEFAULT")
            {
                Some(3)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(n) = gen_token_count {
            let start = self.tokens[self.idx].span.start;
            let mut end = self.tokens[self.idx + n - 1].span.end;
            for _ in 0..n {
                let _ = self.advance();
            }
            let as_then_identity = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Keyword(Keyword::As))
            ) && self.lexeme_at_is(self.idx + 1, "IDENTITY");
            if as_then_identity {
                if let Some(as_tok) = self.advance() {
                    end = as_tok.span.end;
                }
            }
            generated_always_span = Some(Span { start, end });
        }

        // AS-expression: `AS ( expr )` or MSSQL unparenthesized `AS expr`.
        // Span includes the AS keyword.
        if matches!(
            self.peek().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::As))
        ) {
            if let Some(as_tok) = self.advance() {
                let start = as_tok.span.start;
                let mut end = as_tok.span.end;
                if matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(Punctuation::LParen))
                ) {
                    let mut depth: i32 = 0;
                    while let Some(t2) = self.peek() {
                        if matches!(t2.kind, TokenKind::Eof) {
                            break;
                        }
                        let is_lparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::LParen));
                        let is_rparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::RParen));
                        if is_lparen {
                            depth += 1;
                        }
                        if is_rparen {
                            depth -= 1;
                        }
                        end = t2.span.end;
                        let _ = self.advance();
                        if is_rparen && depth == 0 {
                            break;
                        }
                    }
                } else {
                    let mut depth: i32 = 0;
                    while let Some(t2) = self.peek() {
                        if matches!(
                            t2.kind,
                            TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
                        ) {
                            break;
                        }
                        let is_lparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::LParen));
                        let is_rparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::RParen));
                        let is_comma =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::Comma));
                        if depth == 0 && (is_comma || is_rparen) {
                            break;
                        }
                        let lex = t2.lexeme(self.source);
                        if depth == 0
                            && (is_column_tail_clause_lexeme(lex)
                                || is_generated_storage_lexeme(lex))
                        {
                            break;
                        }
                        if is_lparen {
                            depth += 1;
                        }
                        if is_rparen {
                            depth -= 1;
                        }
                        end = t2.span.end;
                        let _ = self.advance();
                    }
                }
                virtual_expr_span = Some(Span { start, end });
            }
        }

        // Storage keyword closing a generated expression.
        if virtual_expr_span.is_some() {
            if let Some(t2) = self.peek() {
                if is_generated_storage_lexeme(t2.lexeme(self.source)) {
                    storage_keyword_span = Some(t2.span);
                    let _ = self.advance();
                }
            }
        }

        // Consume the full column-attribute tail as raw tokens up to a
        // column-definition boundary. This covers NOT NULL / NULL / DEFAULT
        // expr / AUTO_INCREMENT / PRIMARY KEY / UNIQUE [KEY] / KEY / COMMENT
        // '...' / COLLATE ... / CHARACTER SET ... / CHECK (...) / REFERENCES
        // ... / Redshift ENCODE <codec> — every dialect's per-column tail,
        // uniformly. The AddColumn formatter re-emits `full_span` verbatim, so
        // growing the span byte-for-byte is correct and dialect-neutral.
        // Boundaries (not consumed): a depth-0 comma (next column / next ALTER
        // action), a depth-0 ')' (closing an `ADD (...)` list), a semicolon, or
        // EOF. Paren depth keeps DEFAULT (expr) / CHECK (...) / ENUM tails whole.
        let mut depth: i32 = 0;
        while let Some(tok) = self.peek() {
            match tok.kind {
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi) => break,
                TokenKind::Punctuation(Punctuation::Comma) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::RParen) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => {
                    depth += 1;
                    let _ = self.advance();
                }
                TokenKind::Punctuation(Punctuation::RParen) => {
                    depth -= 1;
                    let _ = self.advance();
                }
                _ => {
                    let _ = self.advance();
                }
            }
        }

        let end = self.peek().map(|t| t.span.start).unwrap_or(type_end);

        Ok(AstAlterTableColumnDef {
            node_id: self.id_gen.next(),
            full_span: Span {
                start: name_tok.span.start,
                end,
            },
            name_span,
            type_span,
            generated_always_span,
            virtual_expr_span,
            storage_keyword_span,
        })
    }

    fn parse_data_type_simple(&mut self) -> ParseResult<AstDataType> {
        let type_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected data type".to_string(),
                },
            )
        })?;

        let name_span = type_tok.span;

        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let _ = self.advance();
                let mut depth = 1;
                while depth > 0 {
                    if let Some(t) = self.advance() {
                        if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            depth += 1;
                        } else if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                            depth -= 1;
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        // Return simple type (precision/scale parsing would go here if needed)
        Ok(AstDataType::Simple { name_span })
    }

    //
    // Table-Level Policy Parsers (Priority 3)
    //

    fn parse_set_aggregation_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let _action_start = self.current_span().start;

        // SET
        let set_tok = self.advance().expect_invariant(
            "SET keyword consumed after caller match in parse_set_aggregation_policy",
        );
        let set_span = Some(set_tok.span);

        // AGGREGATION
        let aggregation_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected AGGREGATION after SET".to_string(),
                },
            )
        })?;
        let aggregation_span = Some(aggregation_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                aggregation_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after AGGREGATION".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // <policy_name>
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name_span = policy_name_tok.span;

        // Optional ENTITY KEY ( col1, col2, ... )
        let mut entity_key_span = None;
        let mut entity_key_columns = Vec::new();

        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("ENTITY") {
                let entity_tok = self
                    .advance()
                    .expect_invariant("ENTITY keyword consumed after match");

                // KEY
                let key_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        entity_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected KEY after ENTITY".to_string(),
                        },
                    )
                })?;

                entity_key_span = Some(Span {
                    start: entity_tok.span.start,
                    end: key_tok.span.end,
                });

                // (
                let lparen_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        key_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected opening parenthesis after ENTITY KEY".to_string(),
                        },
                    )
                })?;

                if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    return Err(ParseError::new(
                        lparen_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected opening parenthesis after ENTITY KEY".to_string(),
                        },
                    ));
                }

                // Parse column list
                loop {
                    let col_tok = self.advance().ok_or_else(|| {
                        ParseError::new(
                            key_tok.span,
                            ParseErrorKind::InvalidSyntax {
                                message: "Expected column name in ENTITY KEY clause".to_string(),
                            },
                        )
                    })?;
                    entity_key_columns.push(col_tok.span);

                    // Check for comma or closing paren
                    if let Some(next_tok) = self.peek_non_trivia() {
                        if matches!(next_tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            let _ = self.advance();
                            continue;
                        } else if matches!(
                            next_tok.kind,
                            TokenKind::Punctuation(Punctuation::RParen)
                        ) {
                            let _ = self.advance();
                            break;
                        }
                    }

                    return Err(ParseError::new(
                        col_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected comma or closing parenthesis in ENTITY KEY clause"
                                .to_string(),
                        },
                    ));
                }
            }
        }

        // Optional FORCE
        let mut force_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("FORCE") {
                let force_tok = self.advance().expect_invariant(
                    "FORCE keyword consumed after match in parse_set_aggregation_policy",
                );
                force_span = Some(force_tok.span);
            }
        }

        Ok(AstAlterTableActionKind::SetAggregationPolicy {
            set_span,
            aggregation_span,
            policy_span,
            policy_name_span,
            entity_key_span,
            entity_key_columns,
            force_span,
        })
    }

    fn parse_unset_aggregation_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        // UNSET
        let unset_tok = self.advance().expect_invariant(
            "UNSET keyword consumed after caller match in parse_unset_aggregation_policy",
        );
        let unset_span = Some(unset_tok.span);

        // AGGREGATION
        let aggregation_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                unset_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected AGGREGATION after UNSET".to_string(),
                },
            )
        })?;
        let aggregation_span = Some(aggregation_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                aggregation_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after AGGREGATION".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        Ok(AstAlterTableActionKind::UnsetAggregationPolicy {
            unset_span,
            aggregation_span,
            policy_span,
        })
    }

    fn parse_set_join_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let _action_start = self.current_span().start;

        // SET
        let set_tok = self
            .advance()
            .expect_invariant("SET keyword consumed after caller match in parse_set_join_policy");
        let set_span = Some(set_tok.span);

        // JOIN
        let join_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                set_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected JOIN after SET".to_string(),
                },
            )
        })?;
        let join_span = Some(join_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                join_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after JOIN".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        // <policy_name>
        let policy_name_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name after POLICY".to_string(),
                },
            )
        })?;
        let policy_name_span = policy_name_tok.span;

        // Optional FORCE
        let mut force_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("FORCE") {
                let force_tok = self.advance().expect_invariant(
                    "FORCE keyword consumed after match in parse_set_join_policy",
                );
                force_span = Some(force_tok.span);
            }
        }

        Ok(AstAlterTableActionKind::SetJoinPolicy {
            set_span,
            join_span,
            policy_span,
            policy_name_span,
            force_span,
        })
    }

    fn parse_unset_join_policy(&mut self) -> ParseResult<AstAlterTableActionKind> {
        // UNSET
        let unset_tok = self.advance().expect_invariant(
            "UNSET keyword consumed after caller match in parse_unset_join_policy",
        );
        let unset_span = Some(unset_tok.span);

        // JOIN
        let join_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                unset_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected JOIN after UNSET".to_string(),
                },
            )
        })?;
        let join_span = Some(join_tok.span);

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                join_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected POLICY after JOIN".to_string(),
                },
            )
        })?;
        let policy_span = Some(policy_tok.span);

        Ok(AstAlterTableActionKind::UnsetJoinPolicy {
            unset_span,
            join_span,
            policy_span,
        })
    }

    /// Parse `ADD DATA METRIC FUNCTION <name> [ON (<cols>)]` (cursor at DATA).
    fn parse_add_data_metric_function(
        &mut self,
        add_span: Option<Span>,
    ) -> ParseResult<AstAlterTableActionKind> {
        let (data_span, metric_span, function_span, function_name_span, on_span, columns_span) =
            self.parse_data_metric_function_attachment()?;
        Ok(AstAlterTableActionKind::AddDataMetricFunction {
            add_span,
            data_span,
            metric_span,
            function_span,
            function_name_span,
            on_span,
            columns_span,
        })
    }

    /// Parse `DROP DATA METRIC FUNCTION <name> [ON (<cols>)]` (cursor at DATA).
    fn parse_drop_data_metric_function(
        &mut self,
        drop_span: Option<Span>,
    ) -> ParseResult<AstAlterTableActionKind> {
        let (data_span, metric_span, function_span, function_name_span, on_span, columns_span) =
            self.parse_data_metric_function_attachment()?;
        Ok(AstAlterTableActionKind::DropDataMetricFunction {
            drop_span,
            data_span,
            metric_span,
            function_span,
            function_name_span,
            on_span,
            columns_span,
        })
    }

    /// Shared body for ADD / DROP DATA METRIC FUNCTION: consumes
    /// `DATA METRIC FUNCTION <name> [ON <cols>]` and returns the spans.
    #[allow(clippy::type_complexity)] // tuple mirrors the AST action fields 1:1
    fn parse_data_metric_function_attachment(
        &mut self,
    ) -> ParseResult<(
        Option<Span>,
        Option<Span>,
        Option<Span>,
        Span,
        Option<Span>,
        Span,
    )> {
        let data_tok = self.advance().expect_invariant("DATA consumed after peek");
        let metric_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                data_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected METRIC after DATA".to_string(),
                },
            )
        })?;
        let function_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                metric_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected FUNCTION after METRIC".to_string(),
                },
            )
        })?;
        let function_name_span = self.parse_qualified_name_span()?;

        let mut on_span = None;
        let mut columns_span = function_name_span;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On))
                || tok.lexeme(self.source).eq_ignore_ascii_case("ON")
            {
                let on_tok = self.advance().expect_invariant("ON consumed after peek");
                on_span = Some(on_tok.span);
                let cols_start = self.current_span().start;
                let cols_end = self.consume_until_comma_or_end()?;
                columns_span = Span {
                    start: cols_start,
                    end: cols_end,
                };
            }
        }

        Ok((
            Some(data_tok.span),
            Some(metric_tok.span),
            Some(function_tok.span),
            function_name_span,
            on_span,
            columns_span,
        ))
    }

    // ========================================================================
    // BigQuery ALTER COLUMN sub-action helpers
    // ========================================================================

    /// Parse ALTER COLUMN <col> SET { OPTIONS(...) | DATA TYPE <type> | DEFAULT <expr> }
    fn parse_bq_alter_column_set(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let set_tok = self.advance().expect_invariant("SET keyword consumed");
        let set_span = Some(set_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            // ALTER COLUMN <col> SET OPTIONS (...)
            if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") {
                let options_tok = self.advance().expect_invariant("OPTIONS consumed");
                let options_span = Some(options_tok.span);
                let list_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::AlterColumnSetOptions {
                    alter_span,
                    column_span,
                    column_name_span,
                    set_span,
                    options_span,
                    options_list_span: Span {
                        start: list_start,
                        end,
                    },
                });
            }
            // ALTER COLUMN <col> SET DATA TYPE <type>
            if tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
                let data_tok = self.advance().expect_invariant("DATA consumed");
                let data_span_val = Some(data_tok.span);
                // Expect TYPE keyword
                let type_span_val = if let Some(t) = self.peek_non_trivia() {
                    if matches!(t.kind, TokenKind::Keyword(Keyword::Type)) {
                        let tt = self.advance().expect_invariant("TYPE consumed");
                        Some(tt.span)
                    } else {
                        None
                    }
                } else {
                    None
                };
                // Consume the data type expression (may be complex: STRUCT<...>, ARRAY<...>)
                let dt_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::AlterColumnSetDataType {
                    alter_span,
                    column_span,
                    column_name_span,
                    set_span,
                    data_span: data_span_val,
                    type_span: type_span_val,
                    data_type_span: Span {
                        start: dt_start,
                        end,
                    },
                });
            }
            // ALTER COLUMN <col> SET DEFAULT <expr>
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                let default_tok = self.advance().expect_invariant("DEFAULT consumed");
                let default_span = Some(default_tok.span);
                let expr_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                return Ok(AstAlterTableActionKind::AlterColumnSetDefault {
                    alter_span,
                    column_span,
                    column_name_span,
                    set_span,
                    default_span,
                    expr_span: Span {
                        start: expr_start,
                        end,
                    },
                });
            }
        }

        // Fallback: generic AlterColumn for unrecognized SET sub-actions
        let op_start = column_name_span.end;
        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span: Span {
                start: op_start,
                end,
            },
        })
    }

    /// Parse ALTER COLUMN <col> DROP { NOT NULL | DEFAULT }
    fn parse_bq_alter_column_drop(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let drop_tok = self.advance().expect_invariant("DROP keyword consumed");
        let drop_span = Some(drop_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            // ALTER COLUMN <col> DROP NOT NULL
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                let not_tok = self.advance().expect_invariant("NOT consumed");
                let not_span = Some(not_tok.span);
                // NULL is Literal(Null), not a keyword
                let null_span = if let Some(n) = self.peek_non_trivia() {
                    if matches!(n.kind, TokenKind::Literal(crate::lexer::LiteralKind::Null)) {
                        let nt = self.advance().expect_invariant("NULL consumed");
                        Some(nt.span)
                    } else {
                        None
                    }
                } else {
                    None
                };
                return Ok(AstAlterTableActionKind::AlterColumnDropNotNull {
                    alter_span,
                    column_span,
                    column_name_span,
                    drop_span,
                    not_span,
                    null_span,
                });
            }
            // ALTER COLUMN <col> DROP DEFAULT
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                let default_tok = self.advance().expect_invariant("DEFAULT consumed");
                let default_span = Some(default_tok.span);
                return Ok(AstAlterTableActionKind::AlterColumnDropDefault {
                    alter_span,
                    column_span,
                    column_name_span,
                    drop_span,
                    default_span,
                });
            }
        }

        // Fallback: generic AlterColumn for unrecognized DROP sub-actions
        let op_start = column_name_span.end;
        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span: Span {
                start: op_start,
                end,
            },
        })
    }

    fn consume_until_comma_or_end(&mut self) -> ParseResult<u32> {
        let mut end = self.current_span().start;
        let mut depth = 0;

        while let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) && depth == 0 {
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth -= 1;
            }
            end = tok.span.end;
            let _ = self.advance();
        }

        Ok(end)
    }

    fn peek_at(&self, idx: usize) -> Option<&'a crate::lexer::Token> {
        if idx < self.tokens.len() {
            Some(&self.tokens[idx])
        } else {
            None
        }
    }
}
