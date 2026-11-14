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
    AstAlterTable, AstAlterTableAction, AstAlterTableActionKind, AstAlteredNullability,
    AstAlteredType, AstRowLevelSecurityMode, AstStmt,
};
use crate::ast::{AstAlterTableColumnDef, AstDataType};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Punctuation, Span, TokenKind};
use crate::parser::core::{NamePosition, Parser};
use crate::parser::create_table::{is_column_tail_clause_lexeme, is_generated_storage_lexeme};
use crate::parser::tag::TagListShape;

/// `ALTER TABLE ... ADD <X>` starters that introduce something other than a
/// column definition: anonymous constraints, indexes, partitions, system
/// periods, search optimization, old-style MSSQL `ADD DEFAULT ... FOR`,
/// row policies, and an `IF` that does not open `IF NOT EXISTS`. These keep
/// the Unknown path.
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
        let (name_span, (name_first, name_past)) = self.parse_table_name()?;
        let name_id = self.id_gen.next();
        let name = self.object_ref_of_range(name_first, name_past, name_id);

        // Parse actions; each parameter's value a `SET` gives is recorded as
        // every statement setting one records it.
        let actions_start = self.current_span().start;
        let actions_first = self.idx;
        let (actions, action_ids, commas) = self.parse_alter_table_actions()?;
        self.record_setting_clause_secrets(actions_first, self.idx);
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
            name,
            written_name_span: name_span,
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

    /// The table name: `[ONLY] name [*]` (PostgreSQL's `ONLY` and `*` stay in
    /// its span), read as an object name; where no name is read there, every
    /// token up to an action's keyword. With it, the range of the tokens of
    /// the name itself, `ONLY` and `*` left out.
    fn parse_table_name(&mut self) -> ParseResult<(Span, (usize, usize))> {
        let start = self.idx;
        let name_at = if self.word_at(start, "ONLY") && self.object_name_end(start + 1).is_some() {
            start + 1
        } else {
            start
        };
        if let Some(mut end) = self.object_name_end(name_at) {
            let star = self.tokens.get(end).is_some_and(|t| {
                matches!(t.kind, TokenKind::Operator(_)) && t.lexeme(self.source) == "*"
            });
            let name_past = end;
            if star {
                end += 1;
            }
            self.idx = end;
            return Ok((
                Span {
                    start: self.tokens[start].span.start,
                    end: self.tokens[end - 1].span.end,
                },
                (name_at, name_past),
            ));
        }

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

        Ok((
            Span {
                start: start_pos,
                end: end_pos,
            },
            (start, self.idx),
        ))
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

        // Whether the actions so far end a list of column alterations after
        // `ALTER` or `MODIFY`, which a later item continues.
        let mut alters_columns = false;
        loop {
            let lead = self.idx;
            let continues = alters_columns && self.column_alteration_item_at(lead);
            let action = self.parse_single_alter_action(continues)?;
            alters_columns = continues || self.column_alteration_led_at(lead);
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

    /// Whether the action at `i` alters a column after `ALTER` or `MODIFY`,
    /// `COLUMN` written or not.
    fn column_alteration_led_at(&self, i: usize) -> bool {
        (self.word_at(i, "ALTER") || self.word_at(i, "MODIFY"))
            && ((self.word_at(i + 1, "COLUMN")
                && self
                    .peek_at(i + 2)
                    .is_some_and(|name| self.can_be_identifier_token(name)))
                || self.bare_column_alteration_at(i + 1, self.named_table_action_at(i).is_none()))
    }

    /// One action; `continues` says it is a later `[COLUMN] <name>
    /// <operation>` item of a list of column alterations.
    fn parse_single_alter_action(&mut self, continues: bool) -> ParseResult<AstAlterTableAction> {
        let expected = |p: &Self| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ALTER TABLE action".to_string(),
                },
            )
        };
        let mut start_tok = self.peek_non_trivia().ok_or_else(|| expected(self))?;

        let action_start = start_tok.span.start;
        // T-SQL's `WITH {CHECK | NOCHECK}` before `ADD` or a constraint
        // check belongs to the action it precedes.
        let checked = self
            .any_words_end(self.idx, &[&["WITH", "CHECK"], &["WITH", "NOCHECK"]])
            .filter(|&k| {
                self.word_at(k, "ADD")
                    || self
                        .any_words_end(k, &[&["CHECK", "CONSTRAINT"], &["NOCHECK", "CONSTRAINT"]])
                        .is_some()
            });
        if let Some(k) = checked {
            self.idx = k;
            start_tok = self.peek_non_trivia().ok_or_else(|| expected(self))?;
        }
        let first_idx = self.idx;
        let kind: AstAlterTableActionKind;

        if continues {
            kind = self.parse_column_alteration(None, true, action_start)?;
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("ADD")
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
        } else if start_tok.lexeme(self.source).eq_ignore_ascii_case("CHANGE") {
            kind = self.parse_change_column_action()?;
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
        } else if let Some(typed) = self.try_parse_owner_or_partition_action()? {
            kind = typed;
        } else if let Some(grammar_end) = self.tsql_table_action_end(self.idx) {
            let target = self
                .tsql_switch_target_at(self.idx)
                .and_then(|at| self.object_ref_at(at, self.id_gen.next()))
                .map(|(_, target)| target);
            let bound = self.clauses_bound(grammar_end);
            let end = if bound == usize::MAX {
                let _ = self.advance();
                self.consume_until_comma_or_end()?
            } else {
                self.consume_action_before(bound)
            };
            kind = match target {
                Some(target) => AstAlterTableActionKind::SwitchTo { target },
                None => AstAlterTableActionKind::GovernanceSpan {
                    span: Span {
                        start: action_start,
                        end,
                    },
                },
            };
        } else {
            kind = self.parse_governance_action()?;
        }

        // An action kept as written whose leading words say what it is.
        let kind = if let AstAlterTableActionKind::Unknown { span }
        | AstAlterTableActionKind::GovernanceSpan { span } = kind
        {
            match self.named_table_action_at(first_idx) {
                Some(named) => AstAlterTableActionKind::NamedAction {
                    kind: named,
                    span,
                    name_span: match named {
                        crate::ast::AstNamedTableAction::Inherit
                        | crate::ast::AstNamedTableAction::NoInherit => {
                            self.inherited_table_at(first_idx)
                        }
                        crate::ast::AstNamedTableAction::DropConstraint
                        | crate::ast::AstNamedTableAction::DropIndex
                        | crate::ast::AstNamedTableAction::DropForeignKey
                        | crate::ast::AstNamedTableAction::DropCheck
                        | crate::ast::AstNamedTableAction::DropPartition
                        | crate::ast::AstNamedTableAction::DropPeriod
                        | crate::ast::AstNamedTableAction::AddPrimaryKey
                        | crate::ast::AstNamedTableAction::AddUnique
                        | crate::ast::AstNamedTableAction::AddCheck
                        | crate::ast::AstNamedTableAction::AddIndex
                        | crate::ast::AstNamedTableAction::AddPartition
                        | crate::ast::AstNamedTableAction::AddPeriod
                        | crate::ast::AstNamedTableAction::AddDefault
                        | crate::ast::AstNamedTableAction::CheckConstraint
                        | crate::ast::AstNamedTableAction::NocheckConstraint
                        | crate::ast::AstNamedTableAction::EnableTrigger
                        | crate::ast::AstNamedTableAction::DisableTrigger
                        | crate::ast::AstNamedTableAction::ChangeTracking
                        | crate::ast::AstNamedTableAction::FiletableNamespace
                        | crate::ast::AstNamedTableAction::Rebuild
                        | crate::ast::AstNamedTableAction::RenameIndex
                        | crate::ast::AstNamedTableAction::RenameConstraint
                        | crate::ast::AstNamedTableAction::AlterIndex
                        | crate::ast::AstNamedTableAction::AlterConstraint
                        | crate::ast::AstNamedTableAction::ValidateConstraint
                        | crate::ast::AstNamedTableAction::TableOption
                        | crate::ast::AstNamedTableAction::ReplicaIdentity
                        | crate::ast::AstNamedTableAction::Distribution
                        | crate::ast::AstNamedTableAction::PartitionMaintenance
                        | crate::ast::AstNamedTableAction::RuleState
                        | crate::ast::AstNamedTableAction::SearchOptimization
                        | crate::ast::AstNamedTableAction::DropUnique
                        | crate::ast::AstNamedTableAction::ResetOptions
                        | crate::ast::AstNamedTableAction::RowLevelSecurity
                        | crate::ast::AstNamedTableAction::KeysState
                        | crate::ast::AstNamedTableAction::DropFeature
                        | crate::ast::AstNamedTableAction::PredictiveOptimization => {
                            self.dropped_object_name_at(first_idx)
                        }
                    },
                },
                None => kind,
            }
        } else {
            kind
        };

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
                return self.parse_added_columns(add_span, Some(col_tok.span));
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT") {
                let constraint_idx = self.idx;
                let constraint_tok = self.advance().expect_invariant(
                    "CONSTRAINT keyword consumed after match in parse_add_action",
                );
                let details_start = self.current_span().start;
                let end = self.consume_until_comma_or_end()?;
                let details = self.parse_constraint_details(constraint_idx, self.idx);
                let expressions = self.constraint_expressions(constraint_idx, self.idx);
                let default_span = self.constraint_default(constraint_idx, self.idx);

                return Ok(AstAlterTableActionKind::AddConstraint {
                    add_span,
                    constraint_span: Some(constraint_tok.span),
                    details_span: Span {
                        start: details_start,
                        end,
                    },
                    details,
                    expressions,
                    default_span,
                });
            } else if (tok.lexeme(self.source).eq_ignore_ascii_case("FOREIGN")
                && self.lexeme_at_is(self.idx + 1, "KEY"))
                || (tok.lexeme(self.source).eq_ignore_ascii_case("PRIMARY")
                    && self.lexeme_at_is(self.idx + 1, "KEY"))
                || tok.lexeme(self.source).eq_ignore_ascii_case("UNIQUE")
            {
                let kind_idx = self.idx;
                let details_start = tok.span.start;
                let end = self.consume_until_comma_or_end()?;
                let details = self.parse_constraint_details(kind_idx, self.idx);
                let expressions = self.constraint_expressions(kind_idx, self.idx);
                let default_span = self.constraint_default(kind_idx, self.idx);

                return Ok(AstAlterTableActionKind::AddConstraint {
                    add_span,
                    constraint_span: None,
                    details_span: Span {
                        start: details_start,
                        end,
                    },
                    details,
                    expressions,
                    default_span,
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("DATA")
                && self
                    .peek_at(self.idx + 1)
                    .is_some_and(|t2| t2.lexeme(self.source).eq_ignore_ascii_case("METRIC"))
            {
                // ADD DATA METRIC FUNCTION <name> ON (<cols>)
                return self.parse_add_data_metric_function(add_span);
            } else if self.bare_added_column_at(self.idx) {
                return self.parse_added_columns(add_span, None);
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

    /// Whether a column definition, `[IF NOT EXISTS]` past, starts at `i`
    /// after a bare `ADD` (T-SQL's idiom, accepted by most dialects): a name
    /// that starts no other `ADD` form, then a type or `AS` (a computed
    /// column).
    fn bare_added_column_at(&self, i: usize) -> bool {
        let at = self.words_end(i, &["IF", "NOT", "EXISTS"]).unwrap_or(i);
        self.peek_at(at).is_some_and(|name| {
            self.can_be_identifier_token(name)
                && !is_non_column_add_starter(name.lexeme(self.source))
        }) && self.peek_at(at + 1).is_some_and(|next| {
            self.can_be_identifier_token(next)
                || matches!(next.kind, TokenKind::Keyword(Keyword::As))
        })
    }

    /// The columns `ADD [COLUMN | COLUMNS]` adds: `[IF NOT EXISTS]`, then
    /// definitions listed with commas or in parentheses.
    fn parse_added_columns(
        &mut self,
        add_span: Option<Span>,
        column_span: Option<Span>,
    ) -> ParseResult<AstAlterTableActionKind> {
        let if_not_exists_span = if self.words_end(self.idx, &["IF", "NOT", "EXISTS"]).is_some() {
            self.parse_optional_if_not_exists()?
        } else {
            None
        };
        let open = self
            .peek()
            .filter(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)))
            .map(|t| t.span);
        if let Some(open) = open {
            let _ = self.advance();
            let columns = self.parse_column_definitions()?;
            let close = self
                .peek()
                .filter(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)))
                .map(|t| t.span)
                .ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected ')' after the column definitions".to_string(),
                        },
                    )
                })?;
            let _ = self.advance();
            return Ok(AstAlterTableActionKind::AddColumn {
                add_span,
                column_span,
                if_not_exists_span,
                columns_span: Span {
                    start: open.start,
                    end: close.end,
                },
                parenthesized: true,
                columns,
            });
        }
        let start = self.current_span().start;
        let columns = self.parse_column_definitions()?;
        let end = columns.last().map_or(start, |last| last.full_span.end);
        Ok(AstAlterTableActionKind::AddColumn {
            add_span,
            column_span,
            if_not_exists_span,
            columns_span: Span { start, end },
            parenthesized: false,
            columns,
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
                let col_names_start = self.current_span().start;
                self.consume_if_exists();
                let (columns, list_end) = self.dropped_columns_at(self.idx);
                let end = match list_end {
                    Some(list_end) => self.consume_action_before(list_end),
                    None => self.consume_until_comma_or_end()?,
                };

                return Ok(AstAlterTableActionKind::DropColumn {
                    drop_span,
                    column_span,
                    columns_span: Span {
                        start: col_names_start,
                        end,
                    },
                    columns,
                });
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT") {
                let constraint_tok = self.advance().expect_invariant(
                    "CONSTRAINT keyword consumed after match in parse_drop_action",
                );
                // `[IF EXISTS] name [WITH (…)] [CASCADE | RESTRICT]`; past
                // a bare name the action is kept as written.
                let name_at = self.words_end(self.idx, &["IF", "EXISTS"]);
                let item_end = self
                    .object_name_end(name_at.unwrap_or(self.idx))
                    .map(|k| {
                        self.words_end(k, &["WITH"])
                            .and_then(|w| self.parens_end(w))
                            .unwrap_or(k)
                    })
                    .map(|k| {
                        self.any_words_end(k, &[&["CASCADE"], &["RESTRICT"]])
                            .unwrap_or(k)
                    });
                if let Some(item_end) = item_end.filter(|&e| e > self.idx + 1) {
                    let end = self.consume_action_before(item_end);
                    return Ok(AstAlterTableActionKind::Unknown {
                        span: Span {
                            start: drop_tok.span.start,
                            end,
                        },
                    });
                }
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

        // T-SQL's `DROP [IF EXISTS] constraint_name`.
        self.consume_if_exists();
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
            } else if let (true, Some(to), Some(new)) = (
                self.can_be_identifier_token(tok),
                self.peek_at(self.idx + 1)
                    .filter(|to| to.lexeme(self.source).eq_ignore_ascii_case("TO")),
                self.peek_at(self.idx + 2)
                    .filter(|new| self.can_be_identifier_token(new)),
            ) {
                // `RENAME <old> TO <new>`: a column, `COLUMN` left out.
                let (old_name_span, to_span, new_name_span) = (tok.span, Some(to.span), new.span);
                for _ in 0..3 {
                    let _ = self.advance();
                }
                return Ok(AstAlterTableActionKind::RenameColumn {
                    rename_span,
                    column_span: None,
                    old_name_span,
                    to_span,
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

    /// `CHANGE [COLUMN] <name> <alter-column clause>` (an altered column) or
    /// `CHANGE [COLUMN] <old> <new> <definition>`; anything else after
    /// `CHANGE` is kept as written.
    fn parse_change_column_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        let change_tok = self
            .advance()
            .expect_invariant("CHANGE keyword consumed after caller match");
        let column_span = if self.word_at(self.idx, "COLUMN") {
            self.advance().map(|t| t.span)
        } else {
            None
        };
        let altered = self
            .peek_at(self.idx)
            .filter(|name| self.can_be_identifier_token(name))
            .filter(|_| self.alter_column_clause_at(self.idx + 1));
        if let Some(name) = altered {
            let _ = self.advance();
            return self.finish_column_alteration(Some(change_tok.span), column_span, name.span);
        }
        let names = (
            self.peek_at(self.idx)
                .filter(|old| self.can_be_identifier_token(old)),
            self.peek_at(self.idx + 1)
                .filter(|new| self.can_be_identifier_token(new)),
        );
        if let (Some(old), Some(new)) = names {
            let (old_name_span, new_name_span) = (old.span, new.span);
            for _ in 0..2 {
                let _ = self.advance();
            }
            let definition_start = self.current_span().start;
            let definition_first = self.idx;
            let end = self.consume_until_comma_or_end()?;
            return Ok(AstAlterTableActionKind::ChangeColumn {
                change_span: change_tok.span,
                column_span,
                old_name_span,
                new_name_span,
                definition_span: Span {
                    start: definition_start,
                    end: end.max(definition_start),
                },
                null_written: self.null_written(definition_first, self.idx),
            });
        }
        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span {
                start: change_tok.span.start,
                end,
            },
        })
    }

    fn parse_alter_column_action(&mut self) -> ParseResult<AstAlterTableActionKind> {
        // A type may follow a column's name where the leading words name no
        // other `ALTER` form (`ALTER INDEX`, `ALTER DISTKEY`, …).
        let definition = self.named_table_action_at(self.idx).is_none();
        let alter_tok = self
            .advance()
            .expect_invariant("ALTER keyword consumed after caller match");
        if let Some((columns, close)) = self.column_alteration_list_at(self.idx) {
            let list_start = self.current_span().start;
            let end = self.consume_action_before(close + 1);
            return Ok(AstAlterTableActionKind::AlterColumnList {
                alter_span: alter_tok.span,
                list_span: Span {
                    start: list_start,
                    end,
                },
                columns,
            });
        }
        self.parse_column_alteration(Some(alter_tok.span), definition, alter_tok.span.start)
    }

    /// `[COLUMN] <name> <operation>` after `ALTER` / `MODIFY` (`alter_span`),
    /// or as a later item of a list of them; kept as written from `start`
    /// where it is neither. `definition` says a type may stand for the
    /// operation where `COLUMN` is left out.
    fn parse_column_alteration(
        &mut self,
        alter_span: Option<Span>,
        definition: bool,
        start: u32,
    ) -> ParseResult<AstAlterTableActionKind> {
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
                return self.parse_column_operation(alter_span, Some(col_tok.span), name_tok.span);
            }
        }

        // `{ALTER | MODIFY} <column> <operation>`: a column, `COLUMN` left out.
        if self.bare_column_alteration_at(self.idx, definition) {
            let name = self
                .advance()
                .expect_invariant("column name checked before a bare column alteration");
            return self.parse_column_operation(alter_span, None, name.span);
        }

        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::Unknown {
            span: Span { start, end },
        })
    }

    /// The operation on the column `column_name_span` names, `COLUMN`
    /// (`column_span`) written or not: a tag, mask, masking or projection
    /// policy change, a `SET` / `DROP` the column's form reads, or any
    /// other operation kept as written.
    fn parse_column_operation(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        if let Some(next_tok) = self.peek_non_trivia() {
            if next_tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
                if self.is_tag_pattern() {
                    return self.parse_column_tag_action(alter_span, column_span, column_name_span);
                }
                if self.is_set_mask_pattern() {
                    return self.parse_set_column_mask(alter_span, column_span, column_name_span);
                }
                if self.is_masking_policy_pattern() {
                    return self.parse_set_column_masking_policy(
                        alter_span,
                        column_span,
                        column_name_span,
                    );
                }
                if self.is_projection_policy_pattern() {
                    return self.parse_set_column_projection_policy(
                        alter_span,
                        column_span,
                        column_name_span,
                    );
                }
                return self.parse_bq_alter_column_set(alter_span, column_span, column_name_span);
            }
            if next_tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
                if self.is_tag_pattern() {
                    return self.parse_column_tag_action(alter_span, column_span, column_name_span);
                }
                if self.is_masking_policy_pattern() {
                    return self.parse_unset_column_masking_policy(
                        alter_span,
                        column_span,
                        column_name_span,
                    );
                }
                if self.is_projection_policy_pattern() {
                    return self.parse_unset_column_projection_policy(
                        alter_span,
                        column_span,
                        column_name_span,
                    );
                }
            } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Drop)) {
                if self.is_drop_mask_pattern() {
                    return self.parse_drop_column_mask(alter_span, column_span, column_name_span);
                }
                return self.parse_bq_alter_column_drop(alter_span, column_span, column_name_span);
            }
        }
        self.finish_column_alteration(alter_span, column_span, column_name_span)
    }

    /// Whether `<column> <operation>` starts at `i`, `COLUMN` left out: a
    /// name and an operation's first word, or, where `definition`, a type.
    fn bare_column_alteration_at(&self, i: usize, definition: bool) -> bool {
        let named = self.peek_at(i).is_some_and(|name| {
            self.can_be_identifier_token(name)
                && !["INDEX", "KEY", "CONSTRAINT", "CHECK"]
                    .iter()
                    .any(|word| name.lexeme(self.source).eq_ignore_ascii_case(word))
        });
        let operation_follows = self.column_operation_word_at(i + 1)
            || (definition
                && self
                    .peek_at(i + 1)
                    .is_some_and(|op| self.can_be_identifier_token(op)));
        named && operation_follows
    }

    /// Whether the token at `i` is the first word of an operation on part
    /// of a column, which a column's definition (a type first) is not.
    fn column_operation_word_at(&self, i: usize) -> bool {
        const OPERATIONS: &[&str] = &[
            "TYPE", "SET", "DROP", "RESET", "ADD", "OPTIONS", "COMMENT", "UNSET", "FIRST", "AFTER",
            "SYNC",
        ];
        OPERATIONS.iter().any(|word| self.word_at(i, word))
    }

    /// Whether an item of a list of column alterations, `[COLUMN] <name>
    /// <operation>`, starts at `i`. A word that leads another action is no
    /// column name.
    pub(crate) fn column_alteration_item_at(&self, i: usize) -> bool {
        const ACTION_LEADS: &[&str] = &[
            "ADD", "DROP", "ALTER", "MODIFY", "CHANGE", "RENAME", "CLUSTER", "SET", "UNSET",
            "SWAP", "SUSPEND", "RESUME",
        ];
        if self.word_at(i, "COLUMN") {
            return self
                .peek_at(i + 1)
                .is_some_and(|name| self.can_be_identifier_token(name));
        }
        !ACTION_LEADS.iter().any(|word| self.word_at(i, word))
            && self.named_table_action_at(i).is_none()
            && self.bare_column_alteration_at(i, true)
    }

    /// Each item's column name, and the index of the closing parenthesis,
    /// of `( [COLUMN] <name> <operation>, … )` opening at `open`; `None`
    /// where an item is not a column alteration.
    fn column_alteration_list_at(&self, open: usize) -> Option<(Vec<Span>, usize)> {
        let opens = self
            .peek_at(open)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)));
        if !opens {
            return None;
        }
        let close = self.closing_paren_index(open)?;
        let mut columns = Vec::new();
        let mut item = open + 1;
        let mut depth = 0usize;
        for k in open + 1..=close {
            let kind = &self.peek_at(k)?.kind;
            let ends_item = k == close
                || (depth == 0 && matches!(kind, TokenKind::Punctuation(Punctuation::Comma)));
            if ends_item {
                if !self.column_alteration_item_at(item) {
                    return None;
                }
                let name_at = if self.word_at(item, "COLUMN") {
                    item + 1
                } else {
                    item
                };
                columns.push(self.peek_at(name_at)?.span);
                item = k + 1;
            } else if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth = depth.saturating_sub(1);
            }
        }
        Some((columns, close))
    }

    /// Whether an alter-column clause starts at `i`: `COMMENT '…'`, `FIRST`,
    /// `AFTER <column>`, `TYPE <type>`, `{SET | DROP} {NOT NULL | DEFAULT |
    /// MASK}`, `SYNC IDENTITY`.
    fn alter_column_clause_at(&self, i: usize) -> bool {
        let ends_action = |k: usize| {
            self.peek_at(k).is_none_or(|t| {
                matches!(
                    t.kind,
                    TokenKind::Eof
                        | TokenKind::Punctuation(Punctuation::Semi)
                        | TokenKind::Punctuation(Punctuation::Comma)
                )
            })
        };
        let is_name = |k: usize| {
            self.peek_at(k)
                .is_some_and(|t| self.can_be_identifier_token(t))
        };
        let commented = self.word_at(i, "COMMENT")
            && self
                .peek_at(i + 1)
                .is_some_and(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::String)));
        commented
            || (self.word_at(i, "FIRST") && ends_action(i + 1))
            || (self.word_at(i, "AFTER") && is_name(i + 1) && ends_action(i + 2))
            || (self.word_at(i, "TYPE") && is_name(i + 1))
            || self
                .any_words_end(
                    i,
                    &[
                        &["SET", "NOT", "NULL"],
                        &["DROP", "NOT", "NULL"],
                        &["SET", "DEFAULT"],
                        &["DROP", "DEFAULT"],
                        &["SET", "MASK"],
                        &["DROP", "MASK"],
                        &["SYNC", "IDENTITY"],
                    ],
                )
                .is_some()
    }

    /// An altered column whose name is read: its operation's first word,
    /// then the rest of the action.
    fn finish_column_alteration(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let op_start = self.current_span().start;
        let op_first = self.idx;
        let mut end = op_start;
        let leads = self.peek().filter(|t| {
            !matches!(
                t.kind,
                TokenKind::Eof
                    | TokenKind::Punctuation(Punctuation::Semi)
                    | TokenKind::Punctuation(Punctuation::Comma)
            )
        });
        let altered_type = match leads {
            Some(_) => self.altered_type_at(op_first),
            None => AstAlteredType::Kept,
        };
        if let Some(first) = leads {
            end = first.span.end;
            let _ = self.advance();
            let after_first = self.idx;
            let rest_end = self.consume_until_comma_or_end()?;
            if self.idx > after_first {
                end = rest_end;
            }
        }
        let default_span = self
            .words_end(op_first, &["SET", "DEFAULT"])
            .and_then(|at| self.peek_at(at))
            .map(|first| first.span.start)
            .filter(|start| *start < end)
            .map(|start| Span { start, end });
        let nullability = if self.column_operation_word_at(op_first) {
            AstAlteredNullability::Kept
        } else {
            AstAlteredNullability::Redefined {
                not_null: self.null_written(op_first, self.idx) == Some(false),
            }
        };
        Ok(AstAlterTableActionKind::AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span: Span {
                start: op_start,
                end,
            },
            nullability,
            altered_type,
            default_span,
        })
    }

    /// What the column operation whose first token is at `op_first` does to
    /// the column's type: a definition (a type first: T-SQL `ALTER COLUMN v
    /// NVARCHAR(200)`, MySQL `MODIFY v TEXT`), `TYPE t` or `SET DATA TYPE t`
    /// gives it the type written there; any other operation keeps it.
    fn altered_type_at(&self, op_first: usize) -> AstAlteredType {
        let type_at = if !self.column_operation_word_at(op_first) {
            Some(op_first)
        } else if self.word_at(op_first, "TYPE") {
            Some(op_first + 1)
        } else {
            self.words_end(op_first, &["SET", "DATA", "TYPE"])
        };
        match type_at {
            Some(at) => AstAlteredType::Changed {
                type_span: self.data_type_span_at(at),
            },
            None => AstAlteredType::Kept,
        }
    }

    /// The span of the data type whose name starts at token `at`: its name,
    /// and the parenthesized list after it where one is written.
    fn data_type_span_at(&self, at: usize) -> Option<Span> {
        let (next, name) = self.name_span_at(at, crate::parser::core::NamePosition::DataType)?;
        let opens = self
            .peek_at(next)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)));
        if !opens {
            return Some(name);
        }
        let mut depth = 0usize;
        for k in next.. {
            let tok = self.peek_at(k)?;
            if matches!(tok.kind, TokenKind::Eof) {
                return None;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(Span {
                        start: name.start,
                        end: tok.span.end,
                    });
                }
            }
        }
        None
    }

    /// The name of the constraint, index or key a `DROP` action whose first
    /// token is at `i` drops, `IF EXISTS` skipped.
    fn dropped_object_name_at(&self, i: usize) -> Option<Span> {
        let past = self.any_words_end(
            i,
            &[
                &["DROP", "CONSTRAINT"],
                &["CONSTRAINT"],
                &["DROP", "INDEX"],
                &["DROP", "KEY"],
                &["DROP", "FOREIGN", "KEY"],
                &["DROP", "CHECK"],
            ],
        )?;
        let at = self.words_end(past, &["IF", "EXISTS"]).unwrap_or(past);
        self.peek_at(at)
            .filter(|tok| self.can_be_identifier_token(tok))
            .map(|tok| tok.span)
    }

    /// The parent table a `[NO] INHERIT` action whose first token is at `i`
    /// names.
    fn inherited_table_at(&self, i: usize) -> Option<Span> {
        let past = self.any_words_end(i, &[&["INHERIT"], &["NO", "INHERIT"]])?;
        self.name_span_at(past, NamePosition::Object)
            .map(|(_, span)| span)
    }

    /// What a column definition or operation, its tokens from `from` to
    /// `to`, writes of NULL outside parentheses: `Some(false)` for `NOT
    /// NULL`, `Some(true)` for `NULL`, `None` for neither.
    fn null_written(&self, from: usize, to: usize) -> Option<bool> {
        let mut depth = 0usize;
        let mut written = None;
        for at in from..to.min(self.tokens.len()) {
            let tok = &self.tokens[at];
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                TokenKind::Literal(LiteralKind::Null) => {
                    if depth > 0 {
                        continue;
                    }
                    let negated = at > from
                        && matches!(self.tokens[at - 1].kind, TokenKind::Keyword(Keyword::Not));
                    if negated {
                        return Some(false);
                    }
                    written = Some(true);
                }
                TokenKind::Punctuation(
                    Punctuation::LBracket
                    | Punctuation::RBracket
                    | Punctuation::LCurly
                    | Punctuation::RCurly
                    | Punctuation::Comma
                    | Punctuation::Semi
                    | Punctuation::Dot
                    | Punctuation::Colon,
                )
                | TokenKind::Literal(
                    LiteralKind::String
                    | LiteralKind::StringFragment
                    | LiteralKind::Number
                    | LiteralKind::Position
                    | LiteralKind::Parameter
                    | LiteralKind::Money
                    | LiteralKind::Boolean,
                )
                | TokenKind::Keyword(_)
                | TokenKind::Identifier { .. }
                | TokenKind::Operator(_)
                | TokenKind::LineComment
                | TokenKind::BlockComment
                | TokenKind::JinjaComment
                | TokenKind::JinjaExprOpen
                | TokenKind::JinjaExprClose
                | TokenKind::JinjaStmtOpen
                | TokenKind::JinjaStmtClose
                | TokenKind::JinjaPipe
                | TokenKind::JinjaTilde
                | TokenKind::JinjaDoubleStar
                | TokenKind::JinjaDoubleSlash
                | TokenKind::JinjaDoubleEq
                | TokenKind::JinjaAnd
                | TokenKind::JinjaOr
                | TokenKind::JinjaNot
                | TokenKind::JinjaIn
                | TokenKind::JinjaIs
                | TokenKind::JinjaTrue
                | TokenKind::JinjaFalse
                | TokenKind::JinjaNull
                | TokenKind::JinjaIf
                | TokenKind::JinjaElif
                | TokenKind::JinjaElse
                | TokenKind::JinjaEndIf
                | TokenKind::JinjaFor
                | TokenKind::JinjaEndFor
                | TokenKind::JinjaSet
                | TokenKind::JinjaEndSet
                | TokenKind::JinjaDocs
                | TokenKind::JinjaEndDocs
                | TokenKind::JinjaFilter
                | TokenKind::JinjaEndFilter
                | TokenKind::JinjaCall
                | TokenKind::JinjaEndCall
                | TokenKind::Placeholder
                | TokenKind::Eof
                | TokenKind::Unknown => {}
            }
        }
        written
    }

    /// What the action whose first token is at `i` is, by its leading
    /// words, for an action the parser keeps as written.
    fn named_table_action_at(&self, i: usize) -> Option<crate::ast::AstNamedTableAction> {
        use crate::ast::AstNamedTableAction as N;
        const LEADS: &[(&[&str], N)] = &[
            (&["DROP", "CONSTRAINT"], N::DropConstraint),
            (&["CONSTRAINT"], N::DropConstraint),
            (&["DROP", "INDEX"], N::DropIndex),
            (&["DROP", "KEY"], N::DropIndex),
            (&["DROP", "FOREIGN", "KEY"], N::DropForeignKey),
            (&["DROP", "CHECK"], N::DropCheck),
            (&["DROP", "PARTITION"], N::DropPartition),
            (&["DROP", "IF", "EXISTS", "PARTITION"], N::DropPartition),
            (&["DROP", "PERIOD"], N::DropPeriod),
            (&["ADD", "PRIMARY", "KEY"], N::AddPrimaryKey),
            (&["ADD", "UNIQUE"], N::AddUnique),
            (&["ADD", "CHECK"], N::AddCheck),
            (&["ADD", "INDEX"], N::AddIndex),
            (&["ADD", "KEY"], N::AddIndex),
            (&["ADD", "FULLTEXT"], N::AddIndex),
            (&["ADD", "SPATIAL"], N::AddIndex),
            (&["ADD", "PARTITION"], N::AddPartition),
            (
                &["ADD", "IF", "NOT", "EXISTS", "PARTITION"],
                N::AddPartition,
            ),
            (&["ADD", "PERIOD"], N::AddPeriod),
            (&["ADD", "DEFAULT"], N::AddDefault),
            (&["CHECK", "CONSTRAINT"], N::CheckConstraint),
            (&["NOCHECK", "CONSTRAINT"], N::NocheckConstraint),
            (&["ENABLE", "TRIGGER"], N::EnableTrigger),
            (&["ENABLE", "ALWAYS", "TRIGGER"], N::EnableTrigger),
            (&["ENABLE", "REPLICA", "TRIGGER"], N::EnableTrigger),
            (&["DISABLE", "TRIGGER"], N::DisableTrigger),
            (&["ENABLE", "RULE"], N::RuleState),
            (&["ENABLE", "ALWAYS", "RULE"], N::RuleState),
            (&["ENABLE", "REPLICA", "RULE"], N::RuleState),
            (&["DISABLE", "RULE"], N::RuleState),
            (&["ENABLE", "CHANGE_TRACKING"], N::ChangeTracking),
            (&["DISABLE", "CHANGE_TRACKING"], N::ChangeTracking),
            (&["ENABLE", "FILETABLE_NAMESPACE"], N::FiletableNamespace),
            (&["DISABLE", "FILETABLE_NAMESPACE"], N::FiletableNamespace),
            (&["REBUILD"], N::Rebuild),
            (&["RENAME", "INDEX"], N::RenameIndex),
            (&["RENAME", "KEY"], N::RenameIndex),
            (&["RENAME", "CONSTRAINT"], N::RenameConstraint),
            (&["ALTER", "INDEX"], N::AlterIndex),
            (&["ALTER", "CONSTRAINT"], N::AlterConstraint),
            (&["ALTER", "CHECK"], N::AlterConstraint),
            (&["VALIDATE", "CONSTRAINT"], N::ValidateConstraint),
            (&["ENGINE"], N::TableOption),
            (&["AUTO_INCREMENT"], N::TableOption),
            (&["ROW_FORMAT"], N::TableOption),
            (&["ALGORITHM"], N::TableOption),
            (&["LOCK"], N::TableOption),
            (&["CHARSET"], N::TableOption),
            (&["CHARACTER", "SET"], N::TableOption),
            (&["DEFAULT", "CHARSET"], N::TableOption),
            (&["DEFAULT", "CHARACTER", "SET"], N::TableOption),
            (&["DEFAULT", "COLLATE"], N::TableOption),
            (&["COLLATE"], N::TableOption),
            (&["COMMENT"], N::TableOption),
            (&["CONVERT", "TO"], N::TableOption),
            (&["FORCE"], N::TableOption),
            (&["ORDER", "BY"], N::TableOption),
            (&["KEY_BLOCK_SIZE"], N::TableOption),
            (&["CHECKSUM"], N::TableOption),
            (&["COMPRESSION"], N::TableOption),
            (&["ENCRYPTION"], N::TableOption),
            (&["STATS_PERSISTENT"], N::TableOption),
            (&["PACK_KEYS"], N::TableOption),
            (&["MAX_ROWS"], N::TableOption),
            (&["MIN_ROWS"], N::TableOption),
            (&["AVG_ROW_LENGTH"], N::TableOption),
            (&["DELAY_KEY_WRITE"], N::TableOption),
            (&["INSERT_METHOD"], N::TableOption),
            (&["TABLESPACE"], N::TableOption),
            (&["ALTER", "DISTKEY"], N::Distribution),
            (&["ALTER", "DISTSTYLE"], N::Distribution),
            (&["ALTER", "SORTKEY"], N::Distribution),
            (&["ALTER", "COMPOUND", "SORTKEY"], N::Distribution),
            (&["ALTER", "INTERLEAVED", "SORTKEY"], N::Distribution),
            (&["ALTER", "ENCODE"], N::Distribution),
            (&["TRUNCATE", "PARTITION"], N::PartitionMaintenance),
            (&["COALESCE", "PARTITION"], N::PartitionMaintenance),
            (&["REORGANIZE", "PARTITION"], N::PartitionMaintenance),
            (&["ANALYZE", "PARTITION"], N::PartitionMaintenance),
            (&["CHECK", "PARTITION"], N::PartitionMaintenance),
            (&["OPTIMIZE", "PARTITION"], N::PartitionMaintenance),
            (&["REPAIR", "PARTITION"], N::PartitionMaintenance),
            (&["EXCHANGE", "PARTITION"], N::PartitionMaintenance),
            (&["DISCARD", "PARTITION"], N::PartitionMaintenance),
            (&["IMPORT", "PARTITION"], N::PartitionMaintenance),
            (&["ARCHIVE", "PARTITION"], N::PartitionMaintenance),
            (&["UNARCHIVE", "PARTITION"], N::PartitionMaintenance),
            (&["DISCARD", "TABLESPACE"], N::PartitionMaintenance),
            (&["IMPORT", "TABLESPACE"], N::PartitionMaintenance),
            (&["REMOVE", "PARTITIONING"], N::PartitionMaintenance),
            (&["PARTITION", "BY"], N::PartitionMaintenance),
            (&["RECOVER", "PARTITIONS"], N::PartitionMaintenance),
            (&["TOUCH"], N::PartitionMaintenance),
            (&["ADD", "SEARCH", "OPTIMIZATION"], N::SearchOptimization),
            (&["DROP", "SEARCH", "OPTIMIZATION"], N::SearchOptimization),
            (&["DROP", "UNIQUE"], N::DropUnique),
            (&["RESET"], N::ResetOptions),
            (&["ROW", "LEVEL", "SECURITY"], N::RowLevelSecurity),
            (&["ENABLE", "KEYS"], N::KeysState),
            (&["DISABLE", "KEYS"], N::KeysState),
            (&["DROP", "FEATURE"], N::DropFeature),
            (
                &["ENABLE", "PREDICTIVE", "OPTIMIZATION"],
                N::PredictiveOptimization,
            ),
            (
                &["DISABLE", "PREDICTIVE", "OPTIMIZATION"],
                N::PredictiveOptimization,
            ),
            (
                &["INHERIT", "PREDICTIVE", "OPTIMIZATION"],
                N::PredictiveOptimization,
            ),
            (&["PREDICTIVE", "OPTIMIZATION"], N::PredictiveOptimization),
            (&["INHERIT"], N::Inherit),
            (&["NO", "INHERIT"], N::NoInherit),
            (&["REPLICA", "IDENTITY"], N::ReplicaIdentity),
        ];
        LEADS
            .iter()
            .find(|(words, _)| self.words_end(i, words).is_some())
            .map(|(_, named)| *named)
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

        let start = self.current_span().start;

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
        let start = self.current_span().start;

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

                let function_name_span = self.parse_object_name_span()?;

                let on_tok = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        function_name_span,
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
                        function_name_span,
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
                    function_name_span,
                    on_span,
                    columns_span: Span {
                        start: columns_start,
                        end: last_end,
                    },
                });
            }

            // PG: SET SCHEMA schema
            if tok.lexeme(self.source).eq_ignore_ascii_case("SCHEMA") {
                let saved_idx = self.idx;
                self.advance();
                if let Some(schema) = self.take_name_span(NamePosition::Object) {
                    self.consume_until_comma_or_end()?;
                    return Ok(AstAlterTableActionKind::SetSchema { schema });
                }
                self.idx = saved_idx;
            }

            // SET TAG tag = 'value' (Snowflake)
            if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
                let tag_tok = self
                    .advance()
                    .expect_invariant("TAG keyword consumed after match in parse_set_action");
                let tag_span = Some(tag_tok.span);
                let (assignments_span, tags) = self.parse_tag_list(TagListShape::Assignments)?;
                return Ok(AstAlterTableActionKind::SetTag {
                    set_span,
                    tag_span,
                    assignments_span,
                    tags,
                });
            }
            // Databricks: SET TBLPROPERTIES ('key' = 'value', ...)
            if tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("TBLPROPERTIES")
            {
                let tblproperties_tok = self.advance().expect_invariant("TBLPROPERTIES consumed");
                let tblproperties_span = Some(tblproperties_tok.span);
                self.record_option_list_secrets(self.idx);
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
                self.record_option_list_secrets(self.idx);
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
        let start = self.current_span().start;

        // Check for UNSET TAG or UNSET TBLPROPERTIES
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
                let tag_tok = self
                    .advance()
                    .expect_invariant("TAG keyword consumed after match in parse_unset_action");
                let tag_span = Some(tag_tok.span);
                let (tags_span, tags) = self.parse_tag_list(TagListShape::Names)?;
                return Ok(AstAlterTableActionKind::UnsetTag {
                    unset_span,
                    tag_span,
                    tags_span,
                    tags,
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
        // A later item of T-SQL's `DROP` list: `{COLUMN | CONSTRAINT} [IF EXISTS] …`.
        if start_tok.lexeme(self.source).eq_ignore_ascii_case("COLUMN") {
            let names_start = self.current_span().start;
            self.consume_if_exists();
            let (columns, list_end) = self.dropped_columns_at(self.idx);
            let end = match list_end {
                Some(list_end) => self.consume_action_before(list_end),
                None => self.consume_until_comma_or_end()?,
            };
            return Ok(AstAlterTableActionKind::DropColumn {
                drop_span: None,
                column_span: Some(start_tok.span),
                columns_span: Span {
                    start: names_start,
                    end,
                },
                columns,
            });
        }
        if start_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CONSTRAINT")
        {
            self.consume_if_exists();
        }
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
        let policy_name = self.parse_object_name_span()?;

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
        let policy_name_span = self.parse_object_name_span()?;

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

    /// Whether the next two tokens are `SET TAG` or `UNSET TAG`.
    fn is_tag_pattern(&self) -> bool {
        let verb = self.peek_at(self.idx).is_some_and(|tok| {
            let lexeme = tok.lexeme(self.source);
            lexeme.eq_ignore_ascii_case("SET") || lexeme.eq_ignore_ascii_case("UNSET")
        });
        verb && self
            .peek_at(self.idx + 1)
            .is_some_and(|tok| tok.lexeme(self.source).eq_ignore_ascii_case("TAG"))
    }

    /// `SET TAG name = value {, …}` or `UNSET TAG name {, …}` after
    /// `ALTER | MODIFY [COLUMN] <col>`. The list ends before the next item
    /// of a list of column alterations (`, [COLUMN] <name> <operation>`),
    /// which is its own action.
    fn parse_column_tag_action(
        &mut self,
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
    ) -> ParseResult<AstAlterTableActionKind> {
        let verb_tok = self
            .advance()
            .expect_invariant("SET or UNSET consumed after the tag pattern");
        let verb_span = Some(verb_tok.span);
        let tag_tok = self
            .advance()
            .expect_invariant("TAG consumed after the tag pattern");
        let tag_span = Some(tag_tok.span);
        if verb_tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
            let (assignments_span, tags) = self
                .parse_tag_list_until(TagListShape::Assignments, Self::column_alteration_item_at)?;
            Ok(AstAlterTableActionKind::SetColumnTag {
                alter_span,
                column_span,
                column_name_span,
                set_span: verb_span,
                tag_span,
                assignments_span,
                tags,
            })
        } else {
            let (tags_span, tags) =
                self.parse_tag_list_until(TagListShape::Names, Self::column_alteration_item_at)?;
            Ok(AstAlterTableActionKind::UnsetColumnTag {
                alter_span,
                column_span,
                column_name_span,
                unset_span: verb_span,
                tag_span,
                tags_span,
                tags,
            })
        }
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

        let function_name_span = self.parse_object_name_span()?;

        // `USING COLUMNS (a, 'x', …)`.
        let mut using_columns_span = None;
        let mut using_columns = Vec::new();
        let using = self
            .peek()
            .filter(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Using)))
            .map(|t| t.span);
        if let Some(using) = using.filter(|_| {
            self.is_word(self.peek_ahead(1), "COLUMNS")
                && self.peek_ahead(2).is_some_and(|t| {
                    matches!(
                        t.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    )
                })
        }) {
            self.advance(); // USING
            self.advance(); // COLUMNS
            self.advance(); // (
            loop {
                using_columns.push(self.parse_expr()?);
                let next = self.advance().ok_or_else(|| {
                    ParseError::new(
                        using,
                        ParseErrorKind::InvalidSyntax {
                            message: "Expected ')' after USING COLUMNS".to_string(),
                        },
                    )
                })?;
                match next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {}
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        using_columns_span = Some(Span {
                            start: using.start,
                            end: next.span.end,
                        });
                        break;
                    }
                    _ => {
                        return Err(ParseError::new(
                            next.span,
                            ParseErrorKind::InvalidSyntax {
                                message: "Expected ',' or ')' in USING COLUMNS".to_string(),
                            },
                        ))
                    }
                }
            }
        }

        Ok(AstAlterTableActionKind::SetColumnMask {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            mask_span,
            function_name_span,
            using_columns_span,
            using_columns,
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
        let policy_name_span = self.parse_object_name_span()?;

        // Optional USING (col1, col2, ...)
        let using_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("USING") {
                let using_tok = self
                    .advance()
                    .expect_invariant("USING keyword consumed after match");
                let mut end = using_tok.span.end;

                // Consume USING clause (typically parenthesized column list)
                if let Some(lparen) = self.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        let _ = self.advance();
                        let mut depth = 1;

                        while depth > 0 && self.peek().is_some() {
                            if let Some(tok) = self.advance() {
                                end = tok.span.end;
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

                Some(Span {
                    start: using_tok.span.start,
                    end,
                })
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
        let policy_name_span = self.parse_object_name_span()?;

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
                            // MySQL's column redefinitions.
                            || next.lexeme(self.source).eq_ignore_ascii_case("MODIFY")
                            || next.lexeme(self.source).eq_ignore_ascii_case("CHANGE")
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
        let start_idx = self.idx;
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
                // T-SQL's period and ledger columns: `GENERATED ALWAYS AS
                // {ROW | TRANSACTION_ID | SEQUENCE_NUMBER} {START | END}`.
                let period = self.any_words_end(
                    self.idx,
                    &[
                        &["ROW", "START"],
                        &["ROW", "END"],
                        &["TRANSACTION_ID", "START"],
                        &["TRANSACTION_ID", "END"],
                        &["SEQUENCE_NUMBER", "START"],
                        &["SEQUENCE_NUMBER", "END"],
                    ],
                );
                if let Some(k) = period {
                    end = self.tokens[k - 1].span.end;
                    self.idx = k;
                } else if matches!(
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
                    // Parentheses and `CASE … END` nest; outside them a
                    // statement's first word ends the expression.
                    let mut depth: i32 = 0;
                    while let Some(t2) = self.peek() {
                        if matches!(
                            t2.kind,
                            TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
                        ) {
                            break;
                        }
                        let is_lparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::LParen))
                                || matches!(t2.kind, TokenKind::Keyword(Keyword::Case));
                        let is_rparen =
                            matches!(t2.kind, TokenKind::Punctuation(Punctuation::RParen))
                                || (depth > 0
                                    && matches!(t2.kind, TokenKind::Keyword(Keyword::End)));
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
                        if depth == 0 && !is_lparen && self.starts_statement_after_action(t2) {
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
        let mut foreign_key = None;
        let mut masking_policy = None;
        let mut masking_policy_using = Vec::new();
        let mut tags = Vec::new();
        while let Some(tok) = self.peek() {
            if depth == 0 {
                if foreign_key.is_none() {
                    if let Some(target) = self.words_end(self.idx, &["REFERENCES"]) {
                        foreign_key = self.foreign_key_at(
                            target,
                            self.tokens.len(),
                            name_span.into_iter().collect(),
                            None,
                        );
                    }
                }
                if self.consume_references_clause().is_some() {
                    continue;
                }
            }
            // The names of the clauses read past below.
            if depth == 0 && masking_policy.is_none() {
                if let Some(clause) = self.masking_policy_at(self.idx) {
                    masking_policy = Some(clause.policy);
                    masking_policy_using = clause.columns;
                }
            }
            if depth == 0 && tags.is_empty() {
                if let Some((_, read)) = self
                    .any_words_end(self.idx, &[&["WITH", "TAG"], &["TAG"]])
                    .and_then(|open| {
                        self.parenthesised_tag_list_at(open, TagListShape::Assignments)
                    })
                {
                    tags = read;
                }
            }
            match tok.kind {
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi) => break,
                TokenKind::Punctuation(Punctuation::Comma) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::RParen) if depth == 0 => break,
                // `CASE … END` nests as parentheses do.
                TokenKind::Punctuation(Punctuation::LParen) | TokenKind::Keyword(Keyword::Case) => {
                    depth += 1;
                    let _ = self.advance();
                }
                TokenKind::Keyword(Keyword::End) if depth > 0 => {
                    depth -= 1;
                    let _ = self.advance();
                }
                _ if depth == 0 && self.starts_statement_after_action(tok) => break,
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
        let definition = self.column_as_created(start_idx, self.idx).map(Box::new);

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
            foreign_key,
            masking_policy,
            masking_policy_using,
            tags,
            definition,
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
        let policy_name_span = self.parse_object_name_span()?;

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
        let policy_name_span = self.parse_object_name_span()?;

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
        let set_at = self.idx;
        let set_tok = self.advance().expect_invariant("SET keyword consumed");
        let set_span = Some(set_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            // ALTER COLUMN <col> SET OPTIONS (...)
            if tok.lexeme(self.source).eq_ignore_ascii_case("OPTIONS") {
                let options_tok = self.advance().expect_invariant("OPTIONS consumed");
                let options_span = Some(options_tok.span);
                self.record_option_list_secrets(self.idx);
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
                let expr_span = Span {
                    start: expr_start,
                    end,
                };
                let expr = self.expr_written_at(expr_span).map(Box::new);
                return Ok(AstAlterTableActionKind::AlterColumnSetDefault {
                    alter_span,
                    column_span,
                    column_name_span,
                    set_span,
                    default_span,
                    expr_span,
                    expr,
                });
            }
        }

        // Fallback: generic AlterColumn for unrecognized SET sub-actions
        let op_start = set_tok.span.start;
        let altered_type = self.altered_type_at(set_at);
        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span: Span {
                start: op_start,
                end,
            },
            nullability: AstAlteredNullability::Kept,
            altered_type,
            default_span: None,
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
            // ALTER COLUMN <col> DROP NOT NULL (T-SQL's `DROP NOT FOR
            // REPLICATION` is read by the fallback below)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Not))
                && self.peek_at(self.idx + 1).is_some_and(|t| {
                    matches!(t.kind, TokenKind::Literal(crate::lexer::LiteralKind::Null))
                })
            {
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
        let op_start = drop_tok.span.start;
        let end = self.consume_until_comma_or_end()?;
        Ok(AstAlterTableActionKind::AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span: Span {
                start: op_start,
                end,
            },
            nullability: AstAlteredNullability::Kept,
            altered_type: AstAlteredType::Kept,
            default_span: None,
        })
    }

    /// Whether `tok`, outside parentheses after an action, starts the next
    /// statement: only where statements need no terminator.
    fn starts_statement_after_action(&self, tok: &crate::lexer::Token) -> bool {
        self.ends_unterminated_at(tok, crate::parser::core::StatementContext::ActionTail)
    }

    /// The columns a `DROP COLUMN` names, its `[IF EXISTS]` past, at `at`: a
    /// parenthesised list, or a name and the names after it in a comma list
    /// (the index past the last, where there is more than one). A name
    /// followed by more than the end of the action, or another action's
    /// first words, is the action's only column. Empty where no name is
    /// written first.
    fn dropped_columns_at(&self, at: usize) -> (Vec<Span>, Option<usize>) {
        let is_comma = |i: usize| {
            self.tokens
                .get(i)
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
        };
        let ends_action = |i: usize| {
            self.tokens.get(i).is_none_or(|t| {
                matches!(
                    t.kind,
                    TokenKind::Eof
                        | TokenKind::Punctuation(Punctuation::Semi)
                        | TokenKind::Punctuation(Punctuation::Comma)
                ) || self.starts_statement_after_action(t)
            })
        };
        if self
            .tokens
            .get(at)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)))
        {
            let names = self.object_ref_list_at(at);
            return (names.into_iter().map(|name| name.span).collect(), None);
        }
        let Some((mut end, first)) = self.name_span_at(at, NamePosition::Object) else {
            return (Vec::new(), None);
        };
        let mut columns = vec![first];
        while is_comma(end) {
            let Some((next, name)) = self.name_span_at(end + 1, NamePosition::Object) else {
                break;
            };
            if !ends_action(next) {
                break;
            }
            columns.push(name);
            end = next;
        }
        let list_end = (columns.len() > 1).then_some(end);
        (columns, list_end)
    }

    /// The index past T-SQL's `PARTITION value` at `k`.
    fn tsql_partition_end(&self, k: usize) -> Option<usize> {
        self.words_end(k, &["PARTITION"])
            .and_then(|p| self.option_value_end(p))
            .map(|v| self.parens_end(v).unwrap_or(v))
    }

    /// The index where the target of T-SQL's `SWITCH [PARTITION value] TO
    /// target` at `i` starts.
    fn tsql_switch_target_at(&self, i: usize) -> Option<usize> {
        let k = self.words_end(i, &["SWITCH"])?;
        let k = self.tsql_partition_end(k).unwrap_or(k);
        self.words_end(k, &["TO"])
    }

    /// `OWNER TO principal`, PG's `ATTACH PARTITION name …` and `DETACH
    /// PARTITION name …` at the cursor, consumed. `None`, consuming nothing,
    /// where the action is none of them or no name is written where they
    /// take one.
    fn try_parse_owner_or_partition_action(
        &mut self,
    ) -> ParseResult<Option<AstAlterTableActionKind>> {
        if let Some(after) = self.words_end(self.idx, &["OWNER", "TO"]) {
            let Some((name_end, owner)) = self.name_span_at(after, NamePosition::Object) else {
                return Ok(None);
            };
            self.idx = name_end;
            self.consume_until_comma_or_end()?;
            return Ok(Some(AstAlterTableActionKind::OwnerTo { owner }));
        }
        let attach = self.words_end(self.idx, &["ATTACH", "PARTITION"]);
        let Some(after) = attach.or_else(|| self.words_end(self.idx, &["DETACH", "PARTITION"]))
        else {
            return Ok(None);
        };
        let Some((name_end, partition)) = self.object_ref_at(after, self.id_gen.next()) else {
            return Ok(None);
        };
        self.idx = name_end;
        let rest_start = self.current_span().start;
        let rest_end = self.consume_until_comma_or_end()?;
        let rest = Span {
            start: rest_start,
            end: rest_end,
        };
        Ok(Some(if attach.is_some() {
            AstAlterTableActionKind::AttachPartition {
                partition,
                bound: rest,
            }
        } else {
            AstAlterTableActionKind::DetachPartition {
                partition,
                mode: (rest_end > rest_start).then_some(rest),
            }
        }))
    }

    /// Under T-SQL's `ALTER TABLE` grammar, the index past the action at `i`
    /// that starts with a word no other action does:
    /// `{CHECK | NOCHECK} CONSTRAINT {ALL | name [, name]*}`,
    /// `{ENABLE | DISABLE} {TRIGGER {ALL | name [, name]*} | CHANGE_TRACKING
    /// [WITH (…)] | FILETABLE_NAMESPACE}`, `SWITCH [PARTITION value] TO name
    /// [PARTITION value] [WITH (…)]` and `REBUILD [PARTITION = {ALL | value}]
    /// [WITH (…)]`.
    fn tsql_table_action_end(&self, i: usize) -> Option<usize> {
        let names_or_all = |k: usize| {
            self.words_end(k, &["ALL"])
                .or_else(|| self.comma_list_end(k, |j| self.object_name_end(j)))
        };
        let with_parens = |k: usize| {
            self.words_end(k, &["WITH"])
                .and_then(|w| self.parens_end(w))
                .unwrap_or(k)
        };
        let partition = |k: usize| self.tsql_partition_end(k);
        if let Some(k) =
            self.any_words_end(i, &[&["CHECK", "CONSTRAINT"], &["NOCHECK", "CONSTRAINT"]])
        {
            return names_or_all(k);
        }
        if let Some(k) = self.any_words_end(i, &[&["ENABLE"], &["DISABLE"]]) {
            if let Some(t) = self.words_end(k, &["TRIGGER"]) {
                return names_or_all(t);
            }
            if let Some(c) = self.words_end(k, &["CHANGE_TRACKING"]) {
                return Some(with_parens(c));
            }
            return self.words_end(k, &["FILETABLE_NAMESPACE"]);
        }
        if let Some(k) = self.tsql_switch_target_at(i) {
            let k = self.object_name_end(k)?;
            let k = partition(k).unwrap_or(k);
            return Some(with_parens(k));
        }
        if let Some(k) = self.words_end(i, &["REBUILD"]) {
            let k = self
                .words_end(k, &["PARTITION"])
                .and_then(|p| self.eq_value_end(p))
                .unwrap_or(k);
            return Some(with_parens(k));
        }
        None
    }

    /// The index past a foreign key's `REFERENCES name [(…)]` at `i` and the
    /// referential actions after it: `ON {DELETE | UPDATE} {NO ACTION |
    /// CASCADE | SET NULL [(…)] | SET DEFAULT [(…)] | RESTRICT}`, each event
    /// at most once, then `NOT FOR REPLICATION`.
    fn references_clause_end(&self, i: usize) -> Option<usize> {
        let k = self.words_end(i, &["REFERENCES"])?;
        let k = self.object_name_end(k)?;
        let mut k = self.parens_end(k).unwrap_or(k);
        let mut events = vec!["DELETE", "UPDATE"];
        while let Some((at, after)) = events
            .iter()
            .enumerate()
            .find_map(|(at, event)| self.words_end(k, &["ON", event]).map(|e| (at, e)))
        {
            let Some(end) = self.any_words_end(
                after,
                &[
                    &["NO", "ACTION"],
                    &["CASCADE"],
                    &["SET", "NULL"],
                    &["SET", "DEFAULT"],
                    &["RESTRICT"],
                ],
            ) else {
                break;
            };
            k = self.parens_end(end).unwrap_or(end);
            events.remove(at);
        }
        Some(
            self.words_end(k, &["NOT", "FOR", "REPLICATION"])
                .unwrap_or(k),
        )
    }

    /// Consumes a foreign key's `REFERENCES …` clause at the cursor
    /// ([`Self::references_clause_end`]), returning the end of its last
    /// token; `None`, consuming nothing, where none is written there.
    fn consume_references_clause(&mut self) -> Option<u32> {
        let end = self.references_clause_end(self.idx)?;
        Some(self.consume_action_before(end))
    }

    /// Consumes the action's tokens before `bound`, a terminator ending
    /// them first, and returns the end of the last one.
    fn consume_action_before(&mut self, bound: usize) -> u32 {
        let from = self.idx;
        let mut end = self.current_span().start;
        while self.idx < bound {
            let Some(tok) = self.peek() else { break };
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }
            end = tok.span.end;
            let _ = self.advance();
        }
        // The text is not read: its secrets are recorded as unparsed text's are.
        self.record_unparsed_secrets(from, self.idx);
        end
    }

    fn consume_until_comma_or_end(&mut self) -> ParseResult<u32> {
        let from = self.idx;
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
            if depth == 0 {
                if let Some(clause_end) = self.consume_references_clause() {
                    end = clause_end;
                    continue;
                }
            }
            // `CASE … END` nests as parentheses do.
            let opens = matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::LParen) | TokenKind::Keyword(Keyword::Case)
            );
            if depth == 0 && !opens && self.starts_statement_after_action(tok) {
                break;
            }
            if opens {
                depth += 1;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen))
                || (depth > 0 && matches!(tok.kind, TokenKind::Keyword(Keyword::End)))
            {
                depth -= 1;
            }
            end = tok.span.end;
            let _ = self.advance();
        }

        // The text is not read: its secrets are recorded as unparsed text's are.
        self.record_unparsed_secrets(from, self.idx);
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
