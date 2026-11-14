// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// ============================================================================
// ALTER VIEW / ALTER MATERIALIZED VIEW parser
// ============================================================================
//
// Cross-dialect support (permissive parser — accepts all dialects):
//
// BigQuery:
//   ALTER VIEW [IF EXISTS] name SET OPTIONS (...)
//   ALTER VIEW [IF EXISTS] name ALTER COLUMN [IF EXISTS] col SET OPTIONS (...)
//   ALTER MATERIALIZED VIEW [IF EXISTS] name SET OPTIONS (...)
//
// Snowflake:
//   ALTER VIEW [IF EXISTS] name RENAME TO new_name
//   ALTER VIEW [IF EXISTS] name SET SECURE / UNSET SECURE
//   ALTER VIEW [IF EXISTS] name SET COMMENT = '...' / UNSET COMMENT
//   ALTER VIEW [IF EXISTS] name SET CHANGE_TRACKING = TRUE|FALSE
//   ALTER VIEW [IF EXISTS] name SET/UNSET TAG ...
//   ALTER VIEW [IF EXISTS] name ADD/DROP ROW ACCESS POLICY ...
//   ALTER VIEW [IF EXISTS] name SET/UNSET AGGREGATION POLICY ...
//   ALTER VIEW [IF EXISTS] name SET/UNSET JOIN POLICY ...
//   ALTER VIEW [IF EXISTS] name { ALTER | MODIFY } [COLUMN] col ...
//   ALTER VIEW [IF EXISTS] name ADD [COLUMN] col type ...
//   ALTER VIEW name { SET|UNSET } DATA_METRIC_SCHEDULE / { ADD|DROP } DATA METRIC FUNCTION
//
// PostgreSQL:
//   ALTER VIEW [IF EXISTS] name RENAME TO new_name
//   ALTER VIEW [IF EXISTS] name RENAME [COLUMN] col TO new_col
//   ALTER VIEW [IF EXISTS] name SET (option = value, ...)
//   ALTER VIEW [IF EXISTS] name OWNER TO new_owner
//   ALTER VIEW [IF EXISTS] name ALTER COLUMN col SET DEFAULT expr
//   ALTER VIEW [IF EXISTS] name SET SCHEMA new_schema
//
// Token gotchas (verified via --debug-tokens):
//   - MATERIALIZED is Identifier, NOT Keyword
//   - OPTIONS is Identifier, NOT Keyword
//   - CHANGE_TRACKING, DATA_METRIC_SCHEDULE are single Identifier tokens
//   - AGGREGATION, PROJECTION are Identifier tokens
//   - Two ALTER keywords in ALTER VIEW ... ALTER COLUMN ...
//   - Two IF EXISTS positions possible

use crate::ast::types::{
    AstAlterMaterializedView, AstAlterMaterializedViewAction, AstAlterMaterializedViewActionKind,
    AstAlterView, AstAlterViewAction, AstAlterViewActionKind, AstColumnPolicyUnset,
};
use crate::ast::{AstStmt, AstTagRef};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_table::PolicyClause;
use crate::parser::tag::TagListShape;

/// An `AlterColumn` action whose column and policies are not read: the
/// action without a column, or one the parser keeps as a span.
fn alter_column_unread(action_span: Span) -> AstAlterViewActionKind {
    AstAlterViewActionKind::AlterColumn {
        action_span,
        column: None,
        masking_policy: None,
        masking_policy_using: Vec::new(),
        projection_policy: None,
        tags: Vec::new(),
        policy_unset: None,
    }
}

/// The `ALTER MATERIALIZED VIEW` action an `ALTER VIEW` action reads as: the
/// actions a materialized view has keep their shape, every other action is
/// kept as written.
fn materialized_action_of(action: AstAlterViewAction) -> AstAlterMaterializedViewAction {
    use AstAlterMaterializedViewActionKind as M;
    use AstAlterViewActionKind as V;
    let span = action.span;
    let kind = match action.kind {
        V::AddRowAccessPolicy {
            action_span,
            policy,
            columns,
        } => M::AddRowAccessPolicy {
            action_span,
            policy,
            columns,
        },
        V::DropRowAccessPolicy {
            action_span,
            policy,
        } => M::DropRowAccessPolicy {
            action_span,
            policy,
        },
        V::DropAllRowAccessPolicies { action_span } => M::DropAllRowAccessPolicies { action_span },
        V::RenameColumn {
            action_span,
            old_name_span,
            new_name_span,
        } => M::RenameColumn {
            action_span,
            old_name_span,
            new_name_span,
        },
        V::AlterColumn {
            action_span,
            column,
            masking_policy,
            masking_policy_using: _,
            projection_policy,
            tags: _,
            policy_unset,
        } => M::AlterColumn {
            action_span,
            column,
            masking_policy,
            projection_policy,
            policy_unset,
        },
        V::SetOptions {
            set_span,
            options_span,
            options_list_span,
        } => M::SetOptions {
            set_span,
            options_span,
            options_list_span,
        },
        V::RenameTo { action_span } => M::RenameTo { action_span },
        V::SetSecure { action_span } => M::SetSecure { action_span },
        V::UnsetSecure { action_span } => M::UnsetSecure { action_span },
        V::SetComment { action_span } => M::SetComment { action_span },
        V::UnsetComment { action_span } => M::UnsetComment { action_span },
        V::SetTag { action_span, tags } => M::SetTag { action_span, tags },
        V::UnsetTag { action_span, tags } => M::UnsetTag { action_span, tags },
        V::AlterColumnSetOptions { .. }
        | V::SetChangeTracking { .. }
        | V::SetAggregationPolicy { .. }
        | V::UnsetAggregationPolicy { .. }
        | V::SetJoinPolicy { .. }
        | V::UnsetJoinPolicy { .. }
        | V::AddColumn { .. }
        | V::DataMetricFunction { .. }
        | V::OpaqueRemainder { .. } => M::OpaqueRemainder {
            remainder_span: span,
        },
    };
    AstAlterMaterializedViewAction { span, kind }
}

impl<'a> Parser<'a> {
    // ========================================================================
    // ALTER VIEW [IF EXISTS] <name> <action>
    // ========================================================================

    pub(crate) fn try_parse_alter_view(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_view")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // VIEW
        let view_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VIEW".to_string()])?;
        let view_span = view_tok.span;

        // IF EXISTS (optional)
        let if_exists_span = self.parse_alter_view_if_exists()?;

        // View name (dot-separated qualified name)
        let name_span = self.parse_object_name_span()?;

        // Parse action
        let action = self.parse_alter_view_action()?;

        // Calculate overall span
        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let node = AstAlterView {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            view_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterView(Box::new(node)))
    }

    // ========================================================================
    // ALTER MATERIALIZED VIEW [IF EXISTS] <name> <action>
    // ========================================================================

    pub(crate) fn try_parse_alter_materialized_view(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_materialized_view")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // MATERIALIZED (Identifier, not Keyword!)
        let materialized_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MATERIALIZED".to_string()])?;
        let materialized_span = materialized_tok.span;

        // VIEW
        let view_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["VIEW".to_string()])?;
        let view_span = view_tok.span;

        // IF EXISTS (optional)
        let if_exists_span = self.parse_alter_view_if_exists()?;

        // MV name (dot-separated qualified name)
        let name_span = self.parse_object_name_span()?;

        // Parse action
        let action = self.parse_alter_materialized_view_action()?;

        // Calculate overall span
        let stmt_span = Span {
            start: alter_span.start,
            end: action.span.end,
        };

        let node = AstAlterMaterializedView {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            materialized_span,
            view_span,
            if_exists_span,
            name_span,
            action,
        };
        Ok(AstStmt::AlterMaterializedView(Box::new(node)))
    }

    // ========================================================================
    // Shared helpers
    // ========================================================================

    /// Parse optional IF EXISTS clause for ALTER VIEW / ALTER MATERIALIZED VIEW.
    fn parse_alter_view_if_exists(&mut self) -> ParseResult<Option<Span>> {
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant("IF consumed after peek");
                if let Some(exists_tok) = self.peek_non_trivia() {
                    if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                        let e = self
                            .advance()
                            .expect_invariant("EXISTS consumed after peek");
                        return Ok(Some(Span {
                            start: if_tok.span.start,
                            end: e.span.end,
                        }));
                    }
                }
                return Err(ParseError::new(
                    if_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "ALTER VIEW IF requires EXISTS".to_string(),
                    },
                ));
            }
        }
        Ok(None)
    }

    // ========================================================================
    // ALTER VIEW action parsing
    // ========================================================================

    /// Parse the action part of ALTER VIEW (after the name).
    fn parse_alter_view_action(&mut self) -> ParseResult<AstAlterViewAction> {
        if let Some(tok) = self.peek_non_trivia() {
            let lexeme = tok.lexeme(self.source);

            // RENAME TO <new_name>
            if lexeme.eq_ignore_ascii_case("RENAME") {
                return self.parse_alter_view_rename_to();
            }

            // SET ...
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
                return self.parse_alter_view_set_action();
            }

            // UNSET ...
            if lexeme.eq_ignore_ascii_case("UNSET") {
                return self.parse_alter_view_unset_action();
            }

            // ALTER COLUMN / MODIFY COLUMN (Snowflake and BigQuery)
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Alter)) {
                return self.parse_alter_view_alter_column_action();
            }
            if lexeme.eq_ignore_ascii_case("MODIFY") {
                return self.parse_alter_view_alter_column_action();
            }

            // ADD ROW ACCESS POLICY / ADD [COLUMN] / ADD DATA METRIC FUNCTION
            if lexeme.eq_ignore_ascii_case("ADD") {
                return self.parse_alter_view_add_action();
            }

            // DROP ROW ACCESS POLICY / DROP ALL ROW ACCESS POLICIES / DROP DATA METRIC FUNCTION
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Drop)) {
                return self.parse_alter_view_drop_action();
            }
        }

        if let Some(action) = self.parse_alter_view_definition() {
            return Ok(action);
        }

        // Opaque remainder — for actions we don't explicitly handle
        self.parse_alter_view_as_opaque()
    }

    /// `[(columns)] [WITH attribute [, …]] AS [(] query [)] [WITH [CASCADED |
    /// LOCAL] CHECK OPTION]`: a new definition of the view, kept as written.
    /// It ends where its query does, as `CREATE VIEW`'s does.
    fn parse_alter_view_definition(&mut self) -> Option<AstAlterViewAction> {
        let start_idx = self.idx;
        let mut i = self.parens_end(start_idx).unwrap_or(start_idx);
        let attributes = self.words_end(i, &["WITH"]).and_then(|k| {
            self.comma_list_end(k, |j| {
                self.any_words_end(
                    j,
                    &[&["ENCRYPTION"], &["SCHEMABINDING"], &["VIEW_METADATA"]],
                )
            })
        });
        if let Some(end) = attributes {
            i = end;
        }
        if !self.word_at(i, "AS") {
            return None;
        }
        let start = self.tokens[start_idx].span.start;
        let mut end = self.tokens[i].span.end;
        self.idx = i + 1;
        let has_paren = self
            .peek_non_trivia()
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)));
        if has_paren {
            end = self.advance().expect_invariant("`(` after peek").span.end;
        }
        let query_idx = self.idx;
        match self.parse_statement() {
            Ok(query) => {
                end = query.span().end;
                if has_paren
                    && self.peek_non_trivia().is_some_and(|t| {
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen))
                    })
                {
                    end = self.advance().expect_invariant("`)` after peek").span.end;
                }
                let check_option = self.words_end(self.idx, &["WITH"]).and_then(|k| {
                    let k = self
                        .any_words_end(k, &[&["CASCADED"], &["LOCAL"]])
                        .unwrap_or(k);
                    self.words_end(k, &["CHECK", "OPTION"])
                });
                if let Some(past) = check_option {
                    end = self.tokens[past - 1].span.end;
                    self.idx = past;
                }
            }
            Err(_) => {
                self.idx = query_idx;
                while let Some(tok) = self.peek_non_trivia() {
                    if self.should_stop_scan_at_statement_start(tok)
                        || matches!(
                            tok.kind,
                            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                        )
                    {
                        break;
                    }
                    end = self.advance().expect_invariant("token after peek").span.end;
                }
            }
        }
        let span = Span { start, end };
        Some(AstAlterViewAction {
            span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: span,
            },
        })
    }

    /// Parse RENAME TO <new_name>, or RENAME [COLUMN] <col> TO <new_col>.
    fn parse_alter_view_rename_to(&mut self) -> ParseResult<AstAlterViewAction> {
        let rename_tok = self
            .advance()
            .expect_invariant("RENAME consumed after peek");
        let start = rename_tok.span.start;
        if !self.word_at(self.idx, "TO") {
            return self.parse_alter_view_rename_column(start);
        }

        // TO keyword
        let _to_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;

        // New name (dot-separated)
        let name_span = self.parse_object_name_span()?;

        let action_span = Span {
            start,
            end: name_span.end,
        };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::RenameTo { action_span },
        })
    }

    /// `[COLUMN] <col> TO <new_col>` after the `RENAME` at `start`.
    fn parse_alter_view_rename_column(&mut self, start: u32) -> ParseResult<AstAlterViewAction> {
        if self.word_at(self.idx, "COLUMN") {
            self.advance().expect_invariant("COLUMN after peek");
        }
        let old_name_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["column name".to_string()])?
            .span;
        let to_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
        if !to_tok.lexeme(self.source).eq_ignore_ascii_case("TO") {
            return Err(ParseError::unexpected_token(
                to_tok.span,
                vec!["TO".to_string()],
                Parser::token_description(to_tok, self.source),
            ));
        }
        let new_name_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["new column name".to_string()])?
            .span;
        let action_span = Span {
            start,
            end: new_name_span.end,
        };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::RenameColumn {
                action_span,
                old_name_span,
                new_name_span,
            },
        })
    }

    /// Parse SET ... action.
    /// Dispatches to specific SET sub-actions based on what follows SET.
    fn parse_alter_view_set_action(&mut self) -> ParseResult<AstAlterViewAction> {
        let set_tok = self.advance().expect_invariant("SET consumed after peek");
        let start = set_tok.span.start;
        let set_span = Some(set_tok.span);

        if let Some(tok) = self.peek_non_trivia() {
            let lexeme = tok.lexeme(self.source);

            // SET OPTIONS (...) — BigQuery
            if lexeme.eq_ignore_ascii_case("OPTIONS") {
                let options_tok = self.advance().expect_invariant("OPTIONS consumed");
                let options_span = Some(options_tok.span);
                self.record_option_list_secrets(self.idx);
                let list_start = self.current_span().start;
                let end = self.consume_alter_view_balanced()?;
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetOptions {
                        set_span,
                        options_span,
                        options_list_span: Span {
                            start: list_start,
                            end,
                        },
                    },
                });
            }

            // SET SECURE — Snowflake
            if lexeme.eq_ignore_ascii_case("SECURE") {
                let secure_tok = self.advance().expect_invariant("SECURE consumed");
                let action_span = Span {
                    start,
                    end: secure_tok.span.end,
                };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetSecure { action_span },
                });
            }

            // SET COMMENT = '...' — Snowflake
            if lexeme.eq_ignore_ascii_case("COMMENT") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetComment { action_span },
                });
            }

            // SET CHANGE_TRACKING = TRUE|FALSE — Snowflake
            if lexeme.eq_ignore_ascii_case("CHANGE_TRACKING") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetChangeTracking { action_span },
                });
            }

            // SET TAG ... — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                self.advance().expect_invariant("TAG keyword after peek");
                let (list_span, tags) = self.parse_tag_list(TagListShape::Assignments)?;
                let action_span = Span {
                    start,
                    end: list_span.end,
                };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetTag { action_span, tags },
                });
            }

            // SET AGGREGATION POLICY — Snowflake
            if lexeme.eq_ignore_ascii_case("AGGREGATION") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetAggregationPolicy { action_span },
                });
            }

            // SET JOIN POLICY — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Join)) {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetJoinPolicy { action_span },
                });
            }

            // SET DATA_METRIC_SCHEDULE = ... — Snowflake
            if lexeme.eq_ignore_ascii_case("DATA_METRIC_SCHEDULE") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DataMetricFunction { action_span },
                });
            }

            // SET TBLPROPERTIES (…) — Databricks; kept as the remainder below.
            if lexeme.eq_ignore_ascii_case("TBLPROPERTIES") {
                self.record_option_list_secrets(self.idx + 1);
            }

            // SET ( option = value, ... ) — PostgreSQL
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                self.record_option_list_secrets(self.idx);
                let end = self.consume_alter_view_balanced()?;
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::SetOptions {
                        set_span,
                        options_span: None,
                        options_list_span: Span {
                            start: tok.span.start,
                            end,
                        },
                    },
                });
            }

            // SET SCHEMA new_schema — PostgreSQL
            if lexeme.eq_ignore_ascii_case("SCHEMA") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::OpaqueRemainder {
                        remainder_span: action_span,
                    },
                });
            }

            // SET MASKING POLICY on view itself (without column) — Snowflake
            if lexeme.eq_ignore_ascii_case("MASKING") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: alter_column_unread(action_span),
                });
            }

            // SET PROJECTION POLICY on view itself — Snowflake
            if lexeme.eq_ignore_ascii_case("PROJECTION") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: alter_column_unread(action_span),
                });
            }
        }

        // SET without recognized sub-keyword — consume as opaque
        let end = self.consume_alter_view_until_semi(start);
        let action_span = Span { start, end };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: action_span,
            },
        })
    }

    /// Parse UNSET ... action.
    fn parse_alter_view_unset_action(&mut self) -> ParseResult<AstAlterViewAction> {
        let unset_tok = self.advance().expect_invariant("UNSET consumed after peek");
        let start = unset_tok.span.start;

        if let Some(tok) = self.peek_non_trivia() {
            let lexeme = tok.lexeme(self.source);

            // UNSET SECURE — Snowflake
            if lexeme.eq_ignore_ascii_case("SECURE") {
                let secure_tok = self.advance().expect_invariant("SECURE consumed");
                let action_span = Span {
                    start,
                    end: secure_tok.span.end,
                };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::UnsetSecure { action_span },
                });
            }

            // UNSET COMMENT — Snowflake
            if lexeme.eq_ignore_ascii_case("COMMENT") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::UnsetComment { action_span },
                });
            }

            // UNSET TAG — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                self.advance().expect_invariant("TAG keyword after peek");
                let (list_span, tags) = self.parse_tag_list(TagListShape::Names)?;
                let action_span = Span {
                    start,
                    end: list_span.end,
                };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::UnsetTag { action_span, tags },
                });
            }

            // UNSET AGGREGATION POLICY — Snowflake
            if lexeme.eq_ignore_ascii_case("AGGREGATION") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::UnsetAggregationPolicy { action_span },
                });
            }

            // UNSET JOIN POLICY — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Join)) {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::UnsetJoinPolicy { action_span },
                });
            }

            // UNSET DATA_METRIC_SCHEDULE — Snowflake
            if lexeme.eq_ignore_ascii_case("DATA_METRIC_SCHEDULE") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DataMetricFunction { action_span },
                });
            }

            // UNSET MASKING POLICY — Snowflake
            if lexeme.eq_ignore_ascii_case("MASKING") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: alter_column_unread(action_span),
                });
            }

            // UNSET PROJECTION POLICY — Snowflake
            if lexeme.eq_ignore_ascii_case("PROJECTION") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: alter_column_unread(action_span),
                });
            }
        }

        // UNSET without recognized sub-keyword
        let end = self.consume_alter_view_until_semi(start);
        let action_span = Span { start, end };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: action_span,
            },
        })
    }

    /// Parse ADD ... action (ADD ROW ACCESS POLICY, ADD COLUMN, ADD DATA METRIC FUNCTION)
    fn parse_alter_view_add_action(&mut self) -> ParseResult<AstAlterViewAction> {
        let add_tok = self.advance().expect_invariant("ADD consumed after peek");
        let start = add_tok.span.start;

        if let Some(tok) = self.peek_non_trivia() {
            // ADD ROW ACCESS POLICY
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Row)) {
                let (clause, name_end) = self.take_row_access_policy(start)?;
                let end = self.consume_alter_view_until_semi(name_end);
                let action_span = Span { start, end };
                let (policy, columns) = PolicyClause::parts(clause);
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::AddRowAccessPolicy {
                        action_span,
                        policy,
                        columns,
                    },
                });
            }

            // ADD DATA METRIC FUNCTION
            if tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DataMetricFunction { action_span },
                });
            }

            // ADD [COLUMN] <col> <type> ... — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Column))
                || self.can_be_identifier_token(tok)
            {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::AddColumn { action_span },
                });
            }
        }

        let end = self.consume_alter_view_until_semi(start);
        let action_span = Span { start, end };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: action_span,
            },
        })
    }

    /// Parse DROP ... action (DROP ROW ACCESS POLICY, DROP ALL ROW ACCESS POLICIES, DROP DATA METRIC FUNCTION)
    fn parse_alter_view_drop_action(&mut self) -> ParseResult<AstAlterViewAction> {
        let drop_tok = self.advance().expect_invariant("DROP consumed after peek");
        let start = drop_tok.span.start;

        if let Some(tok) = self.peek_non_trivia() {
            // DROP ROW ACCESS POLICY <name>
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Row)) {
                let (clause, name_end) = self.take_row_access_policy(start)?;
                let end = self.consume_alter_view_until_semi(name_end);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DropRowAccessPolicy {
                        action_span,
                        policy: PolicyClause::parts(clause).0,
                    },
                });
            }

            // DROP ALL ROW ACCESS POLICIES
            if matches!(tok.kind, TokenKind::Keyword(Keyword::All)) {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DropAllRowAccessPolicies { action_span },
                });
            }

            // DROP DATA METRIC FUNCTION
            if tok.lexeme(self.source).eq_ignore_ascii_case("DATA") {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::DataMetricFunction { action_span },
                });
            }

            // DROP COLUMN — Snowflake
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Column)) {
                let end = self.consume_alter_view_until_semi(start);
                let action_span = Span { start, end };
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: alter_column_unread(action_span),
                });
            }
        }

        let end = self.consume_alter_view_until_semi(start);
        let action_span = Span { start, end };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: action_span,
            },
        })
    }

    /// Parse ALTER COLUMN / MODIFY COLUMN action.
    /// Handles both BigQuery (SET OPTIONS) and Snowflake (SET/UNSET MASKING POLICY, etc.)
    fn parse_alter_view_alter_column_action(&mut self) -> ParseResult<AstAlterViewAction> {
        let alter_tok = self
            .advance()
            .expect_invariant("ALTER/MODIFY consumed after peek");
        let action_start = alter_tok.span.start;

        // Peek ahead to see if we have COLUMN keyword
        let has_column_keyword = if let Some(col_tok) = self.peek_non_trivia() {
            matches!(col_tok.kind, TokenKind::Keyword(Keyword::Column))
        } else {
            false
        };

        if has_column_keyword {
            self.advance(); // consume COLUMN
        }

        // Optional IF EXISTS after COLUMN (BigQuery)
        let column_if_exists_span = self.parse_alter_view_if_exists()?;

        // Column name
        let column_name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["column name".to_string()])?;

        // Now look at what follows: SET OPTIONS (BigQuery) vs SET MASKING POLICY (Snowflake) etc.
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
                // Peek past SET to see if next is OPTIONS
                let set_tok = self.advance().expect_invariant("SET consumed");

                if let Some(next_tok) = self.peek_non_trivia() {
                    let next_lexeme = next_tok.lexeme(self.source);
                    if next_lexeme.eq_ignore_ascii_case("OPTIONS") {
                        // BigQuery: ALTER COLUMN col SET OPTIONS (...)
                        let options_tok = self.advance().expect_invariant("OPTIONS consumed");
                        self.record_option_list_secrets(self.idx);
                        let list_start = self.current_span().start;
                        let end = self.consume_alter_view_balanced()?;
                        let action_span = Span {
                            start: action_start,
                            end,
                        };
                        return Ok(AstAlterViewAction {
                            span: action_span,
                            kind: AstAlterViewActionKind::AlterColumnSetOptions {
                                alter_span: Some(alter_tok.span),
                                column_span: None,
                                column_if_exists_span,
                                column_name_span: column_name_tok.span,
                                set_span: Some(set_tok.span),
                                options_span: Some(options_tok.span),
                                options_list_span: Span {
                                    start: list_start,
                                    end,
                                },
                            },
                        });
                    }
                }

                // Snowflake: ALTER/MODIFY COLUMN col SET MASKING POLICY / TAG / etc.
                self.skip_trivia();
                let masking = self.masking_policy_at(self.idx);
                let projection = self.projection_policy_at(self.idx);
                let tag_at = self.words_end(self.idx, &["TAG"]);
                let tags = self.column_tags_at(tag_at, TagListShape::Assignments);
                let name_end = match masking
                    .as_ref()
                    .or(projection.as_ref())
                    .map(|clause| clause.next)
                    .or(tag_at)
                {
                    Some(read_to) => {
                        self.idx = read_to;
                        self.tokens[read_to - 1].span.end
                    }
                    None => action_start,
                };
                let end = self.consume_alter_view_until_semi(name_end);
                let action_span = Span {
                    start: action_start,
                    end,
                };
                let (masking_policy, masking_policy_using) = PolicyClause::parts(masking);
                let (projection_policy, _) = PolicyClause::parts(projection);
                return Ok(AstAlterViewAction {
                    span: action_span,
                    kind: AstAlterViewActionKind::AlterColumn {
                        action_span,
                        column: Some(column_name_tok.span),
                        masking_policy,
                        masking_policy_using,
                        projection_policy,
                        tags,
                        policy_unset: None,
                    },
                });
            }
        }

        // Snowflake: ALTER/MODIFY COLUMN col UNSET/DROP DEFAULT/etc.
        self.skip_trivia();
        let tags = self.column_tags_at(
            self.words_end(self.idx, &["UNSET", "TAG"]),
            TagListShape::Names,
        );
        let policy_unset = self.column_policy_unset_at(self.idx);
        let end = self.consume_alter_view_until_semi(action_start);
        let action_span = Span {
            start: action_start,
            end,
        };
        Ok(AstAlterViewAction {
            span: action_span,
            kind: AstAlterViewActionKind::AlterColumn {
                action_span,
                column: Some(column_name_tok.span),
                masking_policy: None,
                masking_policy_using: Vec::new(),
                projection_policy: None,
                tags,
                policy_unset,
            },
        })
    }

    /// The `UNSET MASKING POLICY` / `UNSET PROJECTION POLICY` written at
    /// token `i`. Nothing is consumed.
    fn column_policy_unset_at(&self, i: usize) -> Option<AstColumnPolicyUnset> {
        let span_to = |end: usize| Span {
            start: self.tokens[i].span.start,
            end: self.tokens[end - 1].span.end,
        };
        if let Some(end) = self.words_end(i, &["UNSET", "MASKING", "POLICY"]) {
            return Some(AstColumnPolicyUnset::Masking { span: span_to(end) });
        }
        self.words_end(i, &["UNSET", "PROJECTION", "POLICY"])
            .map(|end| AstColumnPolicyUnset::Projection { span: span_to(end) })
    }

    /// The tags of the list written at `list_at`, the index past the `TAG`
    /// word that opens it; none where it is not read as a tag list. Nothing
    /// is consumed.
    fn column_tags_at(&self, list_at: Option<usize>, shape: TagListShape) -> Vec<AstTagRef> {
        list_at
            .and_then(|at| self.tag_list_at(at, shape))
            .map(|(_, tags)| tags)
            .unwrap_or_default()
    }

    /// Parse opaque remainder for actions we don't explicitly handle.
    fn parse_alter_view_as_opaque(&mut self) -> ParseResult<AstAlterViewAction> {
        let start = self.current_span().start;
        let end = self.consume_alter_view_until_semi(start);

        // If nothing was consumed, use current position
        let end = if end <= start {
            self.current_span().start
        } else {
            end
        };

        let span = Span { start, end };
        Ok(AstAlterViewAction {
            span,
            kind: AstAlterViewActionKind::OpaqueRemainder {
                remainder_span: span,
            },
        })
    }

    // ========================================================================
    // ALTER MATERIALIZED VIEW action parsing
    // ========================================================================

    /// Parse the action part of ALTER MATERIALIZED VIEW (after the name).
    fn parse_alter_materialized_view_action(
        &mut self,
    ) -> ParseResult<AstAlterMaterializedViewAction> {
        if let Some(tok) = self.peek_non_trivia() {
            let lexeme = tok.lexeme(self.source);
            // The actions a materialized view shares with a view read as the
            // ALTER VIEW forms are.
            let shared = if lexeme.eq_ignore_ascii_case("ADD") {
                Some(self.parse_alter_view_add_action()?)
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Drop)) {
                Some(self.parse_alter_view_drop_action()?)
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Alter))
                || lexeme.eq_ignore_ascii_case("MODIFY")
            {
                Some(self.parse_alter_view_alter_column_action()?)
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
                Some(self.parse_alter_view_set_action()?)
            } else if lexeme.eq_ignore_ascii_case("UNSET") {
                Some(self.parse_alter_view_unset_action()?)
            } else if lexeme.eq_ignore_ascii_case("RENAME") {
                Some(self.parse_alter_view_rename_to()?)
            } else {
                None
            };
            if let Some(action) = shared {
                return Ok(materialized_action_of(action));
            }
        }

        // Unknown action — opaque remainder
        let start = self.current_span().start;
        let end = self.consume_alter_view_until_semi(start);
        let end = if end <= start {
            self.current_span().start
        } else {
            end
        };
        let span = Span { start, end };
        Ok(AstAlterMaterializedViewAction {
            span,
            kind: AstAlterMaterializedViewActionKind::OpaqueRemainder {
                remainder_span: span,
            },
        })
    }

    // ========================================================================
    // Utility helpers
    // ========================================================================

    /// Consume a balanced parenthesized group including the opening and closing parens.
    /// Returns the end position (after closing paren).
    fn consume_alter_view_balanced(&mut self) -> ParseResult<u32> {
        let from = self.idx;
        let mut end = self.current_span().start;
        let mut depth: i32 = 0;
        let mut started = false;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
            ) {
                break;
            }

            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::LParen)
                    | TokenKind::Punctuation(Punctuation::LBracket)
            ) {
                depth += 1;
                started = true;
            }

            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::RParen)
                    | TokenKind::Punctuation(Punctuation::RBracket)
            ) {
                depth -= 1;
            }

            let t = self.advance().expect_invariant("token consumed after peek");
            end = t.span.end;

            // If we started with a paren and closed all of them, we're done
            if started && depth == 0 {
                break;
            }
        }

        // The text is not read: its secrets are recorded as unparsed text's are.
        self.record_unparsed_secrets(from, self.idx);
        Ok(end)
    }

    /// Consumes the `ROW ACCESS POLICY name [ON (…)]` written at the current
    /// token ([`Self::row_access_policy_at`]), returning it and where it
    /// ends; `from` and no clause where the words are not written. Where
    /// no name follows them, the name reader's error.
    fn take_row_access_policy(&mut self, from: u32) -> ParseResult<(Option<PolicyClause>, u32)> {
        self.skip_trivia();
        let Some(words) = self.words_end(self.idx, &["ROW", "ACCESS", "POLICY"]) else {
            return Ok((None, from));
        };
        let Some(clause) = self.row_access_policy_at(self.idx) else {
            self.idx = words;
            return Ok((None, self.parse_object_name_span()?.end));
        };
        self.idx = clause.next;
        let end = self.tokens[clause.next - 1].span.end;
        Ok((Some(clause), end))
    }

    /// Consume all tokens until semicolon or EOF. Returns the end position.
    fn consume_alter_view_until_semi(&mut self, start: u32) -> u32 {
        let from = self.idx;
        let mut end = start;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
            if let Some(t) = self.advance() {
                end = t.span.end;
            } else {
                break;
            }
        }
        // The text is not read: its secrets are recorded as unparsed text's are.
        self.record_unparsed_secrets(from, self.idx);
        end
    }
}
