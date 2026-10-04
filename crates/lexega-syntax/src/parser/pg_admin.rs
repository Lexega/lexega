// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for PostgreSQL administrative statements.
//!
//! - LISTEN / NOTIFY / UNLISTEN (pub/sub)
//! - LOCK TABLE (explicit locking)
//! - CREATE [OR REPLACE] / ALTER / DROP RULE (rewrite rules)
//! - CREATE AGGREGATE / CREATE OPERATOR (extension authoring)
//! - ALTER SYSTEM SET/RESET, SET (runtime config)
//! - DROP OWNED / REASSIGN OWNED (role management)
//! - DISCARD ALL|PLANS|SEQUENCES|TEMP (maintenance)
//! - CLUSTER [table [USING index]] (maintenance)
//! - CREATE/ALTER/DROP PUBLICATION (logical replication)
//! - CREATE/ALTER/DROP SUBSCRIPTION (logical replication)
//! - CREATE/ALTER/DROP TABLESPACE
//! - DROP EXTENSION / SEQUENCE / TYPE / INDEX
//! - ALTER TABLE ... ENABLE/DISABLE TRIGGER

use crate::ast::types::{
    AstPgAlterTableTriggerState, AstPgDropExtension, AstPgDropIndex, AstPgDropRule,
    AstPgDropSequence, AstPgDropType, AstPgSet, AstPgSimpleUtility, AstStmt,
    PgAlterTableTriggerStateAction, PgAlterTableTriggerStateTarget, PgCascadeRestrict, PgSetKind,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    // =======================================================================
    // Helpers
    // =======================================================================

    /// Consume all tokens until (but not including) a semicolon or EOF.
    /// Returns the span covering everything consumed (start..end).
    fn consume_until_semi(&mut self, start: u32) -> u32 {
        let mut end = start;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if let Some(t) = self.advance() {
                end = t.span.end;
            } else {
                break;
            }
        }
        end
    }

    /// Build a simple utility statement from a consumed span.
    fn make_pg_simple(
        &mut self,
        start: u32,
        end: u32,
        constructor: fn(Box<AstPgSimpleUtility>) -> AstStmt,
    ) -> AstStmt {
        let span = Span { start, end };
        constructor(Box::new(AstPgSimpleUtility {
            node_id: self.id_gen.next(),
            span,
        }))
    }

    // =======================================================================
    // LISTEN channel
    // =======================================================================

    pub(crate) fn try_parse_pg_listen_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_listen")?;
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LISTEN".to_string()])?; // consume LISTEN
        let start = tok.span.start;

        // Must have a channel name
        let channel = self.advance().ok_or_else(|| {
            ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "LISTEN requires a channel name".to_string(),
                },
            )
        })?;
        let end = channel.span.end;
        Ok(self.make_pg_simple(start, end, AstStmt::PgListen))
    }

    // =======================================================================
    // NOTIFY channel [, 'payload']
    // =======================================================================

    pub(crate) fn try_parse_pg_notify_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_notify")?;
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NOTIFY".to_string()])?; // consume NOTIFY
        let start = tok.span.start;
        let end = self.consume_until_semi(tok.span.end);
        Ok(self.make_pg_simple(start, end, AstStmt::PgNotify))
    }

    // =======================================================================
    // UNLISTEN channel | *
    // =======================================================================

    pub(crate) fn try_parse_pg_unlisten_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_unlisten")?;
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNLISTEN".to_string()])?; // consume UNLISTEN
        let start = tok.span.start;

        // Must have channel name or *
        let target = self.advance().ok_or_else(|| {
            ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "UNLISTEN requires a channel name or *".to_string(),
                },
            )
        })?;
        let end = target.span.end;
        Ok(self.make_pg_simple(start, end, AstStmt::PgUnlisten))
    }

    // =======================================================================
    // LOCK [TABLE] name [, ...] [IN mode MODE] [NOWAIT]
    // =======================================================================

    pub(crate) fn try_parse_pg_lock_table_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_lock_table")?;
        let tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOCK".to_string()])?; // consume LOCK
        let start = tok.span.start;
        let end = self.consume_until_semi(tok.span.end);
        Ok(self.make_pg_simple(start, end, AstStmt::PgLockTable))
    }

    // =======================================================================
    // CREATE [OR REPLACE] RULE name AS ON event TO table
    //   [WHERE condition] DO [ALSO | INSTEAD] { NOTHING | command | (commands) }
    // =======================================================================

    pub(crate) fn try_parse_pg_create_rule_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_create_rule")?;
        // CREATE is already peeked but not consumed — we're called from
        // the CREATE dispatcher. Let the caller handle CREATE; we just
        // need to consume from the current position.
        //
        // Actually, since this is called after CREATE [OR REPLACE] has
        // been detected and we need to include CREATE in the span, the
        // caller passes us the start position. But our pattern is to
        // start from scratch with the full span.
        //
        // The dispatcher rewinds idx before calling us, so we consume
        // CREATE ourselves.
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let start = create_tok.span.start;

        // Skip OR REPLACE if present
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                self.advance(); // OR
                self.advance(); // REPLACE
            }
        }

        // RULE (identifier)
        self.advance(); // consume RULE

        // Consume everything until semicolon (rule body can contain
        // embedded SQL commands, but they end at the statement-level semi)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgCreateRule))
    }

    // =======================================================================
    // CREATE AGGREGATE name (args) (options)
    // =======================================================================

    pub(crate) fn try_parse_pg_create_aggregate_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_create_aggregate")?;
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let start = create_tok.span.start;
        self.advance(); // AGGREGATE identifier
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgCreateAggregate))
    }

    // =======================================================================
    // CREATE OPERATOR op_symbol (options)
    // =======================================================================

    pub(crate) fn try_parse_pg_create_operator_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_create_operator")?;
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let start = create_tok.span.start;
        self.advance(); // OPERATOR identifier
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgCreateOperator))
    }

    // =======================================================================
    // ALTER SYSTEM SET param = value
    // ALTER SYSTEM RESET param | ALL
    // =======================================================================

    pub(crate) fn try_parse_pg_alter_system_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_alter_system")?;
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?; // ALTER
        let start = alter_tok.span.start;
        self.advance(); // SYSTEM (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgAlterSystem))
    }

    // =======================================================================
    // ALTER TABLESPACE name SET/RESET/RENAME/OWNER TO ...
    // =======================================================================

    pub(crate) fn try_parse_pg_alter_tablespace_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_alter_tablespace")?;
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?; // ALTER
        let start = alter_tok.span.start;
        self.advance(); // TABLESPACE (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgAlterTablespace))
    }

    // =======================================================================
    // DROP OWNED BY role [, ...] [CASCADE | RESTRICT]
    // =======================================================================

    pub(crate) fn try_parse_pg_drop_owned_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_owned")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;
        self.advance(); // OWNED (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgDropOwned))
    }

    // =======================================================================
    // REASSIGN OWNED BY old_role [, ...] TO new_role
    // =======================================================================

    pub(crate) fn try_parse_pg_reassign_owned_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_reassign_owned")?;
        let reassign_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["REASSIGN".to_string()])?; // REASSIGN
        let start = reassign_tok.span.start;
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgReassignOwned))
    }

    // =======================================================================
    // DISCARD ALL | PLANS | SEQUENCES | TEMP | TEMPORARY
    // =======================================================================

    pub(crate) fn try_parse_pg_discard_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_discard")?;
        let discard_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DISCARD".to_string()])?; // DISCARD
        let start = discard_tok.span.start;

        // Must have a target keyword
        let target = self.advance().ok_or_else(|| {
            ParseError::new(
                discard_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "DISCARD requires ALL, PLANS, SEQUENCES, TEMP, or TEMPORARY"
                        .to_string(),
                },
            )
        })?;
        let end = target.span.end;
        Ok(self.make_pg_simple(start, end, AstStmt::PgDiscard))
    }

    // =======================================================================
    // CLUSTER [table_name [USING index_name]]
    // (bare CLUSTER with no args is also valid)
    // =======================================================================

    pub(crate) fn try_parse_pg_cluster_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_cluster")?;
        let cluster_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CLUSTER".to_string()])?; // CLUSTER
        let start = cluster_tok.span.start;
        let end = self.consume_until_semi(cluster_tok.span.end);
        Ok(self.make_pg_simple(start, end, AstStmt::PgCluster))
    }

    // =======================================================================
    // CREATE PUBLICATION name ...
    // ALTER PUBLICATION name ...
    // DROP PUBLICATION name ...
    // =======================================================================

    pub(crate) fn try_parse_pg_publication_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_publication")?;
        let first_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["CREATE or ALTER or DROP".to_string()],
        )?; // CREATE/ALTER/DROP
        let start = first_tok.span.start;
        self.advance(); // PUBLICATION (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgPublication))
    }

    // =======================================================================
    // CREATE SUBSCRIPTION name ...
    // ALTER SUBSCRIPTION name ...
    // DROP SUBSCRIPTION name ...
    // =======================================================================

    pub(crate) fn try_parse_pg_subscription_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_subscription")?;
        let first_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["CREATE or ALTER or DROP".to_string()],
        )?; // CREATE/ALTER/DROP
        let start = first_tok.span.start;
        self.advance(); // SUBSCRIPTION (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgSubscription))
    }

    // CREATE / ALTER / DROP { ROLE | USER | LOGIN } were folded into
    // the dialect-neutral [`crate::parser::principal`] entry points.
    // Old PG-prefixed names (`PgCreateRole` / `PgAlterRole` /
    // `PgDropRole`) erased the user-vs-role distinction; the neutral
    // substrate carries [`PrincipalKind`] on each variant instead.

    // =======================================================================
    // DROP EXTENSION [IF EXISTS] name [CASCADE | RESTRICT]
    // =======================================================================

    // DROP EXTENSION [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
    //
    // Typed AST so PG-EXT-DROP / PG-EXT-CASCADE-DROP predicate on
    // `cascade_restrict` instead of a text scan.
    pub(crate) fn try_parse_pg_drop_extension_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_extension")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;

        // EXTENSION keyword (lexed as Identifier — same as dispatcher check).
        self.advance()
            .ok_or_eof(self.current_span(), vec!["EXTENSION".to_string()])?;

        // Optional IF EXISTS.
        let mut if_exists = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if_exists = true;
            }
        }

        // Comma-separated extension names. Each name may be
        // schema-qualified (`schema.ext`); deeper qualifications are
        // not standard but the dot-separated walker stays defensive.
        fn parse_extension_name_span<'a>(parser: &mut Parser<'a>) -> ParseResult<Span> {
            let first = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec!["extension name".to_string()])?;
            let name_start = first.span.start;
            let mut name_end = first.span.end;

            if let Some(tok) = parser.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                    parser.advance(); // dot
                    let after_dot = parser
                        .advance()
                        .ok_or_eof(parser.current_span(), vec!["extension name".to_string()])?;
                    name_end = after_dot.span.end;
                }
            }

            Ok(Span {
                start: name_start,
                end: name_end,
            })
        }

        let mut extension_names = Vec::new();
        let first_name = parse_extension_name_span(self)?;
        let mut end = first_name.end;
        extension_names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = parse_extension_name_span(self)?;
                end = next_name.end;
                extension_names.push(next_name);
            } else {
                break;
            }
        }

        // Optional CASCADE | RESTRICT (lexed as Identifier).
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lexeme = tok.lexeme(self.source);
                if lexeme.eq_ignore_ascii_case("CASCADE") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                } else if lexeme.eq_ignore_ascii_case("RESTRICT") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                }
            }
        }

        let span = Span { start, end };
        let ast = AstPgDropExtension {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            extension_names,
            cascade_restrict,
        };
        Ok(AstStmt::PgDropExtension(Box::new(ast)))
    }

    // =======================================================================
    // ALTER RULE name ON table RENAME TO new_name
    // =======================================================================

    pub(crate) fn try_parse_pg_alter_rule_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_alter_rule")?;
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?; // ALTER
        let start = alter_tok.span.start;
        self.advance(); // RULE (identifier)
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgAlterRule))
    }

    // =======================================================================
    // DROP RULE [IF EXISTS] name ON table [CASCADE | RESTRICT]
    // =======================================================================

    // DROP RULE [IF EXISTS] name ON table_name [CASCADE | RESTRICT]
    pub(crate) fn try_parse_pg_drop_rule_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_rule")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;

        // RULE keyword.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["RULE".to_string()])?;

        // Optional IF EXISTS.
        let mut if_exists = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if_exists = true;
            }
        }

        // Rule name.
        let rule_name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["rule name".to_string()])?;
        let rule_name = rule_name_tok.span;

        // ON keyword.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;

        // Table name (possibly schema-qualified).
        let table_first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
        let table_start = table_first.span.start;
        let mut table_end = table_first.span.end;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // dot
                let after_dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
                table_end = after_dot.span.end;
            }
        }
        let table_name = Span {
            start: table_start,
            end: table_end,
        };
        let mut end = table_end;

        // Optional CASCADE | RESTRICT.
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("CASCADE") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                } else if lex.eq_ignore_ascii_case("RESTRICT") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                }
            }
        }

        let span = Span { start, end };
        let ast = AstPgDropRule {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            rule_name,
            table_name,
            cascade_restrict,
        };
        Ok(AstStmt::PgDropRule(Box::new(ast)))
    }

    // =======================================================================
    // ALTER TABLE name ENABLE/DISABLE TRIGGER trigger_name|ALL|USER
    // ALTER TABLE name ENABLE REPLICA TRIGGER trigger_name
    // ALTER TABLE name ENABLE ALWAYS TRIGGER trigger_name
    // =======================================================================

    // ALTER TABLE [IF EXISTS] [ONLY] name [*]
    //     { ENABLE [REPLICA | ALWAYS] TRIGGER { name | ALL | USER }
    //     | DISABLE TRIGGER { name | ALL | USER } }
    //
    // Typed AST so PG-TRIG-OFF predicates on the closed-enum
    // `action.kind: disable` instead of a text scan over the statement
    // source.
    pub(crate) fn try_parse_pg_alter_table_trigger_state_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_alter_table_trigger_state")?;
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?; // ALTER
        let start = alter_tok.span.start;

        // TABLE keyword.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;

        // Optional IF EXISTS.
        let mut if_exists = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if_exists = true;
            }
        }

        // Optional ONLY (lexed as Identifier).
        let mut only = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("ONLY")
            {
                self.advance();
                only = true;
            }
        }

        // Table name (possibly schema-qualified, optional trailing `*`).
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
        let table_start = first.span.start;
        let mut table_end = first.span.end;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // dot
                let after_dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["table name".to_string()])?;
                table_end = after_dot.span.end;
            }
        }
        // Optional trailing `*` (inheritance descent marker).
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(_)) && tok.lexeme(self.source) == "*" {
                let star = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["* (descent marker)".to_string()])?;
                table_end = star.span.end;
            }
        }
        let table_name = Span {
            start: table_start,
            end: table_end,
        };

        // Action: ENABLE [REPLICA|ALWAYS] | DISABLE.
        let action_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ENABLE or DISABLE".to_string()])?;
        let action_lexeme = action_tok.lexeme(self.source);
        let action = if action_lexeme.eq_ignore_ascii_case("DISABLE") {
            PgAlterTableTriggerStateAction::Disable
        } else if action_lexeme.eq_ignore_ascii_case("ENABLE") {
            let mut act = PgAlterTableTriggerStateAction::Enable;
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Identifier { .. }) {
                    let lex = tok.lexeme(self.source);
                    if lex.eq_ignore_ascii_case("ALWAYS") {
                        self.advance()
                            .ok_or_eof(self.current_span(), vec!["ALWAYS".to_string()])?;
                        act = PgAlterTableTriggerStateAction::EnableAlways;
                    } else if lex.eq_ignore_ascii_case("REPLICA") {
                        self.advance()
                            .ok_or_eof(self.current_span(), vec!["REPLICA".to_string()])?;
                        act = PgAlterTableTriggerStateAction::EnableReplica;
                    }
                }
            }
            act
        } else {
            return Err(ParseError::new(
                action_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("expected ENABLE or DISABLE, got {}", action_lexeme),
                },
            ));
        };

        // TRIGGER keyword (Identifier).
        self.advance()
            .ok_or_eof(self.current_span(), vec!["TRIGGER".to_string()])?;

        // Target: name | ALL | USER.
        let target_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["trigger name | ALL | USER".to_string()],
        )?;
        let target_lexeme = target_tok.lexeme(self.source);
        let (target, end) = if target_lexeme.eq_ignore_ascii_case("ALL") {
            (PgAlterTableTriggerStateTarget::All, target_tok.span.end)
        } else if target_lexeme.eq_ignore_ascii_case("USER") {
            (PgAlterTableTriggerStateTarget::User, target_tok.span.end)
        } else {
            // Named trigger (possibly schema-qualified — rare but
            // grammar-permitted; defensive dot walk).
            let name_start = target_tok.span.start;
            let mut name_end = target_tok.span.end;
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                    self.advance(); // dot
                    let after_dot = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["trigger name".to_string()])?;
                    name_end = after_dot.span.end;
                }
            }
            (
                PgAlterTableTriggerStateTarget::Named(Span {
                    start: name_start,
                    end: name_end,
                }),
                name_end,
            )
        };

        let span = Span { start, end };
        let ast = AstPgAlterTableTriggerState {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            only,
            table_name,
            action,
            target,
        };
        Ok(AstStmt::PgAlterTableTriggerState(Box::new(ast)))
    }

    // =======================================================================
    // SET [SESSION | LOCAL] role = 'name'
    // SET [SESSION | LOCAL] search_path TO schema [, ...]
    // SET [SESSION | LOCAL] SESSION AUTHORIZATION 'user'
    // SET [SESSION | LOCAL] config_parameter TO value
    // RESET role | search_path | SESSION AUTHORIZATION | ALL
    // =======================================================================

    // SET / RESET dispatcher. The kind is determined by the first
    // (post-SET/RESET, post-optional-SESSION/LOCAL) token.
    pub(crate) fn try_parse_pg_set_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_set")?;
        let leading_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET or RESET".to_string()])?;
        let start = leading_tok.span.start;
        let leading_lexeme = leading_tok.lexeme(self.source).to_ascii_uppercase();
        let is_reset = leading_lexeme == "RESET";

        // Optional SESSION | LOCAL prefix (SET only — RESET grammar
        // does not accept it). LOCAL is a `Keyword`; SESSION is lexed
        // as `Identifier`.
        if !is_reset {
            if let Some(tok) = self.peek_non_trivia() {
                let lex = tok.lexeme(self.source);
                let is_scope_marker = matches!(tok.kind, TokenKind::Keyword(Keyword::Local))
                    || (matches!(tok.kind, TokenKind::Identifier { .. })
                        && (lex.eq_ignore_ascii_case("SESSION")
                            || lex.eq_ignore_ascii_case("LOCAL")));
                if is_scope_marker {
                    // Peek past SESSION/LOCAL to decide if SESSION is
                    // the scope marker or the start of `SESSION
                    // AUTHORIZATION`. Only consume the scope marker
                    // when the token after it is NOT `AUTHORIZATION`.
                    let saved = self.idx;
                    let _ = self.advance(); // SESSION or LOCAL
                    let consume_scope = if lex.eq_ignore_ascii_case("LOCAL") {
                        true
                    } else if let Some(next) = self.peek_non_trivia() {
                        !next
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("AUTHORIZATION")
                    } else {
                        true
                    };
                    if !consume_scope {
                        self.idx = saved;
                    }
                }
            }
        }

        // Classify by next token.
        let kind = if let Some(tok) = self.peek_non_trivia() {
            let lex = tok.lexeme(self.source);
            if lex.eq_ignore_ascii_case("ROLE") {
                if is_reset {
                    PgSetKind::ResetRole
                } else {
                    PgSetKind::SetRole
                }
            } else if lex.eq_ignore_ascii_case("SESSION") {
                // SET SESSION (no scope marker absorbed) — peek for
                // AUTHORIZATION; otherwise treat as a generic param.
                let saved = self.idx;
                let _ = self.advance(); // SESSION
                let is_session_auth = self
                    .peek_non_trivia()
                    .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("AUTHORIZATION"))
                    .unwrap_or(false);
                self.idx = saved;
                if is_session_auth {
                    if is_reset {
                        PgSetKind::ResetSessionAuthorization
                    } else {
                        PgSetKind::SetSessionAuthorization
                    }
                } else if is_reset {
                    PgSetKind::ResetParameter
                } else {
                    PgSetKind::SetParameter
                }
            } else if lex.eq_ignore_ascii_case("AUTHORIZATION") {
                // SET [SESSION] AUTHORIZATION — SESSION absorbed above.
                if is_reset {
                    PgSetKind::ResetSessionAuthorization
                } else {
                    PgSetKind::SetSessionAuthorization
                }
            } else if lex.eq_ignore_ascii_case("ALL") && is_reset {
                PgSetKind::ResetAll
            } else if lex.eq_ignore_ascii_case("SEARCH_PATH") {
                if is_reset {
                    PgSetKind::ResetSearchPath
                } else {
                    PgSetKind::SetSearchPath
                }
            } else if is_reset {
                PgSetKind::ResetParameter
            } else {
                PgSetKind::SetParameter
            }
        } else if is_reset {
            PgSetKind::ResetParameter
        } else {
            PgSetKind::SetParameter
        };

        let end = self.consume_until_semi(start);

        let span = Span { start, end };
        let ast = AstPgSet {
            node_id: self.id_gen.next(),
            span,
            kind,
        };
        Ok(AstStmt::PgSet(Box::new(ast)))
    }

    // =======================================================================
    // DROP SEQUENCE / DROP TYPE / DROP INDEX
    // =======================================================================

    // DROP SEQUENCE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
    pub(crate) fn try_parse_pg_drop_sequence_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_sequence")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;
        let (if_exists, names, cascade_restrict, end) =
            self.parse_pg_drop_name_list_cascade("SEQUENCE", "sequence name")?;

        let span = Span { start, end };
        let ast = AstPgDropSequence {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            sequence_names: names,
            cascade_restrict,
        };
        Ok(AstStmt::PgDropSequence(Box::new(ast)))
    }

    // DROP TYPE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
    pub(crate) fn try_parse_pg_drop_type_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_type")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;
        let (if_exists, names, cascade_restrict, end) =
            self.parse_pg_drop_name_list_cascade("TYPE", "type name")?;

        let span = Span { start, end };
        let ast = AstPgDropType {
            node_id: self.id_gen.next(),
            span,
            if_exists,
            type_names: names,
            cascade_restrict,
        };
        Ok(AstStmt::PgDropType(Box::new(ast)))
    }

    /// Shared body for `DROP <KEYWORD> [IF EXISTS] name [, ...]
    /// [CASCADE | RESTRICT]`. Consumes the `KEYWORD` token, the
    /// optional `IF EXISTS`, the comma-separated name list (each
    /// possibly schema-qualified), and the optional CASCADE/RESTRICT
    /// suffix. Returns `(if_exists, names, cascade_restrict, end_span_pos)`.
    fn parse_pg_drop_name_list_cascade(
        &mut self,
        _keyword_label: &str,
        name_label: &str,
    ) -> ParseResult<(bool, Vec<Span>, Option<PgCascadeRestrict>, u32)> {
        // Consume the object-kind keyword (SEQUENCE, TYPE, etc. — all
        // lexed as Identifier by the dispatcher).
        self.advance()
            .ok_or_eof(self.current_span(), vec![_keyword_label.to_string()])?;

        // Optional IF EXISTS.
        let mut if_exists = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if_exists = true;
            }
        }

        // Comma-separated names with optional schema qualification.
        let parse_name = |parser: &mut Parser<'a>, label: &str| -> ParseResult<Span> {
            let first = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec![label.to_string()])?;
            let start = first.span.start;
            let mut end = first.span.end;
            if let Some(tok) = parser.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                    parser.advance(); // dot
                    let after_dot = parser
                        .advance()
                        .ok_or_eof(parser.current_span(), vec![label.to_string()])?;
                    end = after_dot.span.end;
                }
            }
            Ok(Span { start, end })
        };

        let mut names = Vec::new();
        let first_name = parse_name(self, name_label)?;
        let mut end = first_name.end;
        names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = parse_name(self, name_label)?;
                end = next_name.end;
                names.push(next_name);
            } else {
                break;
            }
        }

        // Optional CASCADE | RESTRICT.
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("CASCADE") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                } else if lex.eq_ignore_ascii_case("RESTRICT") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                }
            }
        }

        Ok((if_exists, names, cascade_restrict, end))
    }

    // DROP INDEX [CONCURRENTLY] [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
    //
    // PG's DROP INDEX diverges from the generic `DROP <object>` shape:
    // `CONCURRENTLY` modifies locking semantics, and a comma-separated
    // name list is permitted. Typed AST so PG-IDX-DROP / PG-IDX-CASCADE-DROP
    // predicate on `cascade_restrict` instead of a text scan.
    pub(crate) fn try_parse_pg_drop_index_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_index")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;

        // INDEX keyword (lexed as Identifier — same as dispatcher check).
        self.advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;

        // Optional CONCURRENTLY (lexed as Identifier).
        let mut concurrently = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("CONCURRENTLY")
            {
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["CONCURRENTLY".to_string()])?;
                concurrently = true;
            }
        }

        // Optional IF EXISTS.
        let mut if_exists = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if_exists = true;
            }
        }

        // Comma-separated index names. Each name may be schema-qualified
        // (`schema.idx`); deeper qualifications are not standard for
        // indexes but the dot-separated walker stays defensive.
        fn parse_index_name_span<'a>(parser: &mut Parser<'a>) -> ParseResult<Span> {
            let first = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec!["index name".to_string()])?;
            let name_start = first.span.start;
            let mut name_end = first.span.end;

            if let Some(tok) = parser.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                    parser.advance(); // dot
                    let after_dot = parser
                        .advance()
                        .ok_or_eof(parser.current_span(), vec!["index name".to_string()])?;
                    name_end = after_dot.span.end;
                }
            }

            Ok(Span {
                start: name_start,
                end: name_end,
            })
        }

        let mut index_names = Vec::new();
        let first_name = parse_index_name_span(self)?;
        let mut end = first_name.end;
        index_names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = parse_index_name_span(self)?;
                end = next_name.end;
                index_names.push(next_name);
            } else {
                break;
            }
        }

        // Optional MySQL `ON tbl_name` target (`DROP INDEX idx ON t`).
        let mut on_table_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                self.advance(); // ON
                let table = self.parse_qualified_name_span()?;
                end = table.end;
                on_table_span = Some(table);
            }
        }

        // Optional CASCADE | RESTRICT (lexed as Identifier).
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lexeme = tok.lexeme(self.source);
                if lexeme.eq_ignore_ascii_case("CASCADE") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                } else if lexeme.eq_ignore_ascii_case("RESTRICT") {
                    let t = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    end = t.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                }
            }
        }

        let span = Span { start, end };
        let ast = AstPgDropIndex {
            node_id: self.id_gen.next(),
            span,
            concurrently,
            if_exists,
            index_names,
            on_table_span,
            cascade_restrict,
        };
        Ok(AstStmt::PgDropIndex(Box::new(ast)))
    }

    // =======================================================================
    // CREATE / DROP TABLESPACE
    // =======================================================================

    pub(crate) fn try_parse_pg_create_tablespace_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_create_tablespace")?;
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let start = create_tok.span.start;
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgCreateTablespace))
    }

    pub(crate) fn try_parse_pg_drop_tablespace_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_drop_tablespace")?;
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?; // DROP
        let start = drop_tok.span.start;
        let end = self.consume_until_semi(start);
        Ok(self.make_pg_simple(start, end, AstStmt::PgDropTablespace))
    }
}
