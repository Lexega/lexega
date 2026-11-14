// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for PostgreSQL administrative statements.
//!
//! - LISTEN / NOTIFY / UNLISTEN (pub/sub)
//! - LOCK TABLE (explicit locking; also MySQL's LOCK TABLES), MySQL UNLOCK TABLES
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
    AstMysqlUnlockTables, AstPgAlterTableTriggerState, AstPgCluster, AstPgCreateRule,
    AstPgDropExtension, AstPgDropIndex, AstPgDropRule, AstPgDropSequence, AstPgDropType,
    AstPgListen, AstPgLockTable, AstPgNotify, AstPgSet, AstPgSimpleUtility, AstPgUnlisten, AstStmt,
    PgAlterTableTriggerStateAction, PgAlterTableTriggerStateTarget, PgCascadeRestrict, PgSetKind,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::{NamePosition, Parser};

impl<'a> Parser<'a> {
    // =======================================================================
    // Helpers
    // =======================================================================

    /// Consume all tokens until (but not including) a semicolon, a `)` it
    /// did not open (the one closing a rule's command list) or EOF.
    /// Returns the end of everything consumed, `start` where nothing is.
    /// The text is not read: its secrets are recorded as unparsed text's are.
    fn consume_until_semi(&mut self, start: u32) -> u32 {
        let from = self.idx;
        let mut end = start;
        let mut open = 0usize;
        while let Some(tok) = self.peek_non_trivia() {
            let kind = &tok.kind;
            if matches!(kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
                open += 1;
            } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
                match open.checked_sub(1) {
                    Some(inner) => open = inner,
                    None => break,
                }
            }
            let Some(consumed) = self.advance() else {
                break;
            };
            end = consumed.span.end;
        }
        self.record_unparsed_secrets(from, self.idx);
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
        let channel = self.take_channel().ok_or_else(|| {
            ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "LISTEN requires a channel name".to_string(),
                },
            )
        })?;
        Ok(AstStmt::PgListen(Box::new(AstPgListen {
            node_id: self.id_gen.next(),
            span: Span {
                start,
                end: channel.end,
            },
            channel,
        })))
    }

    /// The channel name of a `LISTEN`, `NOTIFY` or `UNLISTEN` at the current
    /// token, consumed: the object name that starts there, else the one
    /// token (a string or a reserved word).
    fn take_channel(&mut self) -> Option<Span> {
        self.take_name_span(NamePosition::Object)
            .or_else(|| self.advance().map(|token| token.span))
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
        let tokens = self.tokens;
        let channel = tokens
            .get(self.idx)
            .filter(|next| {
                !matches!(
                    next.kind,
                    TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
                )
            })
            .and_then(|_| self.take_channel());
        let payload = channel.and_then(|_| {
            let comma = tokens.get(self.idx)?;
            let literal = tokens.get(self.idx + 1)?;
            (matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma))
                && matches!(
                    literal.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::String)
                ))
            .then_some(literal.span)
        });
        let end = self.consume_until_semi(channel.map_or(tok.span.end, |name| name.end));
        Ok(AstStmt::PgNotify(Box::new(AstPgNotify {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            channel,
            payload,
        })))
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
        let star = self
            .tokens
            .get(self.idx)
            .filter(|next| matches!(next.kind, TokenKind::Operator(Operator::Star)))
            .map(|next| next.span);
        let channel = match star {
            Some(_) => {
                self.advance();
                None
            }
            None => Some(self.take_channel().ok_or_else(|| {
                ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "UNLISTEN requires a channel name or *".to_string(),
                    },
                )
            })?),
        };
        let end = star.or(channel).map_or(tok.span.end, |name| name.end);
        Ok(AstStmt::PgUnlisten(Box::new(AstPgUnlisten {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            channel,
        })))
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
        let from = self.idx;
        let end = self.consume_until_semi(tok.span.end);
        let tables = self.lock_tables(from, self.idx);
        Ok(AstStmt::PgLockTable(Box::new(AstPgLockTable {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            tables,
        })))
    }

    /// The tables of the `LOCK` statement whose tokens after `LOCK` are
    /// `from..to`: each item of the comma list, past `TABLE` / `TABLES` and
    /// `ONLY`, is a name; what follows a name up to the next comma (`*`,
    /// `AS alias READ`) is not read.
    fn lock_tables(&self, from: usize, to: usize) -> Vec<crate::ast::AstObjectRef> {
        let mut tables = Vec::new();
        let mut at = from;
        let skips = |at: usize, word: &str| self.word_at(at, word) && at + 1 < to;
        if skips(at, "TABLE") || skips(at, "TABLES") {
            at += 1;
        }
        if self.words_end(at, &["INSTANCE", "FOR", "BACKUP"]).is_some() {
            return tables;
        }
        while at < to {
            if skips(at, "ONLY") {
                at += 1;
            }
            let Some((after, name)) = self.object_ref_at(at, self.id_gen.next()) else {
                break;
            };
            tables.push(name);
            at = after;
            while at < to && !self.comma_at(at) {
                at = self.parens_end(at).unwrap_or(at + 1);
            }
            at += 1;
        }
        tables
    }

    /// Whether the token at `i` is a comma.
    fn comma_at(&self, i: usize) -> bool {
        self.tokens
            .get(i)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
    }

    // =======================================================================
    // UNLOCK {TABLES | TABLE} (MySQL; releases what LOCK TABLES took)
    // =======================================================================

    pub(crate) fn try_parse_mysql_unlock_tables_stmt(&mut self) -> ParseResult<AstStmt> {
        let unlock = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNLOCK".to_string()])?;
        let tables = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLES".to_string()])?;
        Ok(AstStmt::MysqlUnlockTables(Box::new(AstMysqlUnlockTables {
            node_id: self.id_gen.next(),
            span: Span {
                start: unlock.span.start,
                end: tables.span.end,
            },
            unlock_span: unlock.span,
            tables_span: tables.span,
        })))
    }

    // =======================================================================
    // CREATE [OR REPLACE] RULE name AS ON event TO table
    //   [WHERE condition] DO [ALSO | INSTEAD] { NOTHING | command | (commands) }
    // =======================================================================

    pub(crate) fn try_parse_pg_create_rule_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("pg_create_rule")?;
        // The CREATE dispatcher rewinds to `CREATE`.
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let or_replace = matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Or))
        );
        if or_replace {
            self.advance(); // OR
            self.expect_keyword(Keyword::Replace)?;
        }
        self.advance()
            .ok_or_eof(self.current_span(), vec!["RULE".to_string()])?;
        let rule_name = self.parse_qualified_name_span()?;
        self.expect_keyword(Keyword::As)?;
        self.expect_keyword(Keyword::On)?;
        let event_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["SELECT, INSERT, UPDATE or DELETE".to_string()],
        )?;
        if !matches!(
            event_tok.kind,
            TokenKind::Keyword(
                Keyword::Select | Keyword::Insert | Keyword::Update | Keyword::Delete
            )
        ) {
            return Err(ParseError::unexpected_token(
                event_tok.span,
                vec!["SELECT, INSERT, UPDATE or DELETE".to_string()],
                Self::token_description(event_tok, self.source),
            ));
        }
        let event = event_tok.span;
        self.expect_keyword(Keyword::To)?;
        let table_name = self.parse_qualified_name_span()?;
        let condition = if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Where))
        ) {
            self.advance();
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        let mut end = self.expect_keyword(Keyword::Do)?.end;
        let mut instead = false;
        if let Some(tok) = self.peek_non_trivia() {
            let word = tok.lexeme(self.source);
            if word.eq_ignore_ascii_case("INSTEAD") || word.eq_ignore_ascii_case("ALSO") {
                instead = word.eq_ignore_ascii_case("INSTEAD");
                end = tok.span.end;
                self.advance();
            }
        }
        let actions_from = self.idx;
        let actions = match self.parse_pg_rule_actions() {
            Ok((actions, actions_end)) => {
                end = actions_end;
                actions
            }
            // Commands that do not parse to the statement's end are kept as
            // written, unread.
            Err(_) => {
                self.idx = actions_from;
                end = self.consume_until_semi(end);
                Vec::new()
            }
        };
        Ok(AstStmt::PgCreateRule(Box::new(AstPgCreateRule {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            or_replace,
            rule_name,
            event,
            table_name,
            condition,
            instead,
            actions,
        })))
    }

    /// Whether the `CREATE RULE` at the current token is T-SQL's, `CREATE
    /// RULE name AS <condition>`: its `AS` is not followed by `ON`.
    pub(crate) fn create_rule_is_condition(&self) -> bool {
        let rule = (self.idx..self.tokens.len()).find(|&i| self.word_at(i, "RULE"));
        let Some(name_end) = rule.and_then(|rule| self.object_name_end(rule + 1)) else {
            return false;
        };
        self.tokens
            .get(name_end)
            .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::As)))
            && !self
                .tokens
                .get(name_end + 1)
                .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::On)))
    }

    /// T-SQL `CREATE RULE name AS <condition>`.
    pub(crate) fn try_parse_mssql_create_rule_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_create_rule")?;
        // The CREATE dispatcher rewinds to `CREATE`.
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["RULE".to_string()])?;
        let name = self.parse_object_name_span()?;
        self.expect_keyword(Keyword::As)?;
        let condition = self.parse_expr()?;
        let span = Span {
            start,
            end: condition.span().end,
        };
        Ok(AstStmt::MssqlCreateRule(Box::new(
            crate::ast::AstMssqlCreateRule {
                node_id: self.id_gen.next(),
                span,
                name,
                condition: Box::new(condition),
            },
        )))
    }

    /// A rule's `NOTHING` (no command), one command, or `( command ; … )`,
    /// each command ending where the statement does (`;` or the end of
    /// input) or, in a list, at its `;` or `)`. Returns the commands and
    /// where the last token read ends.
    fn parse_pg_rule_actions(&mut self) -> ParseResult<(Vec<AstStmt>, u32)> {
        let tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["NOTHING or a command".to_string()],
        )?;
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Nothing)) {
            let end = tok.span.end;
            self.advance();
            return Ok((Vec::new(), end));
        }
        if !matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            let action = self.parse_statement()?;
            let end = action.span().end;
            self.expect_rule_action_end(false)?;
            return Ok((vec![action], end));
        }
        self.advance();
        let mut actions = Vec::new();
        loop {
            let next = self
                .peek_non_trivia()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            if matches!(next.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                self.advance();
            } else if matches!(next.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                let end = next.span.end;
                self.advance();
                return Ok((actions, end));
            } else {
                actions.push(self.parse_statement()?);
                self.expect_rule_action_end(true)?;
            }
        }
    }

    /// Fails unless a rule's command ends here: at `;` or the end of input,
    /// or — `in_list` — at `;` or `)`. Consumes nothing.
    fn expect_rule_action_end(&mut self, in_list: bool) -> ParseResult<()> {
        let Some(tok) = self.peek_non_trivia() else {
            return Ok(());
        };
        let ends = matches!(
            tok.kind,
            TokenKind::Eof | TokenKind::Punctuation(Punctuation::Semi)
        ) || (in_list
            && matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)));
        if ends {
            Ok(())
        } else {
            Err(ParseError::unexpected_token(
                tok.span,
                vec![if in_list { "; or )" } else { ";" }.to_string()],
                Self::token_description(tok, self.source),
            ))
        }
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
        self.record_setting_secrets(self.idx);
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
        let from = self.idx;
        let end = self.consume_until_semi(cluster_tok.span.end);
        let (table, index) = self.cluster_targets(from, self.idx);
        Ok(AstStmt::PgCluster(Box::new(AstPgCluster {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            table,
            index,
        })))
    }

    /// The table and index of the `CLUSTER` statement whose tokens after
    /// `CLUSTER` are `from..to`: `[VERBOSE | (options)] table [USING index]`
    /// or `[VERBOSE] index ON table`.
    fn cluster_targets(
        &self,
        from: usize,
        to: usize,
    ) -> (
        Option<crate::ast::AstObjectRef>,
        Option<crate::ast::AstObjectRef>,
    ) {
        let mut at = from;
        if let Some(options_end) = self.parens_end(at) {
            at = options_end;
        } else if self.word_at(at, "VERBOSE") {
            at += 1;
        }
        if at >= to {
            return (None, None);
        }
        let Some((after, first)) = self.object_ref_at(at, self.id_gen.next()) else {
            return (None, None);
        };
        let second = |word: &str| {
            self.words_end(after, &[word])
                .and_then(|name| self.object_ref_at(name, self.id_gen.next()))
                .map(|(_, name)| name)
        };
        match (second("USING"), second("ON")) {
            (Some(index), _) => (Some(first), Some(index)),
            (None, Some(table)) => (Some(table), Some(first)),
            (None, None) => (Some(first), None),
        }
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

        // `{CREATE | ALTER} SUBSCRIPTION name CONNECTION 'conninfo'`.
        let clause = self.idx + 1;
        if self
            .tokens
            .get(clause)
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("CONNECTION"))
        {
            self.record_libpq_connection_string_secrets(clause + 1);
        }
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

        // Comma-separated extension names.
        let mut extension_names = Vec::new();
        let first_name = self.parse_object_name_span()?;
        let mut end = first_name.end;
        extension_names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = self.parse_object_name_span()?;
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
        let table_name = self.parse_object_name_span()?;
        let mut end = table_name.end;

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
        let name = self.parse_object_name_span()?;
        let table_start = name.start;
        let mut table_end = name.end;
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
        let target_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["trigger name | ALL | USER".to_string()],
        )?;
        let target_lexeme = target_tok.lexeme(self.source);
        let (target, end) = if target_lexeme.eq_ignore_ascii_case("ALL") {
            self.advance();
            (PgAlterTableTriggerStateTarget::All, target_tok.span.end)
        } else if target_lexeme.eq_ignore_ascii_case("USER") {
            self.advance();
            (PgAlterTableTriggerStateTarget::User, target_tok.span.end)
        } else {
            // Named trigger (possibly schema-qualified).
            let name = self.parse_object_name_span()?;
            let name_start = name.start;
            let mut name_end = name.end;
            // T-SQL names a list of triggers (`trg_a, trg_b`); read under a
            // dialect whose statements end where their grammar does.
            let mut list_end = self.idx;
            while self
                .tokens
                .get(list_end)
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
            {
                match self.object_name_end(list_end + 1) {
                    Some(next) => list_end = next,
                    None => break,
                }
            }
            let bound = self.clauses_bound(list_end);
            if bound != usize::MAX && bound > self.idx {
                name_end = self.tokens[bound - 1].span.end;
                self.idx = bound;
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
        self.record_setting_secrets(self.idx);
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
        // A setting is named by a word: T-SQL's `SET @v = …` names none.
        let named = self.peek_non_trivia().is_some_and(|tok| {
            matches!(
                tok.kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            )
        });
        if matches!(kind, PgSetKind::SetParameter | PgSetKind::ResetParameter) && !named {
            return Err(ParseError::new(
                leading_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("{leading_lexeme} names no configuration parameter"),
                },
            ));
        }

        // The schemas of `SET search_path { TO | = } a, b`.
        let mut search_path = Vec::new();
        let mut read_to = start;
        if kind == PgSetKind::SetSearchPath {
            let mut taken = self.advance().map(|tok| tok.span.end); // SEARCH_PATH
            if self.peek_non_trivia().is_some_and(|tok| {
                matches!(tok.kind, TokenKind::Keyword(Keyword::To))
                    || tok.lexeme(self.source) == "="
            }) {
                taken = self.advance().map(|tok| tok.span.end).or(taken);
            }
            while let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    break;
                }
                let names_no_schema = matches!(
                    tok.kind,
                    TokenKind::Punctuation(Punctuation::Comma)
                        | TokenKind::Keyword(Keyword::Default)
                );
                if !names_no_schema {
                    search_path.push(tok.span);
                }
                taken = self.advance().map(|tok| tok.span.end).or(taken);
            }
            read_to = taken.unwrap_or(start);
        }

        let end = self.consume_until_semi(read_to);

        let span = Span { start, end };
        let ast = AstPgSet {
            node_id: self.id_gen.next(),
            span,
            kind,
            search_path,
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
            self.parse_pg_drop_name_list_cascade("SEQUENCE")?;

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
            self.parse_pg_drop_name_list_cascade("TYPE")?;

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
        let mut names = Vec::new();
        let first_name = self.parse_object_name_span()?;
        let mut end = first_name.end;
        names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = self.parse_object_name_span()?;
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

        // Comma-separated index names. Each name may be qualified
        // (`schema.idx`, T-SQL's `table.idx` and `schema.table.idx`).
        let mut index_names = Vec::new();
        let first_name = self.parse_object_name_span()?;
        let mut end = first_name.end;
        index_names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next_name = self.parse_object_name_span()?;
                end = next_name.end;
                index_names.push(next_name);
            } else {
                break;
            }
        }

        // Optional MySQL / T-SQL `ON tbl_name` target (`DROP INDEX idx ON
        // t`), T-SQL's `WITH (…)` after it and its `, idx ON t …` for each
        // further index; `on_table_span` is the first table.
        let mut on_table_span = None;
        while self
            .peek_non_trivia()
            .is_some_and(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::On)))
        {
            self.advance(); // ON
            let table = self.parse_qualified_name_span()?;
            end = table.end;
            on_table_span.get_or_insert(table);
            if let Some(after) = self
                .words_end(self.idx, &["WITH"])
                .and_then(|w| self.parens_end(w))
            {
                self.idx = after;
                end = self.tokens[after - 1].span.end;
            }
            let another = self
                .tokens
                .get(self.idx)
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
                && self
                    .object_name_end(self.idx + 1)
                    .is_some_and(|k| self.word_at(k, "ON"));
            if !another {
                break;
            }
            self.advance(); // comma
            let next_name = self.parse_object_name_span()?;
            end = next_name.end;
            index_names.push(next_name);
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
