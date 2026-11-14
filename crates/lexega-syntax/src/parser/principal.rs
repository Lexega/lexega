// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dialect-neutral parser for `CREATE / ALTER / DROP { USER | ROLE | LOGIN }`.
//!
//! User / Role / Login are distinct database objects in every supported
//! dialect (Snowflake: separate USER + ROLE; MSSQL: LOGIN + USER + ROLE;
//! PG: fused ROLE with `LOGIN` / `NOLOGIN` flag; MySQL: USER + ROLE).
//! The [`PrincipalKind`] discriminator carries that distinction so
//! downstream consumers dispatch on the kind, not on a dialect-prefixed
//! variant name.
//!
//! Dialect-specific clauses ride as typed `Option<...>` fields on
//! [`CreatePrincipalOptions`]:
//! - `password_literal` — Snowflake `PASSWORD = '<lit>'`, PG `[ENCRYPTED]
//!   PASSWORD '<lit>'`, MSSQL `WITH PASSWORD = '<lit>'`, MySQL
//!   `IDENTIFIED BY '<lit>'`.
//! - `mssql_source` — typed classification of the MSSQL source clause
//!   (`FROM EXTERNAL PROVIDER`, `WITH PASSWORD`, `FOR LOGIN`,
//!   `WITHOUT LOGIN`, …).
//! - `mysql_host` — inner content span of the `'host'` half of MySQL
//!   `'user'@'host'`.
//!
//! The parser is the single text → typed conversion site for this
//! surface.

use crate::ast::types::{
    AstAccountPolicyKind, AstAlterPrincipal, AstCreatePrincipal, AstDropPrincipal,
    AstMssqlLoginOptions, AstMssqlPrincipalSource, AstObjectRef, AstPrincipalEnabledState,
    AstPrincipalMembership, AstPrincipalMembershipKind, AstRoleAttribute, AstRoleAttributeKind,
    AstSecondaryRolesMode, AstSnowflakeUserOptions, AstStmt, CreatePrincipalOptions, PrincipalKind,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::formatter::config::dollar_quoted_token_ranges;
use crate::lexer::{
    is_charset_introducer, IdentifierKind, Keyword, LiteralKind, Operator, Punctuation, Span,
    Token, TokenKind, LITERAL_PREFIXES,
};
use crate::parser::core::Parser;

/// What `consume_principal_options_body` finds in a principal statement's
/// body: the span consumed, the password literal, the `ENABLE` / `DISABLE`
/// state, the role attributes, and the Snowflake user and T-SQL login
/// options.
type PrincipalOptionsBody = (
    Option<Span>,
    Option<Span>,
    Option<AstPrincipalEnabledState>,
    Vec<AstRoleAttribute>,
    Option<AstSnowflakeUserOptions>,
    Option<AstMssqlLoginOptions>,
    bool,
);

impl<'a> Parser<'a> {
    /// `CREATE { USER | ROLE | LOGIN } [IF NOT EXISTS] <name> [options...]`
    pub(crate) fn try_parse_create_principal_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_principal")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // Optional `OR REPLACE` (Snowflake `CREATE OR REPLACE DATABASE
        // ROLE`) — sits between CREATE and the principal-kind keywords.
        let or_replace = self.consume_or_replace();

        // USER | ROLE | LOGIN | [SERVER|APPLICATION] ROLE | DATABASE ROLE —
        // lexed as Identifier (or Keyword for SERVER/APPLICATION) in every
        // dialect.
        let (principal_kind, server_scope, kw_end) = self.consume_principal_kind_tokens()?;
        let keyword_span = Span { start, end: kw_end };

        // Optional `IF NOT EXISTS`.
        let if_not_exists = self.consume_if_not_exists();

        // Principal name. MySQL accepts a quoted string literal here
        // (`'bob'`) plus optional `@'host'`; every other dialect uses an
        // identifier. The lexer tags string-literal tokens as Literal,
        // identifiers as Identifier — both occupy a single span here.
        let (name_span, mysql_host) = self.consume_principal_name()?;

        // MSSQL: peek-classify the source clause before consuming the
        // options body so the typed variant is the single source of truth
        // for downstream layers.
        let mssql_source = if self.dialect.login_has_source_clause() {
            Some(classify_mssql_principal_source(self))
        } else {
            None
        };

        // Walk the remaining options body to (a) record its span and
        // (b) capture the password literal if any of
        // `PASSWORD [=] '<lit>'` / `IDENTIFIED BY '<lit>'` patterns
        // appear at the top level of this options body.
        let body_start = mysql_host.map(|s| s.end).unwrap_or(name_span.end);
        let (
            trailing_span,
            password_literal,
            enabled_state,
            role_attributes,
            snowflake_user,
            mssql_login,
            password_set,
        ) = self.consume_principal_options_body(body_start);

        let end = trailing_span.map(|s| s.end).unwrap_or(body_start);
        let span = Span { start, end };

        let ast = AstCreatePrincipal {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            principal_kind,
            server_scope,
            name_span,
            if_not_exists,
            or_replace,
            options: CreatePrincipalOptions {
                password_literal,
                password_set,
                mssql_source,
                mysql_host,
                enabled_state,
                trailing_span,
                role_attributes,
                snowflake_user,
                mssql_login,
            },
        };
        Ok(AstStmt::CreatePrincipal(Box::new(ast)))
    }

    /// `ALTER { USER | ROLE | LOGIN } [IF EXISTS] <name> [options...]`
    ///
    /// Excludes the narrow Snowflake `ALTER USER … { SET | UNSET }
    /// AUTHENTICATION POLICY` slice — that path is taken by the
    /// dispatcher before reaching this entry point.
    pub(crate) fn try_parse_alter_principal_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_principal")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;

        // USER | ROLE | LOGIN | [SERVER|APPLICATION] ROLE
        let (principal_kind, server_scope, kw_end) = self.consume_principal_kind_tokens()?;
        let keyword_span = Span { start, end: kw_end };

        let if_exists = self.consume_if_exists();

        let (name_span, mysql_host) = self.consume_principal_name()?;

        // T-SQL `ADD MEMBER <p>` / `DROP MEMBER <p>` — typed before the
        // permissive options-body fallback consumes it.
        let membership = self.consume_principal_membership()?;

        let mssql_source = if self.dialect.login_has_source_clause() {
            Some(classify_mssql_principal_source(self))
        } else {
            None
        };

        let body_start = membership
            .map(|m| m.member_span.end)
            .or(mysql_host.map(|s| s.end))
            .unwrap_or(name_span.end);
        let (
            trailing_span,
            password_literal,
            enabled_state,
            role_attributes,
            snowflake_user,
            mssql_login,
            password_set,
        ) = self.consume_principal_options_body(body_start);

        let end = trailing_span.map(|s| s.end).unwrap_or(body_start);
        let span = Span { start, end };

        let ast = AstAlterPrincipal {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            principal_kind,
            name_span,
            if_exists,
            server_scope,
            membership,
            options: CreatePrincipalOptions {
                password_literal,
                password_set,
                mssql_source,
                mysql_host,
                enabled_state,
                trailing_span,
                role_attributes,
                snowflake_user,
                mssql_login,
            },
        };
        Ok(AstStmt::AlterPrincipal(Box::new(ast)))
    }

    /// `DROP { USER | ROLE | LOGIN } [IF EXISTS] <name> [, ...]`
    pub(crate) fn try_parse_drop_principal_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_principal")?;

        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;

        let (principal_kind, server_scope, kw_end) = self.consume_principal_kind_tokens()?;
        let keyword_span = Span { start, end: kw_end };

        let if_exists = self.consume_if_exists();

        // Comma-separated principal names, each with a MySQL account's
        // optional `@host`.
        let mut names = Vec::new();
        let mut end;
        loop {
            let (name, host) = self.consume_principal_name()?;
            end = match host {
                // The host's span leaves out its closing quote.
                Some(_) => self.tokens[self.idx - 1].span.end,
                None => name.end,
            };
            names.push(name);
            match self.peek_non_trivia() {
                Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) => {
                    self.advance(); // comma
                }
                Some(_) | None => break,
            }
        }

        let span = Span { start, end };
        let ast = AstDropPrincipal {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            principal_kind,
            server_scope,
            if_exists,
            names,
        };
        Ok(AstStmt::DropPrincipal(Box::new(ast)))
    }

    // ---------- helpers ----------

    /// Consume the principal-kind keyword token(s): `USER` / `ROLE` /
    /// `LOGIN` / `GROUP`, or the two-token T-SQL forms `SERVER ROLE`
    /// and `APPLICATION ROLE`. Returns `(kind, server_scope, end)`.
    fn consume_principal_kind_tokens(&mut self) -> ParseResult<(PrincipalKind, bool, u32)> {
        let kw_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["USER, ROLE, or LOGIN".to_string()],
        )?;
        let kw_lexeme = kw_tok.lexeme(self.source);
        let kw_span = kw_tok.span;

        // Two-token prefixes: SERVER ROLE / APPLICATION ROLE / DATABASE
        // ROLE. `is_server` is true only for the T-SQL SERVER scope.
        let prefix = if kw_lexeme.eq_ignore_ascii_case("SERVER") {
            Some((PrincipalKind::Role, true))
        } else if kw_lexeme.eq_ignore_ascii_case("APPLICATION") {
            Some((PrincipalKind::ApplicationRole, false))
        } else if kw_lexeme.eq_ignore_ascii_case("DATABASE") {
            Some((PrincipalKind::DatabaseRole, false))
        } else {
            None
        };
        if let Some((kind, is_server)) = prefix {
            let role_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["ROLE".to_string()])?;
            if !role_tok.lexeme(self.source).eq_ignore_ascii_case("ROLE") {
                return Err(ParseError::invalid_statement(
                    role_tok.span,
                    format!(
                        "expected ROLE after {}, found {}",
                        kw_lexeme.to_uppercase(),
                        role_tok.lexeme(self.source)
                    ),
                ));
            }
            return Ok((kind, is_server, role_tok.span.end));
        }

        let principal_kind = principal_kind_from_lexeme(kw_lexeme).ok_or_else(|| {
            ParseError::invalid_statement(
                kw_span,
                format!("expected USER, ROLE, or LOGIN, found {kw_lexeme}"),
            )
        })?;
        Ok((principal_kind, false, kw_span.end))
    }

    /// Consume an optional T-SQL `{ ADD | DROP } MEMBER <name>` clause;
    /// restore cursor on mismatch.
    fn consume_principal_membership(&mut self) -> ParseResult<Option<AstPrincipalMembership>> {
        let saved = self.idx;
        let Some(t1) = self.peek_non_trivia() else {
            return Ok(None);
        };
        let kind = if t1.lexeme(self.source).eq_ignore_ascii_case("ADD") {
            AstPrincipalMembershipKind::AddMember
        } else if t1.lexeme(self.source).eq_ignore_ascii_case("DROP") {
            AstPrincipalMembershipKind::DropMember
        } else {
            return Ok(None);
        };
        self.advance(); // ADD | DROP
        let Some(t2) = self.peek_non_trivia() else {
            self.idx = saved;
            return Ok(None);
        };
        if !t2.lexeme(self.source).eq_ignore_ascii_case("MEMBER") {
            self.idx = saved;
            return Ok(None);
        }
        self.advance(); // MEMBER
        let member_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["member principal".to_string()])?;
        Ok(Some(AstPrincipalMembership {
            kind,
            member_span: member_tok.span,
        }))
    }

    /// Consume an optional `OR REPLACE`; restore cursor on mismatch.
    fn consume_or_replace(&mut self) -> bool {
        let saved = self.idx;
        let Some(t1) = self.peek_non_trivia() else {
            return false;
        };
        if !t1.lexeme(self.source).eq_ignore_ascii_case("OR") {
            return false;
        }
        self.advance(); // OR
        let Some(t2) = self.peek_non_trivia() else {
            self.idx = saved;
            return false;
        };
        if !t2.lexeme(self.source).eq_ignore_ascii_case("REPLACE") {
            self.idx = saved;
            return false;
        }
        self.advance(); // REPLACE
        true
    }

    /// Consume an optional `IF NOT EXISTS`; restore cursor on mismatch.
    fn consume_if_not_exists(&mut self) -> bool {
        let saved = self.idx;
        let Some(t1) = self.peek_non_trivia() else {
            return false;
        };
        if !matches!(t1.kind, TokenKind::Keyword(Keyword::If)) {
            return false;
        }
        self.advance(); // IF
        let Some(t2) = self.peek_non_trivia() else {
            self.idx = saved;
            return false;
        };
        if !t2.lexeme(self.source).eq_ignore_ascii_case("NOT") {
            self.idx = saved;
            return false;
        }
        self.advance(); // NOT
        let Some(t3) = self.peek_non_trivia() else {
            self.idx = saved;
            return false;
        };
        if !t3.lexeme(self.source).eq_ignore_ascii_case("EXISTS") {
            self.idx = saved;
            return false;
        }
        self.advance(); // EXISTS
        true
    }

    /// Consume an optional `IF EXISTS`; restore cursor on mismatch.
    pub(crate) fn consume_if_exists(&mut self) -> bool {
        let saved = self.idx;
        let Some(t1) = self.peek_non_trivia() else {
            return false;
        };
        if !matches!(t1.kind, TokenKind::Keyword(Keyword::If)) {
            return false;
        }
        self.advance(); // IF
        let Some(t2) = self.peek_non_trivia() else {
            self.idx = saved;
            return false;
        };
        if !t2.lexeme(self.source).eq_ignore_ascii_case("EXISTS") {
            self.idx = saved;
            return false;
        }
        self.advance(); // EXISTS
        true
    }

    /// Consume the principal name token, plus an optional MySQL `@host`
    /// suffix. Returns `(name_span, mysql_host_inner_span)` where the
    /// host span is `None` for non-MySQL forms and points at the host
    /// without its quotes when present.
    pub(crate) fn consume_principal_name(&mut self) -> ParseResult<(Span, Option<Span>)> {
        // Canonical name parser handles single, dotted (`db.role` for a
        // Snowflake DATABASE ROLE), and string-literal (MySQL `'bob'`)
        // forms, stopping at the first non-dot token so the `@host` and
        // options-body parsing below stay intact.
        let name_span = self.parse_qualified_name_span()?;

        let mut mysql_host = None;
        if let Some((end, host)) = self.mysql_account_host_at(self.idx) {
            self.idx = end;
            mysql_host = Some(host);
        }

        Ok((name_span, mysql_host))
    }

    /// Walk forward from the current cursor, consuming tokens until a
    /// top-level semicolon or EOF. Returns:
    /// - `trailing_span`: the span covering everything consumed (`None`
    ///   when nothing was consumed).
    /// - `password_literal`: inner-content span of a `PASSWORD [=] '<lit>'`
    ///   or `IDENTIFIED BY '<lit>'` clause if one appears (first match).
    /// - `enabled_state`: T-SQL `ENABLE` / `DISABLE` action if one
    ///   appears at the top level of the body (first match).
    fn consume_principal_options_body(&mut self, body_start: u32) -> PrincipalOptionsBody {
        let initial_idx = self.idx;
        let mut end = body_start;
        let mut password_literal = None;
        let mut password_set = false;
        let mut enabled_state = None;
        let mut role_attributes = Vec::new();
        let mut snowflake_user = AstSnowflakeUserOptions::default();
        let mut has_snowflake = false;
        let mut mssql_login = AstMssqlLoginOptions::default();
        let mut has_mssql_login = false;
        let bound = self.clauses_bound(self.tsql_principal_clauses_end(self.idx));

        while self.idx < self.tokens.len() && self.idx < bound {
            let tok = &self.tokens[self.idx];
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) => break,
                _ => {}
            }

            if let Some((kind, negated)) = role_attribute_from_lexeme(tok.lexeme(self.source)) {
                role_attributes.push(AstRoleAttribute {
                    kind,
                    negated,
                    span: tok.span,
                });
            }

            // Snowflake `CREATE/ALTER USER` governance object-properties.
            // Recognized permissively (they appear only in Snowflake
            // syntax); each requires `<NAME> = <value>` so `UNSET <NAME>`
            // forms never capture. Pure recognition; no judgement here.
            has_snowflake |= recognize_snowflake_user_property(
                &mut snowflake_user,
                self.tokens,
                self.idx,
                self.source,
                self.dialect,
            );

            if snowflake_user.network_policy.is_none() {
                if let Some(policy) = self.network_policy_at(self.idx) {
                    snowflake_user.network_policy = Some(policy);
                    has_snowflake = true;
                }
            }

            // `UNSET NETWORK_POLICY`, alone or in an `UNSET a, b` list.
            if self.word_at(self.idx, "NETWORK_POLICY") && self.in_unset_list(self.idx) {
                snowflake_user.network_policy_unset = true;
                has_snowflake = true;
            }

            // `SET {PASSWORD | SESSION} POLICY <name>`.
            if self.idx > 0 && self.word_at(self.idx - 1, "SET") {
                if let Some((_, kind, policy)) = self.account_policy_at(self.idx) {
                    let slot = match kind {
                        AstAccountPolicyKind::Password => Some(&mut snowflake_user.password_policy),
                        AstAccountPolicyKind::Session => Some(&mut snowflake_user.session_policy),
                        AstAccountPolicyKind::Packages => None,
                    };
                    if let Some(slot) = slot.filter(|slot| slot.is_none()) {
                        *slot = Some(policy);
                        has_snowflake = true;
                    }
                }
            }

            // T-SQL `CREATE/ALTER LOGIN` password-policy options. Same
            // permissive stance: the `= ON|OFF` assignment form appears
            // only in T-SQL login syntax. Pure recognition; no judgement
            // here.
            has_mssql_login |= recognize_mssql_login_property(
                &mut mssql_login,
                self.tokens,
                self.idx,
                self.source,
                self.dialect,
            );

            password_set |= self.password_clause_at(self.idx);

            if password_literal.is_none() {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("PASSWORD") {
                    password_literal = self.string_literal_after(self.idx);
                } else if let Some(by) = self.identified_by_at(self.idx) {
                    password_literal = self.string_literal_after(by);
                }
            }

            if enabled_state.is_none() {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("ENABLE") {
                    enabled_state = Some(AstPrincipalEnabledState::Enable);
                } else if lex.eq_ignore_ascii_case("DISABLE") {
                    enabled_state = Some(AstPrincipalEnabledState::Disable);
                }
            }

            end = tok.span.end;
            self.idx += 1;
        }

        // Every password the clauses write is masked out of output surfaces,
        // and every secret a setting assignment gives.
        self.record_secret_literals(initial_idx, self.idx);
        self.record_setting_clause_secrets(initial_idx, self.idx);
        // A rendered placeholder is not a statically-known password — drop
        // the capture (masking above still applies) so consumers do not
        // mistake it for a hard-coded value.
        let password_literal = password_literal.filter(|pw| !self.span_overlaps_placeholder(*pw));

        let trailing_span = if self.idx > initial_idx {
            Some(Span {
                start: body_start,
                end,
            })
        } else {
            None
        };
        (
            trailing_span,
            password_literal,
            enabled_state,
            role_attributes,
            has_snowflake.then_some(snowflake_user),
            has_mssql_login.then_some(mssql_login),
            password_set,
        )
    }

    /// The index of the `BY` of MySQL's `IDENTIFIED BY` or `IDENTIFIED WITH
    /// plugin BY` written at `i`.
    fn identified_by_at(&self, i: usize) -> Option<usize> {
        if !self.word_at(i, "IDENTIFIED") {
            return None;
        }
        let after = |k: usize| next_non_trivia_idx(self.tokens, k + 1);
        let next = after(i)?;
        let by = if self.word_at(next, "WITH") {
            after(after(next)?)?
        } else {
            next
        };
        self.word_at(by, "BY").then_some(by)
    }

    /// Whether the word at `i` starts a clause that sets the password:
    /// `PASSWORD` followed by `=` or a string, or MySQL's `IDENTIFIED [WITH
    /// plugin] BY` and a string or `RANDOM PASSWORD`. `PASSWORD NULL`,
    /// `PASSWORD POLICY`, `IDENTIFIED WITH plugin` alone and `IDENTIFIED
    /// WITH plugin AS 'hash'` are not.
    fn password_clause_at(&self, i: usize) -> bool {
        let is_string = |k: Option<usize>| {
            k.is_some_and(|k| {
                matches!(
                    self.tokens[k].kind,
                    TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
                )
            })
        };
        let after = |k: usize| next_non_trivia_idx(self.tokens, k + 1);
        if self.word_at(i, "PASSWORD") {
            let next = after(i);
            return is_string(next)
                || next.is_some_and(|k| {
                    matches!(self.tokens[k].kind, TokenKind::Operator(Operator::Eq))
                });
        }
        self.identified_by_at(i).is_some_and(|by| {
            is_string(after(by))
                || after(by)
                    .filter(|&random| self.word_at(random, "RANDOM"))
                    .and_then(after)
                    .is_some_and(|password| self.word_at(password, "PASSWORD"))
        })
    }

    /// Whether the property name at `i` is listed by an `UNSET`: right
    /// after it, or after other names of its comma-separated list.
    fn in_unset_list(&self, i: usize) -> bool {
        let mut j = i;
        while j > 0 {
            let prev = j - 1;
            if self.word_at(prev, "UNSET") {
                return true;
            }
            let is_comma = matches!(
                self.tokens[prev].kind,
                TokenKind::Punctuation(Punctuation::Comma)
            );
            if is_comma && prev > 0 && self.is_word_at(prev - 1) {
                j = prev - 1;
            } else {
                break;
            }
        }
        false
    }

    /// The policy named by `NETWORK_POLICY = name` at `i`, without
    /// consuming. A value that reads as no name (a string literal, a
    /// reserved word) is the single token.
    fn network_policy_at(&self, i: usize) -> Option<AstObjectRef> {
        if !self.word_at(i, "NETWORK_POLICY") {
            return None;
        }
        let eq = next_non_trivia_idx(self.tokens, i + 1)?;
        if !matches!(self.tokens[eq].kind, TokenKind::Operator(Operator::Eq)) {
            return None;
        }
        let value = next_non_trivia_idx(self.tokens, eq + 1)?;
        if let Some((_, policy)) = self.object_ref_at(value, self.id_gen.next()) {
            return Some(policy);
        }
        if matches!(
            self.tokens[value].kind,
            TokenKind::Punctuation(_) | TokenKind::Operator(_)
        ) {
            return None;
        }
        Some(self.object_ref_of_range(value, value + 1, self.id_gen.next()))
    }

    /// The index past the T-SQL clauses of a `CREATE` / `ALTER` `USER`,
    /// `LOGIN` or `ROLE` at `i`, in any order: `{FOR | FROM} {LOGIN |
    /// CERTIFICATE | ASYMMETRIC KEY} name`, `FROM {EXTERNAL PROVIDER |
    /// WINDOWS}`, `WITHOUT LOGIN`, `AUTHORIZATION name`, `ENABLE`,
    /// `DISABLE`, `{ADD | DROP} {CREDENTIAL | MEMBER} name`, and `WITH
    /// option [, option]*`.
    fn tsql_principal_clauses_end(&self, mut i: usize) -> usize {
        while let Some(next) = self.tsql_principal_clause_end(i).filter(|&next| next > i) {
            i = next;
        }
        i
    }

    fn tsql_principal_clause_end(&self, i: usize) -> Option<usize> {
        let name_end = |k: usize| self.option_value_end(k);
        if self.word_at(i, "FOR") || self.word_at(i, "FROM") {
            if let Some(k) = self.any_words_end(
                i + 1,
                &[&["LOGIN"], &["CERTIFICATE"], &["ASYMMETRIC", "KEY"]],
            ) {
                return name_end(k);
            }
            return self
                .word_at(i, "FROM")
                .then(|| self.any_words_end(i + 1, &[&["EXTERNAL", "PROVIDER"], &["WINDOWS"]]))
                .flatten();
        }
        if let Some(k) = self.any_words_end(
            i,
            &[
                &["ADD", "CREDENTIAL"],
                &["DROP", "CREDENTIAL"],
                &["ADD", "MEMBER"],
                &["DROP", "MEMBER"],
                &["AUTHORIZATION"],
            ],
        ) {
            return name_end(k);
        }
        // `ENABLE TRIGGER …` / `DISABLE TRIGGER …` leads the next statement.
        if let Some(k) = self
            .any_words_end(i, &[&["WITHOUT", "LOGIN"], &["ENABLE"], &["DISABLE"]])
            .filter(|_| !self.leads_statement(i))
        {
            return Some(k);
        }
        self.with_list_end(i, |k| self.tsql_principal_option_end(k))
    }

    /// The index past a principal's `WITH` option at `i`: `NO CREDENTIAL`,
    /// or `name = value` and the words a password may carry after it
    /// (`HASHED`, `MUST_CHANGE`, `UNLOCK`, `OLD_PASSWORD = value`).
    fn tsql_principal_option_end(&self, i: usize) -> Option<usize> {
        if let Some(end) = self.words_end(i, &["NO", "CREDENTIAL"]) {
            return Some(end);
        }
        if !self.is_word_at(i) {
            return None;
        }
        let mut end = self.eq_value_end(i + 1)?;
        while let Some(next) = self
            .any_words_end(end, &[&["HASHED"], &["MUST_CHANGE"], &["UNLOCK"]])
            .or_else(|| {
                self.words_end(end, &["OLD_PASSWORD"])
                    .and_then(|k| self.eq_value_end(k))
            })
        {
            end = next;
        }
        Some(end)
    }
}

/// Recognize a T-SQL `CREATE/ALTER LOGIN` password-policy option at
/// `idx` and record its value span into `out`. Returns `true` if an
/// option was recognized. Each option requires the `<NAME> = <value>`
/// assignment form.
fn recognize_mssql_login_property(
    out: &mut AstMssqlLoginOptions,
    tokens: &[Token],
    idx: usize,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> bool {
    let lex = tokens[idx].lexeme(source);
    if lex.eq_ignore_ascii_case("CHECK_POLICY") {
        set_once(
            &mut out.check_policy,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("CHECK_EXPIRATION") {
        set_once(
            &mut out.check_expiration,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else {
        false
    }
}

/// Recognize a Snowflake `CREATE/ALTER USER` governance object-property
/// at `idx` and record its value span / parsed form into `out`. Returns
/// `true` if a property was recognized. Each property requires the
/// `<NAME> = <value>` assignment form; bare `UNSET <NAME>` is not a
/// value-bearing assertion and is left for `trailing_span`.
fn recognize_snowflake_user_property(
    out: &mut AstSnowflakeUserOptions,
    tokens: &[Token],
    idx: usize,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> bool {
    let lex = tokens[idx].lexeme(source);
    if lex.eq_ignore_ascii_case("DEFAULT_ROLE") {
        set_once(
            &mut out.default_role,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("TYPE") {
        set_once(
            &mut out.user_type,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("MUST_CHANGE_PASSWORD") {
        set_once(
            &mut out.must_change_password,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("DISABLED") {
        set_once(
            &mut out.disabled,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("MINS_TO_BYPASS_MFA") {
        set_once(
            &mut out.mins_to_bypass_mfa,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("DAYS_TO_EXPIRY") {
        set_once(
            &mut out.days_to_expiry,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("MINS_TO_UNLOCK") {
        set_once(
            &mut out.mins_to_unlock,
            peek_assigned_value_after(tokens, idx, source, dialect),
        )
    } else if lex.eq_ignore_ascii_case("RSA_PUBLIC_KEY") {
        // Presence only; the public key value is not captured.
        if has_assignment(tokens, idx) && !out.rsa_public_key_set {
            out.rsa_public_key_set = true;
            true
        } else {
            false
        }
    } else if lex.eq_ignore_ascii_case("RSA_PUBLIC_KEY_2") {
        if has_assignment(tokens, idx) && !out.rsa_public_key_2_set {
            out.rsa_public_key_2_set = true;
            true
        } else {
            false
        }
    } else if lex.eq_ignore_ascii_case("DEFAULT_SECONDARY_ROLES") {
        if out.default_secondary_roles.is_none() {
            if let Some(mode) = peek_secondary_roles_after(tokens, idx, source, dialect) {
                out.default_secondary_roles = Some(mode);
                return true;
            }
        }
        false
    } else {
        false
    }
}

/// Assign `value` into `slot` only if the slot is empty and `value` is
/// `Some`; returns whether a new value was recorded.
fn set_once(slot: &mut Option<Span>, value: Option<Span>) -> bool {
    if slot.is_none() {
        if let Some(v) = value {
            *slot = Some(v);
            return true;
        }
    }
    false
}

/// True iff the next non-trivia token after `keyword_idx` is `=`.
fn has_assignment(tokens: &[Token], keyword_idx: usize) -> bool {
    next_non_trivia_idx(tokens, keyword_idx + 1)
        .map(|i| matches!(tokens[i].kind, TokenKind::Operator(Operator::Eq)))
        .unwrap_or(false)
}

/// For `<NAME> = <value>`: require the `=`, then return the value token's
/// span. `None` when no `=` follows (e.g. `UNSET <NAME>`) or no value
/// token follows the `=`.
fn peek_assigned_value_after(
    tokens: &[Token],
    keyword_idx: usize,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<Span> {
    let eq_idx = next_non_trivia_idx(tokens, keyword_idx + 1)?;
    if !matches!(tokens[eq_idx].kind, TokenKind::Operator(Operator::Eq)) {
        return None;
    }
    let val_idx = next_non_trivia_idx(tokens, eq_idx + 1)?;
    if matches!(
        tokens[val_idx].kind,
        TokenKind::Punctuation(_) | TokenKind::Operator(_)
    ) {
        return None;
    }
    Some(inner_literal_span(tokens[val_idx].span, source, dialect))
}

/// For `DEFAULT_SECONDARY_ROLES = ( ... )`: require `= (`, then classify
/// the parenthesized content as [`AstSecondaryRolesMode::None`] (empty)
/// or [`AstSecondaryRolesMode::All`] (contains `ALL`). Returns `None`
/// for unrecognized forms.
fn peek_secondary_roles_after(
    tokens: &[Token],
    keyword_idx: usize,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<AstSecondaryRolesMode> {
    let eq_idx = next_non_trivia_idx(tokens, keyword_idx + 1)?;
    if !matches!(tokens[eq_idx].kind, TokenKind::Operator(Operator::Eq)) {
        return None;
    }
    let open_idx = next_non_trivia_idx(tokens, eq_idx + 1)?;
    if !matches!(
        tokens[open_idx].kind,
        TokenKind::Punctuation(Punctuation::LParen)
    ) {
        return None;
    }
    let mut i = next_non_trivia_idx(tokens, open_idx + 1)?;
    if matches!(tokens[i].kind, TokenKind::Punctuation(Punctuation::RParen)) {
        return Some(AstSecondaryRolesMode::None);
    }
    while i < tokens.len() {
        match tokens[i].kind {
            TokenKind::Punctuation(Punctuation::RParen) | TokenKind::Eof => break,
            _ => {}
        }
        let inner = inner_literal_span(tokens[i].span, source, dialect);
        if source[inner.start as usize..inner.end as usize].eq_ignore_ascii_case("ALL") {
            return Some(AstSecondaryRolesMode::All);
        }
        i = next_non_trivia_idx(tokens, i + 1)?;
    }
    None
}

/// Recognize a PG `CREATE/ALTER ROLE` capability keyword (positive or
/// `NO…` negated form). Pure recognition; no judgement here.
fn role_attribute_from_lexeme(lex: &str) -> Option<(AstRoleAttributeKind, bool)> {
    use AstRoleAttributeKind as K;
    let (negated, base) = if lex.len() > 2 && lex[..2].eq_ignore_ascii_case("NO") {
        (true, &lex[2..])
    } else {
        (false, lex)
    };
    let kind = if base.eq_ignore_ascii_case("SUPERUSER") {
        K::Superuser
    } else if base.eq_ignore_ascii_case("CREATEDB") {
        K::CreateDb
    } else if base.eq_ignore_ascii_case("CREATEROLE") {
        K::CreateRole
    } else if base.eq_ignore_ascii_case("LOGIN") {
        K::Login
    } else if base.eq_ignore_ascii_case("INHERIT") {
        K::Inherit
    } else if base.eq_ignore_ascii_case("REPLICATION") {
        K::Replication
    } else if base.eq_ignore_ascii_case("BYPASSRLS") {
        K::BypassRls
    } else {
        return None;
    };
    Some((kind, negated))
}

fn principal_kind_from_lexeme(lex: &str) -> Option<PrincipalKind> {
    if lex.eq_ignore_ascii_case("USER") {
        Some(PrincipalKind::User)
    } else if lex.eq_ignore_ascii_case("ROLE") {
        Some(PrincipalKind::Role)
    } else if lex.eq_ignore_ascii_case("LOGIN") {
        Some(PrincipalKind::Login)
    } else if lex.eq_ignore_ascii_case("GROUP") {
        Some(PrincipalKind::Group)
    } else {
        None
    }
}

pub(crate) fn is_skippable(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
    )
}

/// Whether `t` is a quoted string literal.
fn quoted(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
    )
}

pub(crate) fn next_non_trivia_idx(tokens: &[Token], from: usize) -> Option<usize> {
    let mut i = from;
    while i < tokens.len() {
        if is_skippable(&tokens[i]) && !matches!(tokens[i].kind, TokenKind::Eof) {
            i += 1;
            continue;
        }
        if matches!(tokens[i].kind, TokenKind::Eof) {
            return None;
        }
        return Some(i);
    }
    None
}

/// How a literal [`Parser::one_literal_at`] reads is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiteralSpelling {
    /// A quoted string, alone or with a prefix or a charset introducer.
    Quoted,
    /// A dollar-quoted string.
    DollarQuoted,
    /// A dollar-quoted string whose closer is not written: its content runs
    /// to the end of the text.
    UnclosedDollarQuoted,
    /// A hexadecimal or bit-value number (`0x…`, `0b…`).
    Number,
    /// A quoted string a template writes into, unrendered (`'a{{ x }}b'`,
    /// lexed as string fragments around the template), alone or with a
    /// prefix, closed or running to the end of the text: masked whole, and
    /// no literal value.
    Templated,
}

/// A literal [`Parser::one_literal_at`] or [`Parser::literal_at`] reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadLiteral {
    /// Its content: inside the quotes, after the prefix or `0x` / `0b`.
    pub(crate) content: Span,
    /// The index of its first token (a prefix or introducer included).
    pub(crate) first: usize,
    /// The index past its last token.
    pub(crate) past: usize,
    pub(crate) spelling: LiteralSpelling,
}

impl<'a> Parser<'a> {
    /// Records, to be masked out of every output, each secret value — a
    /// string or a binary literal in any spelling ([`Self::secret_value_at`]),
    /// or the one MySQL's `PASSWORD(…)` / `OLD_PASSWORD(…)` hashes — written
    /// in the tokens `from..to`: the value after `PASSWORD`, `OLD_PASSWORD`,
    /// `NEW_PASSWORD`, `MEDIAPASSWORD`, MySQL's replication
    /// `MASTER_PASSWORD` / `SOURCE_PASSWORD`, `SECRET`, `KEY_SOURCE` or
    /// `IDENTITY_VALUE` (an `=` between them optional), after MySQL's
    /// `PASSWORD FOR user =`, after `IDENTIFIED BY` and `IDENTIFIED WITH
    /// plugin {BY | AS}`, and after MySQL's `REPLACE` naming the current
    /// password.
    pub(crate) fn record_secret_literals(&mut self, from: usize, to: usize) {
        let word = |i: usize, w: &str| {
            self.tokens
                .get(i)
                .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case(w))
        };
        let next = |i: usize| next_non_trivia_idx(self.tokens, i + 1);
        let mut spans = Vec::new();
        for i in from..to.min(self.tokens.len()) {
            let lex = self.tokens[i].lexeme(self.source);
            let introducer = if lex.eq_ignore_ascii_case("PASSWORD") {
                // MySQL's `PASSWORD FOR user = value`.
                match next(i).filter(|&f| word(f, "FOR")) {
                    Some(f) => self
                        .mysql_principal_end(f + 1)
                        .filter(|&eq| {
                            matches!(
                                self.tokens.get(eq).map(|t| &t.kind),
                                Some(TokenKind::Operator(Operator::Eq))
                            )
                        })
                        .map(|eq| eq - 1),
                    None => Some(i),
                }
            } else if [
                "OLD_PASSWORD",
                "NEW_PASSWORD",
                "MEDIAPASSWORD",
                "MASTER_PASSWORD",
                "SOURCE_PASSWORD",
                "SECRET",
                "KEY_SOURCE",
                "IDENTITY_VALUE",
                "REPLACE",
            ]
            .iter()
            .any(|w| lex.eq_ignore_ascii_case(w))
            {
                Some(i)
            } else if lex.eq_ignore_ascii_case("IDENTIFIED") {
                match next(i) {
                    Some(by) if word(by, "BY") => Some(by),
                    // `IDENTIFIED WITH plugin {BY | AS} value`.
                    Some(with) if word(with, "WITH") => next(with)
                        .and_then(next)
                        .filter(|&k| word(k, "BY") || word(k, "AS")),
                    Some(_) | None => None,
                }
            } else {
                None
            };
            if let Some(span) = introducer.and_then(|k| self.secret_value_after(k)) {
                spans.push(span);
            }
        }
        self.redaction_spans.extend(spans);
    }

    /// Records, to be masked out of every output, the value of each `key
    /// [=] value` option in the tokens `from..to` (inside an `OPTIONS (…)`
    /// list) whose key names a password or a secret ([`Self::record_keyed_secrets`]).
    pub(crate) fn record_option_secrets(&mut self, from: usize, to: usize) {
        self.record_keyed_secrets(from, to, KeyDepth::TopLevel);
    }

    /// Records, to be masked out of every output, the secrets written in the
    /// tokens `from..to`, text no reader parsed: the values
    /// [`Self::record_secret_literals`] reads, each literal written after a
    /// key that names a password or a secret, at any depth
    /// ([`Self::record_keyed_secrets`]), and the secrets of the connection
    /// string a call written there passes where its function takes one
    /// ([`Self::record_libpq_call_secrets`]). No other value is masked.
    ///
    /// What a token holds is read from it and the tokens after it, so each
    /// token is read once, however many spans of text not parsed hold it.
    pub(crate) fn record_unparsed_secrets(&mut self, from: usize, to: usize) {
        let to = to.min(self.tokens.len());
        let mut at = from;
        loop {
            let start = self
                .unparsed_secrets_read
                .first_unread(at, self.tokens.len());
            if start >= to {
                break;
            }
            let end = self.unparsed_secrets_read.unread_run_end(start, to);
            self.record_unparsed_run_secrets(start, end);
            self.unparsed_secrets_read
                .read(start, end, self.tokens.len());
            at = end;
        }
    }

    /// [`Self::record_unparsed_secrets`] of the tokens `from..to`, none read
    /// before.
    fn record_unparsed_run_secrets(&mut self, from: usize, to: usize) {
        self.record_secret_literals(from, to);
        self.record_keyed_secrets(from, to, KeyDepth::Any);
        self.record_setting_clause_secrets(from, to);
        let tokens = self.tokens;
        for i in from..to.min(tokens.len()) {
            if !matches!(
                tokens[i].kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                continue;
            }
            let Some(open) = next_non_trivia_idx(tokens, i + 1).filter(|&open| {
                matches!(
                    tokens[open].kind,
                    TokenKind::Punctuation(Punctuation::LParen)
                )
            }) else {
                continue;
            };
            self.record_libpq_call_secrets(tokens[i].lexeme(self.source), open);
        }
    }

    /// Records, to be masked out of every output, the literal value
    /// ([`Self::secret_value_at`]) of each `key [=] value` in the tokens
    /// `from..to` whose key, written as a name or as a string in any
    /// spelling ([`Self::one_literal_at`]), names a password or a secret
    /// ([`crate::secrets::is_secret_name`]); a key is
    /// read where `depth` says.
    fn record_keyed_secrets(&mut self, from: usize, to: usize, depth: KeyDepth) {
        let mut spans = Vec::new();
        let mut nesting = 0u32;
        for i in from..to.min(self.tokens.len()) {
            let tok = &self.tokens[i];
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                nesting += 1;
                continue;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                nesting = nesting.saturating_sub(1);
                continue;
            }
            let read_here = match depth {
                KeyDepth::TopLevel => nesting == 0,
                KeyDepth::Any => true,
            };
            if !read_here {
                continue;
            }
            let quoted_key = self.one_literal_at(i).filter(|key| {
                key.first == i
                    && matches!(
                        key.spelling,
                        LiteralSpelling::Quoted | LiteralSpelling::DollarQuoted
                    )
            });
            let (key, past_key) = match quoted_key {
                Some(key) => (
                    self.source
                        .get(key.content.start as usize..key.content.end as usize)
                        .unwrap_or(""),
                    key.past,
                ),
                None if matches!(
                    tok.kind,
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                ) =>
                {
                    (tok.lexeme(self.source), i + 1)
                }
                None => continue,
            };
            if !crate::secrets::is_secret_name(key) {
                continue;
            }
            let Some(mut value) = next_non_trivia_idx(self.tokens, past_key) else {
                continue;
            };
            if matches!(self.tokens[value].kind, TokenKind::Operator(Operator::Eq)) {
                value += 1;
            }
            spans.extend(self.secret_value_at(value));
        }
        self.redaction_spans.extend(spans);
    }

    /// [`Self::record_option_secrets`] over the parenthesised option or
    /// property list (`OPTIONS (…)`, `TBLPROPERTIES (…)`, `DBPROPERTIES
    /// (…)`) whose `(` is the first token from `i` that is not a comment.
    pub(crate) fn record_option_list_secrets(&mut self, i: usize) {
        let Some(open) = next_non_trivia_idx(self.tokens, i) else {
            return;
        };
        if let Some(past) = self.parens_end(open) {
            self.record_option_secrets(open + 1, past - 1);
        }
    }

    /// [`Self::record_option_list_secrets`] where the reader reads the
    /// list's entries but not text a value nests in parentheses: a key is
    /// read at any depth, as in text no reader parsed.
    pub(crate) fn record_property_list_secrets(&mut self, i: usize) {
        let Some(open) = next_non_trivia_idx(self.tokens, i) else {
            return;
        };
        if let Some(past) = self.parens_end(open) {
            self.record_keyed_secrets(open + 1, past - 1, KeyDepth::Any);
        }
    }

    /// Records, to be masked out of every output, the secret arguments of a
    /// call to `procedure` (the parts of its name, as the dialect compares
    /// a routine's): each argument named for a password or a secret
    /// ([`crate::secrets::is_secret_name`]), each the dialect's system
    /// routine that name calls takes a password in
    /// ([`crate::dialect::Dialect::system_routine`]), and the secret values
    /// of a connection-string argument
    /// ([`Self::record_connection_string_secrets`]). Returns the indices of
    /// the secret arguments.
    pub(crate) fn record_call_argument_secrets(
        &mut self,
        procedure: &[&str],
        args: &[crate::ast::AstCallArg],
    ) -> Vec<usize> {
        let names: Vec<Option<&str>> = args
            .iter()
            .map(|arg| {
                arg.name.as_ref().map(|n| {
                    self.source
                        .get(n.span.start as usize..n.span.end as usize)
                        .unwrap_or("")
                        .trim_start_matches('@')
                })
            })
            .collect();
        let uses = self
            .dialect
            .system_routine(procedure)
            .map(|routine| {
                let written: Vec<crate::dialect::WrittenArgument<'_>> = args
                    .iter()
                    .zip(&names)
                    .map(|(arg, name)| crate::dialect::WrittenArgument {
                        name: *name,
                        value: crate::dialect::WrittenValue::of(&arg.value),
                    })
                    .collect();
                routine.argument_uses(&written)
            })
            .unwrap_or_default();
        let mut secrets = Vec::new();
        let mut connection_strings = Vec::new();
        for (position, arg) in args.iter().enumerate() {
            let name = names.get(position).copied().flatten();
            let reads = uses.get(position).copied().flatten();
            let secret = name.is_some_and(crate::secrets::is_secret_name)
                || reads == Some(crate::dialect::ArgumentUse::Credential);
            let connection_string = reads == Some(crate::dialect::ArgumentUse::ConnectionString);
            if !(secret || connection_string) {
                continue;
            }
            let value_start = arg.name_op_span.map_or(arg.span.start, |op| op.end);
            let idx = self.tokens.partition_point(|t| t.span.start < value_start);
            if secret {
                if let Some(span) = self.secret_value_at(idx) {
                    self.redaction_spans.push(span);
                }
                secrets.push(position);
            } else {
                connection_strings.push(idx);
            }
        }
        for idx in connection_strings {
            self.record_connection_string_secrets(idx);
        }
        secrets
    }

    /// Makes the string of each argument at `indices` that overlaps a
    /// rendered placeholder a templated string: the value is injected later
    /// and is no literal.
    pub(crate) fn template_placeholder_arguments(
        &self,
        args: &mut [crate::ast::AstCallArg],
        indices: &[usize],
    ) {
        for &i in indices {
            if let Some(crate::ast::AstCallArg {
                value:
                    crate::ast::AstExpr::Literal {
                        literal: literal @ crate::ast::AstLiteral::String { .. },
                        ..
                    },
                ..
            }) = args.get_mut(i)
            {
                let span = literal.span();
                if self.span_overlaps_placeholder(span) {
                    *literal = crate::ast::AstLiteral::StringWithJinja { span };
                }
            }
        }
    }

    /// Records, to be masked out of every output, the secrets the arguments
    /// of `OPENROWSET (…)` / `OPENDATASOURCE (…)` write, whose parenthesis
    /// opens at `open` ([`crate::secrets::connection_call_strings`]): the
    /// password of a `'data source';'user';'password'` run, and the secret
    /// values of a connection string.
    pub(crate) fn record_connection_call_secrets(&mut self, open: usize) {
        if self.parens_end(open).is_none() {
            return;
        }
        let tokens = self.tokens;
        for string in crate::secrets::connection_call_strings(&tokens[open + 1..]) {
            let i = open + 1 + string.token;
            match string.place_in_run {
                Some(place) => {
                    let secret = crate::secrets::LOGIN_RUN_KEYS
                        .get(place)
                        .is_some_and(|key| crate::secrets::is_secret_name(key));
                    if !secret {
                        continue;
                    }
                    if let Some(span) = self.secret_value_at(i) {
                        self.redaction_spans.push(span);
                    }
                }
                None => self.record_connection_string_secrets(i),
            }
        }
    }

    /// Records, to be masked out of every output, the value of each `key =
    /// value` entry of the connection string written as the string literal
    /// at `idx` (`Server=s;Uid=u;Pwd=…;`) whose key names a password or a
    /// secret ([`crate::secrets::connection_string_secret_values`]): a
    /// position that takes a connection string, read as one whatever its
    /// text.
    pub(crate) fn record_connection_string_secrets(&mut self, idx: usize) {
        let Some(tok) = self.tokens.get(idx) else {
            return;
        };
        if !matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
            return;
        }
        let content = inner_literal_span(tok.span, self.source, self.dialect);
        let Some(text) = self
            .source
            .get(content.start as usize..content.end as usize)
        else {
            return;
        };
        let spans: Vec<Span> = crate::secrets::connection_string_secret_values(text)
            .into_iter()
            .map(|value| Span {
                start: content.start + value.start as u32,
                end: content.start + value.end as u32,
            })
            .collect();
        self.redaction_spans.extend(spans);
    }

    /// Records, to be masked out of every output, the secrets every string
    /// literal of the tokens writes in its text, whatever statement or
    /// position holds it ([`Self::record_literal_secrets_in`]).
    pub(crate) fn record_string_literal_secrets(&mut self) {
        self.record_literal_secrets_in(self.tokens);
    }

    /// Records, to be masked out of every output, the secrets the string
    /// literals of a routine or `DO` body written as string literals, among
    /// the tokens `from..to`, write: each is SQL text, lexed where its text
    /// is written in the source, whose literals are read as the script's
    /// are ([`Self::record_literal_secrets_in`]).
    pub(crate) fn record_string_body_secrets(&mut self, from: usize, to: usize) {
        let tokens = self.tokens;
        for tok in tokens.get(from..to).unwrap_or_default() {
            if !matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
                continue;
            }
            let body = self
                .source
                .get(tok.span.start as usize..tok.span.end as usize)
                .and_then(|raw| crate::lexer::decode_string_literal(raw, self.dialect))
                .filter(|decoded| decoded.closed)
                .and_then(|decoded| {
                    super::unload::tokens_at_source(self.source, tok.span, &decoded, self.dialect)
                });
            if let Some((body, _)) = body {
                self.record_literal_secrets_in(&body);
            }
        }
    }

    /// Records, to be masked out of every output, the secrets the text of
    /// each string literal of `tokens`, placed where their text is written
    /// in the source, writes ([`Self::record_literal_text_secrets`]). A
    /// dollar-quoted string is lexed as tokens between two delimiters; the
    /// source between them is read as one literal. Where the dialect joins
    /// string literals written one after another (MySQL `'a' 'b'`), the
    /// joined text is read too.
    fn record_literal_secrets_in(&mut self, tokens: &[Token]) {
        let mut run: Vec<Span> = Vec::new();
        for tok in tokens {
            let is_string = matches!(tok.kind, TokenKind::Literal(LiteralKind::String));
            if is_string || matches!(tok.kind, TokenKind::Literal(LiteralKind::StringFragment)) {
                let content = inner_literal_span(tok.span, self.source, self.dialect);
                self.record_literal_text_secrets(content);
            }
            if is_string && self.dialect.adjacent_string_literals_join() {
                run.push(inner_literal_span(tok.span, self.source, self.dialect));
            } else {
                self.record_joined_literal_secrets(&std::mem::take(&mut run));
            }
        }
        self.record_joined_literal_secrets(&run);
        for (opener, closer) in dollar_quoted_token_ranges(self.source, tokens) {
            if let (Some(open), Some(close)) = (tokens.get(opener), tokens.get(closer)) {
                self.record_literal_text_secrets(Span {
                    start: open.span.end,
                    end: close.span.start,
                });
            }
        }
    }

    /// Records, to be masked out of every output, the secrets the literal
    /// text at `content` writes: the password of each URL it holds with user
    /// information ([`crate::secrets::url_password_ranges`]), and, where the
    /// text reads as a connection string, each value written under a key
    /// that names a password or a secret
    /// ([`crate::secrets::written_connection_string_secret_values`]).
    fn record_literal_text_secrets(&mut self, content: Span) {
        self.record_joined_literal_text_secrets(&[content]);
    }

    /// [`Self::record_literal_text_secrets`] of the text the literals whose
    /// contents are `run`, two or more written one after another, join into.
    fn record_joined_literal_secrets(&mut self, run: &[Span]) {
        if run.len() > 1 {
            self.record_joined_literal_text_secrets(run);
        }
    }

    /// Records, to be masked out of every output, the secrets the text the
    /// literal contents `parts` join into writes
    /// ([`Self::record_literal_text_secrets`]), each at the part or parts
    /// of the source that write it.
    fn record_joined_literal_text_secrets(&mut self, parts: &[Span]) {
        let mut text = String::new();
        let mut placed: Vec<(usize, Span)> = Vec::new();
        for &part in parts {
            let Some(written) = self.source.get(part.start as usize..part.end as usize) else {
                return;
            };
            placed.push((text.len(), part));
            text.push_str(written);
        }
        let secrets: Vec<std::ops::Range<usize>> = crate::secrets::url_password_ranges(&text)
            .into_iter()
            .chain(crate::secrets::written_connection_string_secret_values(
                &text,
            ))
            .filter(|secret| !secret.is_empty())
            .collect();
        for secret in secrets {
            for &(at, part) in &placed {
                let part_end = at + (part.end - part.start) as usize;
                let (start, end) = (secret.start.max(at), secret.end.min(part_end));
                if start < end {
                    self.redaction_spans.push(Span {
                        start: part.start + (start - at) as u32,
                        end: part.start + (end - at) as u32,
                    });
                }
            }
        }
    }

    /// Records, to be masked out of every output, the secret values of the
    /// libpq connection string written as the string literal, in any spelling
    /// ([`Self::one_literal_at`]), at the first token from `i` that is not a
    /// comment ([`libpq_secret_values`]).
    pub(crate) fn record_libpq_connection_string_secrets(&mut self, i: usize) {
        if let Some(chars) = self.literal_value_chars(i) {
            let spans = libpq_secret_values(&chars);
            self.redaction_spans.extend(spans);
        }
    }

    /// Records, to be masked out of every output, the secret each setting
    /// assignment of `SET [SESSION | LOCAL] name {= | TO} value [[,] name =
    /// value …]` gives, whose `SET` is the first token from `i` that is not
    /// a comment: the literal value ([`Self::secret_value_at`]) where `name`
    /// names a password or a secret ([`crate::secrets::is_secret_name`]),
    /// and the secrets of the libpq connection string given to a setting
    /// that holds one ([`LIBPQ_CONNECTION_SETTINGS`]). Snowflake writes the
    /// pairs one after another, with or without commas ("ALTER ACCOUNT",
    /// "ALTER DATABASE", "ALTER WAREHOUSE").
    pub(crate) fn record_setting_secrets(&mut self, i: usize) {
        let tokens = self.tokens;
        let source = self.source;
        let word = |k: usize, w: &str| tokens[k].lexeme(source).eq_ignore_ascii_case(w);
        let next = |k: usize| next_non_trivia_idx(tokens, k + 1);
        let Some(set) = next_non_trivia_idx(tokens, i).filter(|&set| word(set, "SET")) else {
            return;
        };
        let Some(mut first) = next(set) else {
            return;
        };
        if word(first, "SESSION") || word(first, "LOCAL") {
            match next(first) {
                Some(after) => first = after,
                None => return,
            }
        }
        let mut at = Some(first);
        while let Some((first, last, op)) = at.and_then(|k| self.setting_pair_at(k)) {
            let name_span = Span {
                start: tokens[first].span.start,
                end: tokens[last].span.end,
            };
            let after = self.record_setting_value(Some(name_span), op + 1);
            // The pair is read by its grammar: text left unparsed around it
            // does not read it again.
            self.unparsed_secrets_read
                .read(first, after.unwrap_or(tokens.len()), tokens.len());
            let name = source
                .get(tokens[first].span.start as usize..tokens[last].span.end as usize)
                .unwrap_or("");
            if LIBPQ_CONNECTION_SETTINGS
                .iter()
                .any(|setting| name.eq_ignore_ascii_case(setting))
            {
                self.record_libpq_connection_string_secrets(op + 1);
            } else if crate::secrets::is_secret_name(name)
                && !self
                    .dialect
                    .shown_settings()
                    .iter()
                    .any(|setting| setting.name.eq_ignore_ascii_case(name))
            {
                // A setting the dialect documents as holding no secret is
                // shown whatever its name's words.
                if let Some(span) = self.secret_value_at(op + 1) {
                    self.redaction_spans.push(span);
                }
            }
            // The next pair, after a comma or none.
            at = after.and_then(|after| {
                match matches!(
                    tokens[after].kind,
                    TokenKind::Punctuation(Punctuation::Comma)
                ) {
                    true => next(after),
                    false => Some(after),
                }
            });
        }
    }

    /// The `name[.part …] {= | TO}` a setting assignment writes from token
    /// `k`: the indexes of the name's first and last tokens and of its `=`
    /// or `TO`.
    fn setting_pair_at(&self, k: usize) -> Option<(usize, usize, usize)> {
        let tokens = self.tokens;
        let next = |k: usize| next_non_trivia_idx(tokens, k + 1);
        let last = self.setting_name_end(k)?;
        let op = next(last).filter(|&op| {
            matches!(tokens[op].kind, TokenKind::Operator(Operator::Eq))
                || tokens[op].lexeme(self.source).eq_ignore_ascii_case("TO")
        })?;
        Some((k, last, op))
    }

    /// The index of the last token of the name, and the dotted parts
    /// written after it, that starts at token `k`; `None` where no name
    /// starts there.
    fn setting_name_end(&self, k: usize) -> Option<usize> {
        let tokens = self.tokens;
        let is_name_part = |k: usize| {
            matches!(
                tokens[k].kind,
                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            )
        };
        let next = |k: usize| next_non_trivia_idx(tokens, k + 1);
        if !is_name_part(k) {
            return None;
        }
        let mut last = k;
        while let Some(part) = next(last)
            .filter(|&dot| matches!(tokens[dot].kind, TokenKind::Punctuation(Punctuation::Dot)))
            .and_then(next)
            .filter(|&part| is_name_part(part))
        {
            last = part;
        }
        Some(last)
    }

    /// Records the value a statement gives the setting written at `setting`
    /// (`None` for a variable) ([`crate::ast::AstScript::setting_values`]),
    /// written as a setting's value is from token `from`: words, numbers
    /// and strings, each signed or not, written apart by commas, up to the
    /// name of the next pair (`name =`). The index of the first token after
    /// the value; `None` at the end of the text.
    pub(crate) fn record_setting_value(
        &mut self,
        setting: Option<Span>,
        from: usize,
    ) -> Option<usize> {
        let tokens = self.tokens;
        let mut parts = Vec::new();
        let mut at = next_non_trivia_idx(tokens, from);
        let mut rest = None;
        while let Some(mut item) = at {
            // The name of the next pair is not a value.
            let names_a_pair = !parts.is_empty()
                && self
                    .setting_name_end(item)
                    .and_then(|last| next_non_trivia_idx(tokens, last + 1))
                    .is_some_and(|op| matches!(tokens[op].kind, TokenKind::Operator(Operator::Eq)));
            if names_a_pair {
                rest = Some(item);
                break;
            }
            if matches!(
                tokens[item].kind,
                TokenKind::Operator(Operator::Minus | Operator::Plus)
            ) {
                match next_non_trivia_idx(tokens, item + 1) {
                    Some(signed) => item = signed,
                    None => break,
                }
            }
            let token = &tokens[item];
            // A column written `t.c` (a statement's assignment in text not
            // read) and a clause's keyword are no value.
            let qualified = next_non_trivia_idx(tokens, item + 1).is_some_and(|dot| {
                matches!(tokens[dot].kind, TokenKind::Punctuation(Punctuation::Dot))
            });
            let clause = matches!(
                token.kind,
                TokenKind::Keyword(
                    Keyword::Where
                        | Keyword::From
                        | Keyword::Returning
                        | Keyword::Output
                        | Keyword::And
                        | Keyword::Or
                        | Keyword::Order
                        | Keyword::Group
                        | Keyword::Having
                        | Keyword::Limit
                        | Keyword::Union
                        | Keyword::Select
                        | Keyword::Values
                )
            );
            if (qualified && !quoted(token)) || clause {
                rest = Some(item);
                break;
            }
            if quoted(token) {
                parts.push(crate::secrets::string_literal_content(
                    token.span,
                    self.source,
                    self.dialect,
                ));
            } else if matches!(
                token.kind,
                TokenKind::Literal(_) | TokenKind::Identifier { .. } | TokenKind::Keyword(_)
            ) {
                // `DEFAULT` gives the setting no value of its own.
                if !matches!(token.kind, TokenKind::Keyword(Keyword::Default)) {
                    parts.push(token.span);
                }
            } else {
                rest = Some(item);
                break;
            }
            let after = next_non_trivia_idx(tokens, item + 1);
            rest = after;
            at = after
                .filter(|&comma| {
                    matches!(
                        tokens[comma].kind,
                        TokenKind::Punctuation(Punctuation::Comma)
                    )
                })
                .and_then(|comma| next_non_trivia_idx(tokens, comma + 1));
        }
        if !parts.is_empty() {
            self.setting_values
                .push(crate::ast::SettingValue { setting, parts });
        }
        rest
    }

    /// Records the value a statement gives a setting or a variable
    /// ([`crate::ast::AstScript::setting_values`]) as an expression, written
    /// at `value`: each literal of it, a string by its text between its
    /// quotes; a value of one token, that token.
    pub(crate) fn record_setting_expression(&mut self, setting: Option<Span>, value: Span) {
        let tokens = self.tokens;
        let first = tokens.partition_point(|t| t.span.end <= value.start);
        let last = tokens.partition_point(|t| t.span.start < value.end);
        let written: Vec<&crate::lexer::Token> = tokens[first..last]
            .iter()
            .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
            .collect();
        let parts: Vec<Span> = match written.as_slice() {
            [one] if !matches!(one.kind, TokenKind::Literal(_)) => vec![one.span],
            written => written
                .iter()
                .filter(|t| matches!(t.kind, TokenKind::Literal(_)))
                .map(|t| {
                    if quoted(t) {
                        crate::secrets::string_literal_content(t.span, self.source, self.dialect)
                    } else {
                        t.span
                    }
                })
                .collect(),
        };
        if !parts.is_empty() {
            self.setting_values
                .push(crate::ast::SettingValue { setting, parts });
        }
    }

    /// Records, to be masked out of every output, every literal the value a
    /// variable is assigned holds, at any depth (operands, arguments,
    /// branches, casts, parentheses, subqueries), where the variable's name,
    /// written at `name`, names a password or a secret
    /// ([`crate::secrets::is_secret_name`]); `value` is
    /// the expression assigned, each literal of the tokens it was read from
    /// read as [`Self::one_literal_at`] reads one.
    pub(crate) fn record_assigned_secret(&mut self, name: Span, value: &crate::ast::AstExpr) {
        self.record_assigned_value(name, value.span());
    }

    /// [`Self::record_assigned_secret`] of the value written at `span`,
    /// parsed or not.
    pub(crate) fn record_assigned_value(&mut self, name: Span, span: Span) {
        if !self.names_a_secret(name) {
            return;
        }
        let value = self.token_range(span);
        self.record_value_literals(value.start, value.end);
    }

    /// Records, to be masked out of every output, every literal written in
    /// the tokens `from..to` ([`Self::literals_in`]): the value a variable
    /// naming a password or a secret is assigned.
    fn record_value_literals(&mut self, from: usize, to: usize) {
        let spans: Vec<Span> = self
            .literals_in(from..to)
            .map(|literal| literal.content)
            .collect();
        self.redaction_spans.extend(spans);
    }

    /// The tokens written inside `span`.
    fn token_range(&self, span: Span) -> std::ops::Range<usize> {
        let from = self.tokens.partition_point(|t| t.span.start < span.start);
        let to = from + self.tokens[from..].partition_point(|t| t.span.end <= span.end);
        from..to
    }

    /// Each literal written in the tokens `tokens`, in order, each read as
    /// [`Self::one_literal_at`] reads one.
    fn literals_in(
        &self,
        tokens: std::ops::Range<usize>,
    ) -> impl Iterator<Item = ReadLiteral> + '_ {
        let to = tokens.end.min(self.tokens.len());
        let mut at = tokens.start;
        std::iter::from_fn(move || {
            while at < to {
                match self
                    .one_literal_at(at)
                    .filter(|literal| literal.first == at)
                {
                    Some(literal) => {
                        at = literal.past.max(at + 1);
                        return Some(literal);
                    }
                    None => at += 1,
                }
            }
            None
        })
    }

    /// Whether the variable name written at `name` names a password or a
    /// secret ([`crate::secrets::is_secret_name`]).
    pub(crate) fn names_a_secret(&self, name: Span) -> bool {
        let name = self
            .source
            .get(name.start as usize..name.end as usize)
            .unwrap_or("");
        crate::secrets::is_secret_name(name)
    }

    /// [`Self::record_option_list_secrets`] at each `OPTIONS (…)` of the
    /// tokens `from..to`, a run of clauses written in any order.
    pub(crate) fn record_options_clause_secrets(&mut self, from: usize, to: usize) {
        for k in from..to.min(self.tokens.len()) {
            if self.tokens[k]
                .lexeme(self.source)
                .eq_ignore_ascii_case("OPTIONS")
            {
                self.record_option_list_secrets(k + 1);
            }
        }
    }

    /// [`Self::record_setting_secrets`] at each `SET` of the tokens
    /// `from..to`, a run of clauses written in any order.
    pub(crate) fn record_setting_clause_secrets(&mut self, from: usize, to: usize) {
        for k in from..to.min(self.tokens.len()) {
            if self.tokens[k]
                .lexeme(self.source)
                .eq_ignore_ascii_case("SET")
            {
                self.record_setting_secrets(k);
            }
        }
    }

    /// Records, to be masked out of every output, the secrets of the libpq
    /// connection string a call to the function written `function` (by its
    /// last name part), whose parenthesis opens at `open`, takes
    /// ([`LIBPQ_CONNECTION_ARGUMENTS`]).
    pub(crate) fn record_libpq_call_secrets(&mut self, function: &str, open: usize) {
        let called = function.trim();
        let called = called.rsplit('.').next().unwrap_or(called);
        let Some(&(_, place)) = LIBPQ_CONNECTION_ARGUMENTS
            .iter()
            .find(|(f, _)| f.eq_ignore_ascii_case(called))
        else {
            return;
        };
        let Some(past) = self.parens_end(open) else {
            return;
        };
        let mut starts = vec![open + 1];
        let mut depth = 0u32;
        for i in open + 1..past - 1 {
            let kind = &self.tokens[i].kind;
            if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && matches!(kind, TokenKind::Punctuation(Punctuation::Comma)) {
                starts.push(i + 1);
            }
        }
        let argument = match place {
            ConnectionArgument::Last => starts.last().copied(),
            ConnectionArgument::FirstOfSeveral => (starts.len() > 1).then_some(starts[0]),
        };
        if let Some(argument) = argument {
            self.record_libpq_connection_string_secrets(argument);
        }
        // An argument given by a connection parameter's name (`connstr =>
        // '…'`).
        for &start in &starts {
            let Some(name) = next_non_trivia_idx(self.tokens, start) else {
                continue;
            };
            let lexeme = self.tokens[name].lexeme(self.source);
            if !LIBPQ_CONNECTION_PARAMETERS
                .iter()
                .any(|parameter| lexeme.eq_ignore_ascii_case(parameter))
            {
                continue;
            }
            let Some(arrow) = next_non_trivia_idx(self.tokens, name + 1) else {
                continue;
            };
            if matches!(self.tokens[arrow].kind, TokenKind::Operator(Operator::EqGt)) {
                self.record_libpq_connection_string_secrets(arrow + 1);
            }
        }
    }

    /// Records, to be masked out of every output, each literal of the value
    /// a call to PostgreSQL's `set_config(name, value, is_local)`, whose
    /// parenthesis opens at `open`, gives a setting, as `SET name = value`
    /// does ([`Self::record_setting_secrets`]): where the name is one string
    /// literal whose value names a secret
    /// ([`crate::secrets::is_secret_name`]), or is not one
    /// literal (a concatenation, a variable: the setting is not known). The
    /// function called is the name part written last before `open`, folded
    /// as the dialect folds a name, quoted or not.
    pub(crate) fn record_set_config_secrets(&mut self, open: usize) {
        let Some(called) = (0..open)
            .rev()
            .find(|&i| !is_skippable(&self.tokens[i]))
            .map(|i| self.tokens[i].lexeme(self.source))
        else {
            return;
        };
        let fold = |name: &str| crate::dialect::normalize_identifier_in(self.dialect, name);
        if fold(called) != fold("set_config") {
            return;
        }
        let Some(past) = self.parens_end(open) else {
            return;
        };
        // The commas between the arguments.
        let mut commas = Vec::new();
        let mut depth = 0u32;
        for i in open + 1..past - 1 {
            let kind = &self.tokens[i].kind;
            if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && matches!(kind, TokenKind::Punctuation(Punctuation::Comma)) {
                commas.push(i);
            }
        }
        let Some(&name_end) = commas.first() else {
            return;
        };
        let value_end = commas.get(1).copied().unwrap_or(past - 1);
        let names_a_secret = match self.one_literal_at(open + 1) {
            Some(name)
                if matches!(
                    name.spelling,
                    LiteralSpelling::Quoted | LiteralSpelling::DollarQuoted
                ) && next_non_trivia_idx(self.tokens, name.past) == Some(name_end) =>
            {
                let setting: Option<String> = self
                    .literal_value_chars(open + 1)
                    .map(|chars| chars.into_iter().map(|(c, _)| c).collect());
                setting.is_none_or(|setting| crate::secrets::is_secret_name(&setting))
            }
            Some(_) | None => true,
        };
        if names_a_secret {
            self.record_value_literals(name_end + 1, value_end);
        }
    }

    /// The characters of the value of the string literal at the first token
    /// from `i` that is not a comment ([`Self::one_literal_at`]), each with
    /// the span of the source that writes it, decoded by
    /// [`crate::lexer::decode_string_literal`] from the literal's text: from
    /// its prefix where the prefix is written against the string (`E'…'`,
    /// `U&'…'`), else from the string.
    fn literal_value_chars(&self, i: usize) -> Option<Vec<(char, Span)>> {
        let literal = self.one_literal_at(i)?;
        let from = match literal.spelling {
            LiteralSpelling::Number | LiteralSpelling::Templated => return None,
            LiteralSpelling::DollarQuoted | LiteralSpelling::UnclosedDollarQuoted => literal.first,
            LiteralSpelling::Quoted => {
                let mut from = literal.past - 1;
                while from > literal.first
                    && self.tokens[from - 1].span.end == self.tokens[from].span.start
                {
                    from -= 1;
                }
                from
            }
        };
        let start = self.tokens[from].span.start;
        let text = self
            .source
            .get(start as usize..self.tokens.get(literal.past - 1)?.span.end as usize)?;
        let decoded = crate::lexer::decode_string_literal(text, self.dialect)?;
        Some(
            decoded
                .value
                .chars()
                .zip(decoded.sources)
                .map(|(c, s)| {
                    (
                        c,
                        Span {
                            start: start + s.start,
                            end: start + s.end,
                        },
                    )
                })
                .collect(),
        )
    }

    /// The span to mask of the secret value one token after `keyword_idx`
    /// (`[=]` between them), a word written there included, or of the
    /// value MySQL's `PASSWORD(…)` /
    /// `OLD_PASSWORD(…)` hashes there.
    pub(crate) fn secret_value_after(&self, keyword_idx: usize) -> Option<Span> {
        let idx = self.value_idx_after(keyword_idx)?;
        self.secret_value_or_word_at(self.hashed_value_idx(idx)?)
    }

    /// The first token one token after `keyword_idx`, past an `=` between
    /// them.
    pub(crate) fn value_idx_after(&self, keyword_idx: usize) -> Option<usize> {
        let idx = next_non_trivia_idx(self.tokens, keyword_idx + 1)?;
        if matches!(self.tokens[idx].kind, TokenKind::Operator(Operator::Eq)) {
            return next_non_trivia_idx(self.tokens, idx + 1);
        }
        Some(idx)
    }

    /// Where the value written at `idx` starts: inside the parenthesis of
    /// MySQL's `PASSWORD(…)` / `OLD_PASSWORD(…)` named there, else at `idx`;
    /// `None` when such a name is not followed by `(`.
    pub(crate) fn hashed_value_idx(&self, idx: usize) -> Option<usize> {
        let names_hash_call = ["PASSWORD", "OLD_PASSWORD"]
            .iter()
            .any(|w| self.tokens[idx].lexeme(self.source).eq_ignore_ascii_case(w));
        if !names_hash_call {
            return Some(idx);
        }
        let open = next_non_trivia_idx(self.tokens, idx + 1)?;
        matches!(
            self.tokens[open].kind,
            TokenKind::Punctuation(Punctuation::LParen)
        )
        .then_some(open + 1)
    }

    /// The content of the string, in any spelling ([`Self::one_literal_at`];
    /// a quoted or dollar-quoted string, not a `0x…` / `0b…` number), one
    /// token after `keyword_idx` (`[=]` between them).
    fn string_literal_after(&self, keyword_idx: usize) -> Option<Span> {
        let mut idx = next_non_trivia_idx(self.tokens, keyword_idx + 1)?;
        if matches!(self.tokens[idx].kind, TokenKind::Operator(Operator::Eq)) {
            idx = next_non_trivia_idx(self.tokens, idx + 1)?;
        }
        self.one_literal_at(idx)
            .filter(|literal| {
                !matches!(
                    literal.spelling,
                    LiteralSpelling::Number | LiteralSpelling::Templated
                )
            })
            .map(|literal| literal.content)
    }

    /// [`Self::secret_value_at`], or the span of a word or a number written
    /// at the first token from `i` bare or in identifier quotes, where a
    /// statement takes a secret after a credential's keyword (`PASSWORD
    /// word`, `PASSWORD 1234`): the word is the secret. A word that leads a
    /// password option of MySQL's `CREATE | ALTER USER` (`PASSWORD EXPIRE`,
    /// `HISTORY`, `REUSE`, `REQUIRE`: "CREATE USER Statement", "Password
    /// Management Options") is grammar, not a value.
    pub(crate) fn secret_value_or_word_at(&self, i: usize) -> Option<Span> {
        self.secret_value_at(i).or_else(|| {
            let at = next_non_trivia_idx(self.tokens, i)?;
            let token = self.tokens.get(at)?;
            let option = ["EXPIRE", "HISTORY", "REUSE", "REQUIRE"]
                .iter()
                .any(|word| token.lexeme(self.source).eq_ignore_ascii_case(word));
            (matches!(
                token.kind,
                TokenKind::Identifier { .. } | TokenKind::Literal(LiteralKind::Number)
            ) && !option)
                .then_some(token.span)
        })
    }

    /// The span to mask of a literal written at the first token from `i`
    /// that is not a comment ([`Self::literal_at`]), or of a placeholder or
    /// a variable written there (`?`, `@p`), whose value takes the secret's
    /// place.
    pub(crate) fn secret_value_at(&self, i: usize) -> Option<Span> {
        self.literal_at(i)
            .map(|literal| literal.content)
            .or_else(|| {
                let at = next_non_trivia_idx(self.tokens, i)?;
                let token = self.tokens.get(at)?;
                if matches!(
                    token.kind,
                    TokenKind::Placeholder
                        | TokenKind::Identifier {
                            kind: crate::lexer::IdentifierKind::AtVariable,
                            ..
                        }
                ) {
                    return Some(token.span);
                }
                // A bind reference: `:` against the variable's name (`:pw`).
                let name = self.tokens.get(at + 1)?;
                (matches!(
                    token.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                ) && name.span.start == token.span.end
                    && matches!(name.kind, TokenKind::Identifier { .. }))
                .then_some(Span {
                    start: token.span.start,
                    end: name.span.end,
                })
            })
    }

    /// The literal at the first token from `i` that is not a comment
    /// ([`Self::one_literal_at`]) and, when it is a quoted string, plain or
    /// a template writes into it, the strings written after it in either
    /// spelling, which concatenate with it: in every dialect, whatever it
    /// makes of them, a secret's masked span runs over the whole run.
    /// Returns the literal, its content spanning the run, spelt `Templated`
    /// where a template writes into any of its strings.
    pub(crate) fn literal_at(&self, i: usize) -> Option<ReadLiteral> {
        let mut literal = self.one_literal_at(i)?;
        if !matches!(
            literal.spelling,
            LiteralSpelling::Quoted | LiteralSpelling::Templated
        ) {
            return Some(literal);
        }
        while let Some(next) = next_non_trivia_idx(self.tokens, literal.past) {
            let tok = &self.tokens[next];
            if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
                literal.content.end = inner_literal_span(tok.span, self.source, self.dialect).end;
                literal.past = next + 1;
            } else if let Some((templated, after)) =
                matches!(tok.kind, TokenKind::Literal(LiteralKind::StringFragment))
                    .then(|| self.templated_string_at(next))
                    .flatten()
            {
                literal.content.end = templated.end;
                literal.past = after;
                literal.spelling = LiteralSpelling::Templated;
            } else {
                break;
            }
        }
        Some(literal)
    }

    /// A string or binary literal written at the first token from `i` that
    /// is not a comment, in each spelling a lexer gives one: a string
    /// (`'…'`, `"…"`, `E'…'`, T-SQL's `N'…'`); a string with a prefix
    /// written against it (`N'…'`, `X'…'`, `B'…'`, `E'…'`, `r'…'`, `rb'…'`,
    /// PostgreSQL's `U&'…'`, a MySQL charset introducer such as
    /// `_utf8mb4'…'`); a MySQL charset introducer and the literal after it
    /// (`_utf8mb4 '…'`, `_binary 0x…`); `0x…` / `0b…`; a dollar-quoted
    /// string (`$$…$$`, `$tag$…$tag$`, lexed as a tag, its content and the
    /// tag, or as words starting and ending with `$$`); a string a template
    /// writes into ([`Self::templated_string_at`]), alone or after such a
    /// prefix or introducer.
    pub(crate) fn one_literal_at(&self, i: usize) -> Option<ReadLiteral> {
        self.read_literal(i, true)
    }

    /// [`Self::one_literal_at`], reading a charset introducer only where
    /// `introducer_allowed`.
    fn read_literal(&self, i: usize, introducer_allowed: bool) -> Option<ReadLiteral> {
        let idx = next_non_trivia_idx(self.tokens, i)?;
        let tok = &self.tokens[idx];
        let lex = tok.lexeme(self.source);
        let read = |content: Span, past: usize, spelling: LiteralSpelling| {
            Some(ReadLiteral {
                content,
                first: idx,
                past,
                spelling,
            })
        };
        if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
            let content = inner_literal_span(tok.span, self.source, self.dialect);
            return read(content, idx + 1, LiteralSpelling::Quoted);
        }
        if matches!(tok.kind, TokenKind::Literal(LiteralKind::StringFragment)) {
            let (content, past) = self.templated_string_at(idx)?;
            return read(content, past, LiteralSpelling::Templated);
        }
        if matches!(tok.kind, TokenKind::Literal(LiteralKind::Number)) {
            let radix =
                lex.len() > 2 && lex.starts_with('0') && lex[1..].starts_with(['x', 'X', 'b', 'B']);
            if !radix {
                return None;
            }
            let digits = Span {
                start: tok.span.start + 2,
                end: tok.span.end,
            };
            return read(digits, idx + 1, LiteralSpelling::Number);
        }
        let unquoted = matches!(
            tok.kind,
            TokenKind::Identifier {
                kind: IdentifierKind::Unquoted,
                ..
            }
        );
        let dollar_word =
            unquoted && lex.starts_with('$') && !self.dialect.supports_dollar_quoted_strings();
        if crate::parser::core::is_dollar_quote_delimiter(&tok.kind) || dollar_word {
            return self
                .dollar_quoted_literal_at(idx)
                .map(|(content, past, closed)| ReadLiteral {
                    content,
                    first: idx,
                    past,
                    spelling: if closed {
                        LiteralSpelling::DollarQuoted
                    } else {
                        LiteralSpelling::UnclosedDollarQuoted
                    },
                });
        }
        if !unquoted {
            return None;
        }
        let charset = is_charset_introducer(lex);
        // The prefix and the string written against it; PostgreSQL's `U&`
        // lexes as the word and an `&`.
        let mut string = idx + 1;
        let ampersand = self
            .tokens
            .get(string)
            .is_some_and(|t| t.span.start == tok.span.end && t.lexeme(self.source) == "&");
        let prefix = if ampersand {
            string += 1;
            lex.eq_ignore_ascii_case("U")
        } else {
            charset || LITERAL_PREFIXES.iter().any(|p| lex.eq_ignore_ascii_case(p))
        };
        let against = self.tokens.get(string).is_some_and(|t| {
            t.span.start == self.tokens[string - 1].span.end
                && matches!(
                    t.kind,
                    TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
                )
        });
        let literal = if prefix && against {
            self.read_literal(string, false)
        } else if introducer_allowed && charset {
            // A MySQL charset introducer, then the literal it reads.
            self.read_literal(idx + 1, false)
        } else {
            None
        };
        literal.map(|literal| ReadLiteral {
            first: idx,
            ..literal
        })
    }

    /// The quoted string a template writes into whose opening fragment is at
    /// `idx` (`'a`, `N'a`; then templates and fragments up to the one that
    /// closes it, [`Self::templated_string_after`]); where nothing closes
    /// it, it runs to the end of what is written. Returns its content,
    /// between the quotes and templates included, and the index past it;
    /// `None` where the token opens no such string.
    fn templated_string_at(&self, idx: usize) -> Option<(Span, usize)> {
        let open = &self.tokens[idx];
        let lex = open.lexeme(self.source);
        let quote = lex.find('\'')?;
        let continues_a_template = idx > 0 && {
            let before = &self.tokens[idx - 1];
            before.span.end == open.span.start
                && matches!(
                    before.kind,
                    TokenKind::JinjaExprClose | TokenKind::JinjaStmtClose | TokenKind::JinjaComment
                )
        };
        if continues_a_template || !lex[..quote].chars().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        let read = self.templated_string_after(idx);
        let last = self.tokens[read.past - 1].span.end;
        let content = Span {
            start: open.span.start + quote as u32 + 1,
            // Before the closing quote, or to the end of what is written.
            end: if read.closed { last - 1 } else { last },
        };
        Some((content, read.past))
    }

    /// The dollar-quoted string opened at `idx`: a dollar-quote delimiter up
    /// to the next delimiter written as it is; where the lexer types no
    /// delimiter, the word `$tag$` up to the next `$tag$`, or a word
    /// starting with `$$` up to the first word, it included, that ends with
    /// `$$`; unterminated, the rest of the text. Returns its content, the
    /// index past it and whether its closer is written.
    fn dollar_quoted_literal_at(&self, idx: usize) -> Option<(Span, usize, bool)> {
        use crate::parser::core::is_dollar_quote_delimiter;
        let open = &self.tokens[idx];
        let lex = open.lexeme(self.source);
        let (tag, close) = if is_dollar_quote_delimiter(&open.kind) {
            let close = (idx + 1..self.tokens.len()).find(|&j| {
                is_dollar_quote_delimiter(&self.tokens[j].kind)
                    && self.tokens[j].lexeme(self.source) == lex
            });
            (lex, close)
        } else if lex.starts_with("$$") {
            let close = if lex.len() >= 4 && lex.ends_with("$$") {
                Some(idx)
            } else {
                (idx + 1..self.tokens.len())
                    .find(|&j| self.tokens[j].lexeme(self.source).ends_with("$$"))
            };
            ("$$", close)
        } else if crate::parser::core::is_dollar_quote_tag(lex) {
            let close =
                (idx + 1..self.tokens.len()).find(|&j| self.tokens[j].lexeme(self.source) == lex);
            (lex, close)
        } else {
            return None;
        };
        let start = open.span.start + tag.len() as u32;
        let (end, past) = match close {
            Some(j) => (self.tokens[j].span.end - tag.len() as u32, j + 1),
            None => {
                let past = self
                    .tokens
                    .iter()
                    .rposition(|t| !matches!(t.kind, TokenKind::Eof))?
                    + 1;
                (self.tokens[past - 1].span.end, past)
            }
        };
        Some((
            Span {
                start,
                end: end.max(start),
            },
            past,
            close.is_some(),
        ))
    }

    /// The index past a MySQL account name at `i`: `name` or `'user'` and
    /// its optional `@host`, or `CURRENT_USER[()]`.
    pub(crate) fn mysql_principal_end(&self, i: usize) -> Option<usize> {
        let tok = self.tokens.get(i)?;
        let names_user = matches!(
            tok.kind,
            TokenKind::Literal(LiteralKind::String)
                | TokenKind::Identifier { .. }
                | TokenKind::Keyword(_)
        );
        if !names_user {
            return None;
        }
        let user_end = self.parens_end(i + 1).unwrap_or(i + 1);
        Some(
            self.mysql_account_host_at(user_end)
                .map_or(user_end, |(end, _)| end),
        )
    }

    /// The `@host` of a MySQL account name, written at the first token from
    /// `i` that is not a comment: `@` and a quoted host (`'h'`, `"h"`,
    /// `` `h` ``) or an unquoted one, or an unquoted host lexed with its `@`
    /// (`@localhost`). An unquoted host runs on through the words, numbers
    /// and dots written against it (`127.0.0.1`, `db1.example.com`). Returns
    /// the index past the host and the host's span, quotes left out.
    pub(crate) fn mysql_account_host_at(&self, i: usize) -> Option<(usize, Span)> {
        let at = next_non_trivia_idx(self.tokens, i)?;
        let at_tok = &self.tokens[at];
        let unquoted_part = |t: &Token| {
            matches!(
                t.kind,
                TokenKind::Identifier {
                    kind: IdentifierKind::Unquoted,
                    ..
                } | TokenKind::Keyword(_)
                    | TokenKind::Literal(LiteralKind::Number)
            )
        };
        let (first, start) = if matches!(at_tok.kind, TokenKind::Operator(Operator::At)) {
            let h = next_non_trivia_idx(self.tokens, at + 1)?;
            let host = &self.tokens[h];
            let quoted = matches!(
                host.kind,
                TokenKind::Literal(LiteralKind::String)
                    | TokenKind::Identifier {
                        kind: IdentifierKind::Quoted,
                        ..
                    }
            );
            if quoted {
                return Some((
                    h + 1,
                    inner_literal_span(host.span, self.source, self.dialect),
                ));
            }
            if !unquoted_part(host) {
                return None;
            }
            (h, host.span.start)
        } else if matches!(
            at_tok.kind,
            TokenKind::Identifier {
                kind: IdentifierKind::AtVariable,
                ..
            }
        ) && !at_tok.lexeme(self.source).starts_with("@@")
        {
            (at, at_tok.span.start + 1)
        } else {
            return None;
        };
        let mut end = first + 1;
        while self.tokens.get(end).is_some_and(|t| {
            t.span.start == self.tokens[end - 1].span.end
                && (unquoted_part(t) || matches!(t.kind, TokenKind::Punctuation(Punctuation::Dot)))
        }) {
            end += 1;
        }
        Some((
            end,
            Span {
                start,
                end: self.tokens[end - 1].span.end,
            },
        ))
    }
}

/// Where [`Parser::record_keyed_secrets`] reads a key.
#[derive(Debug, Clone, Copy)]
enum KeyDepth {
    /// Outside the parentheses opened in the tokens it reads: the entries of
    /// one option list.
    TopLevel,
    /// At any depth: text no reader parsed.
    Any,
}

/// The tokens [`Parser::record_unparsed_secrets`] has read: for each
/// token, the first token at or after it not read, found without walking
/// the tokens read between them.
#[derive(Debug, Default)]
pub(crate) struct UnparsedSecretsRead {
    /// Where to look on from each token: itself where it is not read. One
    /// entry past the last token. Empty until the first read.
    next: Vec<usize>,
}

impl UnparsedSecretsRead {
    /// The first token at or after `at` not read, of `len` tokens.
    fn first_unread(&mut self, at: usize, len: usize) -> usize {
        if self.next.is_empty() {
            self.next = (0..=len).collect();
        }
        let mut found = at.min(len);
        while self.next[found] != found {
            found = self.next[found];
        }
        // Each token passed on the way leads straight to it from now on.
        let mut passed = at.min(len);
        while passed != found {
            passed = std::mem::replace(&mut self.next[passed], found);
        }
        found
    }

    /// The end of the run of tokens not read that starts at `start`,
    /// before `to`.
    fn unread_run_end(&self, start: usize, to: usize) -> usize {
        (start + 1..to).find(|&i| self.next[i] != i).unwrap_or(to)
    }

    /// Marks the tokens `from..to` read, of `len` tokens.
    fn read(&mut self, from: usize, to: usize, len: usize) {
        if self.next.is_empty() {
            self.next = (0..=len).collect();
        }
        let to = to.min(len);
        for entry in &mut self.next[from.min(to)..to] {
            *entry = to;
        }
    }
}

/// Where a dblink function takes a libpq connection string.
#[derive(Debug, Clone, Copy)]
enum ConnectionArgument {
    /// Its last argument: `dblink_connect([name,] connstr)`.
    Last,
    /// Its first argument when another follows it: `dblink(connstr, sql
    /// [, fail])`; alone, that argument is the SQL.
    FirstOfSeveral,
}

/// The functions that take a libpq connection string, and where.
const LIBPQ_CONNECTION_ARGUMENTS: [(&str, ConnectionArgument); 4] = [
    ("dblink_connect", ConnectionArgument::Last),
    ("dblink_connect_u", ConnectionArgument::Last),
    ("dblink", ConnectionArgument::FirstOfSeveral),
    ("dblink_exec", ConnectionArgument::FirstOfSeveral),
];

/// The names the dblink functions document for the parameter that takes a
/// connection string or a connection's name (dblink, "Functions").
const LIBPQ_CONNECTION_PARAMETERS: [&str; 2] = ["connstr", "connname"];

/// The PostgreSQL settings whose value is a libpq connection string
/// ("Server Configuration", "Standby Servers": `primary_conninfo`).
const LIBPQ_CONNECTION_SETTINGS: [&str; 1] = ["primary_conninfo"];

/// Whether libpq reads `c` as white space (C's `isspace`).
fn is_libpq_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r')
}

/// The spans of the secret values of a libpq connection string, given as
/// its characters with the span that writes each (libpq, "Connection
/// Strings"). In the `key = value` form, entries are separated by white
/// space, a value may be quoted with `'`, and a backslash makes the
/// character after it part of the value; the value of each key that names
/// a password or a secret ([`crate::secrets::is_secret_name`]:
/// `password`, `sslpassword`, …) is secret. libpq rejects the string at
/// its first entry with no `=`, and the reading stops there. In the URI
/// form (`postgresql://` or `postgres://`), the password of its user info
/// (`user:password@`) and the value of each query parameter so named
/// (`?password=…`) are secret.
fn libpq_secret_values(chars: &[(char, Span)]) -> Vec<Span> {
    let at = |k: usize| chars.get(k).map(|&(c, _)| c);
    let span_of = |from: usize, to: usize| Span {
        start: chars[from].1.start,
        end: chars[to - 1].1.end,
    };
    let is_secret = crate::secrets::is_secret_name;
    let mut spans = Vec::new();
    let scheme = ["postgresql://", "postgres://"]
        .iter()
        .find(|s| s.chars().enumerate().all(|(k, c)| at(k) == Some(c)))
        .map(|s| s.len());
    if let Some(scheme) = scheme {
        let user_end = (scheme..chars.len())
            .find(|&k| matches!(chars[k].0, '@' | '/'))
            .unwrap_or(chars.len());
        let mut host = scheme;
        if at(user_end) == Some('@') {
            if let Some(colon) = (scheme..user_end).find(|&k| chars[k].0 == ':') {
                if user_end > colon + 1 {
                    spans.push(span_of(colon + 1, user_end));
                }
            }
            host = user_end + 1;
        }
        let Some(query) = (host..chars.len()).find(|&k| chars[k].0 == '?') else {
            return spans;
        };
        let mut entry = query + 1;
        while entry < chars.len() {
            let end = (entry..chars.len())
                .find(|&k| chars[k].0 == '&')
                .unwrap_or(chars.len());
            let Some(eq) = (entry..end).find(|&k| chars[k].0 == '=') else {
                break;
            };
            if end > eq + 1 && is_secret(&percent_decoded(&chars[entry..eq])) {
                spans.push(span_of(eq + 1, end));
            }
            entry = end + 1;
        }
        return spans;
    }
    let mut k = 0;
    loop {
        while at(k).is_some_and(is_libpq_space) {
            k += 1;
        }
        if k >= chars.len() {
            break;
        }
        let key_start = k;
        while at(k).is_some_and(|c| c != '=' && !is_libpq_space(c)) {
            k += 1;
        }
        let key_end = k;
        while at(k).is_some_and(is_libpq_space) {
            k += 1;
        }
        if at(k) != Some('=') {
            break;
        }
        k += 1;
        while at(k).is_some_and(is_libpq_space) {
            k += 1;
        }
        let quoted = at(k) == Some('\'');
        if quoted {
            k += 1;
        }
        let value_start = k;
        while let Some(c) = at(k) {
            if c == '\\' {
                k = (k + 2).min(chars.len());
            } else if (quoted && c == '\'') || (!quoted && is_libpq_space(c)) {
                break;
            } else {
                k += 1;
            }
        }
        let key: String = chars[key_start..key_end].iter().map(|&(c, _)| c).collect();
        if k > value_start && is_secret(&key) {
            spans.push(span_of(value_start, k));
        }
        if quoted && at(k) == Some('\'') {
            k += 1;
        }
    }
    spans
}

/// The text of `chars` with each `%hh` read as the byte it encodes, as a URI
/// writes a byte.
fn percent_decoded(chars: &[(char, Span)]) -> String {
    let mut bytes = Vec::with_capacity(chars.len());
    let mut k = 0;
    while k < chars.len() {
        let hex = |offset: usize| chars.get(k + offset).and_then(|&(d, _)| d.to_digit(16));
        if let (Some('%'), Some(high), Some(low)) = (chars.get(k).map(|&(c, _)| c), hex(1), hex(2))
        {
            bytes.extend(u8::try_from(high * 16 + low));
            k += 3;
            continue;
        }
        let mut buf = [0; 4];
        bytes.extend_from_slice(chars[k].0.encode_utf8(&mut buf).as_bytes());
        k += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The span between the delimiters of the string literal
/// ([`crate::secrets::string_literal_content`]) or the backquoted name at
/// `span`; `span` itself for any other token.
pub(crate) fn inner_literal_span(
    span: Span,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Span {
    let content = crate::secrets::string_literal_content(span, source, dialect);
    if content != span {
        return content;
    }
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return span;
    };
    match text.strip_prefix('`').and_then(|t| t.strip_suffix('`')) {
        Some(_) => Span {
            start: span.start + 1,
            end: span.end - 1,
        },
        None => span,
    }
}

/// Classify the MSSQL source clause that follows the principal name.
/// Re-exports the existing classifier from `mssql_statements.rs` so the
/// neutral parser can call into it without duplicating the lexeme
/// peek logic.
fn classify_mssql_principal_source(p: &mut Parser) -> AstMssqlPrincipalSource {
    p.classify_mssql_principal_source()
}
