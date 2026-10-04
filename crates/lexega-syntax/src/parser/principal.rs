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
    AstAlterPrincipal, AstCreatePrincipal, AstDropPrincipal, AstMssqlLoginOptions,
    AstMssqlPrincipalSource, AstPrincipalEnabledState, AstPrincipalMembership,
    AstPrincipalMembershipKind, AstRoleAttribute, AstRoleAttributeKind, AstSecondaryRolesMode,
    AstSnowflakeUserOptions, AstStmt, CreatePrincipalOptions, PrincipalKind,
};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Operator, Punctuation, Span, Token, TokenKind};
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

        // Comma-separated principal names. The qualified-name parser
        // handles the `db.role` form for a Snowflake DATABASE ROLE.
        let mut names = Vec::new();
        let first = self.parse_qualified_name_span()?;
        let mut end = first.end;
        names.push(first);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // comma
                let next = self.parse_qualified_name_span()?;
                end = next.end;
                names.push(next);
            } else {
                break;
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
    fn consume_if_exists(&mut self) -> bool {
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

    /// Consume the principal name token, plus an optional MySQL `@'host'`
    /// suffix. Returns `(name_span, mysql_host_inner_span)` where the
    /// host span is `None` for non-MySQL forms and points at the inner
    /// content of the host literal (no surrounding quotes) when present.
    pub(crate) fn consume_principal_name(&mut self) -> ParseResult<(Span, Option<Span>)> {
        // Canonical name parser handles single, dotted (`db.role` for a
        // Snowflake DATABASE ROLE), and string-literal (MySQL `'bob'`)
        // forms, stopping at the first non-dot token so the `@host` and
        // options-body parsing below stay intact.
        let name_span = self.parse_qualified_name_span()?;

        // MySQL `'user'@'host'` — `@` is lexed as Operator::At for dialects
        // where the lexer emits it (MySQL emits AtVariable for `@ident`
        // but a bare `@` between two literals lands on Operator::At post
        // the lexer fix landed earlier on this branch).
        let mut mysql_host = None;
        if let Some(t) = self.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Operator(Operator::At)) {
                self.advance(); // @
                if let Some(host_tok) = self.peek_non_trivia() {
                    let host_span = host_tok.span;
                    self.advance();
                    mysql_host = Some(inner_literal_span(host_span, self.source));
                }
            }
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
        let mut enabled_state = None;
        let mut role_attributes = Vec::new();
        let mut snowflake_user = AstSnowflakeUserOptions::default();
        let mut has_snowflake = false;
        let mut mssql_login = AstMssqlLoginOptions::default();
        let mut has_mssql_login = false;

        while self.idx < self.tokens.len() {
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
            );

            // T-SQL `CREATE/ALTER LOGIN` password-policy options. Same
            // permissive stance: the `= ON|OFF` assignment form appears
            // only in T-SQL login syntax. Pure recognition; no judgement
            // here.
            has_mssql_login |= recognize_mssql_login_property(
                &mut mssql_login,
                self.tokens,
                self.idx,
                self.source,
            );

            if password_literal.is_none() {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("PASSWORD") {
                    password_literal =
                        peek_string_literal_after(self.tokens, self.idx, self.source);
                } else if lex.eq_ignore_ascii_case("IDENTIFIED") {
                    // MySQL: IDENTIFIED BY '<lit>'
                    if let Some(by_idx) = next_non_trivia_idx(self.tokens, self.idx + 1) {
                        let by_tok = &self.tokens[by_idx];
                        if by_tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
                            password_literal =
                                peek_string_literal_after(self.tokens, by_idx, self.source);
                        }
                    }
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

        // Record the password literal so it is masked out of output surfaces.
        if let Some(pw) = password_literal {
            self.redaction_spans.push(pw);
        }
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
        )
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
) -> bool {
    let lex = tokens[idx].lexeme(source);
    if lex.eq_ignore_ascii_case("CHECK_POLICY") {
        set_once(
            &mut out.check_policy,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("CHECK_EXPIRATION") {
        set_once(
            &mut out.check_expiration,
            peek_assigned_value_after(tokens, idx, source),
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
) -> bool {
    let lex = tokens[idx].lexeme(source);
    if lex.eq_ignore_ascii_case("DEFAULT_ROLE") {
        set_once(
            &mut out.default_role,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("NETWORK_POLICY") {
        set_once(
            &mut out.network_policy,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("TYPE") {
        set_once(
            &mut out.user_type,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("MUST_CHANGE_PASSWORD") {
        set_once(
            &mut out.must_change_password,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("DISABLED") {
        set_once(
            &mut out.disabled,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("MINS_TO_BYPASS_MFA") {
        set_once(
            &mut out.mins_to_bypass_mfa,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("DAYS_TO_EXPIRY") {
        set_once(
            &mut out.days_to_expiry,
            peek_assigned_value_after(tokens, idx, source),
        )
    } else if lex.eq_ignore_ascii_case("MINS_TO_UNLOCK") {
        set_once(
            &mut out.mins_to_unlock,
            peek_assigned_value_after(tokens, idx, source),
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
            if let Some(mode) = peek_secondary_roles_after(tokens, idx, source) {
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
fn peek_assigned_value_after(tokens: &[Token], keyword_idx: usize, source: &str) -> Option<Span> {
    let eq_idx = next_non_trivia_idx(tokens, keyword_idx + 1)?;
    if !matches!(tokens[eq_idx].kind, TokenKind::Operator(Operator::Eq)) {
        return None;
    }
    let val_idx = next_non_trivia_idx(tokens, eq_idx + 1)?;
    match tokens[val_idx].kind {
        TokenKind::Punctuation(_) | TokenKind::Operator(_) => None,
        _ => Some(inner_literal_span(tokens[val_idx].span, source)),
    }
}

/// For `DEFAULT_SECONDARY_ROLES = ( ... )`: require `= (`, then classify
/// the parenthesized content as [`AstSecondaryRolesMode::None`] (empty)
/// or [`AstSecondaryRolesMode::All`] (contains `ALL`). Returns `None`
/// for unrecognized forms.
fn peek_secondary_roles_after(
    tokens: &[Token],
    keyword_idx: usize,
    source: &str,
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
        let inner = inner_literal_span(tokens[i].span, source);
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

fn is_skippable(t: &Token) -> bool {
    matches!(
        t.kind,
        TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
    )
}

fn next_non_trivia_idx(tokens: &[Token], from: usize) -> Option<usize> {
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

/// Starting one token after `keyword_idx`, look for `[=] <StringLiteral>`
/// and return the inner-content span (no surrounding quotes). Returns
/// `None` if the sequence doesn't match.
pub(crate) fn peek_string_literal_after(
    tokens: &[Token],
    keyword_idx: usize,
    source: &str,
) -> Option<Span> {
    let mut idx = next_non_trivia_idx(tokens, keyword_idx + 1)?;
    // Optional `=`.
    if matches!(tokens[idx].kind, TokenKind::Operator(Operator::Eq)) {
        idx = next_non_trivia_idx(tokens, idx + 1)?;
    }
    if !matches!(tokens[idx].kind, TokenKind::Literal(LiteralKind::String)) {
        return None;
    }
    Some(inner_literal_span(tokens[idx].span, source))
}

/// Strip outer `'…'` / `"…"` / `` `…` `` quotes from a token's span,
/// returning the inner content span. Returns the input span unchanged
/// if it isn't quoted (e.g., a numeric literal or bare identifier).
pub(crate) fn inner_literal_span(span: Span, source: &str) -> Span {
    let start = span.start as usize;
    let end = span.end as usize;
    if end > start + 1 {
        let bytes = source.as_bytes();
        let first = bytes[start];
        let last = bytes[end - 1];
        if (first == b'\'' && last == b'\'')
            || (first == b'"' && last == b'"')
            || (first == b'`' && last == b'`')
        {
            return Span {
                start: span.start + 1,
                end: span.end - 1,
            };
        }
    }
    span
}

/// Classify the MSSQL source clause that follows the principal name.
/// Re-exports the existing classifier from `mssql_statements.rs` so the
/// neutral parser can call into it without duplicating the lexeme
/// peek logic.
fn classify_mssql_principal_source(p: &mut Parser) -> AstMssqlPrincipalSource {
    p.classify_mssql_principal_source()
}
