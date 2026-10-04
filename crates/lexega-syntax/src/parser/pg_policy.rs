// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PostgreSQL POLICY statements (Row-Level Security).
//!
//! - CREATE POLICY name ON table [AS ...] [FOR ...] [TO ...] [USING (...)] [WITH CHECK (...)]
//! - ALTER POLICY name ON table { RENAME TO new_name | [TO ...] [USING (...)] [WITH CHECK (...)] }
//! - DROP POLICY [IF EXISTS] name ON table [CASCADE | RESTRICT]
//!
//! Token gotchas (verified via --debug-tokens):
//!   PERMISSIVE, RESTRICTIVE, PUBLIC, CURRENT_ROLE, SESSION_USER, CASCADE, RESTRICT → Identifier
//!   CURRENT_USER → Keyword(CurrentUser)
//!   WITH CHECK → two Keywords (With + Check)
//!   FOR command values (ALL, SELECT, INSERT, UPDATE, DELETE) → Keywords

use crate::ast::types::{
    AlterPgPolicyAction, AstAlterPgPolicy, AstCreatePgPolicy, AstDropPgPolicy, AstStmt,
    PgCascadeRestrict, PgPolicyCommand, PgPolicyPermissiveness, PgPolicyRole,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxAlterPgPolicyStmt, SyntaxCreatePgPolicyStmt, SyntaxDropPgPolicyStmt};

impl<'a> Parser<'a> {
    // =========================================================================
    // CREATE POLICY
    // =========================================================================

    /// Parse: CREATE POLICY name ON table_name
    ///     [ AS { PERMISSIVE | RESTRICTIVE } ]
    ///     [ FOR { ALL | SELECT | INSERT | UPDATE | DELETE } ]
    ///     [ TO { role_name | PUBLIC | CURRENT_USER | ... } [, ...] ]
    ///     [ USING ( using_expression ) ]
    ///     [ WITH CHECK ( check_expression ) ]
    pub(crate) fn try_parse_create_pg_policy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_pg_policy")?;

        // CREATE
        let create_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["CREATE".to_string()])
        })?;
        let create_token_id = self.last_token_id();
        let start = create_tok.span.start;

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["POLICY".to_string()])
        })?;
        let policy_token_id = self.last_token_id();
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected POLICY, found '{}'",
                        policy_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Policy name (simple identifier)
        let policy_name = self.parse_pg_policy_identifier()?;

        // ON
        self.expect_keyword(Keyword::On)?;

        // table_name (possibly schema-qualified: schema.table)
        let table_name = self.parse_pg_policy_qualified_name()?;

        // Optional clauses - all order-sensitive per PG grammar
        let mut permissiveness: Option<(PgPolicyPermissiveness, Span)> = None;
        let mut command: Option<(PgPolicyCommand, Span)> = None;
        let mut for_span: Option<Span> = None;
        let mut roles: Vec<PgPolicyRole> = Vec::new();
        let mut to_span: Option<Span> = None;
        let mut using_expr: Option<Box<crate::ast::types::AstExpr>> = None;
        let mut using_span: Option<Span> = None;
        let mut check_expr: Option<Box<crate::ast::types::AstExpr>> = None;
        let mut with_check_span: Option<Span> = None;
        let mut end = table_name.end;

        // [ AS { PERMISSIVE | RESTRICTIVE } ]
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
                let perm_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["PERMISSIVE".to_string(), "RESTRICTIVE".to_string()],
                    )
                })?;
                let lex = perm_tok.lexeme(self.source);
                let kind = if lex.eq_ignore_ascii_case("PERMISSIVE") {
                    PgPolicyPermissiveness::Permissive
                } else if lex.eq_ignore_ascii_case("RESTRICTIVE") {
                    PgPolicyPermissiveness::Restrictive
                } else {
                    return Err(ParseError::new(
                        perm_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: format!("Expected PERMISSIVE or RESTRICTIVE, found '{}'", lex),
                        },
                    ));
                };
                let span = Span {
                    start: as_tok.span.start,
                    end: perm_tok.span.end,
                };
                permissiveness = Some((kind, span));
                end = perm_tok.span.end;
            }
        }

        // [ FOR { ALL | SELECT | INSERT | UPDATE | DELETE } ]
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::For)) {
                let for_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?;
                for_span = Some(for_tok.span);
                let cmd_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["ALL".to_string(), "SELECT".to_string()],
                    )
                })?;
                let cmd = match cmd_tok.kind {
                    TokenKind::Keyword(Keyword::All) => PgPolicyCommand::All,
                    TokenKind::Keyword(Keyword::Select) => PgPolicyCommand::Select,
                    TokenKind::Keyword(Keyword::Insert) => PgPolicyCommand::Insert,
                    TokenKind::Keyword(Keyword::Update) => PgPolicyCommand::Update,
                    TokenKind::Keyword(Keyword::Delete) => PgPolicyCommand::Delete,
                    _ => {
                        return Err(ParseError::new(
                            cmd_tok.span,
                            ParseErrorKind::InvalidSyntax {
                                message: format!(
                                    "Expected ALL, SELECT, INSERT, UPDATE, or DELETE after FOR, found '{}'",
                                    cmd_tok.lexeme(self.source)
                                ),
                            },
                        ));
                    }
                };
                let cmd_span = Span {
                    start: for_tok.span.start,
                    end: cmd_tok.span.end,
                };
                command = Some((cmd, cmd_span));
                end = cmd_tok.span.end;
            }
        }

        // [ TO { role_name | PUBLIC | CURRENT_USER | ... } [, ...] ]
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::To)) {
                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                to_span = Some(to_tok.span);
                let (parsed_roles, last_end) = self.parse_pg_policy_role_list()?;
                roles = parsed_roles;
                end = last_end;
            }
        }

        // [ USING ( using_expression ) ]
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let (expr, span) = self.parse_pg_policy_paren_expr("USING")?;
                using_expr = Some(Box::new(expr));
                using_span = Some(span);
                end = span.end;
            }
        }

        // [ WITH CHECK ( check_expression ) ]
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let (expr, span) = self.parse_pg_policy_with_check()?;
                check_expr = Some(Box::new(expr));
                with_check_span = Some(span);
                end = span.end;
            }
        }

        let stmt_span = Span { start, end };

        // Build CST
        let syntax_id = self
            .syntax_arena
            .alloc_create_pg_policy_stmt(SyntaxCreatePgPolicyStmt {
                create_keyword: create_token_id,
                policy_keyword: policy_token_id,
                span: stmt_span,
            });

        let ast = AstCreatePgPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            policy_name,
            table_name,
            permissiveness,
            command,
            for_span,
            roles,
            to_span,
            using_expr,
            using_span,
            check_expr,
            with_check_span,
        };
        Ok(AstStmt::CreatePgPolicy(Box::new(ast)))
    }

    // =========================================================================
    // ALTER POLICY
    // =========================================================================

    /// Parse: ALTER POLICY name ON table_name { RENAME TO new_name | ... }
    pub(crate) fn try_parse_alter_pg_policy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_pg_policy")?;

        // ALTER
        let alter_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["ALTER".to_string()])
        })?;
        let alter_token_id = self.last_token_id();
        let start = alter_tok.span.start;

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["POLICY".to_string()])
        })?;
        let policy_token_id = self.last_token_id();
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected POLICY, found '{}'",
                        policy_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Policy name
        let policy_name = self.parse_pg_policy_identifier()?;

        // ON
        self.expect_keyword(Keyword::On)?;

        // table_name
        let table_name = self.parse_pg_policy_qualified_name()?;

        // Determine action: RENAME TO or modify (TO/USING/WITH CHECK)
        let mut end = table_name.end;

        let action = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Rename)) {
                // RENAME TO new_name
                let rename_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
                let to_span = self.expect_keyword(Keyword::To)?;
                let new_name = self.parse_pg_policy_identifier()?;
                end = new_name.end;
                AlterPgPolicyAction::Rename {
                    rename_span: rename_tok.span,
                    to_span,
                    new_name,
                }
            } else {
                // Modify form: [TO ...] [USING (...)] [WITH CHECK (...)]
                let mut roles: Vec<PgPolicyRole> = Vec::new();
                let mut mod_to_span: Option<Span> = None;
                let mut using_expr: Option<Box<crate::ast::types::AstExpr>> = None;
                let mut mod_using_span: Option<Span> = None;
                let mut check_expr: Option<Box<crate::ast::types::AstExpr>> = None;
                let mut mod_with_check_span: Option<Span> = None;

                // [ TO { role_name | PUBLIC | ... } [, ...] ]
                if let Some(t) = self.peek() {
                    if matches!(t.kind, TokenKind::Keyword(Keyword::To)) {
                        let to_tok = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                        mod_to_span = Some(to_tok.span);
                        let (parsed_roles, last_end) = self.parse_pg_policy_role_list()?;
                        roles = parsed_roles;
                        end = last_end;
                    }
                }

                // [ USING ( expr ) ]
                if let Some(t) = self.peek() {
                    if matches!(t.kind, TokenKind::Keyword(Keyword::Using)) {
                        let (expr, span) = self.parse_pg_policy_paren_expr("USING")?;
                        using_expr = Some(Box::new(expr));
                        mod_using_span = Some(span);
                        end = span.end;
                    }
                }

                // [ WITH CHECK ( expr ) ]
                if let Some(t) = self.peek() {
                    if matches!(t.kind, TokenKind::Keyword(Keyword::With)) {
                        let (expr, span) = self.parse_pg_policy_with_check()?;
                        check_expr = Some(Box::new(expr));
                        mod_with_check_span = Some(span);
                        end = span.end;
                    }
                }

                AlterPgPolicyAction::Modify {
                    roles,
                    to_span: mod_to_span,
                    using_expr,
                    using_span: mod_using_span,
                    check_expr,
                    with_check_span: mod_with_check_span,
                }
            }
        } else {
            // Empty ALTER POLICY (just name ON table, no action)
            AlterPgPolicyAction::Modify {
                roles: Vec::new(),
                to_span: None,
                using_expr: None,
                using_span: None,
                check_expr: None,
                with_check_span: None,
            }
        };

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_alter_pg_policy_stmt(SyntaxAlterPgPolicyStmt {
                alter_keyword: alter_token_id,
                policy_keyword: policy_token_id,
                span: stmt_span,
            });

        let ast = AstAlterPgPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            policy_name,
            table_name,
            action,
        };
        Ok(AstStmt::AlterPgPolicy(Box::new(ast)))
    }

    // =========================================================================
    // DROP POLICY
    // =========================================================================

    /// Parse: DROP POLICY [IF EXISTS] name ON table_name [CASCADE | RESTRICT]
    pub(crate) fn try_parse_drop_pg_policy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_pg_policy")?;

        // DROP
        let drop_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["DROP".to_string()])
        })?;
        let drop_token_id = self.last_token_id();
        let start = drop_tok.span.start;

        // POLICY
        let policy_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["POLICY".to_string()])
        })?;
        let policy_token_id = self.last_token_id();
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected POLICY, found '{}'",
                        policy_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // [IF EXISTS]
        let mut if_exists = false;
        let mut if_keyword_id: Option<crate::cst::TokenId> = None;
        let mut exists_keyword_id: Option<crate::cst::TokenId> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let _if_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["IF".to_string()])?;
                if_keyword_id = Some(self.last_token_id());
                let exists_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["EXISTS".to_string()])
                })?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: format!(
                                "Expected EXISTS after IF, found '{}'",
                                exists_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                exists_keyword_id = Some(self.last_token_id());
                if_exists = true;
            }
        }

        // Policy name
        let policy_name = self.parse_pg_policy_identifier()?;

        // ON
        self.expect_keyword(Keyword::On)?;

        // table_name
        let table_name = self.parse_pg_policy_qualified_name()?;
        let mut end = table_name.end;

        // [CASCADE | RESTRICT]
        let mut cascade_restrict: Option<PgCascadeRestrict> = None;
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lex = tok.lexeme(self.source);
                if lex.eq_ignore_ascii_case("CASCADE") {
                    let cr_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                    end = cr_tok.span.end;
                } else if lex.eq_ignore_ascii_case("RESTRICT") {
                    let cr_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                    end = cr_tok.span.end;
                }
            }
        }

        let stmt_span = Span { start, end };

        let syntax_id = self
            .syntax_arena
            .alloc_drop_pg_policy_stmt(SyntaxDropPgPolicyStmt {
                drop_keyword: drop_token_id,
                policy_keyword: policy_token_id,
                if_keyword: if_keyword_id,
                exists_keyword: exists_keyword_id,
                span: stmt_span,
            });

        let ast = AstDropPgPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            if_exists,
            policy_name,
            table_name,
            cascade_restrict,
        };
        Ok(AstStmt::DropPgPolicy(Box::new(ast)))
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Parse a simple identifier (for policy names, role names).
    /// Accepts both Identifiers and Keywords used in identifier position.
    fn parse_pg_policy_identifier(&mut self) -> ParseResult<Span> {
        let tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["identifier".to_string()])
        })?;
        match &tok.kind {
            TokenKind::Identifier { .. } => Ok(tok.span),
            TokenKind::Keyword(_) => {
                // Keywords used as identifiers in PG (e.g., policy named "restrict")
                Ok(tok.span)
            }
            _ => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected identifier, found '{}'", tok.lexeme(self.source)),
                },
            )),
        }
    }

    /// Parse a possibly schema-qualified name: [schema.]name
    fn parse_pg_policy_qualified_name(&mut self) -> ParseResult<Span> {
        let first = self.parse_pg_policy_identifier()?;
        let mut end = first.end;

        // Check for dot (schema qualification)
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                let _dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![".".to_string()])?;
                let second = self.parse_pg_policy_identifier()?;
                end = second.end;
            }
        }

        Ok(Span {
            start: first.start,
            end,
        })
    }

    /// Parse a comma-separated list of role specifications.
    /// Roles can be: identifier, PUBLIC, CURRENT_USER, CURRENT_ROLE, SESSION_USER
    fn parse_pg_policy_role_list(&mut self) -> ParseResult<(Vec<PgPolicyRole>, u32)> {
        let mut roles = Vec::new();
        let mut last_end;

        // Parse first role
        let first_span = self.parse_pg_policy_role_spec()?;
        last_end = first_span.end;
        roles.push(PgPolicyRole { span: first_span });

        // Parse additional comma-separated roles
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                let _comma = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![",".to_string()])?;
                let role_span = self.parse_pg_policy_role_spec()?;
                last_end = role_span.end;
                roles.push(PgPolicyRole { span: role_span });
            } else {
                break;
            }
        }

        Ok((roles, last_end))
    }

    /// Parse a single role specification.
    /// Can be: regular identifier, PUBLIC (Identifier), CURRENT_USER (Keyword),
    ///         CURRENT_ROLE (Identifier), SESSION_USER (Identifier)
    fn parse_pg_policy_role_spec(&mut self) -> ParseResult<Span> {
        let tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["role name".to_string()])
        })?;
        match &tok.kind {
            TokenKind::Identifier { .. } => Ok(tok.span),
            // CURRENT_USER is a Keyword
            TokenKind::Keyword(Keyword::CurrentUser) => Ok(tok.span),
            // Other keywords used as role names (e.g., policy might use a keyword as role name)
            TokenKind::Keyword(_) => Ok(tok.span),
            _ => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected role name, found '{}'", tok.lexeme(self.source)),
                },
            )),
        }
    }

    /// Parse a keyword followed by a parenthesized expression: KEYWORD ( expr )
    /// Returns the parsed expression and the full span (from keyword to closing paren).
    fn parse_pg_policy_paren_expr(
        &mut self,
        keyword_name: &str,
    ) -> ParseResult<(crate::ast::types::AstExpr, Span)> {
        // Consume the keyword (e.g., USING)
        let kw_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![keyword_name.to_string()])
        })?;
        let start = kw_tok.span.start;

        // Expect (
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
        })?;
        if !matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lp.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected '(' after {}, found '{}'",
                        keyword_name,
                        lp.lexeme(self.source)
                    ),
                },
            ));
        }

        // Parse expression
        let expr = self.parse_expr()?;

        // Expect )
        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(rp.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rp.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected ')' after {} expression, found '{}'",
                        keyword_name,
                        rp.lexeme(self.source)
                    ),
                },
            ));
        }

        let span = Span {
            start,
            end: rp.span.end,
        };
        Ok((expr, span))
    }

    /// Parse WITH CHECK ( expr ) — two-keyword compound.
    fn parse_pg_policy_with_check(&mut self) -> ParseResult<(crate::ast::types::AstExpr, Span)> {
        // WITH
        let with_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["WITH".to_string()])
        })?;
        let start = with_tok.span.start;
        if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
            return Err(ParseError::new(
                with_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!("Expected WITH, found '{}'", with_tok.lexeme(self.source)),
                },
            ));
        }

        // CHECK
        let check_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["CHECK".to_string()])
        })?;
        if !matches!(check_tok.kind, TokenKind::Keyword(Keyword::Check)) {
            return Err(ParseError::new(
                check_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected CHECK after WITH, found '{}'",
                        check_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // ( expr )
        let lp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
        })?;
        if !matches!(lp.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lp.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected '(' after WITH CHECK, found '{}'",
                        lp.lexeme(self.source)
                    ),
                },
            ));
        }

        let expr = self.parse_expr()?;

        let rp = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
        })?;
        if !matches!(rp.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rp.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected ')' after WITH CHECK expression, found '{}'",
                        rp.lexeme(self.source)
                    ),
                },
            ));
        }

        let span = Span {
            start,
            end: rp.span.end,
        };
        Ok((expr, span))
    }
}
