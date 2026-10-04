// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL `SET` statement family parser.
//!
//! MySQL overloads `SET` heavily. This module dispatches on the token(s)
//! after `SET` into one typed [`AstMysqlSet`] node:
//!
//! - Variable assignment: `SET t = e [, t = e] ...` where `t` is a user
//!   variable (`@v`), an `@@[scope.]` system variable, or a `[GLOBAL |
//!   SESSION | LOCAL] name` system variable; operator `=` or `:=`. The
//!   right-hand side stays a fully parsed expression so concatenation-built
//!   dynamic SQL (`SET @sql := CONCAT(...)`) is visible to consumers.
//! - Keyword-led forms: `NAMES`, `CHARACTER SET` / `CHARSET`, `PASSWORD`,
//!   `ROLE`, `DEFAULT ROLE`, `[GLOBAL | SESSION] TRANSACTION`.
//!
//! Token shapes:
//! - `:=` → Operator(ColonEq); `=` → Operator(Eq)
//! - `@x` / `@@session` / `@@sql_mode` → Identifier{AtVariable}
//! - GLOBAL/LOCAL/DEFAULT/FOR/TRANSACTION → keywords
//! - SESSION/NAMES/CHARACTER/CHARSET/PASSWORD/ROLE → identifiers

use crate::ast::types::{
    AstMysqlRoleSpec, AstMysqlSet, AstMysqlSetAssignment, AstMysqlSetCharacterSet,
    AstMysqlSetDefaultRole, AstMysqlSetKind, AstMysqlSetNames, AstMysqlSetPassword,
    AstMysqlSetRole, AstMysqlSetTarget, AstMysqlSetTransaction, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mysql_set_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_set")?;

        let set_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
        let set_span = set_tok.span;
        let start = set_span.start;

        let kind = self.parse_mysql_set_kind(start)?;

        let end = self.mysql_set_kind_end(&kind, set_span.end);
        let ast = AstMysqlSet {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            set_span,
            kind,
            semicolon_token: None,
        };
        Ok(AstStmt::MysqlSet(Box::new(ast)))
    }

    /// Classify and parse the SET form from the token(s) after `SET`.
    fn parse_mysql_set_kind(&mut self, start: u32) -> ParseResult<AstMysqlSetKind> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected a target after SET".to_string(),
                },
            )
        })?;
        let lex = tok.lexeme(self.source);

        if lex.eq_ignore_ascii_case("NAMES") {
            return Ok(AstMysqlSetKind::Names(Box::new(self.parse_set_names()?)));
        }
        if lex.eq_ignore_ascii_case("CHARSET") || lex.eq_ignore_ascii_case("CHARACTER") {
            return Ok(AstMysqlSetKind::CharacterSet(Box::new(
                self.parse_set_character_set()?,
            )));
        }
        if lex.eq_ignore_ascii_case("PASSWORD") {
            return Ok(AstMysqlSetKind::Password(Box::new(
                self.parse_set_password()?,
            )));
        }
        if lex.eq_ignore_ascii_case("ROLE") {
            return Ok(AstMysqlSetKind::Role(Box::new(self.parse_set_role()?)));
        }
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
            // DEFAULT ROLE — distinguished from a `= DEFAULT` value because
            // DEFAULT can never begin an assignment target.
            return Ok(AstMysqlSetKind::DefaultRole(Box::new(
                self.parse_set_default_role()?,
            )));
        }
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction)) {
            return Ok(AstMysqlSetKind::Transaction(Box::new(
                self.parse_set_transaction(None)?,
            )));
        }
        // A leading GLOBAL/SESSION/LOCAL marker preceding TRANSACTION is the
        // transaction form; otherwise it is a scoped system-variable
        // assignment (handled inside the assignment loop, where scope is
        // per-target).
        if self.peek_is_scope_marker() {
            let after_scope_is_txn = self
                .peek_ahead(1)
                .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Transaction)))
                .unwrap_or(false);
            if after_scope_is_txn {
                let scope_span = self.consume_one_token_span();
                return Ok(AstMysqlSetKind::Transaction(Box::new(
                    self.parse_set_transaction(scope_span)?,
                )));
            }
        }

        Ok(AstMysqlSetKind::Assignments(
            self.parse_set_assignments(start)?,
        ))
    }

    // -- assignment form ----------------------------------------------------

    fn parse_set_assignments(&mut self, _start: u32) -> ParseResult<Vec<AstMysqlSetAssignment>> {
        let mut out = Vec::new();
        loop {
            let assignment = self.parse_one_set_assignment()?;
            out.push(assignment);
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma, continue
                    continue;
                }
            }
            break;
        }
        Ok(out)
    }

    fn parse_one_set_assignment(&mut self) -> ParseResult<AstMysqlSetAssignment> {
        let target = self.parse_set_target()?;
        let target_start = mysql_set_target_span(&target).start;

        let op_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected '=' or ':=' in SET assignment".to_string(),
                },
            )
        })?;
        let assign_op_span = match op_tok.kind {
            TokenKind::Operator(Operator::Eq) | TokenKind::Operator(Operator::ColonEq) => {
                op_tok.span
            }
            _ => {
                return Err(ParseError::new(
                    op_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected '=' or ':=' in SET assignment, found {}",
                            Parser::token_description(op_tok, self.source)
                        ),
                    },
                ));
            }
        };
        self.advance(); // consume operator

        let value = crate::parser::scripting::try_parse_expr_scripting(self)?;
        let end = crate::parser::scripting::expr_span_end(&value);

        Ok(AstMysqlSetAssignment {
            node_id: self.id_gen.next(),
            target,
            assign_op_span,
            value: Box::new(value),
            span: Span {
                start: target_start,
                end,
            },
        })
    }

    fn parse_set_target(&mut self) -> ParseResult<AstMysqlSetTarget> {
        // Optional GLOBAL/SESSION/LOCAL scope (per-target). Only a scope
        // marker when not itself the assignment target (i.e. the token after
        // it is not an assignment operator).
        let scope_span = if self.peek_is_scope_marker() && !self.scope_marker_is_bare_target() {
            self.consume_one_token_span()
        } else {
            None
        };

        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected variable name in SET assignment".to_string(),
                },
            )
        })?;

        if scope_span.is_some() {
            // Scoped system variable: parse a (possibly dotted) name.
            let name_span = self.consume_dotted_name_span();
            return Ok(AstMysqlSetTarget::System {
                scope_span,
                name_span,
            });
        }

        // `@@...` system variable vs `@user` variable: both lex as
        // AtVariable; distinguish on the `@@` prefix.
        if matches!(tok.kind, TokenKind::Identifier { kind } if kind == crate::lexer::IdentifierKind::AtVariable)
        {
            let is_system = tok.lexeme(self.source).starts_with("@@");
            let name_span = self.consume_dotted_name_span();
            return Ok(if is_system {
                AstMysqlSetTarget::SystemAtAt { name_span }
            } else {
                AstMysqlSetTarget::UserVar { name_span }
            });
        }

        // Bare system variable name.
        let name_span = self.consume_dotted_name_span();
        Ok(AstMysqlSetTarget::System {
            scope_span: None,
            name_span,
        })
    }

    /// Consume one name token plus any `.subname` continuation
    /// (`@@session.sql_mode`), returning the covered span.
    fn consume_dotted_name_span(&mut self) -> Span {
        let first = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());
        let mut end = first.end;
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // dot
                if let Some(part) = self.advance() {
                    end = part.span.end;
                    continue;
                }
            }
            break;
        }
        Span {
            start: first.start,
            end,
        }
    }

    // -- scope-marker helpers ----------------------------------------------

    fn peek_is_scope_marker(&mut self) -> bool {
        match self.peek_non_trivia() {
            Some(tok) => {
                let lex = tok.lexeme(self.source);
                matches!(
                    tok.kind,
                    TokenKind::Keyword(Keyword::Global | Keyword::Local)
                ) || (matches!(tok.kind, TokenKind::Identifier { .. })
                    && (lex.eq_ignore_ascii_case("SESSION")
                        || lex.eq_ignore_ascii_case("GLOBAL")
                        || lex.eq_ignore_ascii_case("LOCAL")))
            }
            None => false,
        }
    }

    /// True when the scope-looking word is actually the assignment target
    /// itself (the token after it is an assignment operator).
    fn scope_marker_is_bare_target(&mut self) -> bool {
        self.peek_ahead(1)
            .map(|t| {
                matches!(
                    t.kind,
                    TokenKind::Operator(Operator::Eq) | TokenKind::Operator(Operator::ColonEq)
                )
            })
            .unwrap_or(false)
    }

    fn consume_one_token_span(&mut self) -> Option<Span> {
        self.advance().map(|t| t.span)
    }

    // -- keyword-led forms --------------------------------------------------

    fn parse_set_names(&mut self) -> ParseResult<AstMysqlSetNames> {
        let names_span = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());
        let mut default_span = None;
        let mut charset_span = None;
        let mut collate_span = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                default_span = self.consume_one_token_span();
            } else {
                charset_span = self.consume_one_token_span();
                if let Some(next) = self.peek_non_trivia() {
                    if next.lexeme(self.source).eq_ignore_ascii_case("COLLATE") {
                        let collate_start = next.span.start;
                        self.advance(); // COLLATE
                        let collate_end =
                            self.advance().map(|t| t.span.end).unwrap_or(collate_start);
                        collate_span = Some(Span {
                            start: collate_start,
                            end: collate_end,
                        });
                    }
                }
            }
        }

        Ok(AstMysqlSetNames {
            names_span,
            default_span,
            charset_span,
            collate_span,
        })
    }

    fn parse_set_character_set(&mut self) -> ParseResult<AstMysqlSetCharacterSet> {
        let first = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());
        let mut keyword_end = first.end;
        // `CHARACTER SET` is two tokens; `CHARSET` is one.
        if self
            .source
            .get(first.start as usize..first.end as usize)
            .map(|s| s.eq_ignore_ascii_case("CHARACTER"))
            .unwrap_or(false)
        {
            if let Some(set_tok) = self.peek_non_trivia() {
                if matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set))
                    || set_tok.lexeme(self.source).eq_ignore_ascii_case("SET")
                {
                    keyword_end = set_tok.span.end;
                    self.advance(); // SET
                }
            }
        }
        let keyword_span = Span {
            start: first.start,
            end: keyword_end,
        };

        let mut default_span = None;
        let mut charset_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                default_span = self.consume_one_token_span();
            } else {
                charset_span = self.consume_one_token_span();
            }
        }

        Ok(AstMysqlSetCharacterSet {
            keyword_span,
            default_span,
            charset_span,
        })
    }

    fn parse_set_password(&mut self) -> ParseResult<AstMysqlSetPassword> {
        let password_span = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());

        // Optional `FOR user` — capture the span from FOR up to the `=`.
        let mut for_user_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::For)) {
                let for_start = tok.span.start;
                self.advance(); // FOR
                let mut for_end = for_start;
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(t.kind, TokenKind::Operator(Operator::Eq))
                        || matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi))
                        || matches!(t.kind, TokenKind::Eof)
                    {
                        break;
                    }
                    if let Some(c) = self.advance() {
                        for_end = c.span.end;
                    } else {
                        break;
                    }
                }
                for_user_span = Some(Span {
                    start: for_start,
                    end: for_end,
                });
            }
        }

        let op_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected '=' in SET PASSWORD".to_string(),
                },
            )
        })?;
        if !matches!(op_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                op_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected '=' in SET PASSWORD, found {}",
                        Parser::token_description(op_tok, self.source)
                    ),
                },
            ));
        }
        let assign_op_span = op_tok.span;
        self.advance(); // =

        let value = crate::parser::scripting::try_parse_expr_scripting(self)?;

        Ok(AstMysqlSetPassword {
            password_span,
            for_user_span,
            assign_op_span,
            value: Box::new(value),
        })
    }

    fn parse_set_role(&mut self) -> ParseResult<AstMysqlSetRole> {
        let role_span = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());

        let spec = match self.peek_non_trivia() {
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("DEFAULT") => {
                AstMysqlRoleSpec::Default {
                    span: self.consume_one_token_span().unwrap_or(role_span),
                }
            }
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("NONE") => {
                AstMysqlRoleSpec::None {
                    span: self.consume_one_token_span().unwrap_or(role_span),
                }
            }
            Some(tok) if tok.lexeme(self.source).eq_ignore_ascii_case("ALL") => {
                let all_span = self.consume_one_token_span().unwrap_or(role_span);
                let except_roles_span = if let Some(next) = self.peek_non_trivia() {
                    if next.lexeme(self.source).eq_ignore_ascii_case("EXCEPT") {
                        let start = next.span.start;
                        self.advance(); // EXCEPT
                        let end = self.consume_to_stmt_end(start);
                        Some(Span { start, end })
                    } else {
                        None
                    }
                } else {
                    None
                };
                AstMysqlRoleSpec::All {
                    span: all_span,
                    except_roles_span,
                }
            }
            Some(tok) => {
                let start = tok.span.start;
                let end = self.consume_to_stmt_end(start);
                AstMysqlRoleSpec::Roles {
                    span: Span { start, end },
                }
            }
            None => AstMysqlRoleSpec::Roles { span: role_span },
        };

        Ok(AstMysqlSetRole { role_span, spec })
    }

    fn parse_set_default_role(&mut self) -> ParseResult<AstMysqlSetDefaultRole> {
        let default_span = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());
        let role_span = self.advance().map(|t| t.span).unwrap_or(default_span);

        // roles: NONE | ALL | role list — up to TO.
        let roles_start = self
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(role_span.end);
        let mut roles_end = roles_start;
        let mut to_span = Span {
            start: roles_start,
            end: roles_start,
        };
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::To))
                || tok.lexeme(self.source).eq_ignore_ascii_case("TO")
            {
                to_span = tok.span;
                self.advance(); // TO
                break;
            }
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                || matches!(tok.kind, TokenKind::Eof)
            {
                break;
            }
            if let Some(t) = self.advance() {
                roles_end = t.span.end;
            } else {
                break;
            }
        }
        let roles_span = Span {
            start: roles_start,
            end: roles_end,
        };

        let users_start = self
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(to_span.end);
        let users_end = self.consume_to_stmt_end(users_start);
        let users_span = Span {
            start: users_start,
            end: users_end,
        };

        Ok(AstMysqlSetDefaultRole {
            default_span,
            role_span,
            roles_span,
            to_span,
            users_span,
        })
    }

    fn parse_set_transaction(
        &mut self,
        scope_span: Option<Span>,
    ) -> ParseResult<AstMysqlSetTransaction> {
        let transaction_span = self
            .advance()
            .map(|t| t.span)
            .unwrap_or_else(|| self.current_span());
        let chars_start = self
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(transaction_span.end);
        let chars_end = self.consume_to_stmt_end(chars_start);
        Ok(AstMysqlSetTransaction {
            scope_span,
            transaction_span,
            characteristics_span: Span {
                start: chars_start,
                end: chars_end,
            },
        })
    }

    /// Consume significant tokens up to (not including) a top-level
    /// semicolon or EOF, returning the end position of the last consumed
    /// token. Parenthesised content is consumed wholesale.
    fn consume_to_stmt_end(&mut self, start: u32) -> u32 {
        let mut end = start;
        let mut depth: i32 = 0;
        while let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
            if let Some(t) = self.advance() {
                end = t.span.end;
            } else {
                break;
            }
        }
        end
    }

    fn mysql_set_kind_end(&self, kind: &AstMysqlSetKind, fallback: u32) -> u32 {
        match kind {
            AstMysqlSetKind::Assignments(list) => {
                list.last().map(|a| a.span.end).unwrap_or(fallback)
            }
            AstMysqlSetKind::Names(n) => n
                .collate_span
                .or(n.charset_span)
                .or(n.default_span)
                .map(|s| s.end)
                .unwrap_or(n.names_span.end),
            AstMysqlSetKind::CharacterSet(c) => c
                .charset_span
                .or(c.default_span)
                .map(|s| s.end)
                .unwrap_or(c.keyword_span.end),
            AstMysqlSetKind::Password(p) => crate::parser::scripting::expr_span_end(&p.value),
            AstMysqlSetKind::Role(r) => match &r.spec {
                AstMysqlRoleSpec::Default { span }
                | AstMysqlRoleSpec::None { span }
                | AstMysqlRoleSpec::Roles { span } => span.end,
                AstMysqlRoleSpec::All {
                    span,
                    except_roles_span,
                } => except_roles_span.map(|s| s.end).unwrap_or(span.end),
            },
            AstMysqlSetKind::DefaultRole(d) => d.users_span.end,
            AstMysqlSetKind::Transaction(t) => t.characteristics_span.end,
        }
    }
}

/// Span of just the variable name within a SET assignment target
/// (excludes any scope keyword) — the variable's identity, e.g. `@sql`.
pub fn mysql_set_target_name_span(target: &AstMysqlSetTarget) -> Span {
    match target {
        AstMysqlSetTarget::UserVar { name_span }
        | AstMysqlSetTarget::SystemAtAt { name_span }
        | AstMysqlSetTarget::System { name_span, .. } => *name_span,
    }
}

/// Span covering a SET assignment target.
pub(crate) fn mysql_set_target_span(target: &AstMysqlSetTarget) -> Span {
    match target {
        AstMysqlSetTarget::UserVar { name_span } | AstMysqlSetTarget::SystemAtAt { name_span } => {
            *name_span
        }
        AstMysqlSetTarget::System {
            scope_span,
            name_span,
        } => Span {
            start: scope_span.map(|s| s.start).unwrap_or(name_span.start),
            end: name_span.end,
        },
    }
}
