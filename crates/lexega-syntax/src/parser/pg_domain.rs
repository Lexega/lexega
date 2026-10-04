// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for PostgreSQL DOMAIN statements.
//!
//! - `CREATE DOMAIN name [AS] data_type [COLLATE collation] [DEFAULT expr] [constraint ...]`
//! - `ALTER DOMAIN name <action>` (9 action sub-forms)
//! - `DROP DOMAIN [IF EXISTS] name [, ...] [CASCADE | RESTRICT]`
//!
//! Token gotchas (verified via --debug-tokens):
//! - DOMAIN, COLLATE, ADD, VALIDATE, VALID, CASCADE, RESTRICT, SCHEMA,
//!   CURRENT_ROLE, SESSION_USER, VALUE, type names → all Identifier
//! - NULL → Literal(Null)
//! - AS is optional in CREATE DOMAIN

use crate::ast::types::{
    AlterDomainAction, AstAlterDomain, AstCreateDomain, AstDropDomain, AstStmt, DomainConstraint,
    DomainConstraintKind, PgCascadeRestrict,
};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{SyntaxAlterDomainStmt, SyntaxCreateDomainStmt, SyntaxDropDomainStmt};

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // CREATE DOMAIN name [AS] data_type
    //   [COLLATE collation]
    //   [DEFAULT expression]
    //   [domain_constraint ...]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_domain_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_domain")?;
        let start_span = self.current_span();

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_keyword = self.last_token_id();
        let start = create_tok.span.start;

        // DOMAIN (Identifier)
        let _domain_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DOMAIN".to_string()])?;
        let domain_keyword = self.last_token_id();

        // Domain name (possibly schema-qualified: schema.name)
        let name_start = self.current_span().start;
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["domain name".to_string()])?;
        let mut domain_name_end = name_tok.span.end;

        // Check for schema qualification (dot)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                let after_dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["domain name".to_string()])?;
                domain_name_end = after_dot.span.end;
            }
        }
        let domain_name = Span {
            start: name_start,
            end: domain_name_end,
        };

        // Optional AS keyword
        let mut as_keyword_span = None;
        let mut as_keyword_token = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
                as_keyword_span = Some(as_tok.span);
                as_keyword_token = Some(self.last_token_id());
            }
        }

        // Data type (use span-based approach: consume type name + optional precision/array)
        let data_type_span = self.parse_domain_data_type()?;
        let mut end = data_type_span.end;

        // Optional COLLATE collation
        let mut collate_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("COLLATE")
            {
                let collate_start = tok.span.start;
                self.advance(); // consume COLLATE
                                // collation name (possibly quoted)
                let coll_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["collation name".to_string()])?;
                end = coll_tok.span.end;
                collate_span = Some(Span {
                    start: collate_start,
                    end,
                });
            }
        }

        // Optional DEFAULT expression
        let mut default_expr = None;
        let mut default_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                let default_start = tok.span.start;
                self.advance(); // consume DEFAULT
                let expr = self.parse_expr()?;
                let expr_end = expr.span().end;
                end = expr_end;
                default_span = Some(Span {
                    start: default_start,
                    end: expr_end,
                });
                default_expr = Some(Box::new(expr));
            }
        }

        // Constraints: [CONSTRAINT name] { NOT NULL | NULL | CHECK (expr) }
        let mut constraints = Vec::new();
        loop {
            let idx_before = self.idx;
            if let Some(constraint) = self.try_parse_domain_constraint()? {
                end = constraint.span.end;
                constraints.push(constraint);
                if self.idx == idx_before {
                    break;
                }
            } else {
                break;
            }
        }

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_id = self
            .syntax_arena
            .alloc_create_domain_stmt(SyntaxCreateDomainStmt {
                create_keyword,
                domain_keyword,
                domain_name_span: domain_name,
                as_keyword: as_keyword_token,
                data_type_span,
                span: stmt_span,
            });

        // Build AST node
        let ast = AstCreateDomain {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            domain_name,
            as_keyword_span,
            data_type_span,
            collate_span,
            default_expr,
            default_span,
            constraints,
        };
        Ok(AstStmt::CreateDomain(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // ALTER DOMAIN name <action>
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_alter_domain_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_domain")?;
        let start_span = self.current_span();

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let alter_keyword = self.last_token_id();
        let start = alter_tok.span.start;

        // DOMAIN (Identifier)
        let _domain_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DOMAIN".to_string()])?;
        let domain_keyword = self.last_token_id();

        // Domain name (possibly schema-qualified)
        let name_start = self.current_span().start;
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["domain name".to_string()])?;
        let mut name_end = name_tok.span.end;

        // Check for schema qualification
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                let after_dot = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["domain name".to_string()])?;
                name_end = after_dot.span.end;
            }
        }
        let domain_name = Span {
            start: name_start,
            end: name_end,
        };

        // Parse the action
        let action = self.parse_alter_domain_action()?;
        let action_end = match &action {
            AlterDomainAction::SetDefault { span, .. }
            | AlterDomainAction::DropDefault { span }
            | AlterDomainAction::SetNotNull { span }
            | AlterDomainAction::DropNotNull { span }
            | AlterDomainAction::AddConstraint { span, .. }
            | AlterDomainAction::DropConstraint { span, .. }
            | AlterDomainAction::RenameConstraint { span, .. }
            | AlterDomainAction::ValidateConstraint { span, .. }
            | AlterDomainAction::OwnerTo { span, .. }
            | AlterDomainAction::RenameTo { span, .. }
            | AlterDomainAction::SetSchema { span, .. } => span.end,
        };

        let stmt_span = Span {
            start,
            end: action_end,
        };

        // Build CST node
        let syntax_id = self
            .syntax_arena
            .alloc_alter_domain_stmt(SyntaxAlterDomainStmt {
                alter_keyword,
                domain_keyword,
                domain_name_span: domain_name,
                span: stmt_span,
            });

        let ast = AstAlterDomain {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            domain_name,
            action,
        };
        Ok(AstStmt::AlterDomain(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // DROP DOMAIN [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_drop_domain_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_domain")?;
        let start_span = self.current_span();

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["DROP".to_string()])?;
        let drop_keyword = self.last_token_id();
        let start = drop_tok.span.start;

        // DOMAIN (Identifier)
        let _domain_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DOMAIN".to_string()])?;
        let domain_keyword = self.last_token_id();

        // Optional IF EXISTS
        let mut if_exists = false;
        let mut if_keyword_token = None;
        let mut exists_keyword_token = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance();
                if_keyword_token = Some(self.last_token_id());
                // EXISTS
                let _exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                exists_keyword_token = Some(self.last_token_id());
                if_exists = true;
            }
        }

        // Domain names (comma-separated, possibly schema-qualified)
        let mut domain_names = Vec::new();
        let parse_domain_name_span = |parser: &mut Parser<'a>| -> ParseResult<Span> {
            let name_start = parser.current_span().start;
            let name_tok = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec!["domain name".to_string()])?;
            let mut name_end = name_tok.span.end;

            if let Some(tok) = parser.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                    parser.advance(); // dot
                    let after_dot = parser
                        .advance()
                        .ok_or_eof(parser.current_span(), vec!["domain name".to_string()])?;
                    name_end = after_dot.span.end;
                }
            }

            Ok(Span {
                start: name_start,
                end: name_end,
            })
        };

        let first_name = parse_domain_name_span(self)?;
        let mut end = first_name.end;
        domain_names.push(first_name);

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance(); // consume comma
                let next_name = parse_domain_name_span(self)?;
                end = next_name.end;
                domain_names.push(next_name);
            } else {
                break;
            }
        }

        // Optional CASCADE | RESTRICT
        let mut cascade_restrict = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lexeme = tok.lexeme(self.source);
                if lexeme.eq_ignore_ascii_case("CASCADE") {
                    let cascade_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["CASCADE".to_string()])?;
                    end = cascade_tok.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Cascade);
                } else if lexeme.eq_ignore_ascii_case("RESTRICT") {
                    let restrict_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["RESTRICT".to_string()])?;
                    end = restrict_tok.span.end;
                    cascade_restrict = Some(PgCascadeRestrict::Restrict);
                }
            }
        }

        let stmt_span = Span { start, end };

        // Build CST node
        let syntax_id = self
            .syntax_arena
            .alloc_drop_domain_stmt(SyntaxDropDomainStmt {
                drop_keyword,
                domain_keyword,
                if_keyword: if_keyword_token,
                exists_keyword: exists_keyword_token,
                span: stmt_span,
            });

        let ast = AstDropDomain {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            if_exists,
            domain_names,
            cascade_restrict,
        };
        Ok(AstStmt::DropDomain(Box::new(ast)))
    }

    // -----------------------------------------------------------------------
    // Helper: Parse data type span for DOMAIN
    //
    // Consumes: type_name [( precision [, scale] )] [[] ...]
    // Returns the span covering the entire data type expression.
    // -----------------------------------------------------------------------

    fn parse_domain_data_type(&mut self) -> ParseResult<Span> {
        let start = self.current_span().start;

        // Type name token (Identifier: TEXT, INTEGER, VARCHAR, NUMERIC, etc.)
        let type_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["data type".to_string()])?;
        let mut end = type_tok.span.end;

        // Check for multi-word types like "DOUBLE PRECISION", "CHARACTER VARYING"
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                let lexeme = tok.lexeme(self.source);
                if lexeme.eq_ignore_ascii_case("PRECISION")
                    || lexeme.eq_ignore_ascii_case("VARYING")
                    || lexeme.eq_ignore_ascii_case("ZONE")
                {
                    let multi_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["type modifier".to_string()])?;
                    end = multi_tok.span.end;
                }
            }
        }

        // Optional precision/scale: (N) or (N, M)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                self.advance(); // consume (
                                // Consume everything until matching )
                let mut depth = 1u32;
                while depth > 0 {
                    let inner = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    match inner.kind {
                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                        _ => {}
                    }
                }
                end = self.tokens[self.idx - 1].span.end;
            }
        }

        // Optional array brackets: [] (can repeat)
        loop {
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LBracket)) {
                    self.advance(); // [
                    let rbracket = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["]".to_string()])?;
                    end = rbracket.span.end;
                    continue;
                }
            }
            break;
        }

        Ok(Span { start, end })
    }

    // -----------------------------------------------------------------------
    // Helper: Try to parse a single domain constraint
    //
    // [CONSTRAINT name] { NOT NULL | NULL | CHECK (expression) }
    // Returns None if no constraint is present.
    // -----------------------------------------------------------------------

    fn try_parse_domain_constraint(&mut self) -> ParseResult<Option<DomainConstraint>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };

        // Check what starts the constraint
        let has_constraint_keyword = matches!(tok.kind, TokenKind::Keyword(Keyword::Constraint));
        let is_not = matches!(tok.kind, TokenKind::Keyword(Keyword::Not));
        let is_null = matches!(
            tok.kind,
            TokenKind::Literal(crate::lexer::LiteralKind::Null)
        );
        let is_check = matches!(tok.kind, TokenKind::Keyword(Keyword::Check));

        if !has_constraint_keyword && !is_not && !is_null && !is_check {
            return Ok(None);
        }

        let constraint_start = tok.span.start;

        // Optional CONSTRAINT name
        let mut constraint_name = None;
        if has_constraint_keyword {
            self.advance(); // consume CONSTRAINT
            let name_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["constraint name".to_string()])?;
            constraint_name = Some(name_tok.span);
        }

        // Now determine the kind
        let kind_tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => {
                return Err(crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidStatement {
                        message: "Expected NOT NULL, NULL, or CHECK after CONSTRAINT name"
                            .to_string(),
                    },
                ));
            }
        };

        let kind = if matches!(kind_tok.kind, TokenKind::Keyword(Keyword::Not)) {
            // NOT NULL
            let not_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
            let null_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["NULL".to_string()])?;
            DomainConstraintKind::NotNull {
                span: Span {
                    start: not_tok.span.start,
                    end: null_tok.span.end,
                },
            }
        } else if matches!(
            kind_tok.kind,
            TokenKind::Literal(crate::lexer::LiteralKind::Null)
        ) {
            // NULL
            let null_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["NULL".to_string()])?;
            DomainConstraintKind::Null {
                span: null_tok.span,
            }
        } else if matches!(kind_tok.kind, TokenKind::Keyword(Keyword::Check)) {
            // CHECK (expression)
            let check_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["CHECK".to_string()])?;
            let check_start = check_tok.span.start;

            // Expect (
            let _lparen = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["(".to_string()])?;

            // Parse the expression inside the parens
            let expression = self.parse_expr()?;

            // Expect )
            let rparen = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            let check_end = rparen.span.end;

            DomainConstraintKind::Check {
                check_span: Span {
                    start: check_start,
                    end: check_end,
                },
                expression: Box::new(expression),
            }
        } else {
            return Err(crate::error::ParseError::new(
                kind_tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected NOT NULL, NULL, or CHECK, found '{}'",
                        kind_tok.lexeme(self.source)
                    ),
                },
            ));
        };

        let constraint_end = match &kind {
            DomainConstraintKind::NotNull { span } => span.end,
            DomainConstraintKind::Null { span } => span.end,
            DomainConstraintKind::Check { check_span, .. } => check_span.end,
        };

        Ok(Some(DomainConstraint {
            span: Span {
                start: constraint_start,
                end: constraint_end,
            },
            constraint_name,
            kind,
        }))
    }

    // -----------------------------------------------------------------------
    // Helper: Parse ALTER DOMAIN action
    //
    // Determines which of the 9 sub-forms we're in by peeking at the next
    // keyword/identifier.
    // -----------------------------------------------------------------------

    fn parse_alter_domain_action(&mut self) -> ParseResult<AlterDomainAction> {
        let tok = self.peek_non_trivia().ok_or_else(|| {
            crate::error::ParseError::unexpected_eof(
                self.current_span(),
                vec!["ALTER DOMAIN action".to_string()],
            )
        })?;

        match tok.kind {
            // SET DEFAULT / SET NOT NULL / SET SCHEMA
            TokenKind::Keyword(Keyword::Set) => {
                let set_tok = self.advance().ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
                let action_start = set_tok.span.start;

                let next = self.peek_non_trivia().ok_or_else(|| {
                    crate::error::ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["DEFAULT, NOT NULL, or SCHEMA".to_string()],
                    )
                })?;

                if matches!(next.kind, TokenKind::Keyword(Keyword::Default)) {
                    // SET DEFAULT expression
                    self.advance(); // consume DEFAULT
                    let expression = self.parse_expr()?;
                    let end = expression.span().end;
                    Ok(AlterDomainAction::SetDefault {
                        span: Span {
                            start: action_start,
                            end,
                        },
                        expression: Box::new(expression),
                    })
                } else if matches!(next.kind, TokenKind::Keyword(Keyword::Not)) {
                    // SET NOT NULL
                    self.advance(); // consume NOT
                    let null_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["NULL".to_string()])?;
                    Ok(AlterDomainAction::SetNotNull {
                        span: Span {
                            start: action_start,
                            end: null_tok.span.end,
                        },
                    })
                } else if matches!(next.kind, TokenKind::Identifier { .. })
                    && next.lexeme(self.source).eq_ignore_ascii_case("SCHEMA")
                {
                    // SET SCHEMA new_schema
                    self.advance(); // consume SCHEMA
                    let schema_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["schema name".to_string()])?;
                    Ok(AlterDomainAction::SetSchema {
                        span: Span {
                            start: action_start,
                            end: schema_tok.span.end,
                        },
                        new_schema: schema_tok.span,
                    })
                } else {
                    Err(crate::error::ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected DEFAULT, NOT NULL, or SCHEMA after SET, found '{}'",
                                next.lexeme(self.source)
                            ),
                        },
                    ))
                }
            }

            // DROP DEFAULT / DROP NOT NULL / DROP CONSTRAINT
            TokenKind::Keyword(Keyword::Drop) => {
                let drop_tok = self.advance().ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
                let action_start = drop_tok.span.start;

                let next = self.peek_non_trivia().ok_or_else(|| {
                    crate::error::ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["DEFAULT, NOT NULL, or CONSTRAINT".to_string()],
                    )
                })?;

                if matches!(next.kind, TokenKind::Keyword(Keyword::Default)) {
                    // DROP DEFAULT
                    let default_tok = self.advance().ok_or_eof(self.current_span(), vec!["DEFAULT".to_string()])?;
                    Ok(AlterDomainAction::DropDefault {
                        span: Span {
                            start: action_start,
                            end: default_tok.span.end,
                        },
                    })
                } else if matches!(next.kind, TokenKind::Keyword(Keyword::Not)) {
                    // DROP NOT NULL
                    self.advance(); // consume NOT
                    let null_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["NULL".to_string()])?;
                    Ok(AlterDomainAction::DropNotNull {
                        span: Span {
                            start: action_start,
                            end: null_tok.span.end,
                        },
                    })
                } else if matches!(next.kind, TokenKind::Keyword(Keyword::Constraint)) {
                    // DROP CONSTRAINT [IF EXISTS] name [RESTRICT | CASCADE]
                    self.advance(); // consume CONSTRAINT

                    // Optional IF EXISTS
                    let mut if_exists = false;
                    if let Some(peek) = self.peek_non_trivia() {
                        if matches!(peek.kind, TokenKind::Keyword(Keyword::If)) {
                            self.advance(); // IF
                            self.advance(); // EXISTS
                            if_exists = true;
                        }
                    }

                    let name_tok = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["constraint name".to_string()],
                    )?;
                    let constraint_name = name_tok.span;
                    let mut end = name_tok.span.end;

                    // Optional CASCADE | RESTRICT
                    let mut cascade_restrict = None;
                    if let Some(peek) = self.peek_non_trivia() {
                        if matches!(peek.kind, TokenKind::Identifier { .. }) {
                            let lex = peek.lexeme(self.source);
                            if lex.eq_ignore_ascii_case("CASCADE") {
                                self.advance();
                                end = self.tokens[self.idx - 1].span.end;
                                cascade_restrict = Some(PgCascadeRestrict::Cascade);
                            } else if lex.eq_ignore_ascii_case("RESTRICT") {
                                self.advance();
                                end = self.tokens[self.idx - 1].span.end;
                                cascade_restrict = Some(PgCascadeRestrict::Restrict);
                            }
                        }
                    }

                    Ok(AlterDomainAction::DropConstraint {
                        span: Span {
                            start: action_start,
                            end,
                        },
                        if_exists,
                        constraint_name,
                        cascade_restrict,
                    })
                } else {
                    Err(crate::error::ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected DEFAULT, NOT NULL, or CONSTRAINT after DROP, found '{}'",
                                next.lexeme(self.source)
                            ),
                        },
                    ))
                }
            }

            // RENAME TO / RENAME CONSTRAINT
            TokenKind::Keyword(Keyword::Rename) => {
                let rename_tok = self.advance().ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?;
                let action_start = rename_tok.span.start;

                let next = self.peek_non_trivia().ok_or_else(|| {
                    crate::error::ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["TO or CONSTRAINT".to_string()],
                    )
                })?;

                if matches!(next.kind, TokenKind::Keyword(Keyword::To)) {
                    // RENAME TO new_name
                    self.advance(); // consume TO
                    let new_name_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["new name".to_string()])?;
                    Ok(AlterDomainAction::RenameTo {
                        span: Span {
                            start: action_start,
                            end: new_name_tok.span.end,
                        },
                        new_name: new_name_tok.span,
                    })
                } else if matches!(next.kind, TokenKind::Keyword(Keyword::Constraint)) {
                    // RENAME CONSTRAINT old_name TO new_name
                    self.advance(); // consume CONSTRAINT
                    let old_name_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["constraint name".to_string()])?;
                    let old_name = old_name_tok.span;

                    // TO
                    self.advance()
                        .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;

                    let new_name_tok = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["new constraint name".to_string()],
                    )?;
                    let new_name = new_name_tok.span;

                    Ok(AlterDomainAction::RenameConstraint {
                        span: Span {
                            start: action_start,
                            end: new_name.end,
                        },
                        old_name,
                        new_name,
                    })
                } else {
                    Err(crate::error::ParseError::new(
                        next.span,
                        crate::error::ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected TO or CONSTRAINT after RENAME, found '{}'",
                                next.lexeme(self.source)
                            ),
                        },
                    ))
                }
            }

            // OWNER TO
            TokenKind::Keyword(Keyword::Owner) => {
                let owner_tok = self.advance().ok_or_eof(self.current_span(), vec!["OWNER".to_string()])?;
                let action_start = owner_tok.span.start;

                // TO
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;

                // new_owner | CURRENT_ROLE | CURRENT_USER | SESSION_USER
                let owner_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["owner name".to_string()])?;
                Ok(AlterDomainAction::OwnerTo {
                    span: Span {
                        start: action_start,
                        end: owner_tok.span.end,
                    },
                    new_owner: owner_tok.span,
                })
            }

            // ADD [CONSTRAINT name] { NOT NULL | CHECK (expr) } [NOT VALID]
            TokenKind::Identifier { .. }
                if tok.lexeme(self.source).eq_ignore_ascii_case("ADD") =>
            {
                let add_tok = self.advance().ok_or_eof(self.current_span(), vec!["ADD".to_string()])?;
                let action_start = add_tok.span.start;

                // Parse the constraint
                let constraint = self.try_parse_domain_constraint()?.ok_or_else(|| {
                    crate::error::ParseError::new(
                        self.current_span(),
                        crate::error::ParseErrorKind::InvalidStatement {
                            message:
                                "Expected CONSTRAINT, NOT NULL, or CHECK after ADD".to_string(),
                        },
                    )
                })?;

                let mut end = constraint.span.end;

                // Optional NOT VALID
                let mut not_valid = false;
                if let Some(peek) = self.peek_non_trivia() {
                    if matches!(peek.kind, TokenKind::Keyword(Keyword::Not)) {
                        // Check if next after NOT is VALID (Identifier)
                        let saved = self.idx;
                        self.advance(); // consume NOT
                        if let Some(valid_tok) = self.peek_non_trivia() {
                            if matches!(valid_tok.kind, TokenKind::Identifier { .. })
                                && valid_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("VALID")
                            {
                                let v = self.advance().ok_or_eof(self.current_span(), vec!["VALID".to_string()])?;
                                end = v.span.end;
                                not_valid = true;
                            } else {
                                // Not "NOT VALID", put NOT back
                                self.idx = saved;
                            }
                        } else {
                            self.idx = saved;
                        }
                    }
                }

                Ok(AlterDomainAction::AddConstraint {
                    span: Span {
                        start: action_start,
                        end,
                    },
                    constraint,
                    not_valid,
                })
            }

            // VALIDATE CONSTRAINT name
            TokenKind::Identifier { .. }
                if tok.lexeme(self.source).eq_ignore_ascii_case("VALIDATE") =>
            {
                let validate_tok = self.advance().ok_or_eof(self.current_span(), vec!["VALIDATE".to_string()])?;
                let action_start = validate_tok.span.start;

                // CONSTRAINT
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["CONSTRAINT".to_string()])?;

                let name_tok = self.advance().ok_or_eof(
                    self.current_span(),
                    vec!["constraint name".to_string()],
                )?;

                Ok(AlterDomainAction::ValidateConstraint {
                    span: Span {
                        start: action_start,
                        end: name_tok.span.end,
                    },
                    constraint_name: name_tok.span,
                })
            }

            _ => Err(crate::error::ParseError::new(
                tok.span,
                crate::error::ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected SET, DROP, ADD, RENAME, VALIDATE, or OWNER after ALTER DOMAIN name, found '{}'",
                        tok.lexeme(self.source)
                    ),
                },
            )),
        }
    }
}
