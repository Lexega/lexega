// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE ROW ACCESS POLICY statement parsing
//!
//! Implements parsing for Snowflake CREATE ROW ACCESS POLICY statements,
//! which define function-like policies that return boolean expressions
//! determining row visibility in tables (row-level security).
//!
//! ## Grammar (from Snowflake docs)
//!
//! ```text
//! CREATE [ OR REPLACE ] ROW ACCESS POLICY <name>
//!   AS ( <arg_name> <arg_type> [ , <arg_name> <arg_type> ... ] )
//!   RETURNS BOOLEAN ->
//!     <body_expr>
//!   [ COMMENT = '<string_literal>' ]
//! ```
//!
//! ## Examples
//!
//! ```sql
//! CREATE ROW ACCESS POLICY user_policy
//!   AS (user_id INTEGER) RETURNS BOOLEAN ->
//!     user_id = CURRENT_USER_ID();
//!
//! CREATE OR REPLACE ROW ACCESS POLICY dept_policy
//!   AS (dept VARCHAR, role VARCHAR) RETURNS BOOLEAN ->
//!     dept IN ('HR', 'IT') OR role = 'ADMIN'
//!   COMMENT = 'Restrict by department';
//! ```

use crate::ast::{AstCreateRowAccessPolicy, AstPolicyParameter, AstStmt};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxCreateRowAccessPolicy;

impl<'a> Parser<'a> {
    /// Parse CREATE ROW ACCESS POLICY statement with comprehensive support.
    ///
    /// This parser handles:
    /// - CREATE OR REPLACE variant
    /// - Policy name (qualified or unqualified identifier)
    /// - AS clause with signature: (arg_name type, ...)
    /// - RETURNS BOOLEAN clause (optional in some contexts)
    /// - Arrow operator (->) before body
    /// - Body expression (boolean predicate)
    /// - COMMENT clause for metadata
    ///
    /// Returns Result with detailed error information on parse failure.
    pub(crate) fn try_parse_create_row_access_policy(&mut self) -> ParseResult<AstStmt> {
        // Recursion guard
        let _depth = self.track_depth("create_row_access_policy")?;

        // Consume CREATE keyword
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;
        let create_token_id = self.last_token_id();
        let mut span = create_span;

        // Optional OR REPLACE
        let mut or_replace_span: Option<Span> = None;
        let mut or_token_id: Option<crate::cst::TokenId> = None;
        let mut replace_token_id: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword should be available after peek");
                or_token_id = Some(self.last_token_id());

                if let Some(replace_tok) = self.peek_non_trivia() {
                    if matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                        let replace = self
                            .advance()
                            .expect_invariant("REPLACE keyword should be available after peek");
                        replace_token_id = Some(self.last_token_id());
                        or_replace_span = Some(Span {
                            start: or_tok.span.start,
                            end: replace.span.end,
                        });
                        span.end = replace.span.end;
                    }
                }
            }
        }

        // Expect ROW keyword
        let row_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["ROW".to_string()])?;
        if !matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row)) {
            return Err(ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ROW keyword, found '{}'",
                        row_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let row_keyword = self
            .advance()
            .expect_invariant("ROW keyword should be available after validation");
        let row_span = row_keyword.span;
        let row_token_id = self.last_token_id();
        span.end = row_span.end;

        // Expect ACCESS keyword
        let access_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["ACCESS".to_string()])?;
        if !matches!(access_tok.kind, TokenKind::Keyword(Keyword::Access)) {
            return Err(ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ACCESS keyword, found '{}'",
                        access_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let access_keyword = self
            .advance()
            .expect_invariant("ACCESS keyword should be available after validation");
        let access_span = access_keyword.span;
        let access_token_id = self.last_token_id();
        span.end = access_span.end;

        // Expect POLICY keyword
        let policy_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected POLICY keyword, found '{}'",
                        policy_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let policy_keyword = self
            .advance()
            .expect_invariant("POLICY keyword should be available after validation");
        let policy_span = policy_keyword.span;
        let policy_token_id = self.last_token_id();
        span.end = policy_span.end;

        // Optional IF NOT EXISTS (BigQuery only - before policy name)
        let mut if_not_exists_span: Option<Span> = None;
        let mut if_not_exists_if_token_id: Option<crate::cst::TokenId> = None;
        let mut if_not_exists_not_token_id: Option<crate::cst::TokenId> = None;
        let mut if_not_exists_exists_token_id: Option<crate::cst::TokenId> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant("IF keyword after peek");
                if_not_exists_if_token_id = Some(self.last_token_id());
                let if_start = if_tok.span.start;

                let not_tok = self.advance().ok_or_eof(span, vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::new(
                        not_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected NOT after IF, found '{}'",
                                not_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                if_not_exists_not_token_id = Some(self.last_token_id());

                let exists_tok = self.advance().ok_or_eof(span, vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected EXISTS after IF NOT, found '{}'",
                                exists_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }
                if_not_exists_exists_token_id = Some(self.last_token_id());

                if_not_exists_span = Some(Span {
                    start: if_start,
                    end: exists_tok.span.end,
                });
                span.end = exists_tok.span.end;
            }
        }

        // Parse policy name (required)
        let name_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["policy_name".to_string()])?;
        let policy_name_span = self.parse_policy_name_row_access(name_tok.span)?;
        span.end = policy_name_span.end;

        // =====================================================================
        // Dialect detection: ON → BigQuery path, AS → Snowflake path
        // Per permissive parser philosophy, detect by token presence not dialect.
        // =====================================================================
        let next_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["AS or ON".to_string()])?;

        if matches!(next_tok.kind, TokenKind::Keyword(Keyword::On)) {
            // BigQuery path: ON table [GRANT TO (...)] FILTER USING (...)
            return self.parse_create_row_access_policy_bigquery(
                create_span,
                create_token_id,
                or_replace_span,
                or_token_id,
                replace_token_id,
                row_span,
                row_token_id,
                access_span,
                access_token_id,
                policy_span,
                policy_token_id,
                if_not_exists_span,
                if_not_exists_if_token_id,
                if_not_exists_not_token_id,
                if_not_exists_exists_token_id,
                policy_name_span,
                span,
            );
        }

        // Snowflake path: AS (args) RETURNS BOOLEAN -> body_expr [COMMENT = ...]

        // AS keyword (optional for Snowflake)
        let mut as_span: Option<Span> = None;
        let mut as_token_id: Option<crate::cst::TokenId> = None;

        if matches!(next_tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_keyword = self
                .advance()
                .expect_invariant("AS keyword should be available after peek");
            as_span = Some(as_keyword.span);
            as_token_id = Some(self.last_token_id());
            span.end = as_keyword.span.end;
        }

        // Parse signature: (arg_name type, ...)
        let (signature_span, parameters, lparen_token_id, rparen_token_id) =
            self.parse_row_access_signature(span)?;
        span.end = signature_span.end;

        // Optional RETURNS BOOLEAN clause
        let mut returns_span: Option<Span> = None;
        let mut returns_token_id: Option<crate::cst::TokenId> = None;
        let mut boolean_token_id: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Returns)) {
                let returns_kw = self
                    .advance()
                    .expect_invariant("RETURNS keyword should be available after peek");
                returns_token_id = Some(self.last_token_id());
                let returns_start = returns_kw.span.start;

                // Expect BOOLEAN (as an identifier or keyword)
                if let Some(bool_tok) = self.peek_non_trivia() {
                    // BOOLEAN can be lexed as identifier, keyword, or literal depending on context
                    let is_boolean = matches!(bool_tok.kind, TokenKind::Identifier { .. })
                        && bool_tok.lexeme(self.source).eq_ignore_ascii_case("BOOLEAN");

                    if is_boolean {
                        let boolean_kw = self
                            .advance()
                            .expect_invariant("BOOLEAN identifier should be available after peek");
                        boolean_token_id = Some(self.last_token_id());
                        returns_span = Some(Span {
                            start: returns_start,
                            end: boolean_kw.span.end,
                        });
                        span.end = boolean_kw.span.end;
                    }
                }
            }
        }

        // Expect arrow operator (->)
        let arrow_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["->".to_string()])?;
        if !matches!(arrow_tok.kind, TokenKind::Operator(Operator::RightArrow)) {
            return Err(ParseError::new(
                arrow_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected '->' operator, found '{}'",
                        arrow_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let arrow = self
            .advance()
            .expect_invariant("Arrow operator should be available after validation");
        let arrow_span = arrow.span;
        let arrow_token_id = self.last_token_id();
        span.end = arrow_span.end;

        // Parse body expression (boolean predicate)
        let _body_start = self.current_span().start;
        let body = self.parse_expr_in_mode()?;
        let body_expr_span = body.span();
        span.end = body_expr_span.end;

        // Optional COMMENT clause
        let mut comment_span: Option<Span> = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
                let comment_kw = self
                    .advance()
                    .expect_invariant("COMMENT keyword should be available after peek");
                let comment_start = comment_kw.span.start;

                // Expect = operator
                if let Some(eq_tok) = self.peek_non_trivia() {
                    if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance();

                        // Expect string literal
                        if let Some(str_tok) = self.peek_non_trivia() {
                            if matches!(str_tok.kind, TokenKind::Literal(_)) {
                                let str_val = self.advance().expect_invariant(
                                    "String literal should be available after peek",
                                );
                                comment_span = Some(Span {
                                    start: comment_start,
                                    end: str_val.span.end,
                                });
                                span.end = str_val.span.end;
                            }
                        }
                    }
                }
            }
        }

        // Build CST node
        let syntax_node = SyntaxCreateRowAccessPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            row_keyword: row_token_id,
            access_keyword: access_token_id,
            policy_keyword: policy_token_id,
            // Snowflake-specific
            as_keyword: as_token_id,
            returns_keyword: returns_token_id,
            boolean_keyword: boolean_token_id,
            lparen: Some(lparen_token_id),
            rparen: Some(rparen_token_id),
            arrow_token: Some(arrow_token_id),
            signature_span: Some(signature_span),
            // BigQuery-specific (None for Snowflake)
            if_keyword: None,
            not_keyword: None,
            exists_keyword: None,
            on_keyword: None,
            table_name_span: None,
            grant_to_clause_span: None,
            filter_using_clause_span: None,
            // Common
            policy_name_span,
            body_expr_span,
            comment_span,
            span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_create_row_access_policy(syntax_node);

        // Build AST node (Snowflake variant - BQ fields are None)
        let ast = AstCreateRowAccessPolicy {
            node_id: self.id_gen.next(),
            span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            row_span,
            access_span,
            policy_span,
            policy_name_span,
            // BigQuery fields (None for Snowflake)
            if_not_exists_span: None,
            on_table_span: None,
            table_name_span: None,
            grant_to_span: None,
            grantee_spans: Vec::new(),
            grant_to_clause_span: None,
            filter_using_span: None,
            filter_using_clause_span: None,
            filter_expr: None,
            // Snowflake fields
            as_span,
            signature_span: Some(signature_span),
            returns_span,
            arrow_span: Some(arrow_span),
            body_expr_span: Some(body_expr_span),
            comment_span,
            parameters,
            body: Some(Box::new(body)),
        };

        // Exit recursion guard

        Ok(AstStmt::CreateRowAccessPolicy(Box::new(ast)))
    }

    /// Parse policy/table name (qualified or unqualified identifier).
    ///
    /// Consumes a dotted identifier chain: `name`, `schema.name`, `db.schema.name`.
    /// The first part must be an Identifier or non-reserved keyword.
    /// After a dot, any keyword is allowed (e.g., `dataset.table`).
    /// Stops at the first non-dot, non-identifier boundary to avoid consuming
    /// clause keywords like FILTER that happen to be Identifier tokens.
    fn parse_policy_name_row_access(&mut self, start_span: Span) -> ParseResult<Span> {
        let mut span = start_span;
        let name_start_idx = self.idx;

        // Consume first name part (identifier or non-reserved keyword)
        if let Some(tok) = self.peek_non_trivia() {
            match tok.kind {
                TokenKind::Identifier { .. } => {
                    let t = self
                        .advance()
                        .expect_invariant("Name token should be available after peek");
                    span.end = t.span.end;
                }
                TokenKind::Keyword(_) if self.can_be_identifier_token(tok) => {
                    let t = self
                        .advance()
                        .expect_invariant("Keyword-as-name should be available after peek");
                    span.end = t.span.end;
                }
                _ => {}
            }
        }

        if self.idx == name_start_idx {
            return Err(ParseError::new(
                span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected policy name".to_string(),
                },
            ));
        }

        // Consume dot-separated parts: .part1.part2...
        // After a dot, ANY keyword is valid (e.g., dataset.table, schema.data).
        while let Some(tok) = self.peek_non_trivia() {
            if !matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            // Consume the dot
            let dot = self
                .advance()
                .expect_invariant("Dot should be available after peek");
            span.end = dot.span.end;

            // Consume the identifier after the dot
            if let Some(next) = self.peek_non_trivia() {
                match next.kind {
                    TokenKind::Identifier { .. } => {
                        let t = self.advance().expect_invariant("Identifier after dot");
                        span.end = t.span.end;
                    }
                    TokenKind::Keyword(_) if self.can_be_identifier_after_dot_token(next) => {
                        let t = self.advance().expect_invariant("Keyword after dot");
                        span.end = t.span.end;
                    }
                    _ => break, // Dot with no valid identifier after it
                }
            }
        }

        Ok(span)
    }

    /// Parse policy signature: (arg_name type, arg_name type, ...)
    fn parse_row_access_signature(
        &mut self,
        mut span: Span,
    ) -> ParseResult<(
        Span,
        Vec<AstPolicyParameter>,
        crate::cst::TokenId,
        crate::cst::TokenId,
    )> {
        // Expect opening parenthesis
        let lparen_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "Expected '(' to start signature, found '{}'",
                        lparen_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let lparen = self
            .advance()
            .expect_invariant("Opening parenthesis should be available after validation");
        let lparen_token_id = self.last_token_id();
        let sig_start = lparen.span.start;
        span.end = lparen.span.end;

        let mut parameters = Vec::new();

        // Parse parameters
        loop {
            // Check for closing paren
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    let rparen = self
                        .advance()
                        .expect_invariant("Closing parenthesis should be available after peek");
                    let rparen_token_id = self.last_token_id();
                    let sig_span = Span {
                        start: sig_start,
                        end: rparen.span.end,
                    };
                    return Ok((sig_span, parameters, lparen_token_id, rparen_token_id));
                }
            }

            // Parse parameter: arg_name arg_type
            let param_start = self.current_span().start;

            // Parse parameter name
            let name_tok = self
                .peek_non_trivia()
                .ok_or_eof(span, vec!["parameter_name".to_string()])?;
            if !matches!(name_tok.kind, TokenKind::Identifier { .. }) {
                return Err(ParseError::new(
                    name_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: format!(
                            "Expected parameter name, found '{}'",
                            name_tok.lexeme(self.source)
                        ),
                    },
                ));
            }
            let name = self
                .advance()
                .expect_invariant("Parameter name should be available after validation");
            let name_span = name.span;

            // Parse parameter type (can be multiple tokens: e.g., VARCHAR(100))
            let type_start_idx = self.idx;
            let mut type_span = Span {
                start: self.current_span().start,
                end: self.current_span().start,
            };

            while let Some(tok) = self.peek_non_trivia() {
                match tok.kind {
                    TokenKind::Punctuation(Punctuation::Comma)
                    | TokenKind::Punctuation(Punctuation::RParen) => {
                        break;
                    }
                    _ => {
                        let t = self.advance().expect_invariant(
                            "Parameter type token should be available after peek",
                        );
                        type_span.end = t.span.end;
                    }
                }
            }

            if self.idx == type_start_idx {
                return Err(ParseError::new(
                    name_span,
                    ParseErrorKind::InvalidSyntax {
                        message: "Expected parameter type after parameter name".to_string(),
                    },
                ));
            }

            let param_span = Span {
                start: param_start,
                end: type_span.end,
            };

            parameters.push(AstPolicyParameter {
                node_id: self.id_gen.next(),
                span: param_span,
                name_span,
                type_span,
            });

            span.end = param_span.end;

            // Check for comma (more parameters) or closing paren
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    // Will be handled in next loop iteration
                    continue;
                }
            }

            // If we get here without comma or rparen, something is wrong
            return Err(ParseError::new(
                span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected ',' or ')' after parameter".to_string(),
                },
            ));
        }
    }

    /// Parse BigQuery-style CREATE ROW ACCESS POLICY.
    ///
    /// Called after common prefix (CREATE [OR REPLACE] ROW ACCESS POLICY [IF NOT EXISTS] name)
    /// has been consumed and ON keyword detected.
    ///
    /// Remaining syntax: ON table [GRANT TO (grantees)] FILTER USING (expr)
    #[allow(clippy::too_many_arguments)]
    fn parse_create_row_access_policy_bigquery(
        &mut self,
        create_span: Span,
        create_token_id: crate::cst::TokenId,
        or_replace_span: Option<Span>,
        or_token_id: Option<crate::cst::TokenId>,
        replace_token_id: Option<crate::cst::TokenId>,
        row_span: Span,
        row_token_id: crate::cst::TokenId,
        access_span: Span,
        access_token_id: crate::cst::TokenId,
        policy_span: Span,
        policy_token_id: crate::cst::TokenId,
        if_not_exists_span: Option<Span>,
        if_not_exists_if_token_id: Option<crate::cst::TokenId>,
        if_not_exists_not_token_id: Option<crate::cst::TokenId>,
        if_not_exists_exists_token_id: Option<crate::cst::TokenId>,
        policy_name_span: Span,
        mut span: Span,
    ) -> ParseResult<AstStmt> {
        // ON keyword (already verified by caller)
        let on_tok = self.advance().expect_invariant("ON keyword after peek");
        let on_token_id = self.last_token_id();
        let on_table_span = on_tok.span;
        span.end = on_tok.span.end;

        // Parse table name (may be qualified: project.dataset.table or `backtick-quoted`)
        let table_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["table_name".to_string()])?;
        let table_name_span = self.parse_policy_name_row_access(table_tok.span)?;
        span.end = table_name_span.end;

        // Optional GRANT TO clause
        let mut grant_to_span: Option<Span> = None;
        let mut grantee_spans: Vec<Span> = Vec::new();
        let mut grant_to_clause_span: Option<Span> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Grant)) {
                let grant_tok = self.advance().expect_invariant("GRANT keyword after peek");
                let grant_start = grant_tok.span.start;

                // Expect TO keyword
                let to_tok = self.advance().ok_or_eof(span, vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected TO after GRANT, found '{}'",
                                to_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }

                grant_to_span = Some(Span {
                    start: grant_start,
                    end: to_tok.span.end,
                });

                // Expect opening parenthesis
                let lparen_tok = self.advance().ok_or_eof(span, vec!["(".to_string()])?;
                if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    return Err(ParseError::new(
                        lparen_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected '(' after GRANT TO, found '{}'",
                                lparen_tok.lexeme(self.source)
                            ),
                        },
                    ));
                }

                // Parse grantee list: "user@example.com", "allAuthenticatedUsers", etc.
                loop {
                    if let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                            break;
                        }
                    }

                    // Parse grantee (can be quoted string or identifier)
                    let grantee_tok = self
                        .advance()
                        .ok_or_eof(span, vec!["grantee".to_string()])?;
                    grantee_spans.push(grantee_tok.span);

                    // Optional comma
                    if let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            self.advance(); // consume comma
                        }
                    }
                }

                // Closing parenthesis
                let rparen_tok = self.advance().ok_or_eof(span, vec![")".to_string()])?;

                grant_to_clause_span = Some(Span {
                    start: grant_start,
                    end: rparen_tok.span.end,
                });
                span.end = rparen_tok.span.end;
            }
        }

        // FILTER USING clause (required for BigQuery)
        // Note: FILTER is an Identifier token, not a Keyword
        let filter_tok = self
            .peek_non_trivia()
            .ok_or_eof(span, vec!["FILTER".to_string()])?;

        if !(matches!(filter_tok.kind, TokenKind::Identifier { .. })
            && filter_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("FILTER"))
        {
            return Err(ParseError::new(
                filter_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected FILTER keyword, found '{}'",
                        filter_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let filter_kw = self
            .advance()
            .expect_invariant("FILTER identifier after peek");
        let filter_start = filter_kw.span.start;

        // Expect USING keyword
        let using_tok = self.advance().ok_or_eof(span, vec!["USING".to_string()])?;
        if !matches!(using_tok.kind, TokenKind::Keyword(Keyword::Using)) {
            return Err(ParseError::new(
                using_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected USING after FILTER, found '{}'",
                        using_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        let filter_using_span = Some(Span {
            start: filter_start,
            end: using_tok.span.end,
        });

        // Expect opening parenthesis for filter expression
        let lparen_tok = self.advance().ok_or_eof(span, vec!["(".to_string()])?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected '(' after FILTER USING, found '{}'",
                        lparen_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Parse the filter expression
        let filter_expr = self.parse_expr_in_mode()?;

        // Closing parenthesis
        let rparen_tok = self.advance().ok_or_eof(span, vec![")".to_string()])?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(ParseError::new(
                rparen_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ')' after filter expression, found '{}'",
                        rparen_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        let filter_using_clause_span = Some(Span {
            start: filter_start,
            end: rparen_tok.span.end,
        });
        span.end = rparen_tok.span.end;

        // Build CST node with proper BigQuery-specific fields
        let syntax_node = SyntaxCreateRowAccessPolicy {
            create_keyword: create_token_id,
            or_keyword: or_token_id,
            replace_keyword: replace_token_id,
            row_keyword: row_token_id,
            access_keyword: access_token_id,
            policy_keyword: policy_token_id,
            // Snowflake-specific (None for BigQuery)
            as_keyword: None,
            returns_keyword: None,
            boolean_keyword: None,
            lparen: None,
            rparen: None,
            arrow_token: None,
            signature_span: None,
            // BigQuery-specific
            if_keyword: if_not_exists_if_token_id,
            not_keyword: if_not_exists_not_token_id,
            exists_keyword: if_not_exists_exists_token_id,
            on_keyword: Some(on_token_id),
            table_name_span: Some(table_name_span),
            grant_to_clause_span,
            filter_using_clause_span,
            // Common
            policy_name_span,
            body_expr_span: filter_expr.span(),
            comment_span: None,
            span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_create_row_access_policy(syntax_node);

        // Build AST node (BigQuery variant)
        let ast = AstCreateRowAccessPolicy {
            node_id: self.id_gen.next(),
            span,
            syntax_id: Some(syntax_id),
            create_span,
            or_replace_span,
            row_span,
            access_span,
            policy_span,
            policy_name_span,
            // BigQuery fields
            if_not_exists_span,
            on_table_span: Some(on_table_span),
            table_name_span: Some(table_name_span),
            grant_to_span,
            grantee_spans,
            grant_to_clause_span,
            filter_using_span,
            filter_using_clause_span,
            filter_expr: Some(Box::new(filter_expr)),
            // Snowflake fields (None for BigQuery)
            as_span: None,
            signature_span: None,
            returns_span: None,
            arrow_span: None,
            body_expr_span: None,
            comment_span: None,
            parameters: Vec::new(),
            body: None,
        };
        Ok(AstStmt::CreateRowAccessPolicy(Box::new(ast)))
    }

    /// Parse DROP ROW ACCESS POLICY statement.
    ///
    /// Supports both Snowflake and BigQuery syntax:
    /// Snowflake: DROP ROW ACCESS POLICY [ IF EXISTS ] <name>
    /// BigQuery:  DROP ROW ACCESS POLICY [ IF EXISTS ] <name> ON <table>
    pub(crate) fn try_parse_drop_row_access_policy(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstDropRowAccessPolicy;
        use crate::syntax::SyntaxDropRowAccessPolicy;

        let _depth = self.track_depth("drop_row_access_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // ROW (Keyword)
        let row_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ROW".to_string()])?;
        if !matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row)) {
            return Err(ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ROW keyword".to_string(),
                },
            ));
        }
        let row_span = row_tok.span;
        let row_token_id = self.last_token_id();

        // ACCESS (Keyword)
        let access_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ACCESS".to_string()])?;
        if !matches!(access_tok.kind, TokenKind::Keyword(Keyword::Access)) {
            return Err(ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ACCESS keyword".to_string(),
                },
            ));
        }
        let access_span = access_tok.span;
        let access_token_id = self.last_token_id();

        // POLICY (Keyword)
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY keyword".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_token_id = self.last_token_id();

        // Optional IF EXISTS
        let mut if_exists_span: Option<Span> = None;
        let mut if_keyword: Option<crate::cst::TokenId> = None;
        let mut exists_keyword: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant("IF keyword after peek");
                if_keyword = Some(self.last_token_id());
                let if_start = if_tok.span.start;

                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF".to_string(),
                        },
                    ));
                }
                exists_keyword = Some(self.last_token_id());

                if_exists_span = Some(Span {
                    start: if_start,
                    end: exists_tok.span.end,
                });
            }
        }

        // Policy name (may be qualified: db.schema.name)
        let policy_name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["policy_name".to_string()])?;
        let mut policy_name_span = policy_name_tok.span;

        // Consume any dots and identifiers for qualified names
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                if let Some(ident_tok) = self.peek_non_trivia() {
                    if matches!(ident_tok.kind, TokenKind::Identifier { .. }) {
                        let ident = self.advance().expect_invariant(
                            "Identifier for qualified policy name should be available after peek",
                        );
                        policy_name_span.end = ident.span.end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Optional ON table clause (BigQuery: DROP ROW ACCESS POLICY name ON table)
        let mut on_table_span: Option<Span> = None;
        let mut table_name_span: Option<Span> = None;
        let mut on_keyword_token: Option<crate::cst::TokenId> = None;

        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                let on_tok = self.advance().expect_invariant("ON keyword after peek");
                on_keyword_token = Some(self.last_token_id());
                on_table_span = Some(on_tok.span);

                // Parse table name (may be qualified: project.dataset.table)
                let tbl_tok = self
                    .peek_non_trivia()
                    .ok_or_eof(on_tok.span, vec!["table_name".to_string()])?;
                let tbl_span = self.parse_policy_name_row_access(tbl_tok.span)?;
                table_name_span = Some(tbl_span);
            }
        }

        // Calculate full statement span
        let stmt_end = table_name_span
            .map(|s| s.end)
            .unwrap_or(policy_name_span.end);
        let stmt_span = Span {
            start: drop_span.start,
            end: stmt_end,
        };

        // Build CST node
        let syntax_node = SyntaxDropRowAccessPolicy {
            drop_keyword: drop_token_id,
            row_keyword: row_token_id,
            access_keyword: access_token_id,
            policy_keyword: policy_token_id,
            if_keyword,
            exists_keyword,
            policy_name_span,
            on_keyword: on_keyword_token,
            table_name_span,
            span: stmt_span,
        };

        let syntax_id = self.syntax_arena.alloc_drop_row_access_policy(syntax_node);

        // Build AST node
        let ast = AstDropRowAccessPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            row_span,
            access_span,
            policy_span,
            if_exists_span,
            policy_name_span,
            on_table_span,
            table_name_span,
        };
        Ok(AstStmt::DropRowAccessPolicy(Box::new(ast)))
    }

    /// Parse DROP ALL ROW ACCESS POLICIES ON <table> statement (BigQuery).
    ///
    /// Syntax: DROP ALL ROW ACCESS POLICIES ON <table>
    ///
    /// Note: POLICIES is an Identifier token (not a Keyword).
    pub(crate) fn try_parse_drop_all_row_access_policies(&mut self) -> ParseResult<AstStmt> {
        use crate::ast::AstDropAllRowAccessPolicies;
        use crate::syntax::SyntaxDropAllRowAccessPolicies;

        let _depth = self.track_depth("drop_all_row_access_policies")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // ALL
        let all_tok = self
            .advance()
            .ok_or_eof(drop_span, vec!["ALL".to_string()])?;
        if !matches!(all_tok.kind, TokenKind::Keyword(Keyword::All)) {
            return Err(ParseError::new(
                all_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ALL keyword, found '{}'",
                        all_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let all_span = all_tok.span;
        let all_token_id = self.last_token_id();

        // ROW
        let row_tok = self
            .advance()
            .ok_or_eof(all_span, vec!["ROW".to_string()])?;
        if !matches!(row_tok.kind, TokenKind::Keyword(Keyword::Row)) {
            return Err(ParseError::new(
                row_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ROW keyword, found '{}'",
                        row_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let row_span = row_tok.span;
        let row_token_id = self.last_token_id();

        // ACCESS
        let access_tok = self
            .advance()
            .ok_or_eof(row_span, vec!["ACCESS".to_string()])?;
        if !matches!(access_tok.kind, TokenKind::Keyword(Keyword::Access)) {
            return Err(ParseError::new(
                access_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ACCESS keyword, found '{}'",
                        access_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let access_span = access_tok.span;
        let access_token_id = self.last_token_id();

        // POLICIES (Identifier, not Keyword)
        let policies_tok = self
            .advance()
            .ok_or_eof(access_span, vec!["POLICIES".to_string()])?;
        if !(matches!(policies_tok.kind, TokenKind::Identifier { .. })
            && policies_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("POLICIES"))
        {
            return Err(ParseError::new(
                policies_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected POLICIES, found '{}'",
                        policies_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let policies_span = policies_tok.span;
        let policies_token_id = self.last_token_id();

        // ON keyword (required)
        let on_tok = self
            .advance()
            .ok_or_eof(policies_span, vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(ParseError::new(
                on_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected ON keyword, found '{}'",
                        on_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let on_span = on_tok.span;
        let on_token_id = self.last_token_id();

        // Parse table name (may be qualified: project.dataset.table)
        let table_tok = self
            .peek_non_trivia()
            .ok_or_eof(on_span, vec!["table_name".to_string()])?;
        let table_name_span = self.parse_policy_name_row_access(table_tok.span)?;

        // Calculate full statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: table_name_span.end,
        };

        // Build CST node
        let syntax_node = SyntaxDropAllRowAccessPolicies {
            drop_keyword: drop_token_id,
            all_keyword: all_token_id,
            row_keyword: row_token_id,
            access_keyword: access_token_id,
            policies_token: policies_token_id,
            on_keyword: on_token_id,
            table_name_span,
            span: stmt_span,
        };
        let syntax_id = self
            .syntax_arena
            .alloc_drop_all_row_access_policies(syntax_node);

        // Build AST node
        let ast = AstDropAllRowAccessPolicies {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            all_span,
            row_span,
            access_span,
            policies_span,
            on_span,
            table_name_span,
        };
        Ok(AstStmt::DropAllRowAccessPolicies(Box::new(ast)))
    }
}
