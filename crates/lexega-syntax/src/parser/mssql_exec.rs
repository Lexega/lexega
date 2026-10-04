// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for MSSQL `EXEC` / `EXECUTE` procedure call and dynamic SQL statements.
//!
//! Three main forms:
//!   1. Procedure call: `EXEC[UTE] [schema.]proc_name [@p1 = val1, ...]`
//!   2. Return capture: `EXEC[UTE] @ret = [schema.]proc_name [args]`
//!   3. Dynamic SQL:    `EXEC[UTE] (string_expression)`

use crate::ast::types::{AstImpersonationPrincipalKind, AstMssqlExec, AstMssqlExecuteAs};
use crate::ast::AstStmt;
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse an MSSQL `EXEC` or `EXECUTE` statement.
    ///
    /// Called when the current token is `Identifier "EXEC"` or `Keyword(Execute)`.
    /// The token has NOT been consumed yet.
    pub(crate) fn try_parse_mssql_exec_stmt(&mut self) -> ParseResult<AstStmt> {
        // 1. Consume EXEC or EXECUTE keyword
        let exec_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected EXEC or EXECUTE keyword".to_string(),
                },
            )
        })?;
        let stmt_start = exec_tok.span.start;
        let exec_keyword_span = exec_tok.span;

        // 2. Peek to determine which form we have
        let next = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "EXEC requires procedure name or expression".to_string(),
                },
            )
        })?;

        // Form 3: Dynamic SQL — EXEC ('string expression')
        if matches!(next.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return self.parse_mssql_exec_dynamic(stmt_start, exec_keyword_span);
        }

        // Form 4: Impersonation — EXEC[UTE] AS { LOGIN | USER } = ...
        if matches!(next.kind, TokenKind::Keyword(Keyword::As)) {
            return self.parse_mssql_execute_as(stmt_start);
        }

        // Determine if this is Form 2 (return value capture): EXEC @ret = proc ...
        // Peek: if we see @variable followed by =, that's the return capture form.
        let mut return_var_span: Option<Span> = None;
        if matches!(
            next.kind,
            TokenKind::Identifier {
                kind: crate::lexer::IdentifierKind::AtVariable
            }
        ) {
            // Save position and look ahead for '='
            let saved = self.idx;
            let var_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["@variable".to_string()])?;
            let var_span = var_tok.span;
            if let Some(eq_tok) = self.peek_non_trivia() {
                if matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                    // Form 2: return value capture
                    self.advance(); // consume '='
                    return_var_span = Some(var_span);
                    // Now the next token should be the procedure name
                } else {
                    // Not Form 2 — restore position, this @var is the first arg
                    self.idx = saved;
                }
            } else {
                self.idx = saved;
            }
        }

        // Form 1 or Form 2: parse qualified procedure name
        //   Dot-separated: ident [.ident [.ident]]
        let proc_first = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "EXEC requires procedure name".to_string(),
                },
            )
        })?;

        // The first component of a qualified name can be a keyword (e.g., "master") or identifier
        if !self.can_be_identifier_token(proc_first)
            && !matches!(proc_first.kind, TokenKind::Keyword(_))
        {
            return Err(ParseError::new(
                proc_first.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected procedure name, found {}",
                        Parser::token_description(proc_first, self.source)
                    ),
                },
            ));
        }

        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["procedure name".to_string()])?;
        let name_start = first.span.start;
        let mut name_end = first.span.end;
        // Last dot-part — the base procedure identity.
        let mut base_name_span = first.span;

        // Consume dot-separated additional parts: .ident [.ident].
        // T-SQL allows omitted components (`master..xp_cmdshell`): a dot
        // immediately followed by another dot is an empty slot — skip it
        // and keep consuming so `base_name_span` lands on the final real
        // part (the procedure's own name).
        while let Some(dot_tok) = self.peek_non_trivia() {
            if !matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            self.advance(); // consume dot
            let part = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected identifier after dot in qualified procedure name"
                            .to_string(),
                    },
                )
            })?;
            // Omitted middle component: leave the next dot for the loop.
            if matches!(part.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                name_end = dot_tok.span.end;
                continue;
            }
            if !self.can_be_identifier_token(part) && !matches!(part.kind, TokenKind::Keyword(_)) {
                return Err(ParseError::new(
                    part.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected identifier after dot, found {}",
                            Parser::token_description(part, self.source)
                        ),
                    },
                ));
            }
            let part_tok = self.advance().ok_or_eof(
                self.current_span(),
                vec!["identifier after dot".to_string()],
            )?;
            name_end = part_tok.span.end;
            base_name_span = part_tok.span;
        }

        let procedure_name_span = Span {
            start: name_start,
            end: name_end,
        };

        // Parse arguments (everything until ; or EOF or statement boundary)
        let (args_span, args) = self.parse_mssql_exec_args()?;

        let end = args_span.map(|s| s.end).unwrap_or(name_end);

        Ok(AstStmt::MssqlExec(Box::new(AstMssqlExec {
            node_id: self.id_gen.next(),
            span: Span {
                start: stmt_start,
                end,
            },
            exec_keyword_span,
            return_var_span,
            procedure_name_span: Some(procedure_name_span),
            procedure_base_name_span: Some(base_name_span),
            args_span,
            at_linked_server_span: None,
            args,
        })))
    }

    /// Parse dynamic SQL form: `EXEC ('string expression' [+ @var ...])`
    ///
    /// The opening `(` has NOT been consumed.
    fn parse_mssql_exec_dynamic(
        &mut self,
        stmt_start: u32,
        exec_keyword_span: Span,
    ) -> ParseResult<AstStmt> {
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?; // consume '('
        let args_start = lparen.span.start;
        let mut args_end = lparen.span.end;

        // Lift the parenthesised argument into a typed expression so its
        // concat/format shape and splice positions are visible to consumers
        // the same way they are for `sp_executesql` and
        // `EXECUTE IMMEDIATE`. The dynamic `EXEC(...)` argument is a single
        // (possibly concatenated) string expression. Fall back to a raw
        // paren-depth scan with no typed args when the content is not a
        // single expression we can fully consume — the parser stays
        // permissive and `args_span` still covers the tail.
        let after_lparen = self.idx;
        let arg_start = self
            .peek_non_trivia()
            .map(|t| t.span.start)
            .unwrap_or(lparen.span.end);
        let mut typed_args: Vec<crate::ast::AstCallArg> = Vec::new();
        let lifted = match self.parse_expr() {
            Ok(expr) => {
                // Accept the lift only when the expression is fully followed
                // by the closing paren; otherwise the content is not a single
                // expression we consumed cleanly. Resolve the borrow to a bool
                // before `advance()` needs `&mut self`.
                let closes = matches!(
                    self.peek_non_trivia().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(Punctuation::RParen))
                );
                if closes {
                    let expr_end = crate::parser::scripting::expr_span_end(&expr);
                    // A rendered-template placeholder inside the executed string
                    // is an injection splice; mark it so the dynamic-SQL
                    // classifier treats the arg as dynamic, not a clean literal.
                    let expr = self.promote_placeholder_dynamic_sql_arg(expr);
                    typed_args.push(crate::ast::AstCallArg {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: arg_start,
                            end: expr_end,
                        },
                        name: None,
                        name_op_span: None,
                        value: expr,
                    });
                    let rparen = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                    args_end = rparen.span.end;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        };

        if !lifted {
            typed_args.clear();
            self.idx = after_lparen;
            let mut paren_depth = 1u32;
            while paren_depth > 0 {
                let tok = match self.peek_non_trivia() {
                    Some(t) => t,
                    None => break,
                };
                match tok.kind {
                    TokenKind::Punctuation(Punctuation::LParen) => paren_depth += 1,
                    TokenKind::Punctuation(Punctuation::RParen) => paren_depth -= 1,
                    _ => {}
                }
                let t = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                args_end = t.span.end;
                if paren_depth == 0 {
                    break;
                }
            }
        }

        let args_span = Span {
            start: args_start,
            end: args_end,
        };

        // Optional `AT <linked_server>` clause: the dynamic SQL executes
        // on the remote linked server. `AT` is an Identifier token, not a
        // keyword. The server name is a single identifier (qualified
        // linked-server names are not valid here).
        let mut stmt_end = args_end;
        let mut at_linked_server_span: Option<Span> = None;
        if let Some(at_tok) = self.peek_non_trivia() {
            if matches!(at_tok.kind, TokenKind::Identifier { .. })
                && at_tok.lexeme(self.source).eq_ignore_ascii_case("AT")
            {
                self.advance(); // consume AT
                let server = self
                    .peek_non_trivia()
                    .ok_or_eof(self.current_span(), vec!["linked server name".to_string()])?;
                if !self.can_be_identifier_token(server) {
                    return Err(ParseError::new(
                        server.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Expected linked server name after AT, found {}",
                                Parser::token_description(server, self.source)
                            ),
                        },
                    ));
                }
                let server_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["linked server name".to_string()])?;
                at_linked_server_span = Some(server_tok.span);
                stmt_end = server_tok.span.end;
            }
        }

        Ok(AstStmt::MssqlExec(Box::new(AstMssqlExec {
            node_id: self.id_gen.next(),
            span: Span {
                start: stmt_start,
                end: stmt_end,
            },
            exec_keyword_span,
            return_var_span: None,
            procedure_name_span: None,
            procedure_base_name_span: None,
            args_span: Some(args_span),
            at_linked_server_span,
            // Dynamic-SQL form: the parenthesised string expression, lifted
            // into a single positional arg when the parser could consume it
            // (empty on fallback).
            args: typed_args,
        })))
    }

    /// Parse the argument list for `EXEC proc_name [args]`.
    ///
    /// Arguments are comma-separated and can be:
    ///   - Positional: `value`
    ///   - Named: `@param = value`
    ///   - With OUTPUT: `@param = @var OUTPUT`
    ///   - DEFAULT keyword
    ///
    /// Returns `None` if there are no arguments. Consumes until `;` or EOF.
    pub(crate) fn parse_mssql_exec_args(
        &mut self,
    ) -> ParseResult<(Option<Span>, Vec<crate::ast::AstCallArg>)> {
        let next = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok((None, Vec::new())),
        };

        // If the next token is a semicolon or statement-starting keyword, no args
        if matches!(next.kind, TokenKind::Punctuation(Punctuation::Semi))
            || matches!(next.kind, TokenKind::Eof)
        {
            return Ok((None, Vec::new()));
        }

        let args_start = next.span.start;
        let mut args_end = next.span.start;
        let mut typed_args: Vec<crate::ast::AstCallArg> = Vec::new();

        // Parse each argument as a typed expression with optional
        // `@name =` / `name =>` prefix. Continue past commas.
        while let Some(tok) = self.peek_non_trivia() {
            // Stop on semicolon / EOF / GO batch separator.
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                || matches!(tok.kind, TokenKind::Eof)
            {
                break;
            }
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok.lexeme(self.source).eq_ignore_ascii_case("GO")
            {
                break;
            }

            let arg_start = tok.span.start;

            // Peek-ahead for named-arg form: `@var =` (with `=` NOT
            // immediately followed by `>` for the named-arg / fat-arrow
            // operator).
            let saved_idx = self.idx;
            let mut name_id: Option<crate::ast::AstIdentifier> = None;
            let mut name_op_span: Option<Span> = None;
            if matches!(
                tok.kind,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::AtVariable
                }
            ) {
                let name_span = tok.span;
                let _ = self.advance();
                if let Some(eq) = self.peek() {
                    if matches!(eq.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                        let eq_span = eq.span;
                        let _ = self.advance();
                        let next_after_eq_is_gt = self
                            .peek()
                            .map(|n| {
                                n.span.start == eq_span.end
                                    && matches!(
                                        n.kind,
                                        TokenKind::Operator(crate::lexer::Operator::Gt)
                                    )
                            })
                            .unwrap_or(false);
                        if !next_after_eq_is_gt {
                            name_id = Some(crate::ast::AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: name_span,
                            });
                            name_op_span = Some(eq_span);
                        } else {
                            self.idx = saved_idx;
                        }
                    } else {
                        self.idx = saved_idx;
                    }
                } else {
                    self.idx = saved_idx;
                }
            }

            let expr = match self.parse_expr() {
                Ok(e) => e,
                Err(_) => {
                    // Expression parser bailed — restore and give up
                    // on typed args; raw span still covers the tail.
                    self.idx = saved_idx;
                    break;
                }
            };
            let mut expr_end = crate::parser::scripting::expr_span_end(&expr);
            // T-SQL trailing modifier keywords (OUTPUT, OUT, READONLY)
            // ride after the expression; absorb into the arg span.
            while let Some(post) = self.peek_non_trivia() {
                let absorb = matches!(post.kind, TokenKind::Keyword(crate::lexer::Keyword::Output))
                    || matches!(post.kind, TokenKind::Identifier { .. }) && {
                        let lex = post.lexeme(self.source);
                        lex.eq_ignore_ascii_case("OUT") || lex.eq_ignore_ascii_case("READONLY")
                    };
                if !absorb {
                    break;
                }
                let consumed = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["modifier".to_string()])?;
                expr_end = consumed.span.end;
            }
            args_end = expr_end;
            typed_args.push(crate::ast::AstCallArg {
                node_id: self.id_gen.next(),
                span: Span {
                    start: arg_start,
                    end: expr_end,
                },
                name: name_id,
                name_op_span,
                value: expr,
            });

            // Continue past comma; otherwise terminate.
            if let Some(comma) = self.peek_non_trivia() {
                if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    let _ = self.advance();
                    continue;
                }
            }
            break;
        }

        if args_end > args_start {
            Ok((
                Some(Span {
                    start: args_start,
                    end: args_end,
                }),
                typed_args,
            ))
        } else {
            Ok((None, typed_args))
        }
    }
}

impl<'a> Parser<'a> {
    /// `EXEC[UTE] AS { LOGIN | USER } = <principal> [WITH NO REVERT |
    /// WITH COOKIE INTO @var]`. Cursor sits on `AS` (EXEC consumed).
    fn parse_mssql_execute_as(&mut self, stmt_start: u32) -> ParseResult<AstStmt> {
        let _as_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;

        // LOGIN | USER
        let kind_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["LOGIN or USER".to_string()])?;
        let kind_lex = kind_tok.lexeme(self.source);
        let principal_kind = if kind_lex.eq_ignore_ascii_case("LOGIN") {
            AstImpersonationPrincipalKind::Login
        } else if kind_lex.eq_ignore_ascii_case("USER") {
            AstImpersonationPrincipalKind::User
        } else {
            return Err(ParseError::new(
                kind_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("expected LOGIN or USER after EXECUTE AS, found {kind_lex}"),
                },
            ));
        };
        let keyword_span = Span {
            start: stmt_start,
            end: kind_tok.span.end,
        };

        // =
        let eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "expected = after EXECUTE AS {}, found {}",
                        kind_lex.to_uppercase(),
                        eq_tok.lexeme(self.source)
                    ),
                },
            ));
        }

        // Principal value: string literal or @variable.
        let principal_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["principal".to_string()])?;
        let principal_span = principal_tok.span;
        let mut end = principal_span.end;

        // Optional WITH clause: NO REVERT | COOKIE INTO @var.
        let mut no_revert = false;
        let mut trailing_span = None;
        if let Some(with_tok) = self.peek_non_trivia() {
            if matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                let with_start = with_tok.span.start;
                self.advance(); // WITH
                let mut with_end = with_tok.span.end;
                // Consume the WITH body up to statement end; flag NO REVERT.
                let mut prev_was_no = false;
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(
                        t.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) {
                        break;
                    }
                    let lex = t.lexeme(self.source);
                    if prev_was_no && lex.eq_ignore_ascii_case("REVERT") {
                        no_revert = true;
                    }
                    prev_was_no = lex.eq_ignore_ascii_case("NO");
                    with_end = t.span.end;
                    self.advance();
                }
                trailing_span = Some(Span {
                    start: with_start,
                    end: with_end,
                });
                end = with_end;
            }
        }

        let ast = AstMssqlExecuteAs {
            node_id: self.id_gen.next(),
            span: Span {
                start: stmt_start,
                end,
            },
            keyword_span,
            principal_kind,
            principal_span,
            no_revert,
            trailing_span,
        };
        Ok(AstStmt::MssqlExecuteAs(Box::new(ast)))
    }

    /// `REVERT [WITH COOKIE = @var]` — ends the most recent EXECUTE AS
    /// context switch. Cursor sits on `REVERT`.
    pub(crate) fn try_parse_mssql_revert_stmt(&mut self) -> ParseResult<AstStmt> {
        let revert_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["REVERT".to_string()])?;
        let start = revert_tok.span.start;
        let mut end = revert_tok.span.end;

        let mut with_cookie_span = None;
        if let Some(with_tok) = self.peek_non_trivia() {
            if matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
                let with_start = with_tok.span.start;
                self.advance(); // WITH
                let mut with_end = with_tok.span.end;
                while let Some(t) = self.peek_non_trivia() {
                    if matches!(
                        t.kind,
                        TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                    ) {
                        break;
                    }
                    with_end = t.span.end;
                    self.advance();
                }
                with_cookie_span = Some(Span {
                    start: with_start,
                    end: with_end,
                });
                end = with_end;
            }
        }

        Ok(AstStmt::MssqlRevert {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            with_cookie_span,
        })
    }
}
