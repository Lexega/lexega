// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE TASK statement parsing
//!
//! Implements parsing for Snowflake CREATE TASK statements,
//! which define scheduled SQL execution:
//!
//! ## Grammar (from Snowflake docs)
//!
//! ```text
//! CREATE [ OR REPLACE ] [ OR ALTER ] TASK [ IF NOT EXISTS ] <name>
//!   [ WAREHOUSE = <string> ]
//!   [ SCHEDULE = '...' ]
//!   [ CONFIG = $$...$$  ]
//!   [ ALLOW_OVERLAPPING_EXECUTION = TRUE|FALSE ]
//!   [ USER_TASK_TIMEOUT_MS = <num> ]
//!   [ SUSPEND_TASK_AFTER_NUM_FAILURES = <num> ]
//!   [ ERROR_INTEGRATION = <string> ]
//!   [ SUCCESS_INTEGRATION = <string> ]
//!   [ LOG_LEVEL = ... ]
//!   [ FINALIZE = <string> ]
//!   [ TASK_AUTO_RETRY_ATTEMPTS = <num> ]
//!   [ USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS = <num> ]
//!   [ TARGET_COMPLETION_INTERVAL = ... ]
//!   [ SERVERLESS_TASK_MIN_STATEMENT_SIZE = ... ]
//!   [ SERVERLESS_TASK_MAX_STATEMENT_SIZE = ... ]
//!   [ USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE = ... ]
//!   [ <session_parameter> = <value> [...] ]
//!   [ COMMENT = '...' ]
//!   [ [ WITH ] TAG ( <tag_name> = '<value>' [ , ... ] ) ]
//!   [ AFTER <task_name> [, ...] ]
//!   [ WHEN <condition> ]
//!   [ EXECUTE AS { OWNER | CALLER | USER <user_name> } ]
//! AS
//!   <sql>
//!
//! Or CLONE variant:
//! CREATE [ OR REPLACE ] TASK [ IF NOT EXISTS ] <name>
//!   CLONE <source_task_name>
//!   [ ... ]
//! ```
//!
//! ## Token Reference
//!
//! | SQL Text | Token Kind | Notes |
//! |----------|------------|-------|
//! | TASK | Identifier | NOT a keyword - check lexeme |
//! | WAREHOUSE | Identifier | Property name |
//! | SCHEDULE | Identifier | Property name |
//! | CONFIG | Identifier | Property name |
//! | FINALIZE | Identifier | Property name |
//! | CLONE | Identifier | NOT a keyword |
//! | USER | Identifier | In EXECUTE AS USER context |
//! | OWNER | Identifier | In EXECUTE AS context |
//! | CALLER | Identifier | In EXECUTE AS context |
//! | ALLOW_OVERLAPPING_EXECUTION | Identifier | Single token |
//! | USER_TASK_TIMEOUT_MS | Identifier | Single token |
//! | USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE | Identifier | Single token |
//! | WHEN | Keyword | Can match TokenKind |
//! | AFTER | Keyword | Can match TokenKind |
//! | WITH | Keyword | For WITH TAG |
//! | TAG | Keyword | For WITH TAG |
//! | AS | Keyword | Before body |
//! | COMMENT | Keyword | Can match TokenKind |
//! | EXECUTE | Keyword | For EXECUTE AS |
//! | TRUE/FALSE | Literal(Boolean) | For boolean props |
//! | '5 MINUTES' | Literal(String) | Schedule values |
//! | $$...$$| Dollar quote tokens | For CONFIG JSON |

use crate::ast::{
    AstAlterTask, AstAlterTaskAction, AstAlterTaskActionKind, AstCreateTask, AstDropTask, AstStmt,
    AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Known task property names (all are Identifiers in lexer).
/// Used for recognizing properties vs session parameters.
const _KNOWN_TASK_PROPERTIES: &[&str] = &[
    "WAREHOUSE",
    "SCHEDULE",
    "CONFIG",
    "ALLOW_OVERLAPPING_EXECUTION",
    "OVERLAP_POLICY",
    "USER_TASK_TIMEOUT_MS",
    "SUSPEND_TASK_AFTER_NUM_FAILURES",
    "ERROR_INTEGRATION",
    "SUCCESS_INTEGRATION",
    "LOG_LEVEL",
    "FINALIZE",
    "TASK_AUTO_RETRY_ATTEMPTS",
    "USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS",
    "TARGET_COMPLETION_INTERVAL",
    "SERVERLESS_TASK_MIN_STATEMENT_SIZE",
    "SERVERLESS_TASK_MAX_STATEMENT_SIZE",
    "USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE",
];

/// Parse CREATE TASK statement.
///
/// Entry point expects parser positioned at CREATE token.
/// Returns parsed AstStmt::CreateTask on success.
pub(crate) fn try_parse_create_task(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume CREATE keyword
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let mut span = create_span;

    // Optional OR REPLACE or OR ALTER
    let mut or_replace_span: Option<Span> = None;
    let mut or_alter_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p
                .advance()
                .expect_invariant("OR keyword consumed after match");
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE keyword consumed after match");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                } else if next.lexeme(p.source).eq_ignore_ascii_case("ALTER") {
                    let alter = p
                        .advance()
                        .expect_invariant("ALTER identifier consumed after lexeme check");
                    or_alter_span = Some(Span {
                        start: or_tok.span.start,
                        end: alter.span.end,
                    });
                    span.end = alter.span.end;
                }
            }
        }
    }

    // TASK keyword (Identifier, NOT a Keyword)
    let task_tok = p
        .peek_non_trivia()
        .ok_or_eof(span, vec!["TASK".to_string()])?;
    if !task_tok.lexeme(p.source).eq_ignore_ascii_case("TASK") {
        return Err(ParseError::new(
            task_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TASK keyword, found '{}'",
                    task_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let task = p
        .advance()
        .expect_invariant("TASK identifier consumed after lexeme check");
    let task_span = task.span;
    span.end = task_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match");
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    let _not = p
                        .advance()
                        .expect_invariant("NOT keyword consumed after match");
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS keyword consumed after match");
                            if_not_exists_span = Some(Span {
                                start: if_tok.span.start,
                                end: exists.span.end,
                            });
                            span.end = exists.span.end;
                        }
                    }
                }
            }
        }
    }

    // Task name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;
    span.end = name_span.end;

    // Initialize all optional spans
    let mut warehouse_span: Option<Span> = None;
    let mut schedule_span: Option<Span> = None;
    let mut config_span: Option<Span> = None;
    let mut allow_overlapping_execution_span: Option<Span> = None;
    let mut overlap_policy_span: Option<Span> = None;
    let mut user_task_timeout_ms_span: Option<Span> = None;
    let mut suspend_task_after_num_failures_span: Option<Span> = None;
    let mut error_integration_span: Option<Span> = None;
    let mut success_integration_span: Option<Span> = None;
    let mut log_level_span: Option<Span> = None;
    let mut finalize_span: Option<Span> = None;
    let mut task_auto_retry_attempts_span: Option<Span> = None;
    let mut user_task_minimum_trigger_interval_span: Option<Span> = None;
    let mut target_completion_interval_span: Option<Span> = None;
    let mut serverless_task_min_span: Option<Span> = None;
    let mut serverless_task_max_span: Option<Span> = None;
    let mut user_task_managed_initial_warehouse_size_span: Option<Span> = None;
    let mut comment_span: Option<Span> = None;
    let mut with_tag_span: Option<Span> = None;
    let mut after_span: Option<Span> = None;
    let mut when_span: Option<Span> = None;
    let mut execute_as_span: Option<Span> = None;
    let mut as_span: Option<Span> = None;
    let mut clone_span: Option<Span> = None;
    let mut session_parameters_spans: Vec<Span> = Vec::new();
    let mut extras: Vec<AstUnknownClause> = Vec::new();

    // Parse options until AS keyword, CLONE, or statement end
    while let Some(tok) = p.peek_non_trivia() {
        // Stop at AS keyword (start of body)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            break;
        }

        // Stop at semicolon
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        let lexeme = &tok.lexeme(p.source);

        // Check for CLONE first (identifier, not keyword)
        if lexeme.eq_ignore_ascii_case("CLONE") {
            clone_span = Some(parse_clone_clause(p)?);
            span.end = clone_span.as_ref().unwrap().end;
            // After CLONE, no body - break out
            break;
        }

        // WHEN keyword - condition clause
        if matches!(tok.kind, TokenKind::Keyword(Keyword::When)) {
            when_span = Some(parse_when_clause(p)?);
            span.end = when_span.as_ref().unwrap().end;
            continue;
        }

        // AFTER keyword - task dependencies
        if matches!(tok.kind, TokenKind::Keyword(Keyword::After)) {
            after_span = Some(parse_after_clause(p)?);
            span.end = after_span.as_ref().unwrap().end;
            continue;
        }

        // WITH keyword - could be WITH TAG
        if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
            with_tag_span = Some(parse_with_tag_clause(p)?);
            span.end = with_tag_span.as_ref().unwrap().end;
            continue;
        }

        // TAG keyword (without WITH)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            with_tag_span = Some(parse_tag_only_clause(p)?);
            span.end = with_tag_span.as_ref().unwrap().end;
            continue;
        }

        // EXECUTE keyword - EXECUTE AS clause
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Execute)) {
            execute_as_span = Some(parse_execute_as_clause(p)?);
            span.end = execute_as_span.as_ref().unwrap().end;
            continue;
        }

        // COMMENT keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            comment_span = Some(parse_property_clause(p)?);
            span.end = comment_span.as_ref().unwrap().end;
            continue;
        }

        // All task properties are Identifiers - check by lexeme
        if lexeme.eq_ignore_ascii_case("WAREHOUSE") {
            warehouse_span = Some(parse_property_clause(p)?);
            span.end = warehouse_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SCHEDULE") {
            schedule_span = Some(parse_property_clause(p)?);
            span.end = schedule_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("CONFIG") {
            config_span = Some(parse_config_clause(p)?);
            span.end = config_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("ALLOW_OVERLAPPING_EXECUTION") {
            allow_overlapping_execution_span = Some(parse_property_clause(p)?);
            span.end = allow_overlapping_execution_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("OVERLAP_POLICY") {
            overlap_policy_span = Some(parse_property_clause(p)?);
            span.end = overlap_policy_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("USER_TASK_TIMEOUT_MS") {
            user_task_timeout_ms_span = Some(parse_property_clause(p)?);
            span.end = user_task_timeout_ms_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SUSPEND_TASK_AFTER_NUM_FAILURES") {
            suspend_task_after_num_failures_span = Some(parse_property_clause(p)?);
            span.end = suspend_task_after_num_failures_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("ERROR_INTEGRATION") {
            error_integration_span = Some(parse_property_clause(p)?);
            span.end = error_integration_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SUCCESS_INTEGRATION") {
            success_integration_span = Some(parse_property_clause(p)?);
            span.end = success_integration_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("LOG_LEVEL") {
            log_level_span = Some(parse_property_clause(p)?);
            span.end = log_level_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("FINALIZE") {
            finalize_span = Some(parse_property_clause(p)?);
            span.end = finalize_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("TASK_AUTO_RETRY_ATTEMPTS") {
            task_auto_retry_attempts_span = Some(parse_property_clause(p)?);
            span.end = task_auto_retry_attempts_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS") {
            user_task_minimum_trigger_interval_span = Some(parse_property_clause(p)?);
            span.end = user_task_minimum_trigger_interval_span
                .as_ref()
                .unwrap()
                .end;
        } else if lexeme.eq_ignore_ascii_case("TARGET_COMPLETION_INTERVAL") {
            target_completion_interval_span = Some(parse_property_clause(p)?);
            span.end = target_completion_interval_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SERVERLESS_TASK_MIN_STATEMENT_SIZE") {
            serverless_task_min_span = Some(parse_property_clause(p)?);
            span.end = serverless_task_min_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("SERVERLESS_TASK_MAX_STATEMENT_SIZE") {
            serverless_task_max_span = Some(parse_property_clause(p)?);
            span.end = serverless_task_max_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE") {
            user_task_managed_initial_warehouse_size_span = Some(parse_property_clause(p)?);
            span.end = user_task_managed_initial_warehouse_size_span
                .as_ref()
                .unwrap()
                .end;
        } else if is_known_session_parameter(lexeme) {
            // Session parameter like TIMEZONE, QUERY_TAG, etc.
            let param_span = parse_property_clause(p)?;
            session_parameters_spans.push(param_span);
            span.end = param_span.end;
        } else {
            // Unknown property - preserve as extra (defensive design)
            let introducer_span = tok.span;
            let prop_span = parse_property_clause(p)?;
            extras.push(AstUnknownClause {
                node_id: p.id_gen.next(),
                introducer: Some(introducer_span),
                span: prop_span,
                kind: UnknownKind::Property,
            });
            span.end = prop_span.end;
        }
    }

    // Handle body (AS <sql>) or CLONE
    let mut body: Option<Result<Box<AstStmt>, Span>> = None;

    if clone_span.is_none() {
        // Expect AS keyword and body
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                let as_tok = p
                    .advance()
                    .expect_invariant("AS keyword consumed after match");
                as_span = Some(as_tok.span);
                span.end = as_tok.span.end;

                // Parse the SQL statement body
                match p.parse_statement() {
                    Ok(stmt) => {
                        span.end = stmt.span().end;
                        body = Some(Ok(Box::new(stmt)));
                    }
                    Err(_) => {
                        // Capture unparseable body as span
                        let body_start = p.current_span().start;
                        let body_end = skip_to_statement_end(p);
                        body = Some(Err(Span {
                            start: body_start,
                            end: body_end,
                        }));
                        span.end = body_end;
                    }
                }
            } else if !matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                // Not AS, not semicolon - error
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "CREATE TASK requires AS <sql> or CLONE <source>".to_string(),
                    },
                ));
            }
        }
    }

    let node = AstCreateTask {
        node_id: p.id_gen.next(),
        span,
        create_span,
        or_replace_span,
        or_alter_span,
        task_span,
        if_not_exists_span,
        name_span,
        warehouse_span,
        schedule_span,
        config_span,
        allow_overlapping_execution_span,
        overlap_policy_span,
        user_task_timeout_ms_span,
        suspend_task_after_num_failures_span,
        error_integration_span,
        success_integration_span,
        log_level_span,
        finalize_span,
        task_auto_retry_attempts_span,
        user_task_minimum_trigger_interval_span,
        target_completion_interval_span,
        serverless_task_min_span,
        serverless_task_max_span,
        user_task_managed_initial_warehouse_size_span,
        comment_span,
        session_parameters_spans,
        with_tag_span,
        after_span,
        when_span,
        execute_as_span,
        as_span,
        body,
        clone_span,
        extras,
    };

    Ok(AstStmt::CreateTask(Box::new(node)))
}

/// Skip to statement end (semicolon or EOF), return end position
fn skip_to_statement_end(p: &mut Parser<'_>) -> u32 {
    let mut end = p.current_span().end;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed during skip_to_statement_end");
        end = t.span.end;
    }
    end
}

/// Skip to matching closing paren, return end position
fn skip_to_matching_paren(p: &mut Parser<'_>) -> ParseResult<u32> {
    let mut depth = 1;
    while let Some(tok) = p.advance() {
        match tok.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(tok.span.end);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::new(
        p.current_span(),
        ParseErrorKind::InvalidStatement {
            message: "Unmatched parenthesis".to_string(),
        },
    ))
}

/// Parse KEY = VALUE clause, return span covering entire clause
fn parse_property_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let key_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;
    let start = key_tok.span.start;
    let mut end = key_tok.span.end;

    // Expect =
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            let eq = p
                .advance()
                .expect_invariant("= operator consumed after match in parse_property_clause");
            end = eq.span.end;

            // Value (could be string, identifier, number, boolean, or parenthesized)
            if let Some(val) = p.peek_non_trivia() {
                if matches!(val.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                } else {
                    let v = p.advance().expect_invariant(
                        "property value consumed after peek in parse_property_clause",
                    );
                    end = v.span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse CONFIG = $$...$$  clause (handles dollar-quoted JSON)
///
/// CONFIG values are typically dollar-quoted strings containing JSON.
/// The lexer tokenizes the entire dollar-quoted content as a single string literal.
fn parse_config_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let key_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CONFIG".to_string()])?;
    let start = key_tok.span.start;
    let mut end = key_tok.span.end;

    // Expect =
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            let eq = p
                .advance()
                .expect_invariant("= operator consumed after match in parse_config_clause");
            end = eq.span.end;

            // The value should be a single token (dollar-quoted string or regular string)
            if let Some(val) = p.peek_non_trivia() {
                // Dollar-quoted strings are tokenized as Literal(String) by the lexer
                // Just consume the next token as the value
                if matches!(val.kind, TokenKind::Literal(_)) {
                    let v = p
                        .advance()
                        .expect_invariant("CONFIG value literal consumed after match");
                    end = v.span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse CLONE <source_task_name> clause
fn parse_clone_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let clone_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CLONE".to_string()])?;
    let start = clone_tok.span.start;

    // Parse source task name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    Ok(Span {
        start,
        end: name_span.end,
    })
}

/// Parse AFTER task1 [, task2, ...] clause
fn parse_after_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let after_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AFTER".to_string()])?;
    let start = after_tok.span.start;
    let mut end;

    // Parse first task name
    let name_span = p.parse_qualified_name_span()?;
    end = name_span.end;

    // Parse additional comma-separated task names
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
            let _ = p
                .advance()
                .expect_invariant("comma consumed after match in parse_after_clause");
            let next_name = p.parse_qualified_name_span()?;
            end = next_name.end;
        } else {
            break;
        }
    }

    Ok(Span { start, end })
}

/// Parse WHEN <condition> clause
fn parse_when_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let when_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WHEN".to_string()])?;
    let start = when_tok.span.start;
    let mut end = when_tok.span.end;

    // Parse condition expression until AS, semicolon, or statement end
    // The condition can be complex (function calls, parens, etc.)
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            break;
        }
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            p.advance();
            end = skip_to_matching_paren(p)?;
        } else {
            let t = p
                .advance()
                .expect_invariant("condition token consumed during parse_when_clause");
            end = t.span.end;
        }
    }

    Ok(Span { start, end })
}

/// Parse [WITH] TAG (...) clause
fn parse_with_tag_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let with_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WITH".to_string()])?;
    let start = with_tok.span.start;
    let mut end = with_tok.span.end;

    // Expect TAG
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            let tag = p
                .advance()
                .expect_invariant("TAG keyword consumed after match in parse_with_tag_clause");
            end = tag.span.end;

            // Expect (...)
            if let Some(lparen) = p.peek_non_trivia() {
                if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Parse TAG (...) clause (without WITH prefix)
fn parse_tag_only_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let tag_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TAG".to_string()])?;
    let start = tag_tok.span.start;
    let mut end = tag_tok.span.end;

    // Expect (...)
    if let Some(lparen) = p.peek_non_trivia() {
        if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            p.advance();
            end = skip_to_matching_paren(p)?;
        }
    }

    Ok(Span { start, end })
}

/// Parse EXECUTE AS { OWNER | CALLER | USER <username> } clause
fn parse_execute_as_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let execute_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["EXECUTE".to_string()])?;
    let start = execute_tok.span.start;
    let mut end = execute_tok.span.end;

    // Expect AS
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_tok = p
                .advance()
                .expect_invariant("AS keyword consumed after match in parse_execute_as_clause");
            end = as_tok.span.end;

            // Expect OWNER, CALLER, or USER (all are Identifiers)
            if let Some(mode) = p.peek_non_trivia() {
                let mode_lexeme = &mode.lexeme(p.source);
                if mode_lexeme.eq_ignore_ascii_case("OWNER")
                    || mode_lexeme.eq_ignore_ascii_case("CALLER")
                {
                    let m = p
                        .advance()
                        .expect_invariant("OWNER/CALLER identifier consumed after lexeme check");
                    end = m.span.end;
                } else if mode_lexeme.eq_ignore_ascii_case("USER") {
                    let user_tok = p
                        .advance()
                        .expect_invariant("USER identifier consumed after lexeme check");
                    let _user_end = user_tok.span.end;
                    // Expect user name
                    let name_span = p.parse_qualified_name_span()?;
                    end = name_span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Check if identifier is a known Snowflake session parameter
fn is_known_session_parameter(lexeme: &str) -> bool {
    // Common session parameters that might appear in TASK definitions
    let session_params = [
        "TIMEZONE",
        "QUERY_TAG",
        "STATEMENT_TIMEOUT_IN_SECONDS",
        "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS",
        "LOCK_TIMEOUT",
        "TRANSACTION_DEFAULT_ISOLATION_LEVEL",
        "TWO_DIGIT_CENTURY_START",
        "DATE_INPUT_FORMAT",
        "DATE_OUTPUT_FORMAT",
        "TIME_INPUT_FORMAT",
        "TIME_OUTPUT_FORMAT",
        "TIMESTAMP_INPUT_FORMAT",
        "TIMESTAMP_OUTPUT_FORMAT",
        "TIMESTAMP_NTZ_OUTPUT_FORMAT",
        "TIMESTAMP_LTZ_OUTPUT_FORMAT",
        "TIMESTAMP_TZ_OUTPUT_FORMAT",
        "TIMESTAMP_TYPE_MAPPING",
        "WEEK_START",
        "WEEK_OF_YEAR_POLICY",
        "BINARY_INPUT_FORMAT",
        "BINARY_OUTPUT_FORMAT",
        "GEOGRAPHY_OUTPUT_FORMAT",
        "GEOMETRY_OUTPUT_FORMAT",
        "JSON_INDENT",
        "QUOTED_IDENTIFIERS_IGNORE_CASE",
        "ROWS_PER_RESULTSET",
        "ERROR_ON_NONDETERMINISTIC_MERGE",
        "ERROR_ON_NONDETERMINISTIC_UPDATE",
        "AUTOCOMMIT",
        "STRICT_JSON_OUTPUT",
        "ENABLE_UNLOAD_PHYSICAL_TYPE_OPTIMIZATION",
        "CLIENT_TIMESTAMP_TYPE_MAPPING",
        "CLIENT_RESULT_CHUNK_SIZE",
        "CLIENT_PREFETCH_THREADS",
        "CLIENT_SESSION_KEEP_ALIVE",
        "ABORT_DETACHED_QUERY",
        "USE_CACHED_RESULT",
        "MULTI_STATEMENT_COUNT",
        "CLIENT_METADATA_REQUEST_USE_CONNECTION_CTX",
        "QUERY_RESULT_FORMAT",
        "S3_STAGE_VPCE_DNS_NAME",
        "SEARCH_PATH",
        "PARSE_JSON_STRINGS_AS_DOUBLE",
    ];

    session_params
        .iter()
        .any(|&p| lexeme.eq_ignore_ascii_case(p))
}

// ============================================================================
// DROP TASK
// ============================================================================

/// Parse DROP TASK statement.
///
/// Syntax: DROP TASK [IF EXISTS] <name>
///
/// Entry point expects parser positioned at DROP token.
pub(crate) fn try_parse_drop_task(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume DROP keyword
    let drop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let drop_span = drop_tok.span;

    // TASK keyword (Identifier, NOT Keyword)
    let task_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TASK".to_string()])?;
    if !task_tok.lexeme(p.source).eq_ignore_ascii_case("TASK") {
        return Err(ParseError::new(
            task_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TASK keyword, found '{}'",
                    task_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let task_span = task_tok.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match in try_parse_drop_task");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant(
                        "EXISTS keyword consumed after match in try_parse_drop_task",
                    );
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                }
            }
        }
    }

    // Task name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Statement span
    let stmt_span = Span {
        start: drop_span.start,
        end: name_span.end,
    };

    let node = AstDropTask {
        node_id: p.id_gen.next(),
        span: stmt_span,
        drop_span,
        task_span,
        if_exists_span,
        name_span,
    };

    Ok(AstStmt::DropTask(Box::new(node)))
}

// ============================================================================
// ALTER TASK
// ============================================================================

/// Parse ALTER TASK statement.
///
/// Syntax: ALTER TASK [IF EXISTS] <name> <action>
///
/// Entry point expects parser positioned at ALTER token.
pub(crate) fn try_parse_alter_task(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume ALTER keyword
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;

    // TASK keyword (Identifier, NOT Keyword)
    let task_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TASK".to_string()])?;
    if !task_tok.lexeme(p.source).eq_ignore_ascii_case("TASK") {
        return Err(ParseError::new(
            task_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TASK keyword, found '{}'",
                    task_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let task_span = task_tok.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match in try_parse_alter_task");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant(
                        "EXISTS keyword consumed after match in try_parse_alter_task",
                    );
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                }
            }
        }
    }

    // Task name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Parse the action
    let (action, extras) = parse_alter_task_action(p)?;
    let action_span = action.span;

    // Statement span
    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };

    let node = AstAlterTask {
        node_id: p.id_gen.next(),
        span: stmt_span,
        alter_span,
        task_span,
        if_exists_span,
        name_span,
        action_span,
        action,
        extras,
    };

    Ok(AstStmt::AlterTask(Box::new(node)))
}

/// Parse the action part of ALTER TASK
fn parse_alter_task_action(
    p: &mut Parser<'_>,
) -> ParseResult<(AstAlterTaskAction, Vec<AstUnknownClause>)> {
    let mut extras: Vec<AstUnknownClause> = Vec::new();

    let tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["action".to_string()])?;

    let action_start = tok.span.start;

    // Dispatch based on action type
    let kind = if tok.lexeme(p.source).eq_ignore_ascii_case("RESUME") {
        // RESUME
        let resume_tok = p
            .advance()
            .expect_invariant("RESUME identifier consumed after lexeme check");
        AstAlterTaskActionKind::Resume {
            resume_span: resume_tok.span,
        }
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("SUSPEND") {
        // SUSPEND
        let suspend_tok = p
            .advance()
            .expect_invariant("SUSPEND identifier consumed after lexeme check");
        AstAlterTaskActionKind::Suspend {
            suspend_span: suspend_tok.span,
        }
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("ADD") {
        // ADD AFTER <task> [, <task>, ...]
        parse_add_after_action(p)?
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("REMOVE") {
        // REMOVE AFTER or REMOVE WHEN
        parse_remove_action(p)?
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
        // SET ...
        parse_set_action(p, &mut extras)?
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset)) {
        // UNSET ...
        parse_unset_action(p)?
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("MODIFY") {
        // MODIFY AS or MODIFY WHEN
        parse_modify_action(p)?
    } else {
        // Unknown action - preserve as extra
        let unknown_span = skip_to_statement_end_span(p);
        extras.push(AstUnknownClause {
            node_id: p.id_gen.next(),
            introducer: Some(tok.span),
            span: unknown_span,
            kind: UnknownKind::Clause,
        });
        // Return a dummy resume action (will be overridden by extras)
        AstAlterTaskActionKind::Resume {
            resume_span: unknown_span,
        }
    };

    let _action_end = p.current_span().start.saturating_sub(1).max(action_start);
    let action_span = Span {
        start: action_start,
        end: match &kind {
            AstAlterTaskActionKind::Resume { resume_span } => resume_span.end,
            AstAlterTaskActionKind::Suspend { suspend_span } => suspend_span.end,
            AstAlterTaskActionKind::AddAfter {
                task_names_span, ..
            } => task_names_span.end,
            AstAlterTaskActionKind::RemoveAfter {
                task_names_span, ..
            } => task_names_span.end,
            AstAlterTaskActionKind::Set {
                properties_span, ..
            } => properties_span.end,
            AstAlterTaskActionKind::SetTag {
                assignments_span, ..
            } => assignments_span.end,
            AstAlterTaskActionKind::SetFinalize { value_span, .. } => value_span.end,
            AstAlterTaskActionKind::Unset {
                properties_span, ..
            } => properties_span.end,
            AstAlterTaskActionKind::UnsetTag { tags_span, .. } => tags_span.end,
            AstAlterTaskActionKind::UnsetFinalize { finalize_span, .. } => finalize_span.end,
            AstAlterTaskActionKind::ModifyAs { body, .. } => match body {
                Ok(stmt) => stmt.span().end,
                Err(span) => span.end,
            },
            AstAlterTaskActionKind::ModifyWhen { condition_span, .. } => condition_span.end,
            AstAlterTaskActionKind::RemoveWhen { when_span, .. } => when_span.end,
        },
    };

    let action = AstAlterTaskAction {
        node_id: p.id_gen.next(),
        span: action_span,
        kind,
    };

    Ok((action, extras))
}

/// Parse ADD AFTER action
fn parse_add_after_action(p: &mut Parser<'_>) -> ParseResult<AstAlterTaskActionKind> {
    // ADD
    let add_tok = p
        .advance()
        .expect_invariant("ADD identifier consumed after lexeme check");
    let add_span = add_tok.span;

    // AFTER (Keyword)
    let after_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AFTER".to_string()])?;
    if !matches!(after_tok.kind, TokenKind::Keyword(Keyword::After)) {
        return Err(ParseError::new(
            after_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AFTER keyword, found '{}'",
                    after_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let after_span = after_tok.span;

    // Parse task names (comma-separated)
    let names_start = p.current_span().start;
    let mut names_end;

    loop {
        let name_span = p.parse_qualified_name_span()?;
        names_end = name_span.end;

        // Check for comma
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterTaskActionKind::AddAfter {
        add_span,
        after_span,
        task_names_span: Span {
            start: names_start,
            end: names_end,
        },
    })
}

/// Parse REMOVE action (REMOVE AFTER or REMOVE WHEN)
fn parse_remove_action(p: &mut Parser<'_>) -> ParseResult<AstAlterTaskActionKind> {
    // REMOVE
    let remove_tok = p
        .advance()
        .expect_invariant("REMOVE identifier consumed after lexeme check");
    let remove_span = remove_tok.span;

    let next = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["AFTER or WHEN".to_string()])?;

    if matches!(next.kind, TokenKind::Keyword(Keyword::After)) {
        // REMOVE AFTER <task> [, <task>, ...]
        let after_tok = p
            .advance()
            .expect_invariant("AFTER keyword consumed after match in parse_remove_action");
        let after_span = after_tok.span;

        // Parse task names
        let names_start = p.current_span().start;
        let mut names_end;

        loop {
            let name_span = p.parse_qualified_name_span()?;
            names_end = name_span.end;

            if let Some(tok) = p.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    p.advance();
                    continue;
                }
            }
            break;
        }

        Ok(AstAlterTaskActionKind::RemoveAfter {
            remove_span,
            after_span,
            task_names_span: Span {
                start: names_start,
                end: names_end,
            },
        })
    } else if matches!(next.kind, TokenKind::Keyword(Keyword::When)) {
        // REMOVE WHEN
        let when_tok = p
            .advance()
            .expect_invariant("WHEN keyword consumed after match in parse_remove_action");
        let when_span = when_tok.span;

        Ok(AstAlterTaskActionKind::RemoveWhen {
            remove_span,
            when_span,
        })
    } else {
        Err(ParseError::new(
            next.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AFTER or WHEN after REMOVE, found '{}'",
                    next.lexeme(p.source)
                ),
            },
        ))
    }
}

/// Parse SET action
fn parse_set_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<AstAlterTaskActionKind> {
    // SET
    let set_tok = p
        .advance()
        .expect_invariant("SET keyword consumed after match");
    let set_span = set_tok.span;

    let next = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;

    // SET TAG
    if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
        let tag_tok = p
            .advance()
            .expect_invariant("TAG keyword consumed after match in parse_set_action");
        let tag_span = tag_tok.span;

        // Parse tag assignments
        let assignments_span = parse_tag_assignments(p)?;

        return Ok(AstAlterTaskActionKind::SetTag {
            set_span,
            tag_span,
            assignments_span,
        });
    }

    // SET FINALIZE = <task>
    if next.lexeme(p.source).eq_ignore_ascii_case("FINALIZE") {
        let finalize_tok = p.advance().expect_invariant(
            "FINALIZE identifier consumed after lexeme check in parse_set_action",
        );
        let finalize_span = finalize_tok.span;

        // Expect =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '=' after FINALIZE".to_string(),
                },
            ));
        }

        // Parse root task name
        let value_span = p.parse_qualified_name_span()?;

        return Ok(AstAlterTaskActionKind::SetFinalize {
            set_span,
            finalize_span,
            value_span,
        });
    }

    // SET <property> = <value> [...]
    let properties_start = next.span.start;
    let mut properties_end = properties_start;

    while let Some(tok) = p.peek_non_trivia() {
        // Stop at semicolon
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        // Parse property assignment (name = value)
        let prop_span = parse_alter_task_property(p, extras)?;
        properties_end = prop_span.end;
    }

    Ok(AstAlterTaskActionKind::Set {
        set_span,
        properties_span: Span {
            start: properties_start,
            end: properties_end,
        },
    })
}

/// Parse UNSET action
fn parse_unset_action(p: &mut Parser<'_>) -> ParseResult<AstAlterTaskActionKind> {
    // UNSET
    let unset_tok = p
        .advance()
        .expect_invariant("UNSET keyword consumed after match");
    let unset_span = unset_tok.span;

    let next = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;

    // UNSET TAG
    if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
        let tag_tok = p
            .advance()
            .expect_invariant("TAG keyword consumed after match in parse_unset_action");
        let tag_span = tag_tok.span;

        // Parse tag names (comma-separated identifiers)
        let tags_start = p.current_span().start;
        let mut tags_end;

        loop {
            let tag_name_span = p.parse_qualified_name_span()?;
            tags_end = tag_name_span.end;

            if let Some(tok) = p.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    p.advance();
                    continue;
                }
            }
            break;
        }

        return Ok(AstAlterTaskActionKind::UnsetTag {
            unset_span,
            tag_span,
            tags_span: Span {
                start: tags_start,
                end: tags_end,
            },
        });
    }

    // UNSET FINALIZE
    if next.lexeme(p.source).eq_ignore_ascii_case("FINALIZE") {
        let finalize_tok = p.advance().expect_invariant(
            "FINALIZE identifier consumed after lexeme check in parse_unset_action",
        );
        let finalize_span = finalize_tok.span;

        return Ok(AstAlterTaskActionKind::UnsetFinalize {
            unset_span,
            finalize_span,
        });
    }

    // UNSET <property> [, <property>, ...]
    let properties_start = next.span.start;
    let mut properties_end = properties_start;

    while let Some(tok) = p.peek_non_trivia() {
        // Stop at semicolon
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        // Consume property name
        let prop_tok = p
            .advance()
            .expect_invariant("property name consumed during UNSET property list");
        properties_end = prop_tok.span.end;

        // Check for comma
        if let Some(comma) = p.peek_non_trivia() {
            if matches!(comma.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterTaskActionKind::Unset {
        unset_span,
        properties_span: Span {
            start: properties_start,
            end: properties_end,
        },
    })
}

/// Parse MODIFY action (MODIFY AS or MODIFY WHEN)
fn parse_modify_action(p: &mut Parser<'_>) -> ParseResult<AstAlterTaskActionKind> {
    // MODIFY
    let modify_tok = p
        .advance()
        .expect_invariant("MODIFY identifier consumed after lexeme check");
    let modify_span = modify_tok.span;

    let next = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["AS or WHEN".to_string()])?;

    if matches!(next.kind, TokenKind::Keyword(Keyword::As)) {
        // MODIFY AS <sql>
        let as_tok = p
            .advance()
            .expect_invariant("AS keyword consumed after match in parse_modify_action");
        let as_span = as_tok.span;

        // Parse the SQL statement body
        match p.parse_statement() {
            Ok(stmt) => Ok(AstAlterTaskActionKind::ModifyAs {
                modify_span,
                as_span,
                body: Ok(Box::new(stmt)),
            }),
            Err(_) => {
                // Capture unparseable body as span
                let body_span = skip_to_statement_end_span(p);
                Ok(AstAlterTaskActionKind::ModifyAs {
                    modify_span,
                    as_span,
                    body: Err(body_span),
                })
            }
        }
    } else if matches!(next.kind, TokenKind::Keyword(Keyword::When)) {
        // MODIFY WHEN <condition>
        let when_tok = p
            .advance()
            .expect_invariant("WHEN keyword consumed after match in parse_modify_action");
        let when_span = when_tok.span;

        // Parse condition until semicolon (function call like SYSTEM$STREAM_HAS_DATA)
        let condition_start = p.current_span().start;
        let condition_end = skip_to_statement_end_pos(p);

        Ok(AstAlterTaskActionKind::ModifyWhen {
            modify_span,
            when_span,
            condition_span: Span {
                start: condition_start,
                end: condition_end,
            },
        })
    } else {
        Err(ParseError::new(
            next.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AS or WHEN after MODIFY, found '{}'",
                    next.lexeme(p.source)
                ),
            },
        ))
    }
}

/// Parse tag assignments: tag_name = 'value' [, ...]
fn parse_tag_assignments(p: &mut Parser<'_>) -> ParseResult<Span> {
    let start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let _tag_name_span = p.parse_qualified_name_span()?;

        // =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected '=' in tag assignment".to_string(),
                },
            ));
        }

        // Value
        let value_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["tag value".to_string()])?;
        end = value_tok.span.end;

        // Check for comma
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(Span { start, end })
}

/// Parse a single property assignment for ALTER TASK SET
fn parse_alter_task_property(
    p: &mut Parser<'_>,
    _extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<Span> {
    let tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["property name".to_string()])?;
    let start = tok.span.start;
    let mut end = tok.span.end;

    // Expect =
    if let Some(eq) = p.peek_non_trivia() {
        if matches!(eq.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
            p.advance();

            // Parse value (could be string, number, boolean, or identifier)
            if let Some(val) = p.peek_non_trivia() {
                // Handle parenthesized values like (ON_ERROR='skip_file')
                if matches!(val.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                } else {
                    let val_tok = p.advance().expect_invariant(
                        "property value consumed after peek in parse_alter_task_property",
                    );
                    end = val_tok.span.end;
                }
            }
        }
    }

    Ok(Span { start, end })
}

/// Skip to statement end and return span
fn skip_to_statement_end_span(p: &mut Parser<'_>) -> Span {
    let start = p.current_span().start;
    let end = skip_to_statement_end_pos(p);
    Span { start, end }
}

/// Skip to statement end (semicolon or EOF), return end position
fn skip_to_statement_end_pos(p: &mut Parser<'_>) -> u32 {
    let mut end = p.current_span().end;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed during skip_to_statement_end_pos");
        end = t.span.end;
    }
    end
}
