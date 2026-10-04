// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for ALTER PROCEDURE statements.
//!
//! Syntax:
//! ```text
//! ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) <action>
//! ```
//!
//! Actions:
//!   - `RENAME TO <new_name>`
//!   - `SET <property> = <value> [, ...]`
//!   - UNSET COMMENT
//!   - `SET TAG <name> = <value> [, ...] / UNSET TAG <name> [, ...]`
//!   - EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }

use crate::ast::types::{AstUnknownClause, ExecuteAsMode, UnknownKind};
use crate::ast::AstStmt;
use crate::ast::{AstAlterProcedure, AstAlterProcedureAction, AstAlterProcedureActionKind};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

// Reuse helpers from alter_function
use super::alter_function::{consume_balanced_parens, parse_signature_type_list};

/// Parse ALTER PROCEDURE statement.
///
/// Entry point expects parser positioned at ALTER token.
/// Returns parsed AstStmt::AlterProcedure on success.
pub(crate) fn try_parse_alter_procedure(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("alter_procedure")?;

    // ALTER
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;

    // PROCEDURE
    let procedure_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["PROCEDURE".to_string()])?;
    if !matches!(procedure_tok.kind, TokenKind::Keyword(Keyword::Procedure)) {
        return Err(ParseError::new(
            procedure_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected PROCEDURE after ALTER, found '{}'",
                    procedure_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let procedure_span = procedure_tok.span;

    // Optional IF EXISTS
    let if_exists_span = parse_if_exists_ap(p)?;

    // Procedure name (qualified name)
    let name_span = p.parse_qualified_name_span()?;

    // Signature: (type, type, ...)
    let signature_span = parse_signature_type_list(p)?;

    // Parse action
    let mut extras: Vec<AstUnknownClause> = Vec::new();
    let action = parse_alter_procedure_action(p, &mut extras)?;
    let action_span = action.span;

    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };

    Ok(AstStmt::AlterProcedure(Box::new(AstAlterProcedure {
        node_id: p.id_gen.next(),
        span: stmt_span,
        alter_span,
        procedure_span,
        if_exists_span,
        name_span,
        signature_span,
        action_span,
        action,
        extras,
    })))
}

/// Parse optional IF EXISTS clause.
fn parse_if_exists_ap(p: &mut Parser<'_>) -> ParseResult<Option<Span>> {
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF consumed after kind check");

            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let e = p
                        .advance()
                        .expect_invariant("EXISTS consumed after kind check");
                    return Ok(Some(Span {
                        start: if_tok.span.start,
                        end: e.span.end,
                    }));
                }
            }

            return Err(ParseError::new(
                if_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "ALTER PROCEDURE IF requires EXISTS".to_string(),
                },
            ));
        }
    }
    Ok(None)
}

/// Parse ALTER PROCEDURE action.
fn parse_alter_procedure_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<AstAlterProcedureAction> {
    let action_start = p.current_span().start;

    let kind = if let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Keyword(Keyword::Rename) => parse_rename_action_proc(p)?,
            TokenKind::Keyword(Keyword::Set) => parse_set_action_procedure(p)?,
            TokenKind::Keyword(Keyword::Unset) => parse_unset_action_procedure(p)?,
            TokenKind::Keyword(Keyword::Execute) => parse_execute_as_action(p)?,
            _ => {
                // Unknown action - consume to end of statement
                let span = consume_to_statement_end_proc(p, action_start)?;
                extras.push(AstUnknownClause {
                    node_id: p.id_gen.next(),
                    introducer: None,
                    span,
                    kind: UnknownKind::Clause,
                });
                AstAlterProcedureActionKind::Unknown { span }
            }
        }
    } else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected action (RENAME, SET, UNSET, or EXECUTE AS)".to_string(),
            },
        ));
    };

    let action_span = Span {
        start: action_start,
        end: get_action_end_proc(&kind),
    };

    Ok(AstAlterProcedureAction {
        node_id: p.id_gen.next(),
        span: action_span,
        kind,
    })
}

/// Get the end position of a procedure action.
fn get_action_end_proc(kind: &AstAlterProcedureActionKind) -> u32 {
    match kind {
        AstAlterProcedureActionKind::RenameTo { new_name_span, .. } => new_name_span.end,
        AstAlterProcedureActionKind::SetSecure { secure_span, .. } => secure_span.end,
        AstAlterProcedureActionKind::UnsetSecure { secure_span, .. } => secure_span.end,
        AstAlterProcedureActionKind::SetProperties {
            properties_span, ..
        } => properties_span.end,
        AstAlterProcedureActionKind::UnsetComment { comment_span, .. } => comment_span.end,
        AstAlterProcedureActionKind::SetTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterProcedureActionKind::UnsetTag { tags_span, .. } => tags_span.end,
        AstAlterProcedureActionKind::ExecuteAs { mode_span, .. } => mode_span.end,
        AstAlterProcedureActionKind::Unknown { span } => span.end,
    }
}

/// Parse RENAME TO action.
fn parse_rename_action_proc(p: &mut Parser<'_>) -> ParseResult<AstAlterProcedureActionKind> {
    let rename_tok = p.advance().expect_invariant("RENAME verified by caller");
    let rename_span = rename_tok.span;

    let to_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TO".to_string()])?;
    if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
        return Err(ParseError::new(
            to_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected TO after RENAME".to_string(),
            },
        ));
    }
    let to_span = to_tok.span;

    let new_name_span = p.parse_qualified_name_span()?;

    Ok(AstAlterProcedureActionKind::RenameTo {
        rename_span,
        to_span,
        new_name_span,
    })
}

/// Parse SET action for procedure.
fn parse_set_action_procedure(p: &mut Parser<'_>) -> ParseResult<AstAlterProcedureActionKind> {
    let set_tok = p.advance().expect_invariant("SET verified by caller");
    let set_span = set_tok.span;

    if let Some(tok) = p.peek_non_trivia() {
        // SET SECURE (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Secure)) {
            let secure = p
                .advance()
                .expect_invariant("SECURE consumed after kind check");
            return Ok(AstAlterProcedureActionKind::SetSecure {
                set_span,
                secure_span: secure.span,
            });
        }
        // SET TAG (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return parse_set_tag_action_proc(p, set_span);
        }
        // SET <property> = <value> (Identifier or keyword used as identifier: COMMENT, LOG_LEVEL, etc.)
        if p.can_be_identifier_token(tok) {
            return parse_set_properties_proc(p, set_span);
        }
    }

    Err(ParseError::new(
        set_span,
        ParseErrorKind::InvalidStatement {
            message: "Expected TAG or property name after SET".to_string(),
        },
    ))
}

/// Parse UNSET action for procedure.
fn parse_unset_action_procedure(p: &mut Parser<'_>) -> ParseResult<AstAlterProcedureActionKind> {
    let unset_tok = p.advance().expect_invariant("UNSET verified by caller");
    let unset_span = unset_tok.span;

    if let Some(tok) = p.peek_non_trivia() {
        // UNSET SECURE (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Secure)) {
            let secure = p
                .advance()
                .expect_invariant("SECURE consumed after kind check");
            return Ok(AstAlterProcedureActionKind::UnsetSecure {
                unset_span,
                secure_span: secure.span,
            });
        }
        // UNSET TAG (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return parse_unset_tag_action_proc(p, unset_span);
        }
        // UNSET COMMENT (Identifier or keyword used as identifier)
        if p.can_be_identifier_token(tok) {
            let comment_tok = p
                .advance()
                .expect_invariant("property name consumed after kind check");
            return Ok(AstAlterProcedureActionKind::UnsetComment {
                unset_span,
                comment_span: comment_tok.span,
            });
        }
    }

    Err(ParseError::new(
        unset_span,
        ParseErrorKind::InvalidStatement {
            message: "Expected TAG or COMMENT after UNSET".to_string(),
        },
    ))
}

/// Parse EXECUTE AS action.
///
/// Syntax: EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }
/// All tokens are Keywords.
fn parse_execute_as_action(p: &mut Parser<'_>) -> ParseResult<AstAlterProcedureActionKind> {
    let execute_tok = p.advance().expect_invariant("EXECUTE verified by caller");
    let execute_span = execute_tok.span;

    // AS
    let as_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AS".to_string()])?;
    if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
        return Err(ParseError::new(
            as_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected AS after EXECUTE".to_string(),
            },
        ));
    }
    let as_span = as_tok.span;

    // Mode: OWNER | CALLER | RESTRICTED CALLER
    let mode_tok = p.advance().ok_or_eof(
        p.current_span(),
        vec!["OWNER, CALLER, or RESTRICTED".to_string()],
    )?;

    let (mode, mode_span) = if matches!(mode_tok.kind, TokenKind::Keyword(Keyword::Owner)) {
        (ExecuteAsMode::Owner, mode_tok.span)
    } else if matches!(mode_tok.kind, TokenKind::Keyword(Keyword::Caller)) {
        (ExecuteAsMode::Caller, mode_tok.span)
    } else if matches!(mode_tok.kind, TokenKind::Keyword(Keyword::Restricted)) {
        // RESTRICTED CALLER - need to consume CALLER too
        let caller_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["CALLER".to_string()])?;
        if !matches!(caller_tok.kind, TokenKind::Keyword(Keyword::Caller)) {
            return Err(ParseError::new(
                caller_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected CALLER after RESTRICTED".to_string(),
                },
            ));
        }
        (
            ExecuteAsMode::RestrictedCaller,
            Span {
                start: mode_tok.span.start,
                end: caller_tok.span.end,
            },
        )
    } else {
        return Err(ParseError::new(
            mode_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected OWNER, CALLER, or RESTRICTED CALLER, found '{}'",
                    mode_tok.lexeme(p.source)
                ),
            },
        ));
    };

    Ok(AstAlterProcedureActionKind::ExecuteAs {
        execute_span,
        as_span,
        mode,
        mode_span,
    })
}

/// Parse SET TAG action for procedure.
fn parse_set_tag_action_proc(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterProcedureActionKind> {
    let tag_tok = p.advance().expect_invariant("TAG verified by caller");
    let tag_span = tag_tok.span;

    // Parse tag assignments: name = 'value' [, ...]
    let assignments_start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let _tag_name_span = p.parse_qualified_name_span()?;

        // =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected = after tag name".to_string(),
                },
            ));
        }

        // Value (string literal)
        let value_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["tag value".to_string()])?;
        end = value_tok.span.end;

        // Check for comma (more assignments)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance(); // consume comma
                continue;
            }
        }
        break;
    }

    Ok(AstAlterProcedureActionKind::SetTag {
        set_span,
        tag_span,
        assignments_span: Span {
            start: assignments_start,
            end,
        },
    })
}

/// Parse UNSET TAG action for procedure.
fn parse_unset_tag_action_proc(
    p: &mut Parser<'_>,
    unset_span: Span,
) -> ParseResult<AstAlterProcedureActionKind> {
    let tag_tok = p.advance().expect_invariant("TAG verified by caller");
    let tag_span = tag_tok.span;

    // Parse tag names: name [, name, ...]
    let tags_start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let tag_name_span = p.parse_qualified_name_span()?;
        end = tag_name_span.end;

        // Check for comma
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterProcedureActionKind::UnsetTag {
        unset_span,
        tag_span,
        tags_span: Span {
            start: tags_start,
            end,
        },
    })
}

/// Parse SET <property> = <value> [, ...] action for procedure.
fn parse_set_properties_proc(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterProcedureActionKind> {
    let props_start = p.current_span().start;
    let mut end = props_start;

    loop {
        // Property name (Identifier)
        let _prop_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["property name".to_string()])?;

        // =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected = after property name".to_string(),
                },
            ));
        }

        // Value - could be string, identifier, or parenthesized list
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                // Parenthesized value like (integration1, integration2)
                let paren_span = consume_balanced_parens(p)?;
                end = paren_span.end;
            } else {
                // Simple value
                let value_tok = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["property value".to_string()])?;
                end = value_tok.span.end;
            }
        }

        // Check for comma (more properties)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterProcedureActionKind::SetProperties {
        set_span,
        properties_span: Span {
            start: props_start,
            end,
        },
    })
}

/// Consume tokens until statement end (semicolon or EOF).
fn consume_to_statement_end_proc(p: &mut Parser<'_>, start: u32) -> ParseResult<Span> {
    let mut end = start;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p.advance().expect_invariant("token consumed after peek");
        end = t.span.end;
    }
    Ok(Span { start, end })
}
