// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for PROJECTION POLICY statements.
//!
//! Implements formatting for:
//! - `CREATE [OR REPLACE] PROJECTION POLICY [IF NOT EXISTS] name AS () RETURNS PROJECTION_CONSTRAINT -> <body>`
//! - `ALTER PROJECTION POLICY [IF EXISTS] name { RENAME TO | SET BODY | SET/UNSET TAG | SET/UNSET COMMENT }`
//! - `DROP PROJECTION POLICY [IF EXISTS] name`

use crate::ast::{
    AstAlterProjectionPolicy, AstAlterProjectionPolicyActionKind, AstCreateProjectionPolicy,
    AstDropProjectionPolicy,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format CREATE PROJECTION POLICY statement.
pub fn format_create_projection_policy(
    printer: &mut Printer,
    stmt: &AstCreateProjectionPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_projection_policy(id));
    if let Some(s) = syntax {
        // CREATE keyword
        printer.push_keyword_token_id(s.create_keyword);

        // OR REPLACE (individual keyword tokens)
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }

        // PROJECTION (Identifier token)
        printer.space();
        printer.push_token_id(s.projection_token);

        // POLICY keyword
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);

        // IF NOT EXISTS
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }

        // Policy name
        printer.space();
        printer.push_identifier_span_v2(s.policy_name_span);

        // AS keyword
        if let Some(as_kw) = s.as_keyword {
            printer.space();
            printer.push_keyword_token_id(as_kw);
        }

        // Empty params ()
        if let Some(lparen) = s.lparen_token {
            printer.space();
            printer.push_token_id(lparen);
            if let Some(rparen) = s.rparen_token {
                printer.push_token_id(rparen);
            }
        }

        // RETURNS keyword
        if let Some(returns_kw) = s.returns_keyword {
            printer.space();
            printer.push_keyword_token_id(returns_kw);
        }

        // Return type (content span — PROJECTION_CONSTRAINT identifier)
        if let Some(return_type_span) = s.return_type_span {
            printer.space();
            printer.push_span(return_type_span);
        }

        // Arrow operator
        if let Some(arrow) = s.arrow_token {
            printer.space();
            printer.push_token_id(arrow);
            printer.newline();
        }

        // Body expression (via AST expression formatter)
        if let Some(ref body) = stmt.body_expr {
            printer.indent_up();
            use crate::formatter::statements::select::format_expression;
            format_expression(printer, body)?;
            printer.indent_down();
        } else {
            // Fallback: emit body span as-is
            printer.push_span(s.body_span);
        }

        // Optional COMMENT clause
        if let Some(comment_span) = s.comment_span {
            printer.newline();
            printer.push_span(comment_span);
        }

        // Extras (unknown properties - preserve as-is, from AST)
        for extra in &stmt.extras {
            printer.push_span(extra.span);
        }

        return Ok(());
    }

    // Fallback: span-based
    printer.push_keyword_span(stmt.create_span);
    if let Some(or_replace_span) = stmt.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }
    printer.space();
    printer.push_span(stmt.projection_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_not_exists_span) = stmt.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    if let Some(as_span) = stmt.as_span {
        printer.space();
        printer.push_span(as_span);
    }
    if let Some(empty_params_span) = stmt.empty_params_span {
        printer.space();
        printer.push_span(empty_params_span);
    }
    if let Some(returns_span) = stmt.returns_span {
        printer.space();
        printer.push_span(returns_span);
    }
    if let Some(return_type_span) = stmt.return_type_span {
        printer.space();
        printer.push_span(return_type_span);
    }
    if let Some(arrow_span) = stmt.arrow_span {
        printer.space();
        printer.push_span(arrow_span);
        printer.newline();
    }
    if let Some(ref body) = stmt.body_expr {
        printer.indent_up();
        use crate::formatter::statements::select::format_expression;
        format_expression(printer, body)?;
        printer.indent_down();
    } else {
        printer.push_span(stmt.body_span);
    }
    if let Some(comment_span) = stmt.comment_span {
        printer.newline();
        printer.push_span(comment_span);
    }
    for extra in &stmt.extras {
        printer.push_span(extra.span);
    }
    Ok(())
}

/// Format ALTER PROJECTION POLICY statement.
pub fn format_alter_projection_policy(
    printer: &mut Printer,
    stmt: &AstAlterProjectionPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER PROJECTION POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_projection_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.projection_token); // PROJECTION is Identifier
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);
    } else {
        printer.push_keyword_span(stmt.alter_span);
        printer.space();
        printer.push_span(stmt.projection_span);
        printer.space();
        printer.push_span(stmt.policy_span);
        if let Some(if_exists_span) = stmt.if_exists_span {
            printer.space();
            printer.push_span(if_exists_span);
        }
        printer.space();
        printer.push_identifier_span_v2(stmt.name_span);
    }

    // Format the action
    printer.space();
    match &stmt.action.kind {
        AstAlterProjectionPolicyActionKind::SetBody {
            set_span,
            body_span,
            arrow_span,
            expression_span: _,
            body_expr,
        } => {
            // SET keyword
            if let Some(set_span) = set_span {
                printer.push_span(*set_span);
                printer.space();
            }
            // BODY keyword
            if let Some(body_span) = body_span {
                printer.push_span(*body_span);
                printer.space();
            }
            // Arrow operator
            if let Some(arrow_span) = arrow_span {
                printer.push_span(*arrow_span);
            }
            printer.newline();

            // Body expression - format properly if available
            if let Some(ref body) = body_expr {
                printer.indent_up();
                use crate::formatter::statements::select::format_expression;
                format_expression(printer, body)?;
                printer.indent_down();
            }

            // Ensure source cursor covers full action span
            printer.emit_all_tokens_until(stmt.action_span.end);
        }
        AstAlterProjectionPolicyActionKind::RenameTo {
            rename_span,
            to_span,
            new_name_span,
        } => {
            if let Some(rename_span) = rename_span {
                printer.push_span(*rename_span);
                printer.space();
            }
            if let Some(to_span) = to_span {
                printer.push_span(*to_span);
                printer.space();
            }
            printer.push_identifier_span_v2(*new_name_span);
        }
        AstAlterProjectionPolicyActionKind::SetTag {
            set_span,
            tag_span,
            assignments_span,
        } => {
            if let Some(set_span) = set_span {
                printer.push_span(*set_span);
                printer.space();
            }
            if let Some(tag_span) = tag_span {
                printer.push_span(*tag_span);
                printer.space();
            }
            printer.push_span(*assignments_span);
        }
        AstAlterProjectionPolicyActionKind::UnsetTag {
            unset_span,
            tag_span,
            tags_span,
        } => {
            if let Some(unset_span) = unset_span {
                printer.push_span(*unset_span);
                printer.space();
            }
            if let Some(tag_span) = tag_span {
                printer.push_span(*tag_span);
                printer.space();
            }
            printer.push_span(*tags_span);
        }
        AstAlterProjectionPolicyActionKind::SetComment {
            set_span,
            comment_span,
            eq_span,
            comment_value_span,
        } => {
            if let Some(set_span) = set_span {
                printer.push_span(*set_span);
                printer.space();
            }
            if let Some(comment_span) = comment_span {
                printer.push_span(*comment_span);
                printer.space();
            }
            if let Some(eq_span) = eq_span {
                printer.push_span(*eq_span);
                printer.space();
            }
            printer.push_span(*comment_value_span);
        }
        AstAlterProjectionPolicyActionKind::UnsetComment {
            unset_span,
            comment_span,
        } => {
            if let Some(unset_span) = unset_span {
                printer.push_span(*unset_span);
                printer.space();
            }
            if let Some(comment_span) = comment_span {
                printer.push_span(*comment_span);
            }
        }
    }

    Ok(())
}

/// Format DROP PROJECTION POLICY statement.
pub fn format_drop_projection_policy(
    printer: &mut Printer,
    stmt: &AstDropProjectionPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_projection_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_token_id(s.projection_token); // PROJECTION is Identifier
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.policy_name_span);
        return Ok(());
    }

    // Fallback: span-based
    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.projection_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    Ok(())
}
