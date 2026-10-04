// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for ALTER MASKING POLICY statements.
//!
//! Uses CST token IDs for header keyword emission when available.
//! Action body formatting remains span/expression-based.

use crate::ast::{AstAlterMaskingPolicy, AstAlterMaskingPolicyActionKind};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_alter_masking_policy(
    printer: &mut Printer,
    stmt: &AstAlterMaskingPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER MASKING POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_masking_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_keyword_token_id(s.masking_keyword);
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
        printer.push_span(stmt.masking_span);
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
        AstAlterMaskingPolicyActionKind::SetBody {
            set_span,
            body_span,
            arrow_span,
            expression_span: _,
            body,
        } => {
            if let Some(set_span) = set_span {
                printer.push_span(*set_span);
                printer.space();
            }
            if let Some(body_span) = body_span {
                printer.push_span(*body_span);
                printer.space();
            }
            if let Some(arrow_span) = arrow_span {
                printer.push_span(*arrow_span);
            }
            printer.newline();

            printer.indent_up();
            use crate::formatter::statements::select::format_expression;
            format_expression(printer, body)?;
            printer.indent_down();

            printer.emit_all_tokens_until(stmt.action_span.end);
        }
        _ => {
            printer.push_span(stmt.action_span);
        }
    }

    Ok(())
}
