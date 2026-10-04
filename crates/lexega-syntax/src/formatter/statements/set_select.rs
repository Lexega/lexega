// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SET SELECT statement formatter (UNION/INTERSECT/EXCEPT)

use crate::ast::{AstSetModifier, AstSetOpKind, AstSetSelect};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a SET SELECT statement (UNION/INTERSECT/EXCEPT)
///
/// SET SELECT is a binary tree structure:
/// - left: `Box<AstStmt>` (can be Select or SetSelect)
/// - op: UNION | INTERSECT | EXCEPT
/// - modifier: None | All | Distinct
/// - right: `Box<AstStmt>` (can be Select or SetSelect)
///
/// This is a CST-preserving formatter - we preserve parentheses and operator
/// tokens from the source. The set_op_syntax_id field references a
/// SyntaxSetOperator node that owns the operator and modifier token IDs.
pub fn format_set_select(
    printer: &mut Printer,
    set_select: &AstSetSelect,
) -> Result<(), FormatterError> {
    printer.enter_recursion("set_select")?;

    // Emit opening paren if this SetSelect is parenthesized
    if let Some(paren_id) = set_select.paren_syntax_id {
        if let Some(subquery) = printer.get_subquery(paren_id) {
            printer.push_token_id(subquery.l_paren);
        }
    }

    // Format left operand - dispatch handles Select vs nested SetSelect
    super::format_select(printer, &set_select.left)?;

    // Format set operator (UNION/INTERSECT/EXCEPT [ALL|DISTINCT])
    printer.newline();
    format_set_operator(printer, set_select)?;

    // Format right operand - dispatch handles Select vs nested SetSelect
    printer.newline();
    super::format_select(printer, &set_select.right)?;

    // Trailing ORDER BY / LIMIT / OFFSET applying to the whole set operation.
    let body_end = set_select.right.span().end;
    if let Some(ref order_by) = set_select.order_by {
        printer.newline();
        super::select::format_order_by_clause_tracked(printer, order_by, body_end)?;
    }
    let limit_prev_end = set_select
        .order_by
        .as_ref()
        .map(|o| o.span.end)
        .unwrap_or(body_end);
    super::select::format_limit_offset_tail(
        printer,
        set_select.limit.as_deref(),
        set_select.offset.as_deref(),
        set_select.limit_keyword_span,
        set_select.fetch_clause_span,
        set_select.offset_keyword_span,
        set_select.limit_offset_comma_span,
        limit_prev_end,
    )?;

    // Emit closing paren if this SetSelect is parenthesized
    if let Some(paren_id) = set_select.paren_syntax_id {
        if let Some(subquery) = printer.get_subquery(paren_id) {
            printer.push_token_id(subquery.r_paren);
        }
    }

    // Emit semicolon if present (scripting/Jinja context)
    if let Some(semi_id) = set_select.semicolon_token {
        printer.push_token_id(semi_id);
    }

    printer.exit_recursion();
    Ok(())
}

/// Format the set operator keyword(s) using CST token IDs when available,
/// falling back to keyword synthesis only when no syntax node exists.
fn format_set_operator(
    printer: &mut Printer,
    set_select: &AstSetSelect,
) -> Result<(), FormatterError> {
    // Try to emit from CST tokens first (preferred path)
    if let Some(syntax_id) = set_select.set_op_syntax_id {
        if let Some(syntax) = printer.get_set_operator(syntax_id) {
            // Emit the operator keyword token (UNION/INTERSECT/EXCEPT/MINUS)
            printer.push_token_id(syntax.op_keyword);

            // Emit the optional modifier token (ALL/DISTINCT)
            if let Some(mod_token) = syntax.modifier_keyword {
                printer.space();
                printer.push_token_id(mod_token);
            }

            return Ok(());
        }
    }

    // Fallback: synthesize keywords (for programmatically-constructed ASTs
    // without a syntax arena, e.g. from tests or transformations)
    let op_keyword = match set_select.op {
        AstSetOpKind::Union => "UNION",
        AstSetOpKind::Intersect => "INTERSECT",
        AstSetOpKind::Except => "EXCEPT",
        AstSetOpKind::Minus => "MINUS",
    };
    printer.push_keyword(op_keyword);

    match set_select.modifier {
        AstSetModifier::All => {
            printer.space();
            printer.push_keyword("ALL");
        }
        AstSetModifier::Distinct => {
            printer.space();
            printer.push_keyword("DISTINCT");
        }
        AstSetModifier::None => {}
    }

    Ok(())
}
