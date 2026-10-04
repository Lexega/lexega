// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for ROW ACCESS POLICY statements.
//!
//! Uses CST token IDs for header keyword emission when available.
//! Body expressions are formatted via the AST expression formatter.

use crate::ast::{
    AstAlterRowAccessPolicy, AstAlterRowAccessPolicyActionKind, AstCreateRowAccessPolicy,
    AstDropAllRowAccessPolicies, AstDropRowAccessPolicy,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a CREATE ROW ACCESS POLICY statement
///
/// Handles both Snowflake and BigQuery variants:
/// - Snowflake: CREATE [OR REPLACE] ROW ACCESS POLICY name AS (args) RETURNS BOOLEAN -> body [COMMENT = ...]
/// - BigQuery:  CREATE [OR REPLACE] ROW ACCESS POLICY [IF NOT EXISTS] name ON table [GRANT TO (...)] FILTER USING (...)
pub fn format_create_row_access_policy(
    printer: &mut Printer,
    stmt: &AstCreateRowAccessPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_row_access_policy(id));
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

        // ROW ACCESS POLICY keywords
        printer.space();
        printer.push_keyword_token_id(s.row_keyword);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);

        // IF NOT EXISTS (BigQuery)
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

        // ON table (BigQuery)
        if let Some(on_kw) = s.on_keyword {
            printer.space();
            printer.push_keyword_token_id(on_kw);
            if let Some(table_name_span) = s.table_name_span {
                printer.space();
                printer.push_identifier_span_v2(table_name_span);
            }
        }

        // GRANT TO clause (BigQuery — content span)
        if let Some(grant_to_clause_span) = s.grant_to_clause_span {
            printer.newline();
            printer.push_span(grant_to_clause_span);
        }

        // FILTER USING clause (BigQuery — content span)
        if let Some(filter_using_clause_span) = s.filter_using_clause_span {
            printer.newline();
            printer.push_span(filter_using_clause_span);
        }

        // AS keyword (Snowflake)
        if let Some(as_kw) = s.as_keyword {
            printer.space();
            printer.push_keyword_token_id(as_kw);
        }

        // Signature (Snowflake — content span)
        if let Some(signature_span) = s.signature_span {
            printer.space();
            printer.push_span(signature_span);
        }

        // RETURNS keyword (Snowflake)
        if let Some(returns_kw) = s.returns_keyword {
            printer.space();
            printer.push_keyword_token_id(returns_kw);
        }

        // BOOLEAN (Snowflake — Identifier token)
        if let Some(boolean_kw) = s.boolean_keyword {
            printer.space();
            printer.push_token_id(boolean_kw);
        }

        // Arrow operator (Snowflake — structural token)
        if let Some(arrow) = s.arrow_token {
            printer.space();
            printer.push_token_id(arrow);
            printer.newline();
        }

        // Body expression (Snowflake — format via AST expression formatter)
        if let Some(ref body) = stmt.body {
            printer.indent_up();
            use crate::formatter::statements::select::format_expression;
            format_expression(printer, body)?;
            printer.indent_down();
        }

        // COMMENT clause (content span)
        if let Some(comment_span) = s.comment_span {
            printer.newline();
            printer.push_span(comment_span);
        }

        return Ok(());
    }

    // Fallback: span-based emission
    printer.push_keyword_span(stmt.create_span);
    if let Some(or_replace_span) = stmt.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }
    printer.space();
    printer.push_span(stmt.row_span);
    printer.space();
    printer.push_span(stmt.access_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_not_exists_span) = stmt.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    if let Some(on_table_span) = stmt.on_table_span {
        printer.space();
        printer.push_span(on_table_span);
        if let Some(table_name_span) = stmt.table_name_span {
            printer.space();
            printer.push_identifier_span_v2(table_name_span);
        }
    }
    if let Some(grant_to_clause_span) = stmt.grant_to_clause_span {
        printer.newline();
        printer.push_span(grant_to_clause_span);
    }
    if let Some(filter_using_clause_span) = stmt.filter_using_clause_span {
        printer.newline();
        printer.push_span(filter_using_clause_span);
    }
    if let Some(as_span) = stmt.as_span {
        printer.space();
        printer.push_span(as_span);
    }
    if let Some(signature_span) = stmt.signature_span {
        printer.space();
        printer.push_span(signature_span);
    }
    if let Some(returns_span) = stmt.returns_span {
        printer.space();
        printer.push_span(returns_span);
    }
    if let Some(arrow_span) = stmt.arrow_span {
        printer.space();
        printer.push_span(arrow_span);
        printer.newline();
    }
    if let Some(ref body) = stmt.body {
        printer.indent_up();
        use crate::formatter::statements::select::format_expression;
        format_expression(printer, body)?;
        printer.indent_down();
    }
    if let Some(comment_span) = stmt.comment_span {
        printer.newline();
        printer.push_span(comment_span);
    }
    Ok(())
}

/// Format an ALTER ROW ACCESS POLICY statement
pub fn format_alter_row_access_policy(
    printer: &mut Printer,
    stmt: &AstAlterRowAccessPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER ROW ACCESS POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_row_access_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_keyword_token_id(s.row_keyword);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
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
        printer.push_span(stmt.row_span);
        printer.space();
        printer.push_span(stmt.access_span);
        printer.space();
        printer.push_span(stmt.policy_span);
        if let Some(if_exists_span) = stmt.if_exists_span {
            printer.space();
            printer.push_span(if_exists_span);
        }
        printer.space();
        printer.push_identifier_span_v2(stmt.name_span);
    }

    // Format the action (unchanged — action CST only has span)
    printer.space();
    match &stmt.action.kind {
        AstAlterRowAccessPolicyActionKind::SetBody {
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

/// Format a DROP ROW ACCESS POLICY statement.
pub fn format_drop_row_access_policy(
    printer: &mut Printer,
    stmt: &AstDropRowAccessPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_row_access_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_keyword_token_id(s.row_keyword);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
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

        if let Some(on_kw) = s.on_keyword {
            printer.space();
            printer.push_keyword_token_id(on_kw);
            if let Some(table_name_span) = s.table_name_span {
                printer.space();
                printer.push_identifier_span_v2(table_name_span);
            }
        }

        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.row_span);
    printer.space();
    printer.push_span(stmt.access_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    if let Some(on_table_span) = stmt.on_table_span {
        printer.space();
        printer.push_span(on_table_span);
        if let Some(table_name_span) = stmt.table_name_span {
            printer.space();
            printer.push_identifier_span_v2(table_name_span);
        }
    }
    Ok(())
}

/// Format a DROP ALL ROW ACCESS POLICIES statement.
pub fn format_drop_all_row_access_policies(
    printer: &mut Printer,
    stmt: &AstDropAllRowAccessPolicies,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_all_row_access_policies(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_keyword_token_id(s.all_keyword);
        printer.space();
        printer.push_keyword_token_id(s.row_keyword);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
        printer.space();
        printer.push_token_id(s.policies_token);
        printer.space();
        printer.push_keyword_token_id(s.on_keyword);
        printer.space();
        printer.push_identifier_span_v2(s.table_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.all_span);
    printer.space();
    printer.push_span(stmt.row_span);
    printer.space();
    printer.push_span(stmt.access_span);
    printer.space();
    printer.push_span(stmt.policies_span);
    printer.space();
    printer.push_span(stmt.on_span);
    printer.space();
    printer.push_identifier_span_v2(stmt.table_name_span);
    Ok(())
}
