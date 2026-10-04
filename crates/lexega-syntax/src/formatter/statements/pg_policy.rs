// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatters for PostgreSQL POLICY statements (Row-Level Security).
//!
//! - CREATE POLICY: CST-based keyword emission + expression formatting for USING/WITH CHECK
//! - ALTER POLICY: CST-based for keywords + expression formatting
//! - DROP POLICY: CST-based for keywords, span-based for names

use crate::ast::types::{
    AlterPgPolicyAction, AstAlterPgPolicy, AstCreatePgPolicy, AstDropPgPolicy, PgCascadeRestrict,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format a CREATE POLICY statement.
pub fn format_create_pg_policy(
    printer: &mut Printer,
    stmt: &AstCreatePgPolicy,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_create_pg_policy_stmt(syntax_id);
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(syntax.create_keyword);

            // POLICY
            printer.space();
            printer.push_keyword_token_id(syntax.policy_keyword);

            // Policy name
            printer.space();
            printer.push_span(stmt.policy_name);

            // ON table_name
            printer.space();
            printer.push_keyword("ON");
            printer.space();
            printer.push_span(stmt.table_name);

            // [ AS PERMISSIVE | RESTRICTIVE ]
            if let Some((_perm, span)) = &stmt.permissiveness {
                printer.space();
                printer.push_span(*span);
            }

            // [ FOR command ]
            if let Some((_cmd, cmd_span)) = &stmt.command {
                printer.space();
                printer.push_span(*cmd_span);
            }

            // [ TO role_list ]
            if !stmt.roles.is_empty() {
                printer.space();
                if let Some(to_sp) = stmt.to_span {
                    printer.push_span(to_sp);
                } else {
                    printer.push_keyword("TO");
                }
                for (i, role) in stmt.roles.iter().enumerate() {
                    if i == 0 {
                        printer.space();
                    } else {
                        printer.push(", ");
                    }
                    printer.push_span(role.span);
                }
            }

            // [ USING ( expr ) ]
            if let Some(ref using_expr) = stmt.using_expr {
                printer.space();
                if let Some(using_sp) = stmt.using_span {
                    // Emit USING keyword (first 5 chars of using_span)
                    let kw_span = Span {
                        start: using_sp.start,
                        end: using_sp.start + 5,
                    };
                    printer.push_span(kw_span);
                } else {
                    printer.push_keyword("USING");
                }
                printer.push(" (");
                crate::formatter::statements::select::format_expression(printer, using_expr)?;
                printer.push_char(')');
            }

            // [ WITH CHECK ( expr ) ]
            if let Some(ref check_expr) = stmt.check_expr {
                printer.space();
                if let Some(wc_sp) = stmt.with_check_span {
                    // Emit WITH CHECK keywords (first 10 chars: "WITH CHECK")
                    let kw_span = Span {
                        start: wc_sp.start,
                        end: wc_sp.start + 10,
                    };
                    printer.push_span(kw_span);
                } else {
                    printer.push_keyword("WITH CHECK");
                }
                printer.push(" (");
                crate::formatter::statements::select::format_expression(printer, check_expr)?;
                printer.push_char(')');
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

/// Format an ALTER POLICY statement.
pub fn format_alter_pg_policy(
    printer: &mut Printer,
    stmt: &AstAlterPgPolicy,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_alter_pg_policy_stmt(syntax_id);
            let _ = syntax_arena;

            // ALTER
            printer.push_keyword_token_id(syntax.alter_keyword);

            // POLICY
            printer.space();
            printer.push_keyword_token_id(syntax.policy_keyword);

            // Policy name
            printer.space();
            printer.push_span(stmt.policy_name);

            // ON table_name
            printer.space();
            printer.push_keyword("ON");
            printer.space();
            printer.push_span(stmt.table_name);

            // Action
            printer.space();
            format_alter_pg_policy_action(printer, &stmt.action)?;

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

/// Format an ALTER POLICY action.
fn format_alter_pg_policy_action(
    printer: &mut Printer,
    action: &AlterPgPolicyAction,
) -> Result<(), FormatterError> {
    match action {
        AlterPgPolicyAction::Rename {
            rename_span,
            to_span,
            new_name,
        } => {
            printer.push_span(*rename_span);
            printer.space();
            printer.push_span(*to_span);
            printer.space();
            printer.push_span(*new_name);
        }
        AlterPgPolicyAction::Modify {
            roles,
            to_span,
            using_expr,
            using_span,
            check_expr,
            with_check_span,
        } => {
            let mut need_space = false;

            // [ TO role_list ]
            if !roles.is_empty() {
                if let Some(to_sp) = to_span {
                    printer.push_span(*to_sp);
                } else {
                    printer.push_keyword("TO");
                }
                for (i, role) in roles.iter().enumerate() {
                    if i == 0 {
                        printer.space();
                    } else {
                        printer.push(", ");
                    }
                    printer.push_span(role.span);
                }
                need_space = true;
            }

            // [ USING ( expr ) ]
            if let Some(ref expr) = using_expr {
                if need_space {
                    printer.space();
                }
                if let Some(u_sp) = using_span {
                    let kw_span = Span {
                        start: u_sp.start,
                        end: u_sp.start + 5,
                    };
                    printer.push_span(kw_span);
                } else {
                    printer.push_keyword("USING");
                }
                printer.push(" (");
                crate::formatter::statements::select::format_expression(printer, expr)?;
                printer.push_char(')');
                need_space = true;
            }

            // [ WITH CHECK ( expr ) ]
            if let Some(ref expr) = check_expr {
                if need_space {
                    printer.space();
                }
                if let Some(wc_sp) = with_check_span {
                    let kw_span = Span {
                        start: wc_sp.start,
                        end: wc_sp.start + 10,
                    };
                    printer.push_span(kw_span);
                } else {
                    printer.push_keyword("WITH CHECK");
                }
                printer.push(" (");
                crate::formatter::statements::select::format_expression(printer, expr)?;
                printer.push_char(')');
            }
        }
    }
    Ok(())
}

/// Format a DROP POLICY statement.
pub fn format_drop_pg_policy(
    printer: &mut Printer,
    stmt: &AstDropPgPolicy,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_drop_pg_policy_stmt(syntax_id);
            let _ = syntax_arena;

            // DROP
            printer.push_keyword_token_id(syntax.drop_keyword);

            // POLICY
            printer.space();
            printer.push_keyword_token_id(syntax.policy_keyword);

            // [IF EXISTS]
            if let Some(if_kw) = syntax.if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(exists_kw) = syntax.exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Policy name
            printer.space();
            printer.push_span(stmt.policy_name);

            // ON table_name
            printer.space();
            printer.push_keyword("ON");
            printer.space();
            printer.push_span(stmt.table_name);

            // [CASCADE | RESTRICT]
            if let Some(cr) = &stmt.cascade_restrict {
                printer.space();
                match cr {
                    PgCascadeRestrict::Cascade => printer.push_keyword("CASCADE"),
                    PgCascadeRestrict::Restrict => printer.push_keyword("RESTRICT"),
                }
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}
