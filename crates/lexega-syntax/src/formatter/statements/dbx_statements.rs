// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for Databricks OPTIMIZE statement.
//!
//! `OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]`

use crate::ast::types::AstOptimize;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format a Databricks OPTIMIZE statement with proper keyword casing and spacing.
pub fn format_optimize(printer: &mut Printer, stmt: &AstOptimize) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_optimize_stmt(syntax_id);
            let _ = syntax_arena;

            // OPTIMIZE (identifier token)
            printer.push_token_id(syntax.optimize_keyword);

            // table_name (possibly qualified)
            printer.space();
            printer.push_span(syntax.table_name_span);

            // [FULL]
            if let Some(full_kw) = syntax.full_keyword {
                printer.space();
                printer.push_keyword_token_id(full_kw);
            }

            // [WHERE predicate]
            if let Some(where_kw) = syntax.where_keyword {
                printer.newline();
                printer.push_keyword_token_id(where_kw);
                if let Some(ref where_expr) = stmt.where_predicate {
                    printer.space();
                    crate::formatter::statements::select::format_expression(printer, where_expr)?;
                }
            }

            // [ZORDER BY (col1, col2, ...)]
            if let Some(zorder_kw) = syntax.zorder_keyword {
                printer.newline();
                printer.push_token_id(zorder_kw);
                if let Some(by_kw) = syntax.by_keyword {
                    printer.space();
                    printer.push_keyword_token_id(by_kw);
                }

                // Parenthesized form
                if let Some(lp) = syntax.zorder_l_paren {
                    printer.space();
                    printer.push_token_id(lp);
                    if let Some(rp) = syntax.zorder_r_paren {
                        let rp_tok = printer.get_token_by_id(rp);
                        let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.stmt_span.end);
                        let pos = printer.get_source_position();
                        if rp_start > pos {
                            printer.push_span(Span {
                                start: pos,
                                end: rp_start,
                            });
                        }
                        printer.push_token_id(rp);
                    }
                } else if let Some(cols_span) = stmt.zorder_columns_span {
                    // Non-parenthesized form: emit column spans directly
                    printer.space();
                    printer.push_span(cols_span);
                }
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}
