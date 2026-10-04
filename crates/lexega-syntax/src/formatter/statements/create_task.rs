// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for CREATE TASK statement
//!
//! Formats the DDL structure and properly formats the SQL body.

use crate::ast::AstCreateTask;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a CREATE TASK statement
///
/// This formats the header (CREATE TASK ... options) with span-based
/// emission for the options, then properly formats the `AS <sql>` body.
pub fn format_create_task(
    printer: &mut Printer,
    task: &AstCreateTask,
) -> Result<(), FormatterError> {
    // CREATE keyword
    printer.push_keyword_span(task.create_span);

    // OR REPLACE (if present)
    if let Some(or_replace_span) = task.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }

    // OR ALTER (if present)
    if let Some(or_alter_span) = task.or_alter_span {
        printer.space();
        printer.push_span(or_alter_span);
    }

    // TASK keyword (note: TASK is actually an Identifier in the lexer, not Keyword)
    printer.space();
    printer.push_span(task.task_span);

    // IF NOT EXISTS (if present)
    if let Some(if_not_exists_span) = task.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }

    // Task name
    printer.space();
    printer.push_identifier_span_v2(task.name_span);

    // Collect all option spans that exist, then sort by source position
    // to preserve the original property ordering from the source SQL.
    let mut option_spans: Vec<crate::lexer::Span> = [
        task.warehouse_span,
        task.schedule_span,
        task.config_span,
        task.allow_overlapping_execution_span,
        task.overlap_policy_span,
        task.user_task_timeout_ms_span,
        task.suspend_task_after_num_failures_span,
        task.error_integration_span,
        task.success_integration_span,
        task.log_level_span,
        task.finalize_span,
        task.task_auto_retry_attempts_span,
        task.user_task_minimum_trigger_interval_span,
        task.target_completion_interval_span,
        task.serverless_task_min_span,
        task.serverless_task_max_span,
        task.user_task_managed_initial_warehouse_size_span,
        task.comment_span,
    ]
    .iter()
    .filter_map(|s| *s)
    .collect();
    option_spans.sort_by_key(|s| s.start);

    for option_span in option_spans {
        printer.newline();
        printer.indent_up();
        printer.push_span(option_span);
        printer.indent_down();
    }

    // Session parameters
    for param_span in &task.session_parameters_spans {
        printer.newline();
        printer.indent_up();
        printer.push_span(*param_span);
        printer.indent_down();
    }

    // Task dependencies and execution options - also sorted by source position
    let mut dep_spans: Vec<crate::lexer::Span> = [
        task.with_tag_span,
        task.after_span,
        task.when_span,
        task.execute_as_span,
    ]
    .iter()
    .filter_map(|s| *s)
    .collect();
    dep_spans.sort_by_key(|s| s.start);

    for dep_span in dep_spans {
        printer.newline();
        printer.indent_up();
        printer.push_span(dep_span);
        printer.indent_down();
    }

    // Handle CLONE variant
    if let Some(clone_span) = task.clone_span {
        printer.newline();
        printer.push_span(clone_span);
        return Ok(());
    }

    // AS keyword and SQL body
    if let Some(as_span) = task.as_span {
        printer.newline();
        printer.push_span(as_span);
        printer.newline();

        if let Some(ref body_result) = task.body {
            match body_result {
                Ok(parsed_stmt) => {
                    // Format the parsed statement based on its type
                    use crate::ast::AstStmt;
                    match parsed_stmt.as_ref() {
                        AstStmt::Select(_) | AstStmt::SetSelect(_) => {
                            use crate::formatter::statements::select::format_select;
                            format_select(printer, parsed_stmt.as_ref())?;
                        }
                        AstStmt::Insert(insert) => {
                            use crate::formatter::statements::dml::format_insert;
                            format_insert(printer, insert)?;
                        }
                        AstStmt::Update(update) => {
                            use crate::formatter::statements::dml::format_update;
                            format_update(printer, update)?;
                        }
                        AstStmt::Delete(delete) => {
                            use crate::formatter::statements::dml::format_delete;
                            format_delete(printer, delete)?;
                        }
                        AstStmt::Merge(merge) => {
                            use crate::formatter::statements::dml::format_merge;
                            format_merge(printer, merge)?;
                        }
                        AstStmt::Call { span, .. } => {
                            // CALL procedure - emit span as-is
                            printer.push_span(*span);
                        }
                        AstStmt::ExecuteImmediate { span, .. } => {
                            // EXECUTE IMMEDIATE - emit span as-is
                            printer.push_span(*span);
                        }
                        _ => {
                            // Other statement types - emit span as-is
                            printer.push_span(parsed_stmt.span());
                        }
                    }
                }
                Err(body_span) => {
                    // Body couldn't be parsed, emit span as-is
                    printer.emit_comments_before(body_span.start);
                    printer.push_span(*body_span);
                }
            }
        }
    }

    // Unknown/extra properties (defensive design)
    for extra in &task.extras {
        printer.newline();
        printer.indent_up();
        printer.push_span(extra.span);
        printer.indent_down();
    }

    Ok(())
}
