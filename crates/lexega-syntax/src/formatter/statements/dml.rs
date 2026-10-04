// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DML statement formatters: INSERT, UPDATE, DELETE, MERGE
//!
//! These formatters handle data manipulation statements with proper
//! indentation and alignment following the formatter configuration.

use crate::ast::{
    AstDelete, AstInsert, AstInsertSourceKind, AstMerge, AstMergeActionKind, AstMergeClause,
    AstUpdate,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format INSERT statement
pub fn format_insert(printer: &mut Printer, insert: &AstInsert) -> Result<(), FormatterError> {
    // WITH clause (writable CTEs) before INSERT
    if let Some(ref with_clause) = insert.with_clause {
        super::select::format_with_clause(printer, with_clause)?;
        printer.newline();
    }

    // INSERT keyword - use push_keyword_span to emit trivia
    printer.push_keyword_span(insert.keyword_span);

    // MySQL: LOW_PRIORITY / HIGH_PRIORITY, then IGNORE
    if let Some(ref priority) = insert.priority {
        printer.space();
        printer.push_keyword_span(priority.span());
    }
    if let Some(ignore_span) = insert.ignore_span {
        printer.space();
        printer.push_keyword_span(ignore_span);
    }

    // OVERWRITE (if present)
    if let Some(overwrite_span) = insert.overwrite_span {
        printer.space();
        printer.push_keyword_span(overwrite_span);
    }

    // OR REPLACE (Databricks, if present)
    if let Some(replace_span) = insert.replace_span {
        printer.space();
        printer.push_span(replace_span);
    }

    // INTO keyword — optional in MySQL, so only emit when present
    if let Some(into_span) = insert.into_span {
        printer.space();
        printer.push_keyword_span(into_span);
    }

    // Target table - use push_identifier_span_v2 for identifier casing
    if let Some(table_span) = insert.target_table_span {
        printer.space();
        printer.push_identifier_span_v2(table_span);
    }

    // MySQL: PARTITION (p, ...) selection
    if let Some(partition_span) = insert.partition_span {
        printer.space();
        printer.push_span(partition_span);
    }

    // MSSQL: Table hints, e.g. WITH (TABLOCK)
    if let Some(ref hints) = insert.table_hints {
        printer.space();
        printer.push_span(hints.span);
    }

    // Column list (if present)
    if let Some(columns_span) = insert.columns_span {
        printer.space();
        printer.push_span(columns_span);
    }

    // PostgreSQL: OVERRIDING { SYSTEM | USER } VALUE
    if let Some(ov_span) = insert.overriding_value_span {
        printer.newline();
        printer.push_span(ov_span);
    }

    // Source data
    match insert.source_kind {
        AstInsertSourceKind::DefaultValues => {
            // PostgreSQL: INSERT INTO t DEFAULT VALUES
            if let Some(dv_span) = insert.default_values_span {
                printer.newline();
                printer.push_span(dv_span);
            } else {
                printer.newline();
                printer.push_keyword("DEFAULT");
                printer.space();
                printer.push_keyword("VALUES");
            }
        }
        AstInsertSourceKind::Values => {
            if let Some(_values_span) = insert.values_span {
                let multiline =
                    printer.config().insert_values_on_newlines && insert.values_rows.len() > 1;

                // Always put VALUES on newline for consistency
                printer.newline();
                if let Some(vk_span) = insert.values_keyword_span {
                    printer.push_keyword_span(vk_span);
                } else {
                    printer.push_keyword("VALUES");
                }

                let leading_comma =
                    printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

                // Check if we have parsed expressions or need to fall back to
                // spans. MySQL ROW(...) rows carry a keyword the parsed-expr
                // path would drop, so they always emit via spans.
                let use_parsed = !insert.values_rows.is_empty() && !insert.values_row_constructor;

                if use_parsed {
                    // Format using parsed expressions with parenthesized style
                    use crate::formatter::config::ParenthesizedExprStyle;
                    use crate::formatter::statements::select::format_expression;

                    let paren_style = printer.config().parenthesized_expr_style;

                    for (idx, row_exprs) in insert.values_rows.iter().enumerate() {
                        if leading_comma && idx > 0 {
                            printer.push_char(',');
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }

                        if idx == 0 {
                            printer.space();
                        } else if multiline {
                            printer.newline();
                            printer.push("       "); // Align with VALUES
                        } else if printer.config().space_after_comma {
                            printer.space();
                        }

                        // Format the parenthesized row
                        printer.push_char('(');

                        match paren_style {
                            ParenthesizedExprStyle::Expanded if row_exprs.len() > 1 => {
                                printer.newline();
                                printer.indent_up();
                                for (expr_idx, expr) in row_exprs.iter().enumerate() {
                                    if leading_comma && expr_idx > 0 {
                                        printer.push_char(',');
                                        if printer.config().space_after_comma {
                                            printer.space();
                                        }
                                    }
                                    format_expression(printer, expr)?;
                                    if !leading_comma && expr_idx < row_exprs.len() - 1 {
                                        printer.push_char(',');
                                    }
                                    if expr_idx < row_exprs.len() - 1 {
                                        printer.newline();
                                    }
                                }
                                printer.indent_down();
                                printer.newline();
                            }
                            _ => {
                                // Compact style - all on one line
                                for (expr_idx, expr) in row_exprs.iter().enumerate() {
                                    if expr_idx > 0 {
                                        printer.push_char(',');
                                        if printer.config().space_after_comma {
                                            printer.space();
                                        }
                                    }
                                    format_expression(printer, expr)?;
                                }
                            }
                        }

                        printer.push_char(')');

                        if !leading_comma && idx < insert.values_rows.len() - 1 {
                            printer.push_char(',');
                        }
                    }
                } else {
                    // Fallback: use spans (for backwards compatibility)
                    for (idx, row_span) in insert.values_rows_spans.iter().enumerate() {
                        if leading_comma && idx > 0 {
                            printer.push_char(',');
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }

                        if idx == 0 {
                            printer.space();
                        } else if multiline {
                            printer.newline();
                            printer.push("       "); // Align with VALUES
                        } else if printer.config().space_after_comma {
                            printer.space();
                        }

                        printer.push_span(*row_span);

                        if !leading_comma && idx < insert.values_rows_spans.len() - 1 {
                            printer.push_char(',');
                        }
                    }
                }

                // Trailing comma if configured
                if printer.config().trailing_commas
                    && !leading_comma
                    && !insert.values_rows.is_empty()
                {
                    printer.push_char(',');
                }
            }
        }
        AstInsertSourceKind::Query => {
            if let Some(ref parsed_query) = insert.query {
                // Use the parsed SELECT/WITH statement for proper formatting
                printer.newline();
                use crate::formatter::statements::select::format_select;
                format_select(printer, parsed_query.as_ref())?;
            } else if let Some(body_span) = insert.body_span {
                // Fallback: extract body as-is if not parsed
                printer.newline();
                printer.push_span(body_span);
            }
        }
        AstInsertSourceKind::SetAssignments => {
            // MySQL INSERT ... SET — emit the clause verbatim from source
            if let Some(set_span) = insert.set_clause_span {
                printer.space();
                printer.push_span(set_span);
            } else if let Some(body_span) = insert.body_span {
                printer.space();
                printer.push_span(body_span);
            }
        }
        AstInsertSourceKind::Unknown => {
            // Fallback: extract body as-is
            if let Some(body_span) = insert.body_span {
                printer.newline();
                printer.push_span(body_span);
            }
        }
    }

    // MySQL 8.0.19 row alias: AS alias [(col, ...)]
    if let Some(row_alias_span) = insert.row_alias_span {
        printer.space();
        printer.push_span(row_alias_span);
    }

    // ON CONFLICT clause (PostgreSQL upsert)
    if let Some(ref on_conflict) = insert.on_conflict {
        printer.newline();
        printer.push_span(on_conflict.span);
    }

    // ON DUPLICATE KEY UPDATE clause (MySQL upsert)
    if let Some(ref odku) = insert.on_duplicate_key_update {
        printer.newline();
        printer.push_span(odku.span);
    }

    // OUTPUT clause (MSSQL)
    if let Some(ref output) = insert.output {
        printer.newline();
        printer.push_span(output.span);
    }

    // RETURNING clause (PostgreSQL)
    if let Some(ref returning) = insert.returning {
        format_returning(printer, returning)?;
    }

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = insert.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Calculate maximum column name width for UPDATE SET alignment
fn calculate_max_update_column_width(
    printer: &Printer,
    assignments: &[crate::ast::AstSetAssignment],
) -> usize {
    use crate::formatter::statements::select::format_expression;

    assignments
        .iter()
        .map(|assignment| {
            // Create a temporary printer to measure formatted column expression width
            let mut temp_printer = Printer::new(
                printer.config(),
                printer.source(),
                None, // No CST needed for width measurement
            );
            if format_expression(&mut temp_printer, &assignment.column).is_ok() {
                let output = temp_printer.output_string();
                // For multi-line column expressions, use the last line width
                output.lines().last().unwrap_or(output).len()
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

/// Format a single UPDATE SET assignment with optional alignment
fn format_update_assignment(
    printer: &mut Printer,
    assignment: &crate::ast::AstSetAssignment,
    max_column_width: usize,
) -> Result<(), FormatterError> {
    use crate::formatter::statements::select::format_expression;

    // Track position before formatting column
    let start_pos = printer.output_pos();

    // Format column expression
    format_expression(printer, &assignment.column)?;

    // Measure the width of the last line only (for multi-line column expressions)
    let end_pos = printer.output_pos();
    let output_slice = &printer.output_string()[start_pos..end_pos];
    let last_line = output_slice.lines().last().unwrap_or(output_slice);
    let last_line_width = last_line.len();

    // Add padding for alignment if enabled
    if max_column_width > 0 && last_line_width <= max_column_width {
        let padding = max_column_width - last_line_width + 1; // +1 for minimum space
        for _ in 0..padding {
            printer.push(" ");
        }
    } else {
        printer.space();
    }

    // Equals operator - use push_span to preserve trailing trivia (comments after =)
    printer.push_span(assignment.equals_span);
    printer.space();

    // Format value expression
    format_expression(printer, &assignment.value)?;

    Ok(())
}

/// Format UPDATE statement
/// Emit a MySQL trailing `ORDER BY ... LIMIT n` tail on UPDATE/DELETE.
/// ORDER BY is emitted verbatim from its clause span; LIMIT keyword is
/// re-cased and its row-count expression formatted structurally.
fn format_dml_order_limit_tail(
    printer: &mut Printer,
    order_by: Option<&crate::ast::AstOrderBy>,
    limit: Option<&crate::ast::AstExpr>,
    limit_keyword_span: Option<Span>,
) -> Result<(), FormatterError> {
    if let Some(ob) = order_by {
        printer.newline_if_needed();
        printer.push_span(ob.span);
    }
    if let Some(kw) = limit_keyword_span {
        printer.newline_if_needed();
        printer.push_keyword_span(kw);
        if let Some(lim) = limit {
            printer.space();
            crate::formatter::statements::select::format_expression(printer, lim)?;
        }
    }
    Ok(())
}

pub fn format_update(printer: &mut Printer, update: &AstUpdate) -> Result<(), FormatterError> {
    // WITH clause (writable CTEs) before UPDATE
    if let Some(ref with_clause) = update.with_clause {
        super::select::format_with_clause(printer, with_clause)?;
        printer.newline();
    }

    // UPDATE keyword - use push_keyword_span to emit trivia
    printer.push_keyword_span(update.keyword_span);

    // MySQL: LOW_PRIORITY / IGNORE modifiers
    if let Some(sp) = update.low_priority_span {
        printer.space();
        printer.push_keyword_span(sp);
    }
    if let Some(sp) = update.ignore_span {
        printer.space();
        printer.push_keyword_span(sp);
    }

    // T-SQL: optional TOP clause
    if let Some(ref top) = update.top {
        printer.space();
        super::select::format_top_clause(printer, top)?;
    }

    // Target table (with possible alias/time travel). The span already
    // includes any attached join chain (multi-table UPDATE) and any
    // MySQL PARTITION (p, ...) selection.
    if let Some(target) = &update.target_table {
        printer.space();
        if let Some(only_span) = target.only_span {
            printer.push_keyword_span(only_span);
            printer.space();
        }
        printer.push_span(target.span);
    }

    // MySQL multi-table comma form: additional target tables.
    for extra in &update.additional_targets {
        printer.push_char(',');
        printer.space();
        crate::formatter::statements::format_table_ref(printer, extra)?;
    }

    // SET keyword
    if update.set_span.is_some() {
        printer.newline();
        if let Some(set_kw_span) = update.set_keyword_span {
            printer.push_keyword_span(set_kw_span);
        } else {
            printer.push_keyword("SET");
        }

        let leading_comma =
            printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

        // Calculate max column width for alignment if enabled
        let max_column_width =
            if printer.config().align_update_set && update.set_assignments.len() > 1 {
                calculate_max_update_column_width(printer, &update.set_assignments)
            } else {
                0
            };

        // Format assignments
        for (idx, assignment) in update.set_assignments.iter().enumerate() {
            // For leading comma style with idx > 0, emit comma between previous and current
            if leading_comma && idx > 0 {
                let prev_assignment = &update.set_assignments[idx - 1];
                printer.push_comma_from_source(prev_assignment.span.end, assignment.span.start);
                if printer.config().space_after_comma {
                    printer.space();
                }
            }

            if idx == 0 {
                printer.space();
            } else {
                printer.newline_if_needed();
                printer.push("    "); // Indent continuations
            }

            // Format column = value with optional alignment
            format_update_assignment(printer, assignment, max_column_width)?;

            // For trailing comma style, emit comma between current and next
            if !leading_comma && idx < update.set_assignments.len() - 1 {
                let next_assignment = &update.set_assignments[idx + 1];
                printer.push_comma_from_source(assignment.span.end, next_assignment.span.start);
            }
        }

        // Trailing comma if configured
        if printer.config().trailing_commas && !leading_comma && !update.set_assignments.is_empty()
        {
            printer.push_char(',');
        }
    }

    // FROM clause (if present)
    if !update.from.is_empty() {
        printer.newline_if_needed();
        if let Some(from_kw_span) = update.from_keyword_span {
            printer.push_keyword_span(from_kw_span);
        } else {
            printer.push_keyword("FROM");
        }
        for (idx, table_ref) in update.from.iter().enumerate() {
            if idx == 0 {
                printer.space();
            } else {
                printer.push_char(',');
                if printer.config().space_after_comma {
                    printer.space();
                } else {
                    printer.newline();
                    printer.push("     "); // Align with FROM
                }
            }
            // Use recursive table reference formatting instead of opaque span
            crate::formatter::statements::format_table_ref(printer, table_ref)?;
        }
    }

    // WHERE clause (if present)
    if let Some(where_expr) = &update.where_clause {
        printer.newline_if_needed();
        if let Some(where_kw_span) = update.where_keyword_span {
            printer.push_keyword_span(where_kw_span);
        } else {
            printer.push_keyword("WHERE");
        }
        printer.space();
        crate::formatter::statements::select::format_expression(printer, where_expr)?;
    }

    // MySQL: trailing ORDER BY ... LIMIT n
    format_dml_order_limit_tail(
        printer,
        update.order_by.as_deref(),
        update.limit.as_deref(),
        update.limit_keyword_span,
    )?;

    // OUTPUT clause (MSSQL)
    if let Some(ref output) = update.output {
        printer.newline_if_needed();
        printer.push_span(output.span);
    }

    // RETURNING clause (PostgreSQL)
    if let Some(ref returning) = update.returning {
        format_returning(printer, returning)?;
    }

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = update.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format DELETE statement
pub fn format_delete(printer: &mut Printer, delete: &AstDelete) -> Result<(), FormatterError> {
    // WITH clause (writable CTEs) before DELETE
    if let Some(ref with_clause) = delete.with_clause {
        super::select::format_with_clause(printer, with_clause)?;
        printer.newline();
    }

    // DELETE keyword - use push_keyword_span to emit trivia
    printer.push_keyword_span(delete.keyword_span);

    // MySQL: LOW_PRIORITY / QUICK / IGNORE modifiers
    if let Some(sp) = delete.low_priority_span {
        printer.space();
        printer.push_keyword_span(sp);
    }
    if let Some(sp) = delete.quick_span {
        printer.space();
        printer.push_keyword_span(sp);
    }
    if let Some(sp) = delete.ignore_span {
        printer.space();
        printer.push_keyword_span(sp);
    }

    // T-SQL: optional TOP clause
    if let Some(ref top) = delete.top {
        printer.space();
        super::select::format_top_clause(printer, top)?;
    }

    // MySQL multi-table target list before FROM (`DELETE t1, t2 FROM ...`).
    for (idx, tgt) in delete.targets.iter().enumerate() {
        if idx == 0 {
            printer.space();
        } else {
            printer.push_char(',');
            printer.space();
        }
        printer.push_span(tgt.span);
    }

    // FROM keyword (always present in Snowflake)
    printer.space();
    if let Some(from_kw_span) = delete.from_keyword_span {
        printer.push_keyword_span(from_kw_span);
    } else {
        printer.push_keyword("FROM");
    }

    // Target table. The span already includes any attached join chain and
    // any MySQL PARTITION (p, ...) selection.
    if let Some(target) = &delete.target_table {
        printer.space();
        if let Some(only_span) = target.only_span {
            printer.push_keyword_span(only_span);
            printer.space();
        }
        printer.push_span(target.span);
    }

    // USING clause (if present)
    if !delete.using.is_empty() {
        printer.newline();
        if let Some(using_kw_span) = delete.using_keyword_span {
            printer.push_keyword_span(using_kw_span);
        } else {
            printer.push_keyword("USING");
        }

        let multiline = printer.config().delete_using_on_newlines && delete.using.len() > 1;

        for (idx, table_ref) in delete.using.iter().enumerate() {
            if idx == 0 {
                printer.space();
            } else {
                printer.push_char(',');
                if multiline {
                    printer.newline();
                    printer.push("      "); // Align with USING
                } else if printer.config().space_after_comma {
                    printer.space();
                }
            }
            // Recursive emission so an attached join chain (`USING t1 JOIN
            // t2 ON ...`) is formatted, not flattened into one identifier.
            crate::formatter::statements::format_table_ref(printer, table_ref)?;
        }
    }

    // WHERE clause (if present)
    if let Some(where_expr) = &delete.where_clause {
        printer.newline();
        if let Some(where_kw_span) = delete.where_keyword_span {
            printer.push_keyword_span(where_kw_span);
        } else {
            printer.push_keyword("WHERE");
        }
        printer.space();
        crate::formatter::statements::select::format_expression(printer, where_expr)?;
    }

    // MySQL: trailing ORDER BY ... LIMIT n
    format_dml_order_limit_tail(
        printer,
        delete.order_by.as_deref(),
        delete.limit.as_deref(),
        delete.limit_keyword_span,
    )?;

    // OUTPUT clause (MSSQL)
    if let Some(ref output) = delete.output {
        printer.newline_if_needed();
        printer.push_span(output.span);
    }

    // RETURNING clause (PostgreSQL)
    if let Some(ref returning) = delete.returning {
        format_returning(printer, returning)?;
    }

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = delete.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format MERGE statement
pub fn format_merge(printer: &mut Printer, merge: &AstMerge) -> Result<(), FormatterError> {
    // WITH clause (CTEs) before MERGE
    if let Some(ref with_clause) = merge.with_clause {
        super::select::format_with_clause(printer, with_clause)?;
        printer.newline();
    }

    // MERGE keyword - push_keyword_span uses the actual span and emits trivia
    printer.push_keyword_span(merge.keyword_span);

    // Databricks: optional WITH SCHEMA EVOLUTION
    if let Some(with_schema_span) = merge.with_schema_evolution_span {
        printer.space();
        printer.push_span(with_schema_span);
    }

    // INTO target_table. `target_table_span` covers only the table
    // reference tokens; the INTO keyword (when present in the source)
    // is carried separately via `into_span`.
    if let Some(into_span) = merge.into_span {
        printer.space();
        printer.push_keyword_span(into_span);
    }
    if let Some(target_span) = merge.target_table_span {
        printer.space();
        printer.push_span(target_span);
    }

    // USING source - check if we have a parsed subquery
    if let Some(ref subquery) = merge.using_subquery {
        // We have a parsed subquery - format it nicely
        printer.newline();
        if let Some(using_kw_span) = merge.using_keyword_span {
            printer.push_keyword_span(using_kw_span);
        } else {
            printer.push_keyword("USING");
        }
        printer.space();

        // Find the opening paren position from the source to emit its trivia
        // The paren should be between USING keyword and subquery start
        let source = printer.source().to_string();
        let using_kw_end = if let Some(using_span) = merge.using_span {
            using_span.start + 5 // USING is 5 chars
        } else {
            merge.keyword_span.end
        };
        let search_start = using_kw_end as usize;
        let search_end = subquery.span().start as usize;
        if search_end > search_start {
            if let Some(paren_rel) = source[search_start..search_end].find('(') {
                let paren_pos = using_kw_end + paren_rel as u32;
                // Push the paren using push_span to emit its trivia
                printer.push_span(Span {
                    start: paren_pos,
                    end: paren_pos + 1,
                });
            } else {
                printer.push_char('(');
            }
        } else {
            printer.push_char('(');
        }

        // Check parenthesized expression style
        use crate::formatter::config::ParenthesizedExprStyle;
        let paren_style = printer.config().parenthesized_expr_style;

        match paren_style {
            ParenthesizedExprStyle::Expanded => {
                printer.newline();
                printer.indent_up();
                crate::formatter::statements::select::format_select(printer, subquery)?;
                printer.indent_down();
                printer.newline();
            }
            ParenthesizedExprStyle::Compact => {
                crate::formatter::statements::select::format_select(printer, subquery)?;
            }
        }

        // Find closing paren in source after subquery
        let source = printer.source().to_string();
        let search_start = subquery.span().end as usize;
        let search_end = if let Some(alias_span) = merge.using_alias_span {
            alias_span.start as usize
        } else if let Some(on_span) = merge.on_span {
            on_span.start as usize
        } else {
            source.len()
        };

        if let Some(rparen_rel) = source[search_start..search_end].find(')') {
            let rparen_pos = search_start as u32 + rparen_rel as u32;
            // Emit closing paren and everything after it (AS keyword, alias) up to target
            if let Some(alias_span) = merge.using_alias_span {
                printer.push_span(Span {
                    start: rparen_pos,
                    end: alias_span.end,
                });
            } else {
                printer.push_span(Span {
                    start: rparen_pos,
                    end: rparen_pos + 1,
                });
            }
        } else {
            // Fallback: manually emit
            printer.push_char(')');
            if let Some(alias_span) = merge.using_alias_span {
                printer.space();
                printer.push_identifier_span_v2(alias_span);
            }
        }
    } else if let Some(using_span) = merge.using_span {
        // Fallback: use the span (table reference or unparsed subquery)
        printer.newline();
        printer.push_span(using_span);
    }

    // ON condition - on_span includes "ON t.id = s.id"
    if let Some(on_span) = merge.on_span {
        printer.newline();
        printer.push_span(on_span);
    }

    // WHEN clauses
    for clause in &merge.clauses {
        format_merge_clause(printer, clause)?;
    }

    // OUTPUT clause (MSSQL)
    if let Some(ref output) = merge.output {
        printer.newline();
        printer.push_span(output.span);
    }

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = merge.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format a single WHEN MATCHED/NOT MATCHED clause
fn format_merge_clause(
    printer: &mut Printer,
    clause: &AstMergeClause,
) -> Result<(), FormatterError> {
    printer.newline();
    // WHEN - use push_keyword_span to emit trivia
    printer.push_keyword_span(clause.when_span);
    printer.space();

    // NOT (for NOT MATCHED)
    if let Some(not_span) = clause.not_span {
        printer.push_keyword_span(not_span);
        printer.space();
    }

    // MATCHED (mandatory per Snowflake syntax)
    printer.push_keyword_span(clause.matched_span);

    // BY SOURCE (for NOT MATCHED BY SOURCE)
    if let Some((by_span, source_span)) = clause.by_source_span {
        printer.space();
        printer.push_keyword_span(by_span);
        printer.space();
        printer.push_keyword_span(source_span);
    }

    // AND condition (if present)
    if let Some(and_span) = clause.and_condition_span {
        printer.space();
        // and_condition_span includes "AND condition"
        printer.push_span(and_span);
    }

    // THEN (mandatory per Snowflake syntax)
    printer.space();
    printer.push_keyword_span(clause.then_span);

    // Action (UPDATE/DELETE/INSERT)
    format_merge_action(printer, &clause.action)?;

    Ok(())
}

/// Format MERGE action (UPDATE/DELETE/INSERT)
fn format_merge_action(
    printer: &mut Printer,
    action: &AstMergeActionKind,
) -> Result<(), FormatterError> {
    match action {
        AstMergeActionKind::UpdateAllByName {
            update_span,
            all_span,
            by_span,
            name_span,
        } => {
            printer.newline();
            printer.push_keyword_span(*update_span);
            printer.space();
            printer.push_keyword_span(*all_span);
            printer.space();
            printer.push_keyword_span(*by_span);
            printer.space();
            printer.push_keyword_span(*name_span);
        }
        AstMergeActionKind::UpdateSetStar { update_span } => {
            printer.newline();
            printer.push_span(*update_span);
        }
        AstMergeActionKind::UpdateSet {
            set_span,
            assignments: _,
        } => {
            printer.newline();
            // set_span covers "UPDATE SET col = val, ..." - emit entire range with trivia
            printer.push_span(*set_span);
        }
        AstMergeActionKind::Delete { delete_span } => {
            printer.newline();
            printer.push_keyword_span(*delete_span);
        }
        AstMergeActionKind::InsertAllByName {
            insert_span,
            all_span,
            by_span,
            name_span,
        } => {
            printer.newline();
            printer.push_keyword_span(*insert_span);
            printer.space();
            printer.push_keyword_span(*all_span);
            printer.space();
            printer.push_keyword_span(*by_span);
            printer.space();
            printer.push_keyword_span(*name_span);
        }
        AstMergeActionKind::InsertStar { insert_span } => {
            printer.newline();
            printer.push_span(*insert_span);
        }
        AstMergeActionKind::InsertValues {
            insert_span,
            columns_span: _,
            columns,
            values_span: _,
            values,
            syntax_id,
        } => {
            printer.newline();

            // Try to use syntax layer for proper token emission
            if let Some(sid) = syntax_id {
                if let Some(syntax) = printer.get_merge_insert_values(*sid) {
                    // Emit INSERT keyword with trivia
                    printer.push_keyword_token_id(syntax.insert_keyword);
                    printer.space();

                    // Emit column list if present
                    if let (Some(lp), Some(rp)) = (syntax.columns_lparen, syntax.columns_rparen) {
                        printer.push_token_id(lp);
                        for (i, col_expr) in columns.iter().enumerate() {
                            if i > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            crate::formatter::statements::select::format_expression(
                                printer, col_expr,
                            )?;
                        }
                        printer.push_token_id(rp);
                        printer.space();
                    }

                    // Emit VALUES keyword with trivia
                    printer.push_keyword_token_id(syntax.values_keyword);
                    printer.space();

                    // Emit values list
                    printer.push_token_id(syntax.values_lparen);
                    for (i, val_expr) in values.iter().enumerate() {
                        if i > 0 {
                            printer.push_comma();
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }
                        crate::formatter::statements::select::format_expression(printer, val_expr)?;
                    }
                    printer.push_token_id(syntax.values_rparen);
                } else {
                    // Fallback to span-based emission
                    printer.push_span(*insert_span);
                }
            } else {
                // No syntax layer - fallback to span-based emission
                printer.push_span(*insert_span);
            }
        }
    }

    Ok(())
}

/// Format RETURNING clause (PostgreSQL)
fn format_returning(
    printer: &mut Printer,
    returning: &crate::ast::AstReturning,
) -> Result<(), FormatterError> {
    printer.newline();

    // Get CST node if available for exact token emission
    if let Some(syntax_id) = returning.syntax_id {
        if let Some(syntax) = printer.get_syntax_returning(syntax_id) {
            // Emit RETURNING keyword token
            printer.push_keyword_token_id(syntax.returning_token);
            printer.space();

            // Format item list (expr [AS alias], ...)
            for (idx, item) in returning.items.iter().enumerate() {
                if idx > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_returning_item(printer, item)?;
            }

            return Ok(());
        }
    }

    // Fallback: emit RETURNING keyword from AST span
    printer.push_keyword_span(returning.returning_span);
    printer.space();

    // Format item list
    for (idx, item) in returning.items.iter().enumerate() {
        if idx > 0 {
            printer.push_comma();
            if printer.config().space_after_comma {
                printer.space();
            }
        }
        format_returning_item(printer, item)?;
    }

    Ok(())
}

/// Format a single RETURNING item: expr [AS alias]
fn format_returning_item(
    printer: &mut Printer,
    item: &crate::ast::AstReturningItem,
) -> Result<(), FormatterError> {
    // Format the expression
    crate::formatter::statements::select::format_expression(printer, &item.expr)?;

    // Format optional alias
    if let Some(ref alias) = item.alias {
        printer.space();
        if let Some(as_span) = alias.as_span {
            printer.push_keyword_span(as_span);
            printer.space();
        }
        printer.push_span(alias.ident.span);
    }

    Ok(())
}
