// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Multi-table INSERT formatter
//!
//! Handles Snowflake multi-table INSERT statements:
//! - INSERT ALL - unconditional multi-target insert
//! - INSERT FIRST/ALL WHEN - conditional multi-target insert

use crate::ast::{
    AstMultiInsert, AstMultiInsertIntoClause, AstMultiInsertMode, AstMultiInsertWhenClause,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format multi-table INSERT statement
///
/// Snowflake syntax:
/// ```sql
/// INSERT [OVERWRITE] ALL
///   INTO table1 VALUES (...)
///   INTO table2 (cols) VALUES (...)
///   SELECT ...;
///
/// INSERT [OVERWRITE] FIRST
///   WHEN condition1 THEN
///     INTO table1 VALUES (...)
///   WHEN condition2 THEN
///     INTO table2 VALUES (...)
///   ELSE
///     INTO table3 VALUES (...)
///   SELECT ...;
/// ```
pub fn format_multi_insert(
    printer: &mut Printer,
    multi_insert: &AstMultiInsert,
) -> Result<(), FormatterError> {
    // INSERT keyword
    printer.emit_comments_before(multi_insert.keyword_span.start);
    printer.push_keyword("INSERT");

    // OVERWRITE (if present)
    if let Some(overwrite_span) = multi_insert.overwrite_span {
        printer.emit_comments_before(overwrite_span.start);
        printer.space();
        printer.push_keyword("OVERWRITE");
    }

    // ALL or FIRST keyword
    printer.emit_comments_before(multi_insert.mode_span.start);
    printer.space();
    match multi_insert.mode {
        AstMultiInsertMode::UnconditionalAll => {
            printer.push_keyword("ALL");
        }
        AstMultiInsertMode::ConditionalFirst => {
            printer.push_keyword("FIRST");
        }
        AstMultiInsertMode::ConditionalAll => {
            printer.push_keyword("ALL");
        }
    }

    // Handle unconditional multi-insert (INSERT ALL INTO ... INTO ...)
    if matches!(multi_insert.mode, AstMultiInsertMode::UnconditionalAll) {
        for into_clause in &multi_insert.into_clauses {
            format_into_clause(printer, into_clause)?;
        }
    }

    // Handle conditional multi-insert (INSERT FIRST/ALL WHEN ... THEN INTO ...)
    for when_clause in &multi_insert.when_clauses {
        format_when_clause(printer, when_clause)?;
    }

    // ELSE clause (if present)
    if !multi_insert.else_into_clauses.is_empty() {
        printer.newline();
        printer.push_keyword("ELSE");
        for into_clause in &multi_insert.else_into_clauses {
            format_into_clause(printer, into_clause)?;
        }
    }

    // Trailing subquery (SELECT ...) - recursively format it
    if let Some(subquery) = &multi_insert.subquery {
        printer.emit_comments_before(subquery.span().start);
        printer.newline();

        // Recursively format the SELECT statement
        super::format_select(printer, subquery)?;
    }

    Ok(())
}

/// Format a single INTO clause
fn format_into_clause(
    printer: &mut Printer,
    into_clause: &AstMultiInsertIntoClause,
) -> Result<(), FormatterError> {
    printer.emit_comments_before(into_clause.into_span.start);
    printer.newline();

    if printer.config().multi_insert_into_indent {
        printer.indent_up();
    }

    // INTO keyword
    printer.push_keyword("INTO");

    // Target table
    if let Some(table_span) = into_clause.target_table_span {
        printer.emit_comments_before(table_span.start);
        printer.space();
        printer.push_span(table_span);
    }

    // Column list (if present)
    if let Some(columns_span) = into_clause.columns_span {
        printer.emit_comments_before(columns_span.start);
        printer.space();
        printer.push_span(columns_span);
    }

    // VALUES clause (if present)
    if let Some(values_span) = into_clause.values_span {
        printer.emit_comments_before(values_span.start);

        if printer.config().multi_insert_values_on_newline {
            printer.newline();
            if printer.config().multi_insert_into_indent {
                printer.indent_up();
            }
        } else {
            printer.space();
        }

        printer.push_span(values_span);

        if printer.config().multi_insert_values_on_newline
            && printer.config().multi_insert_into_indent
        {
            printer.indent_down();
        }
    }

    if printer.config().multi_insert_into_indent {
        printer.indent_down();
    }
    Ok(())
}

/// Format a WHEN ... THEN ... INTO clause
fn format_when_clause(
    printer: &mut Printer,
    when_clause: &AstMultiInsertWhenClause,
) -> Result<(), FormatterError> {
    printer.emit_comments_before(when_clause.when_span.start);
    printer.newline();

    if printer.config().multi_insert_when_indent {
        printer.indent_up();
    }

    // WHEN keyword
    printer.push_keyword("WHEN");

    // Condition
    if let Some(condition_span) = when_clause.condition_span {
        printer.emit_comments_before(condition_span.start);
        printer.space();
        printer.push_span(condition_span);
    }

    // THEN keyword
    printer.emit_comments_before(when_clause.then_span.start);
    printer.space();
    printer.push_keyword("THEN");

    // INTO clauses for this WHEN
    for into_clause in &when_clause.into_clauses {
        format_into_clause(printer, into_clause)?;
    }

    if printer.config().multi_insert_when_indent {
        printer.indent_down();
    }

    Ok(())
}
