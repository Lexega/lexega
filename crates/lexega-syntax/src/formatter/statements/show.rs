// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SHOW and DESCRIBE statement formatters

use crate::ast::{AstDescribe, AstShow};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format SHOW statement
///
/// Examples:
/// - SHOW TABLES
/// - SHOW TABLES IN schema_name
/// - SHOW TABLES LIKE 'user%'
/// - SHOW VIEWS IN DATABASE mydb
pub fn format_show(printer: &mut Printer, show: &AstShow) -> Result<(), FormatterError> {
    // SHOW keyword - use push_keyword_span for trivia preservation
    printer.push_keyword_span(show.keyword_span);
    printer.space();

    // TERSE (optional) - use push_span for trivia preservation
    if let Some(terse_span) = show.terse_span {
        printer.push_span(terse_span);
        printer.space();
    }

    // HISTORY (optional) - use push_span for trivia preservation
    if let Some(history_span) = show.history_span {
        printer.push_span(history_span);
        printer.space();
    }

    // Object phrase (TABLES, VIEWS, etc.) - use push_span for trivia preservation
    if let Some(obj_span) = show.object_span {
        printer.push_keyword_span(obj_span);
    }

    // LIKE clause - use push_span for trivia preservation
    if let Some(like_span) = show.like_pattern_span {
        printer.space();
        printer.push_keyword("LIKE");
        printer.space();
        printer.push_span(like_span); // String literal - preserve original case
    }

    // IN clause - use push_span for trivia preservation
    if let Some(in_kw_span) = show.in_span {
        printer.space();
        printer.push_span(in_kw_span);
        printer.space();

        // IN scope (DATABASE mydb, SCHEMA myschema, etc.) - use push_span for trivia preservation
        if let Some(scope_span) = show.in_scope_span {
            printer.push_span(scope_span);
        }
    }

    // STARTS WITH clause - use push_span for trivia preservation
    if let Some(starts_span) = show.starts_with_span {
        printer.space();
        printer.push_keyword("STARTS");
        printer.space();
        printer.push_keyword("WITH");
        printer.space();
        printer.push_span(starts_span); // String literal - preserve original case
    }

    // LIMIT clause - use push_span for trivia preservation
    if let Some(limit_span) = show.limit_span {
        printer.space();
        printer.push_keyword("LIMIT");
        printer.space();
        printer.push_span(limit_span); // Number literal - preserve original
    }

    // LIMIT FROM clause (LIMIT n FROM m) - use push_span for trivia preservation
    if let Some(from_span) = show.limit_from_span {
        printer.space();
        printer.push_keyword("FROM");
        printer.space();
        printer.push_span(from_span); // Number literal - preserve original
    }

    Ok(())
}

/// Format DESCRIBE statement
///
/// Examples:
/// - DESCRIBE TABLE users
/// - DESCRIBE VIEW user_view
/// - DESC FUNCTION my_udf
pub fn format_describe(
    printer: &mut Printer,
    describe: &AstDescribe,
) -> Result<(), FormatterError> {
    // DESCRIBE or DESC keyword - use push_keyword_span for trivia preservation
    printer.push_keyword_span(describe.keyword_span);
    printer.space();

    // Object phrase (TABLE my_table, VIEW my_view, etc.) - use push_span for trivia preservation
    if let Some(obj_span) = describe.object_span {
        printer.push_span(obj_span);
    }

    // TYPE clause - use push_span for trivia preservation
    if let Some(type_span) = describe.type_clause_span {
        printer.space();
        printer.push_span(type_span);
    }

    Ok(())
}
