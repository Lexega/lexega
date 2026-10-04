// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Transaction control statement formatters
//!
//! Handles formatting for:
//! - BEGIN TRANSACTION / START TRANSACTION
//! - `COMMIT [WORK]`
//! - `ROLLBACK [WORK]`

use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format BEGIN TRANSACTION / START TRANSACTION statement
///
/// Snowflake syntax:
/// - `BEGIN [WORK | TRANSACTION] [NAME <name>]`
/// - `START TRANSACTION [NAME <name>]`
///
/// The span-only AST node captures the entire statement as a single span.
/// Parser never consumes semicolons - emit the whole span.
pub fn format_begin_transaction(printer: &mut Printer, span: Span) -> Result<(), FormatterError> {
    printer.push_span(span);
    Ok(())
}

/// Format COMMIT statement
///
/// Snowflake syntax: `COMMIT [WORK]`
///
/// The span-only AST node captures the entire statement as a single span.
/// Parser never consumes semicolons - emit the whole span.
pub fn format_commit(printer: &mut Printer, span: Span) -> Result<(), FormatterError> {
    printer.push_span(span);
    Ok(())
}

/// Format ROLLBACK statement
///
/// Snowflake syntax: `ROLLBACK [WORK]`
///
/// The span-only AST node captures the entire statement as a single span.
/// Parser never consumes semicolons - emit the whole span.
pub fn format_rollback(printer: &mut Printer, span: Span) -> Result<(), FormatterError> {
    printer.push_span(span);
    Ok(())
}

/// Format SET session variable statement
///
/// Snowflake syntax:
/// - Single: SET variable_name = expression
/// - Multiple: SET (var1, var2, ...) = (expr1, expr2, ...)
///
/// The span-only AST node captures the entire statement as a single span.
/// Parser includes semicolon in span if present.
pub fn format_set_variable(printer: &mut Printer, span: Span) -> Result<(), FormatterError> {
    printer.push_span(span);
    Ok(())
}
