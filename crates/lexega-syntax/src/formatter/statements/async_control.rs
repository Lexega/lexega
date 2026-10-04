// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Async job control formatters (AWAIT, CANCEL)
//!
//! Handles Snowflake async query management:
//! - AWAIT <query_id>
//! - CANCEL <query_id>

use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format AWAIT statement
///
/// Snowflake syntax: AWAIT <query_id_expr>
///
/// The AST node provides:
/// - span: entire statement
/// - job_id_expr_span: the expression after AWAIT
pub fn format_await(
    printer: &mut Printer,
    _span: Span,
    job_id_span: Span,
) -> Result<(), FormatterError> {
    // AWAIT keyword
    printer.push_keyword("AWAIT");
    printer.space();

    // Job ID expression (preserve as-is)
    printer.push_span(job_id_span);

    Ok(())
}

/// Format CANCEL statement
///
/// Snowflake syntax: CANCEL <query_id_expr>
///
/// The AST node provides:
/// - span: entire statement
/// - job_id_expr_span: the expression after CANCEL
pub fn format_cancel(
    printer: &mut Printer,
    _span: Span,
    job_id_span: Span,
) -> Result<(), FormatterError> {
    // CANCEL keyword
    printer.push_keyword("CANCEL");
    printer.space();

    // Job ID expression (preserve as-is)
    printer.push_span(job_id_span);

    Ok(())
}
