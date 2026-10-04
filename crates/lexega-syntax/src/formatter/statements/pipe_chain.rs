// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Pipe chain formatter
//!
//! Handles Snowflake experimental pipe chain syntax:
//! - stmt1 |> stmt2 |> stmt3

use crate::formatter::config::PipeChainStyle;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format pipe chain statement
///
/// Snowflake syntax (experimental):
/// ```sql
/// SELECT * FROM table1
/// |> SELECT * FROM $1 WHERE x > 10
/// |> SELECT col1, col2 FROM $1
/// ```
///
/// The pipe operator |> passes the result of one statement to the next.
/// $1, $2, etc. refer to previous stages in the chain.
pub fn format_pipe_chain(printer: &mut Printer, span: Span) -> Result<(), FormatterError> {
    match printer.config().pipe_chain_style {
        PipeChainStyle::Preserve => {
            // Keep as-is (preserve original formatting and comments)
            printer.push_span(span);
        }
        PipeChainStyle::Inline => {
            // Compact all on one line - normalize whitespace
            let chain_text = printer.extract_span(span).to_string();
            let normalized = chain_text.split_whitespace().collect::<Vec<_>>().join(" ");
            printer.push(&normalized);
        }
        PipeChainStyle::Stacked => {
            // Put each |> on new line
            let chain_text = printer.extract_span(span).to_string();
            let parts: Vec<&str> = chain_text.split("|>").collect();

            if let Some((first, rest)) = parts.split_first() {
                printer.push(first.trim());

                for part in rest {
                    printer.newline();
                    printer.push("|>");
                    printer.space();
                    printer.push(part.trim());
                }
            } else {
                printer.push_span(span);
            }
        }
    }

    Ok(())
}
