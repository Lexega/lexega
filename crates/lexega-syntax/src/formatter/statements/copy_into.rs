// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! COPY INTO statement formatters
//!
//! Handles Snowflake data loading and unloading:
//! - `COPY INTO <table> FROM <stage>` - load data into table
//! - `COPY INTO <location> FROM <query>` - unload data to stage

use crate::formatter::config::CopyIntoOptionsStyle;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format COPY INTO TABLE statement (data loading)
///
/// Snowflake syntax:
/// ```sql
/// COPY INTO [database.]schema.table
///   FROM @stage/path
///   FILE_FORMAT = (TYPE = 'CSV' ...)
///   PATTERN = '.*\\.csv'
///   ON_ERROR = 'CONTINUE'
///   ...
/// ```
pub fn format_copy_into_table(
    printer: &mut Printer,
    table_name_span: Span,
    from_span: Span,
    options_span: Option<Span>,
) -> Result<(), FormatterError> {
    // COPY INTO keywords
    printer.push_keyword("COPY");
    printer.space();
    printer.push_keyword("INTO");
    printer.space();

    // Target table name
    printer.push_span(table_name_span);

    // FROM clause
    if printer.config().copy_into_from_on_newline {
        printer.newline();
    } else {
        printer.space();
    }
    printer.push_span(from_span);

    // Options (FILE_FORMAT, PATTERN, VALIDATION_MODE, etc.)
    if let Some(opts_span) = options_span {
        match printer.config().copy_into_options_style {
            CopyIntoOptionsStyle::Inline => {
                printer.space();
                printer.push_span(opts_span);
            }
            // The options are a single span, so `Grouped` lays them out as
            // `Stacked` does.
            CopyIntoOptionsStyle::Stacked | CopyIntoOptionsStyle::Grouped => {
                printer.newline();
                printer.indent_up();
                printer.push_span(opts_span);
                printer.indent_down();
            }
        }
    }

    Ok(())
}

/// Format COPY INTO LOCATION statement (data unloading)
///
/// Snowflake syntax:
/// ```sql
/// COPY INTO @stage/path
///   FROM table_name
///   FILE_FORMAT = (TYPE = 'PARQUET')
///   HEADER = TRUE
///   ...
/// ```
pub fn format_copy_into_location(
    printer: &mut Printer,
    into_span: Span,
    from_span: Span,
    options_span: Option<Span>,
) -> Result<(), FormatterError> {
    // COPY INTO keywords with location
    printer.push_keyword("COPY");
    printer.space();
    printer.push_keyword("INTO");
    printer.space();

    // Target location (stage path)
    printer.push_span(into_span);

    // FROM clause (table or query)
    if printer.config().copy_into_from_on_newline {
        printer.newline();
    } else {
        printer.space();
    }
    printer.push_span(from_span);

    // Options (FILE_FORMAT, HEADER, etc.)
    if let Some(opts_span) = options_span {
        match printer.config().copy_into_options_style {
            CopyIntoOptionsStyle::Inline => {
                printer.space();
                printer.push_span(opts_span);
            }
            // The options are a single span, so `Grouped` lays them out as
            // `Stacked` does.
            CopyIntoOptionsStyle::Stacked | CopyIntoOptionsStyle::Grouped => {
                printer.newline();
                printer.indent_up();
                printer.push_span(opts_span);
                printer.indent_down();
            }
        }
    }

    Ok(())
}
