// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for CREATE DYNAMIC TABLE statement
//!
//! Formats the DDL structure and properly formats the SELECT body.

use crate::ast::AstCreateDynamicTable;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a CREATE DYNAMIC TABLE statement
///
/// This formats the header (CREATE DYNAMIC TABLE ... options) with span-based
/// emission for the options, then properly formats the AS SELECT body.
pub fn format_create_dynamic_table(
    printer: &mut Printer,
    dt: &AstCreateDynamicTable,
) -> Result<(), FormatterError> {
    // CREATE keyword
    printer.push_keyword_span(dt.create_span);

    // OR REPLACE (if present)
    if let Some(or_replace_span) = dt.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }

    // OR ALTER (if present)
    if let Some(or_alter_span) = dt.or_alter_span {
        printer.space();
        printer.push_span(or_alter_span);
    }

    // TRANSIENT (if present)
    if let Some(transient_span) = dt.transient_span {
        printer.space();
        printer.push_span(transient_span);
    }

    // DYNAMIC keyword
    printer.space();
    printer.push_span(dt.dynamic_span);

    // ICEBERG (if present)
    if let Some(iceberg_span) = dt.iceberg_span {
        printer.space();
        printer.push_span(iceberg_span);
    }

    // TABLE keyword
    printer.space();
    printer.push_span(dt.table_span);

    // IF NOT EXISTS (if present)
    if let Some(if_not_exists_span) = dt.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }

    // Table name
    printer.space();
    printer.push_identifier_span_v2(dt.name_span);

    // Column definitions (if present)
    if let Some(columns_span) = dt.columns_span {
        printer.space();
        printer.push_span(columns_span);
    }

    // All the options - emit each on its own line for readability
    for option_span in [
        dt.target_lag_span,
        dt.warehouse_span,
        dt.init_warehouse_span,
        dt.refresh_mode_span,
        dt.initialize_span,
        dt.cluster_by_span,
        dt.data_retention_span,
        dt.max_data_extension_span,
        dt.comment_span,
        dt.copy_grants_span,
        dt.row_access_policy_span,
        dt.aggregation_policy_span,
        dt.tag_span,
        dt.require_user_span,
        dt.immutable_where_span,
        dt.backfill_from_span,
    ]
    .iter()
    .filter_map(|s| *s)
    {
        printer.newline();
        printer.indent_up();
        printer.push_span(option_span);
        printer.indent_down();
    }

    // AS keyword and SELECT query
    if let Some(as_span) = dt.as_span {
        printer.newline();
        printer.push_span(as_span);
        printer.newline();

        match &dt.query {
            Ok(parsed_select) => {
                // Format the parsed SELECT/SetSelect statement
                use crate::formatter::statements::select::format_select;
                format_select(printer, parsed_select.as_ref())?;
            }
            Err(query_span) => {
                // Query couldn't be parsed, emit span as-is
                printer.emit_comments_before(query_span.start);
                printer.push_span(*query_span);
            }
        }
    }

    Ok(())
}
