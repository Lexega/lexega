// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::ast::types::AstPgRefreshMatview;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a PostgreSQL REFRESH MATERIALIZED VIEW statement.
pub fn format_pg_refresh_matview(
    printer: &mut Printer,
    stmt: &AstPgRefreshMatview,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_pg_refresh_matview_stmt(syntax_id);
            let _ = syntax_arena;

            // REFRESH
            printer.push_keyword_token_id(syntax.refresh_keyword);

            // MATERIALIZED VIEW
            printer.space();
            printer.push_span(stmt.materialized_view_span);

            // Optional: CONCURRENTLY
            if let Some(conc_span) = stmt.concurrently_span {
                printer.space();
                printer.push_span(conc_span);
            }

            // View name
            printer.space();
            printer.push_span(stmt.name_span);

            // Optional: WITH [NO] DATA
            if let Some(wd_span) = stmt.with_data_span {
                printer.space();
                printer.push_span(wd_span);
            }

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}
