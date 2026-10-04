// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for miscellaneous ALTER statements.

use crate::ast::{AstAlterDynamicTable, AstAlterStage};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_alter_dynamic_table(
    printer: &mut Printer,
    stmt: &AstAlterDynamicTable,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_dynamic_table_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.dynamic_token);
        printer.space();
        printer.push_keyword_token_id(s.table_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);
        if stmt.action_span.start < stmt.action_span.end {
            printer.space();
            printer.push_span(stmt.action_span);
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}

pub fn format_alter_stage(
    printer: &mut Printer,
    stmt: &AstAlterStage,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_stage_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_keyword_token_id(s.stage_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);
        if stmt.action_span.start < stmt.action_span.end {
            printer.space();
            printer.push_span(stmt.action_span);
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}
