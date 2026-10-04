// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! USE statement formatter
//!
//! Handles formatting for:
//! - USE ROLE <role_name>
//! - USE DATABASE <database_name>
//! - USE SCHEMA <schema_name>
//! - USE WAREHOUSE <warehouse_name>
//! - USE SECONDARY ROLES { ALL | NONE }

use crate::ast::AstUse;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format USE statement for session context management
///
/// Snowflake syntax:
/// - USE ROLE <role_name>
/// - USE DATABASE <database_name>
/// - USE SCHEMA [<database_name>.]<schema_name>
/// - USE WAREHOUSE <warehouse_name>
/// - USE SECONDARY ROLES { ALL | NONE }
///
/// The AST node provides structured access to the keyword and object spans.
/// We format with normalized keyword casing while preserving identifier casing.
pub fn format_use_stmt(printer: &mut Printer, use_stmt: &AstUse) -> Result<(), FormatterError> {
    // USE keyword
    printer.push_keyword_span(use_stmt.use_keyword_span);
    printer.space();

    // Optional kind keyword span (ROLE / CATALOG / DATABASE / SCHEMA / WAREHOUSE / SECONDARY ROLES)
    // Some forms are valid without explicit kind keyword (e.g. USE mydb).
    if let Some(kind_span) = use_stmt.kind_keyword_span {
        printer.push_keyword_span(kind_span);
        printer.space();
    }

    // Target object (identifier or qualified name)
    printer.push_span(use_stmt.object_span);

    Ok(())
}
