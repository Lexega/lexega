// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for Databricks `CREATE / ALTER / DROP EXTERNAL LOCATION` statements.
//!
//! CREATE output layout:
//! ```sql
//! CREATE EXTERNAL LOCATION [IF NOT EXISTS] name
//!   URL 'url_string'
//!   WITH (STORAGE CREDENTIAL cred_name)
//!   COMMENT 'text'
//! ```
//!
//! ALTER output layout:
//! ```sql
//! ALTER EXTERNAL LOCATION name
//!   RENAME TO new_name
//! -- or --
//! ALTER EXTERNAL LOCATION name
//!   SET URL 'url' FORCE
//! ```
//!
//! DROP output:
//! ```sql
//! DROP EXTERNAL LOCATION [IF EXISTS] name
//! ```

use crate::ast::types::{
    AlterExternalLocationAction, AstAlterExternalLocation, AstCreateExternalLocation,
    AstDropExternalLocation,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_create_external_location(
    printer: &mut Printer,
    stmt: &AstCreateExternalLocation,
) -> Result<(), FormatterError> {
    // CREATE EXTERNAL LOCATION — keyword portion spans from stmt.span.start
    // through just before IF NOT EXISTS or the location name.
    // We reconstruct: push CREATE, space, EXTERNAL, space, LOCATION
    // But since CREATE is a keyword and EXTERNAL/LOCATION are identifiers,
    // we emit the region from stmt.span.start to location_name_span.start
    // as individual tokens.

    // Emit everything from statement start up to and including the location name
    let header_span = crate::lexer::Span {
        start: stmt.span.start,
        end: stmt.location_name_span.end,
    };
    printer.push_span(header_span);

    // URL clause on new indented line
    printer.newline();
    printer.indent_up();
    printer.push_span(stmt.url_keyword_span);
    printer.space();
    printer.push_span(stmt.url_value_span);

    // WITH (STORAGE CREDENTIAL cred_name) on new indented line
    printer.newline();
    printer.push_span(stmt.with_keyword_span);
    printer.space();
    printer.push_span(stmt.storage_credential_clause_span);

    // Optional COMMENT clause on new indented line
    if let (Some(comment_kw), Some(comment_val)) =
        (stmt.comment_keyword_span, stmt.comment_value_span)
    {
        printer.newline();
        printer.push_span(comment_kw);
        printer.space();
        printer.push_span(comment_val);
    }

    printer.indent_down();

    Ok(())
}

/// Format `ALTER EXTERNAL LOCATION name { RENAME TO | SET URL | SET STORAGE CREDENTIAL | [SET] OWNER TO }`
///
/// Layout: header keywords on one line, action clause indented on the next line.
pub fn format_alter_external_location(
    printer: &mut Printer,
    stmt: &AstAlterExternalLocation,
) -> Result<(), FormatterError> {
    // Header: ALTER EXTERNAL LOCATION name
    printer.push_keyword_span(stmt.alter_span);
    printer.space();
    printer.push_span(stmt.external_span);
    printer.space();
    printer.push_span(stmt.location_kw_span);
    printer.space();
    printer.push_span(stmt.location_name_span);

    // Action clause — indented on new line
    printer.newline();
    printer.indent_up();

    match &stmt.action {
        AlterExternalLocationAction::RenameTo {
            rename_span,
            to_span,
            new_name_span,
        } => {
            printer.push_keyword_span(*rename_span);
            printer.space();
            printer.push_keyword_span(*to_span);
            printer.space();
            printer.push_span(*new_name_span);
        }
        AlterExternalLocationAction::SetUrl {
            set_span,
            url_kw_span,
            url_value_span,
            force_span,
        } => {
            printer.push_keyword_span(*set_span);
            printer.space();
            printer.push_keyword_span(*url_kw_span);
            printer.space();
            printer.push_span(*url_value_span);
            if let Some(fs) = force_span {
                printer.space();
                printer.push_span(*fs);
            }
        }
        AlterExternalLocationAction::SetStorageCredential {
            set_span,
            storage_span,
            credential_kw_span,
            credential_name_span,
        } => {
            printer.push_keyword_span(*set_span);
            printer.space();
            printer.push_keyword_span(*storage_span);
            printer.space();
            printer.push_span(*credential_kw_span);
            printer.space();
            printer.push_span(*credential_name_span);
        }
        AlterExternalLocationAction::OwnerTo {
            set_span,
            owner_span,
            to_span,
            owner_name_span,
        } => {
            if let Some(ss) = set_span {
                printer.push_keyword_span(*ss);
                printer.space();
            }
            printer.push_keyword_span(*owner_span);
            printer.space();
            printer.push_keyword_span(*to_span);
            printer.space();
            printer.push_span(*owner_name_span);
        }
    }

    printer.indent_down();
    Ok(())
}

/// Format `DROP EXTERNAL LOCATION [IF EXISTS] name`
pub fn format_drop_external_location(
    printer: &mut Printer,
    stmt: &AstDropExternalLocation,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.external_span);
    printer.space();
    printer.push_span(stmt.location_kw_span);

    if let Some(ie_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(ie_span);
    }

    printer.space();
    printer.push_span(stmt.location_name_span);
    Ok(())
}
