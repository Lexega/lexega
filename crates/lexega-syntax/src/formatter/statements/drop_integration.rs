// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for DROP INTEGRATION statement variants.

use crate::ast::{
    AstDropApiIntegration, AstDropExternalAccessIntegration, AstDropStorageIntegration,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_drop_api_integration(
    printer: &mut Printer,
    stmt: &AstDropApiIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_api_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        if let Some(api_token) = s.api_token {
            printer.space();
            printer.push_token_id(api_token);
        }
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    if let Some(api_span) = stmt.api_span {
        printer.space();
        printer.push_span(api_span);
    }
    printer.space();
    printer.push_span(stmt.integration_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.integration_name_span);
    Ok(())
}

pub fn format_drop_storage_integration(
    printer: &mut Printer,
    stmt: &AstDropStorageIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_storage_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        if let Some(storage_kw) = s.storage_keyword {
            printer.space();
            printer.push_keyword_token_id(storage_kw);
        }
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    if let Some(storage_span) = stmt.storage_span {
        printer.space();
        printer.push_span(storage_span);
    }
    printer.space();
    printer.push_span(stmt.integration_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.integration_name_span);
    Ok(())
}

pub fn format_drop_external_access_integration(
    printer: &mut Printer,
    stmt: &AstDropExternalAccessIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_external_access_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        if let Some(external_token) = s.external_token {
            printer.space();
            printer.push_token_id(external_token);
        }
        if let Some(access_kw) = s.access_keyword {
            printer.space();
            printer.push_keyword_token_id(access_kw);
        }
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    if let Some(external_span) = stmt.external_span {
        printer.space();
        printer.push_span(external_span);
    }
    if let Some(access_span) = stmt.access_span {
        printer.space();
        printer.push_span(access_span);
    }
    printer.space();
    printer.push_span(stmt.integration_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.integration_name_span);
    Ok(())
}
