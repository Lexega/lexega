// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for ALTER policy/integration statements.

use crate::ast::{
    AstAlterAggregationPolicy, AstAlterApiIntegration, AstAlterAuthenticationPolicy,
    AstAlterExternalAccessIntegration, AstAlterStorageIntegration,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_alter_authentication_policy(
    printer: &mut Printer,
    stmt: &AstAlterAuthenticationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_authentication_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.authentication_token);
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
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

pub fn format_alter_aggregation_policy(
    printer: &mut Printer,
    stmt: &AstAlterAggregationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_aggregation_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.aggregation_token);
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
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

pub fn format_alter_api_integration(
    printer: &mut Printer,
    stmt: &AstAlterApiIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_api_integration_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.api_token);
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

pub fn format_alter_storage_integration(
    printer: &mut Printer,
    stmt: &AstAlterStorageIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_storage_integration_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
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

pub fn format_alter_external_access_integration(
    printer: &mut Printer,
    stmt: &AstAlterExternalAccessIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_external_access_integration_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.external_token);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
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
