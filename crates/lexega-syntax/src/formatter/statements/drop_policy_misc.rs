// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for miscellaneous DROP POLICY statements.

use crate::ast::{AstDropAggregationPolicy, AstDropAuthenticationPolicy, AstDropMaskingPolicy};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_drop_authentication_policy(
    printer: &mut Printer,
    stmt: &AstDropAuthenticationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_authentication_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
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
        printer.push_identifier_span_v2(s.policy_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.authentication_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    Ok(())
}

pub fn format_drop_aggregation_policy(
    printer: &mut Printer,
    stmt: &AstDropAggregationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_aggregation_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
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
        printer.push_identifier_span_v2(s.policy_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.aggregation_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    Ok(())
}

pub fn format_drop_masking_policy(
    printer: &mut Printer,
    stmt: &AstDropMaskingPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_masking_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_token_id(s.masking_token);
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
        printer.push_identifier_span_v2(s.policy_name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.masking_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    Ok(())
}
