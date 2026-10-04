// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for CREATE policy/integration statements.

use crate::ast::{
    AstCreateAggregationPolicy, AstCreateApiIntegration, AstCreateAuthenticationPolicy,
    AstCreateExternalAccessIntegration, AstCreateStorageIntegration,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

pub fn format_create_authentication_policy(
    printer: &mut Printer,
    stmt: &AstCreateAuthenticationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_authentication_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
            if let Some(alter_kw) = s.alter_keyword_in_create {
                printer.space();
                printer.push_keyword_token_id(alter_kw);
            }
        }
        printer.space();
        printer.push_token_id(s.authentication_token);
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.policy_name_span);

        let mut ordered_spans: Vec<Span> = vec![];
        for prop in [
            s.authentication_methods_span,
            s.client_types_span,
            s.client_policy_span,
            s.mfa_enrollment_span,
            s.mfa_policy_span,
            s.pat_policy_span,
            s.workload_identity_policy_span,
            s.security_integrations_span,
            s.comment_span,
        ]
        .into_iter()
        .flatten()
        {
            ordered_spans.push(prop);
        }
        for extra in &stmt.extras {
            ordered_spans.push(extra.span);
        }
        if !ordered_spans.is_empty() {
            ordered_spans.sort_by_key(|span| span.start);
            printer.newline();
            printer.indent_up();
            for span in ordered_spans {
                printer.push_span(span);
                printer.newline();
            }
            printer.indent_down();
        }
        return Ok(());
    }

    printer.push_keyword_span(stmt.create_span);
    if let Some(or_replace_span) = stmt.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }
    if let Some(or_alter_span) = stmt.or_alter_span {
        printer.space();
        printer.push_span(or_alter_span);
    }
    printer.space();
    printer.push_span(stmt.authentication_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_not_exists_span) = stmt.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);

    let mut ordered_spans: Vec<Span> = vec![];
    for prop in [
        stmt.authentication_methods_span,
        stmt.client_types_span,
        stmt.client_policy_span,
        stmt.mfa_enrollment_span,
        stmt.mfa_policy_span,
        stmt.pat_policy_span,
        stmt.workload_identity_policy_span,
        stmt.security_integrations_span,
        stmt.comment_span,
    ]
    .into_iter()
    .flatten()
    {
        ordered_spans.push(prop);
    }
    for extra in &stmt.extras {
        ordered_spans.push(extra.span);
    }
    if !ordered_spans.is_empty() {
        ordered_spans.sort_by_key(|span| span.start);
        printer.newline();
        printer.indent_up();
        for span in ordered_spans {
            printer.push_span(span);
            printer.newline();
        }
        printer.indent_down();
    }
    Ok(())
}

pub fn format_create_aggregation_policy(
    printer: &mut Printer,
    stmt: &AstCreateAggregationPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_aggregation_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }
        printer.space();
        printer.push_token_id(s.aggregation_token);
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.policy_name_span);
        printer.newline();
        printer.indent_up();
        printer.push_span(s.as_signature_span);
        printer.newline();
        printer.push_span(s.returns_span);
        printer.newline();
        printer.push_token_id(s.arrow_token);
        printer.space();
        printer.push_span(s.body_span);
        if let Some(comment_span) = s.comment_span {
            printer.newline();
            printer.push_span(comment_span);
        }
        printer.indent_down();
        for extra in &stmt.extras {
            printer.newline();
            printer.push_span(extra.span);
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}

pub fn format_create_api_integration(
    printer: &mut Printer,
    stmt: &AstCreateApiIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_api_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }
        printer.space();
        printer.push_token_id(s.api_token);
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);

        let mut ordered_spans: Vec<Span> = vec![];
        for prop in [
            s.api_provider_span,
            s.api_aws_role_arn_span,
            s.azure_tenant_id_span,
            s.azure_ad_application_id_span,
            s.google_audience_span,
            s.api_allowed_prefixes_span,
            s.api_blocked_prefixes_span,
            s.api_key_span,
            s.enabled_span,
            s.allowed_authentication_secrets_span,
            s.api_user_authentication_span,
            s.tls_trusted_certificates_span,
            s.use_privatelink_endpoint_span,
            s.comment_span,
        ]
        .into_iter()
        .flatten()
        {
            ordered_spans.push(prop);
        }
        for extra in &stmt.extras {
            ordered_spans.push(extra.span);
        }
        if !ordered_spans.is_empty() {
            ordered_spans.sort_by_key(|span| span.start);
            printer.newline();
            printer.indent_up();
            for span in ordered_spans {
                printer.push_span(span);
                printer.newline();
            }
            printer.indent_down();
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}

pub fn format_create_storage_integration(
    printer: &mut Printer,
    stmt: &AstCreateStorageIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_storage_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_keyword_token_id(s.storage_keyword);
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);

        let mut ordered_spans: Vec<Span> = vec![];
        for prop in [
            s.type_span,
            s.storage_provider_span,
            s.enabled_span,
            s.storage_allowed_locations_span,
            s.storage_blocked_locations_span,
            s.storage_aws_role_arn_span,
            s.storage_aws_external_id_span,
            s.storage_aws_object_acl_span,
            s.azure_tenant_id_span,
            s.use_privatelink_endpoint_span,
            s.comment_span,
        ]
        .into_iter()
        .flatten()
        {
            ordered_spans.push(prop);
        }
        if !ordered_spans.is_empty() {
            ordered_spans.sort_by_key(|span| span.start);
            printer.newline();
            printer.indent_up();
            for span in ordered_spans {
                printer.push_span(span);
                printer.newline();
            }
            printer.indent_down();
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}

pub fn format_create_external_access_integration(
    printer: &mut Printer,
    stmt: &AstCreateExternalAccessIntegration,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_external_access_integration(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }
        printer.space();
        printer.push_token_id(s.external_token);
        printer.space();
        printer.push_keyword_token_id(s.access_keyword);
        printer.space();
        printer.push_keyword_token_id(s.integration_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.integration_name_span);

        let mut ordered_spans: Vec<Span> = vec![];
        for prop in [
            stmt.allowed_network_rules_span,
            stmt.allowed_api_authentication_integrations_span,
            stmt.allowed_authentication_secrets_span,
            stmt.enabled_span,
            stmt.comment_span,
        ]
        .into_iter()
        .flatten()
        {
            ordered_spans.push(prop);
        }
        for extra in &stmt.extras {
            ordered_spans.push(extra.span);
        }
        if !ordered_spans.is_empty() {
            ordered_spans.sort_by_key(|span| span.start);
            printer.newline();
            printer.indent_up();
            for span in ordered_spans {
                printer.push_span(span);
                printer.newline();
            }
            printer.indent_down();
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}
