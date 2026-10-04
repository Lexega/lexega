// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE EXTERNAL FUNCTION`.
//!
//! Sibling-tier carrier analogous to [`super::GitRepositoryPlan`]: a typed
//! projection of the AST that `derive_facts_from_external_function_plan` folds
//! into the public `StatementFacts.ddl.external_function` carrier.
//!
//! An external function ships row data to an external HTTPS endpoint (the
//! `AS '<url>'` proxy/resource) through an `API_INTEGRATION` — a data-egress
//! surface. The endpoint, its scheme, the integration, and the request/
//! response translators are the recognition surface; which endpoints are
//! trusted is YAML.

use crate::ast::AstCreateExternalFunction;
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ExternalFunctionPlan {
    pub target: Option<ExternalFunctionTarget>,
    pub or_replace: bool,
    pub secure: bool,
    /// `API_INTEGRATION` value (upper-cased — it is an identifier).
    pub api_integration: Option<String>,
    /// `AS '<url>'` endpoint, dequoted (case preserved — it is a URL).
    pub endpoint_url: Option<String>,
    /// Lower-cased URL scheme of the endpoint (`https` / `http` / …).
    pub endpoint_scheme: Option<String>,
    pub has_headers: bool,
    pub has_context_headers: bool,
    /// `REQUEST_TRANSLATOR` UDF name (upper-cased).
    pub request_translator: Option<String>,
    /// `RESPONSE_TRANSLATOR` UDF name (upper-cased).
    pub response_translator: Option<String>,
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ExternalFunctionTarget {
    pub name: String,
    pub span: Span,
}

/// Lower a typed [`AstCreateExternalFunction`] into an [`ExternalFunctionPlan`].
pub fn lower_create_external_function_to_plan(
    s: &AstCreateExternalFunction,
    source: &str,
) -> ExternalFunctionPlan {
    let endpoint_url = dequote_text(source, s.endpoint_url_span);
    let endpoint_scheme = endpoint_url.as_deref().and_then(scheme_of);
    ExternalFunctionPlan {
        target: Some(ExternalFunctionTarget {
            name: slice_span(source, s.name_span)
                .unwrap_or("")
                .trim()
                .to_string(),
            span: s.name_span,
        }),
        or_replace: s.or_replace_span.is_some(),
        secure: s.secure_span.is_some(),
        api_integration: upper_text(source, s.api_integration_span),
        endpoint_url,
        endpoint_scheme,
        has_headers: s.headers_span.is_some(),
        has_context_headers: s.context_headers_span.is_some(),
        request_translator: upper_text(source, s.request_translator_span),
        response_translator: upper_text(source, s.response_translator_span),
        node_id: s.node_id,
        span: s.span,
    }
}

/// The scheme portion of a URL (`https://…` → `https`), lower-cased. `None`
/// when the string has no `://` separator.
fn scheme_of(url: &str) -> Option<String> {
    url.split_once("://")
        .map(|(scheme, _)| scheme.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().trim_matches('\'').trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

fn dequote_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().trim_matches('\'').trim().to_string())
        .filter(|s| !s.is_empty())
}
