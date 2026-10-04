// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Source preparation ahead of analysis.
//!
//! Client and deployment substitution is a pair of line-preserving
//! pre-passes: deployment-pipeline variables ([`deployvars::preprocess`],
//! `${VAR}` and friends) first, then SnowSQL `&var`
//! ([`snowsql::preprocess`]). Each leaves a [`PlaceholderRecord`] for
//! every variable it could not resolve.
//!
//! [`RenderArtifacts`] is what analysis consumes: the text to analyze
//! together with its provenance — a [`SourceMap`] from rendered lines
//! back to template lines when a template was rendered, the placeholder
//! counts that feed analysis confidence, and the dependencies a render
//! discovered.

pub mod artifacts;
pub mod context;
pub mod deployvars;
pub mod records;
pub mod snowsql;
pub mod source_map;
pub mod spans;

/// Detect Jinja template syntax (`{{ … }}`, `{% … %}`, `{# … #}`).
///
/// The single detection predicate for every render surface. A strict
/// superset of the lexer's `has_statement_jinja` flag (which is set only
/// when a literal `{{` / `{%` is lexed), so no site needs to tokenize
/// just to answer "is this a template?".
pub fn has_jinja_syntax(content: &str) -> bool {
    content.contains("{{") || content.contains("{%") || content.contains("{#")
}

/// Run the substitution pre-passes over `source`, then `render` the
/// substituted text. The pre-passes' unresolved references go to
/// `unresolved` and fold into the returned placeholder statistics, so
/// they lower analysis confidence.
pub fn render_substituted<E>(
    source: &str,
    dialect: &Option<crate::dialect::DialectRef>,
    substitution: &SubstitutionConfig,
    vars: Option<&VariableContext>,
    unresolved: impl FnOnce(&[PlaceholderRecord]),
    render: impl FnOnce(&str) -> Result<RenderArtifacts, E>,
) -> Result<RenderArtifacts, E> {
    let deploy = deployvars::preprocess(source, dialect, substitution, vars);
    unresolved(&deploy.placeholders);
    let deploy_stats =
        crate::analyzer::compute_placeholder_stats(&deploy.sql, &deploy.placeholders);
    let prepared = snowsql::preprocess(&deploy.sql, dialect, vars);
    let snow_stats =
        crate::analyzer::compute_placeholder_stats(&prepared.sql, &prepared.placeholders);
    let mut artifacts = render(&prepared.sql)?;
    artifacts.placeholders.absorb(&snow_stats);
    artifacts.placeholders.absorb(&deploy_stats);
    // Later stage first — its offsets are the ones most likely to index
    // the analyzed text; each attach is gated on byte-identity.
    artifacts.extend_placeholder_spans_if_current(&prepared.sql, &prepared.placeholders);
    artifacts.extend_placeholder_spans_if_current(&deploy.sql, &deploy.placeholders);
    Ok(artifacts)
}

pub use artifacts::RenderArtifacts;
pub use context::{
    CommandLineOnlyKey, ContextError, SubstitutionSettings, VariableContext, VariableSource,
};
pub use deployvars::{
    DeployVarsPrep, SubstitutionConfig, SubstitutionConfigError, SubstitutionSyntax,
    UnresolvedVariables,
};
pub use records::{DependencyKind, DependencyRecord, PlaceholderKind, PlaceholderRecord};
pub use source_map::{LineSource, SourceMap, SourceMapStats};
