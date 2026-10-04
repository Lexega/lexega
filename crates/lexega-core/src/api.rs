// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Function-style entry points.
//!
//! Each function analyses one source with [`Engine::recognition`]: the
//! [`Engine`] method of the same name, without building an engine first.

use crate::analyzer::{AnalysisConfig, AnalysisReport, RiskError};
use crate::catalog::CatalogIndex;
use crate::dialect::Dialect;
use crate::error::ParseError;
use crate::rules::Signal;
use crate::template::RenderArtifacts;
use crate::{Engine, PreparedScript};

/// Analyse SQL with the built-in rule corpus and default configuration.
pub fn analyze_risk(src: &str) -> Result<AnalysisReport, RiskError> {
    Engine::recognition().analyze_risk(src)
}

/// Analyse a SQL file, using its location to find the project it
/// belongs to.
pub fn analyze_risk_from_file(file_path: &std::path::Path) -> Result<AnalysisReport, RiskError> {
    Engine::recognition().analyze_risk_from_file(file_path)
}

/// Analyse SQL under `policy_config`.
pub fn analyze_risk_with_policy_config(
    src: &str,
    policy_config: &AnalysisConfig,
) -> Result<AnalysisReport, RiskError> {
    Engine::recognition().analyze_risk_with_policy_config(src, policy_config)
}

/// Analyse SQL against an optional catalog snapshot file.
pub fn analyze_risk_with_catalog_path(
    src: &str,
    catalog_path: Option<&str>,
) -> Result<AnalysisReport, RiskError> {
    analyze_risk_with_policy_config_and_catalog_path(src, &AnalysisConfig::default(), catalog_path)
}

/// Analyse SQL under `policy_config` against an optional catalog
/// snapshot file.
pub fn analyze_risk_with_policy_config_and_catalog_path(
    src: &str,
    policy_config: &AnalysisConfig,
    catalog_path: Option<&str>,
) -> Result<AnalysisReport, RiskError> {
    // Parse before loading the catalog, so a malformed source reports its
    // parse error even when the snapshot path is also bad.
    let engine = Engine::recognition();
    let PreparedScript { artifacts, script } =
        engine.prepare_and_parse(src, &policy_config.dialect, None)?;
    let catalog_index = match catalog_path {
        Some(path) => Some(
            CatalogIndex::load_from_path(std::path::Path::new(path)).map_err(|e| {
                RiskError::AnalysisError(format!(
                    "Failed to load catalog snapshot from '{path}': {e}"
                ))
            })?,
        ),
        None => None,
    };
    engine.analyze_script(
        &artifacts,
        &script,
        policy_config,
        catalog_index.as_ref(),
        catalog_path,
        None,
        None,
    )
}

/// Analyse already-rendered SQL with the provenance its
/// [`RenderArtifacts`] carry.
pub fn analyze_risk_with_source_map(
    render: &RenderArtifacts,
    policy_config: &AnalysisConfig,
    catalog_index: Option<&CatalogIndex>,
    source_file: Option<&str>,
) -> Result<AnalysisReport, RiskError> {
    Engine::recognition().analyze_risk_with_source_map(
        render,
        policy_config,
        catalog_index,
        source_file,
    )
}

/// Analyse SQL against a loaded catalog.
pub fn analyze_risk_with_catalog_index(
    src: &str,
    catalog_index: &CatalogIndex,
) -> Result<AnalysisReport, RiskError> {
    analyze_risk_with_policy_config_and_catalog_index(
        src,
        &AnalysisConfig::default(),
        catalog_index,
    )
}

/// Analyse SQL under `policy_config` against a loaded catalog.
pub fn analyze_risk_with_policy_config_and_catalog_index(
    src: &str,
    policy_config: &AnalysisConfig,
    catalog_index: &CatalogIndex,
) -> Result<AnalysisReport, RiskError> {
    Engine::recognition().analyze_risk_with_policy_config_and_catalog(
        src,
        policy_config,
        Some(catalog_index),
        None,
    )
}

/// Signals from the privilege statements of `sql`.
pub fn analyze_privilege_facts(sql: &str) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_privilege_facts(sql)
}

/// Signals from the privilege statements of `sql`, with a catalog.
pub fn analyze_privilege_facts_with_catalog(
    sql: &str,
    catalog: &CatalogIndex,
) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_privilege_facts_with_catalog(sql, catalog)
}

/// Signals from the DDL statements of `sql`.
pub fn analyze_ddl_facts(sql: &str) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_ddl_facts(sql)
}

/// Signals from the DDL statements of `sql`, parsed as `dialect`.
pub fn analyze_ddl_facts_with_dialect(
    sql: &str,
    dialect: &dyn Dialect,
) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_ddl_facts_with_dialect(sql, dialect)
}

/// Signals from the query-bearing statements of `sql`.
pub fn analyze_query_facts(sql: &str) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_query_facts(sql)
}

/// Signals from the query-bearing statements of `sql`, with a catalog.
pub fn analyze_query_facts_with_catalog(
    sql: &str,
    catalog: &CatalogIndex,
) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_query_facts_with_catalog(sql, catalog)
}

/// Signals from the query-bearing statements of `sql`, parsed as
/// `dialect`.
pub fn analyze_query_facts_with_dialect(
    sql: &str,
    dialect: &dyn Dialect,
) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_query_facts_with_dialect(sql, dialect)
}

/// Signals from the policy-attachment statements of `sql`.
pub fn analyze_policy_attachment_facts(sql: &str) -> Result<Vec<Signal>, ParseError> {
    Engine::recognition().analyze_policy_attachment_facts(sql)
}

/// The source as the engine would analyse it, and whether a template
/// was rendered to produce it.
#[doc(hidden)]
pub fn prepare_sql_for_analysis_test(src: &str) -> Result<(String, bool), RiskError> {
    let artifacts = Engine::recognition().prepare_sql(src, None)?;
    let was_rendered = artifacts.source_map.is_some();
    Ok((artifacts.sql, was_rendered))
}
