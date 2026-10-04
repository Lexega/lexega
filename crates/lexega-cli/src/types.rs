// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Option types shared by the command drivers.

use super::artifacts::{DecisionArtifactFormat, ReportArtifactFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RenderDiagnosticsLevel {
    None,
    Summary,
    Impacted,
    All,
}

impl RenderDiagnosticsLevel {
    pub fn from_cli_arg(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "summary" => Ok(Self::Summary),
            "impacted" => Ok(Self::Impacted),
            "all" => Ok(Self::All),
            _ => {
                Err("--render-diagnostics must be one of: none, summary, impacted, all".to_string())
            }
        }
    }
}

/// Configuration for batch processing of SQL files.
///
/// This bundles all the CLI options that flow through batch processing functions
/// like `handle_risk_batch` and `format_batch`. Created once from CLI args,
/// then passed to batch handlers.
#[derive(Clone)]
pub struct BatchProcessingConfig<'a> {
    // Output options
    pub output_format: &'a str,
    pub report_artifact_format: ReportArtifactFormat,
    pub decision_artifact_format: DecisionArtifactFormat,
    pub quiet_mode: bool,
    pub runtime_mode: bool, // Runtime/agent mode: decision-only JSON to stdout

    // Policy options
    pub policy_path: Option<&'a str>,
    pub policy_env: Option<&'a str>,
    pub exceptions_path: Option<&'a str>,
    pub decision_out: Option<&'a str>,
    pub report_out: Option<&'a str>,

    // Policy metadata
    pub policy_team: Option<&'a str>,
    pub policy_job_type: Option<&'a str>,
    pub policy_change_id: Option<&'a str>,
    pub policy_repo: Option<&'a str>,
    pub policy_commit: Option<&'a str>,
    /// Resolved identity (scope/repo/run) stamped on every per-file report
    /// and the batch envelope via `RunIdentity::apply`.
    pub run_identity: crate::ci_env::RunIdentity,

    // Analysis options
    pub catalog_path: Option<&'a str>,
    pub catalog_provider: Option<&'a str>,
    pub custom_rules: Option<Vec<lexega_core::rules::Rule>>,

    // dbt options
    pub load_macros: bool,
    pub dbt_project_path: Option<&'a str>,
    pub fail_on_missing_packages: bool,

    // Variable context — rendered before analysis, same as single-file mode.
    // Threaded so `--var` / `--var-file` / `--snowsql-config` are honored in
    // batch (directory / multi-file) runs, not silently dropped.
    pub jinja_vars: &'a [(String, String)],
    pub jinja_var_files: &'a [String],
    pub snowsql_configs: &'a [String],
    pub env_allowlist: &'a [String],
    pub substitution: &'a lexega_core::template::SubstitutionConfig,

    // Filtering options
    pub min_severity: Option<lexega_core::analyzer::RiskLevel>,

    // Detail mode - show per-file signals in batch output
    pub detail_mode: bool,

    // Dialect
    pub dialect: Option<&'a str>,

    // Debug/diagnostic options
    pub trace_mode: bool,
    pub verbose_mode: bool,
    pub render_diagnostics: RenderDiagnosticsLevel,

    /// Strict-analysis mode. Batch CLI threads this through so per-file
    /// strict enforcement runs during the loop. Defaults to `Permissive`
    /// in both callers that construct this struct.
    pub strict: lexega_core::StrictMode,

    /// Analyze a non-dbt directory as a connected set (scripts resolve
    /// each other's definitions) and report ordering hazards. Off by
    /// default; enabled with `--cross-script`.
    pub cross_script: bool,

    /// Build the Markdown summary even when it is not the output format,
    /// for a caller that posts it.
    pub capture_markdown: bool,

    /// Read each file as of this commit instead of from the working tree.
    pub source_commit: Option<&'a str>,
}

impl<'a> BatchProcessingConfig<'a> {
    /// Check if policy enforcement is enabled
    pub fn policy_enabled(&self) -> bool {
        self.policy_path.is_some()
    }
}
