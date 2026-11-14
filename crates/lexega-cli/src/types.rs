// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Option types shared by the command drivers.

use std::collections::BTreeMap;

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
pub(crate) struct BatchProcessingConfig<'a> {
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
    /// Where a table named without a database or schema is looked for
    /// ([`crate::io::resolve_default_schema`]).
    pub default_schema: Option<&'a lexega_core::ir::SessionContext>,
    pub custom_rules: Option<Vec<lexega_core::rules::Rule>>,
    /// The masking policy the custom rule file states; empty by default.
    pub masking: std::sync::Arc<lexega_core::rules::MaskingPolicy>,

    // dbt options
    pub load_macros: bool,
    pub dbt_project_path: Option<&'a str>,
    /// The profile `--dbt-profile` names, read in place of the project's.
    pub dbt_profile: Option<&'a str>,
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

    // Detail mode - show per-file findings in batch output
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

    /// The files named outright on the command line, by the path each is
    /// reported by: one of these that cannot be read fails the run.
    pub named_files: &'a [String],

    /// The run's reading of the working tree's dbt projects.
    pub projects: &'a lexega_core::template::ProjectsOnDisk,
}

impl<'a> BatchProcessingConfig<'a> {
    /// Check if policy enforcement is enabled
    pub fn policy_enabled(&self) -> bool {
        self.policy_path.is_some()
    }

    /// Whether the run writes something a program reads: a report in a
    /// machine-readable format on stdout, a `--report-out` file, or a
    /// policy's decisions.
    pub fn writes_records(&self) -> bool {
        writes_records(self.output_format, self.report_out, self.policy_path)
    }
}

/// Whether a run with `output_format`, `report_out` and `policy_path`
/// writes something a program reads: a report in a machine-readable format
/// on stdout, a `--report-out` file, or a policy's decisions.
pub fn writes_records(
    output_format: &str,
    report_out: Option<&str>,
    policy_path: Option<&str>,
) -> bool {
    !matches!(output_format, "text" | "markdown") || report_out.is_some() || policy_path.is_some()
}

/// An option given twice with different values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatedOption {
    pub option: String,
    pub first: String,
    pub second: String,
}

impl std::fmt::Display for RepeatedOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is given twice, as '{}' and as '{}'; give it once",
            self.option, self.first, self.second
        )
    }
}

impl std::error::Error for RepeatedOption {}

/// The value each single-valued option of a command line was first given,
/// so that a second, different one is refused rather than replacing the
/// first: a gate must not drop the policy it was given.
#[derive(Debug, Default)]
pub struct GivenOptions {
    values: BTreeMap<String, String>,
}

impl GivenOptions {
    /// Note `option` given as `value`. The same value again is accepted.
    pub fn record(&mut self, option: &str, value: &str) -> Result<(), RepeatedOption> {
        match self.values.get(option) {
            Some(first) if first != value => Err(RepeatedOption {
                option: option.to_string(),
                first: first.clone(),
                second: value.to_string(),
            }),
            Some(_) => Ok(()),
            None => {
                self.values.insert(option.to_string(), value.to_string());
                Ok(())
            }
        }
    }
}
