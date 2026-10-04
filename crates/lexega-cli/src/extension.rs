// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a build plugs into the command drivers.
//!
//! The drivers own argument parsing, file discovery, output and exit
//! codes. An [`Extension`] supplies everything a run can vary by build:
//! which capabilities it may use, the [`Session`] that renders and
//! analyzes sources, the [`PolicyGate`], the renderer `fmt` uses for
//! templates, and any further commands.

use std::path::{Path, PathBuf};

use lexega_core::analyzer::{AnalysisDepth, AnalysisReport};
use lexega_core::dialect::DialectRef;
use lexega_core::rules::Rule;
use lexega_core::template::{RenderArtifacts, SubstitutionConfig};

use crate::artifacts::{DecisionArtifactFormat, ReportArtifactFormat};

/// Something a run can ask for that not every build provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Policy evaluation and decision records.
    PolicyGate,
    /// Analysis of a directory as a connected set of scripts.
    CrossScript,
    /// Decision-only evaluation of one statement at execution time.
    RuntimeMode,
    /// Rendering Jinja / dbt templates before analysis or formatting.
    TemplateRendering,
}

impl Capability {
    /// How the capability reads in a message to the user.
    pub fn label(self) -> &'static str {
        match self {
            Capability::PolicyGate => "policy enforcement and decision records",
            Capability::CrossScript => "cross-script analysis",
            Capability::RuntimeMode => "runtime policy gate for agent-generated SQL",
            Capability::TemplateRendering => "Jinja / dbt template rendering",
        }
    }
}

/// Capabilities implied by the governance options `analyze` and `review`
/// share.
pub fn governance_capabilities(
    policy_path: Option<&str>,
    exceptions_path: Option<&str>,
    decision_out: Option<&str>,
) -> Vec<Capability> {
    let mut needs = Vec::new();
    if policy_path.is_some() || exceptions_path.is_some() || decision_out.is_some() {
        needs.push(Capability::PolicyGate);
    }
    needs
}

/// The options a [`Session`] is opened with.
pub struct SessionOptions<'a> {
    pub jinja_vars: &'a [(String, String)],
    pub jinja_var_files: &'a [String],
    pub snowsql_configs: &'a [String],
    pub env_allowlist: &'a [String],
    pub substitution: &'a SubstitutionConfig,
    pub dbt_profile: Option<&'a str>,
    pub dbt_project_path: Option<&'a str>,
    pub load_macros: bool,
    pub fail_on_missing_packages: bool,
    pub custom_rules: Option<Vec<Rule>>,
    pub trace_mode: bool,
    pub verbose_mode: bool,
    pub catalog_path: Option<&'a str>,
    pub catalog_provider: Option<&'a str>,
    pub dialect_name: Option<&'a str>,
    pub output_format: &'a str,
    pub quiet: bool,
}

/// What a session needs to plan a batch.
pub struct BatchPlan<'a> {
    pub dbt_project_path: Option<&'a str>,
    pub cross_script: bool,
    pub quiet: bool,
}

/// Why one file of a batch produced no report.
pub enum FileFailure {
    /// The source could not be rendered.
    Render(String),
    /// The rendered source could not be analyzed.
    Analysis(String),
}

/// A hazard in the order a connected set of scripts must run in. Files
/// are indices into the planned batch.
pub enum OrderingHazard {
    CircularDependency { files: Vec<usize> },
    MultipleWriters { object: String, files: Vec<usize> },
}

/// The outcome of analyzing a batch as a connected set.
pub struct ConnectedSet {
    /// Producer-before-consumer order, as indices into the planned batch.
    pub order: Vec<usize>,
    pub hazards: Vec<OrderingHazard>,
}

/// Renders and analyzes the sources of one run.
pub trait Session {
    /// The dialect sources are parsed in; `None` is the Snowflake default.
    fn dialect(&self) -> Option<DialectRef>;

    fn set_dialect(&mut self, dialect: Option<DialectRef>);

    /// Substitute variables in `input` and render it if it is a template.
    fn render(&self, input: &str) -> Result<RenderArtifacts, String>;

    /// Analyze rendered text. `source_file` names it in the report.
    fn analyze(
        &self,
        render: &RenderArtifacts,
        source_file: Option<&str>,
    ) -> Result<AnalysisReport, String>;

    /// The order to analyze `files` in, after preparing whatever analysis
    /// across them this session performs.
    fn plan_batch(&mut self, files: &[PathBuf], _plan: &BatchPlan<'_>) -> Vec<PathBuf> {
        files.to_vec()
    }

    /// Render and analyze the `index`-th file of the planned batch.
    /// `input` is its text without a byte-order mark; `had_bom` says
    /// whether one was stripped.
    fn analyze_planned(
        &mut self,
        _index: usize,
        path: &Path,
        input: &str,
        _had_bom: bool,
    ) -> Result<(RenderArtifacts, AnalysisReport), FileFailure> {
        let render = self.render(input).map_err(FileFailure::Render)?;
        let report = self
            .analyze(&render, Some(&path.display().to_string()))
            .map_err(FileFailure::Analysis)?;
        Ok((render, report))
    }

    /// The connected-set outcome, when the planned batch was analyzed as
    /// one.
    fn connected_set(&self) -> Option<&ConnectedSet> {
        None
    }
}

/// The options a [`PolicyGate`] is loaded with.
pub struct PolicySetup<'a> {
    pub policy_path: &'a str,
    pub exceptions_path: Option<&'a str>,
    pub env: Option<&'a str>,
    pub team: Option<&'a str>,
    pub job_type: Option<&'a str>,
    pub change_id: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub commit: Option<&'a str>,
    pub decision_out: Option<&'a str>,
    pub decision_artifact_format: DecisionArtifactFormat,
    pub report_out: Option<&'a str>,
    pub report_artifact_format: ReportArtifactFormat,
    pub output_format: &'a str,
    pub quiet: bool,
    pub runtime_mode: bool,
    /// Whether the run decides many files (`true`) or one source.
    pub batch: bool,
}

/// One file of a batch, for [`PolicyGate::decide_in_batch`].
pub struct BatchCase<'a> {
    /// The rendered text the report describes.
    pub sql: &'a str,
    pub report: &'a AnalysisReport,
    pub file_path: &'a Path,
    /// File-system-safe name for this file's artifacts.
    pub artifact_key: &'a str,
    /// Whether the caller will use [`PolicyOutcome::record`].
    pub want_record: bool,
}

/// What a policy decided about one analyzed source.
pub struct PolicyOutcome {
    pub allowed: bool,
    /// The decision record as written to its artifact, when asked for.
    pub record: Option<serde_json::Value>,
}

/// Evaluates a loaded policy against analysis reports, writes the decision
/// artifacts and reports each outcome to the user.
pub trait PolicyGate {
    /// Decide a single analyzed source. `scope_path` is the file it came
    /// from, absent for standard input.
    fn decide(&self, sql: &str, report: &AnalysisReport, scope_path: Option<&str>)
        -> PolicyOutcome;

    /// Decide one file of a batch.
    fn decide_in_batch(&self, case: &BatchCase<'_>) -> PolicyOutcome;
}

/// The options `fmt` renders templates with.
pub struct FormatRenderOptions<'a> {
    pub jinja_vars: &'a [(String, String)],
    pub jinja_var_files: &'a [String],
    pub dbt_project_path: Option<&'a str>,
    pub dbt_profile: Option<&'a str>,
    pub fail_on_missing_packages: bool,
    pub quiet: bool,
    /// Whether the renderer serves a batch of files or a single source.
    pub batch: bool,
}

/// Renders templates to the SQL text `fmt` formats.
pub trait FormatRenderer {
    fn render(&mut self, source: &str) -> Result<String, String>;
}

/// What a build adds to the command drivers.
pub trait Extension {
    /// The line `--version` prints.
    fn version(&self) -> String;

    /// The name this build's reports give the tool that wrote them.
    fn tool_name(&self) -> &'static str;

    /// Whether this build has `capability` at all. Help lists the options
    /// of a capability only when it does.
    fn offers(&self, capability: Capability) -> bool;

    /// Exit with a message unless this run may use every capability in
    /// `needs`.
    fn authorize(&self, program: &str, needs: &[Capability]);

    /// Open the session that renders and analyzes this run's sources.
    fn open_session(&self, options: SessionOptions<'_>) -> Result<Box<dyn Session>, String>;

    /// Load the policy gate for a run that names a policy.
    fn policy_gate(&self, setup: &PolicySetup<'_>) -> Result<Box<dyn PolicyGate>, String>;

    /// The renderer `fmt` uses for templates.
    fn format_renderer(
        &self,
        options: &FormatRenderOptions<'_>,
    ) -> Result<Box<dyn FormatRenderer>, String>;

    /// Run `command` if this build defines it, taking precedence over the
    /// built-in command of the same name. `false` when it does not.
    fn run_command(&self, command: &str, args: &[String]) -> bool;

    /// Print the top-level usage: every command this build offers.
    fn usage(&self, program: &str);

    /// The sentence shown with a report that ran at reduced depth.
    fn depth_note(&self, depth: &AnalysisDepth) -> String {
        depth.to_string()
    }
}
