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
use lexega_core::template::{ProjectsOnDisk, RenderArtifacts, SubstitutionConfig};

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
    /// The masking policy the custom rule file states; empty by default.
    pub masking: std::sync::Arc<lexega_core::rules::MaskingPolicy>,
    pub trace_mode: bool,
    pub verbose_mode: bool,
    pub catalog_path: Option<&'a str>,
    pub catalog_provider: Option<&'a str>,
    /// The database and schema a table named without them is looked for
    /// in, where the run gives them ([`crate::io::resolve_default_schema`]):
    /// before a dbt profile's, and the dialect's default.
    pub default_schema: Option<&'a lexega_core::ir::SessionContext>,
    pub dialect_name: Option<&'a str>,
    pub output_format: &'a str,
    pub quiet: bool,
    /// The run's reading of the working tree's dbt projects, by which the
    /// scan sorted its files: each project file is read once a run.
    pub projects: &'a ProjectsOnDisk,
    /// Whether the session reviews a commit range of the repository the
    /// working directory is in: naming no project, it then reads none
    /// outside that repository.
    pub change: bool,
}

/// The commit range a change-scoped run reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeRange<'a> {
    pub base: &'a str,
    pub head: &'a str,
    /// The path at `base` of each file the range moves, by its path at
    /// `head`.
    pub renamed_from: &'a std::collections::BTreeMap<String, String>,
    /// The path arguments the run reviews, read as the range's listing of
    /// changed files reads them.
    pub paths: &'a [String],
}

/// What a session needs to plan a batch.
pub struct BatchPlan<'a> {
    pub cross_script: bool,
    pub quiet: bool,
    /// The range a `review` batch covers; each file is read at its head.
    /// `None` when the batch reads the working tree.
    pub change: Option<ChangeRange<'a>>,
}

/// One file of a batch: where it is read from, and the path every report,
/// decision and policy exception names it by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchFile {
    /// The file in the working tree; for a change, its path from the
    /// repository root, read as of a commit.
    pub path: PathBuf,
    /// The path the file is reported by.
    pub name: String,
}

impl BatchFile {
    /// A file of a change, read and named by its path from the repository
    /// root.
    pub fn in_change(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path.display().to_string();
        Self { path, name }
    }
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

    /// Whether the session renders templates; one it does not is analyzed
    /// as written.
    fn renders_templates(&self) -> bool;

    /// Whether a `review` batch compares each file with its version at the
    /// range's base.
    fn compares_changes(&self) -> bool;

    /// Substitute variables in `input` and render it if it is a template.
    fn render(&self, input: &str) -> Result<RenderArtifacts, String>;

    /// As [`render`](Self::render), for `input` read from the file at
    /// `path` (`None` where it was read from no file), so the session can
    /// render it as the file's location gives.
    fn render_file(&self, _path: Option<&Path>, input: &str) -> Result<RenderArtifacts, String> {
        self.render(input)
    }

    /// Analyze rendered text. `source_file` names it in the report.
    fn analyze(
        &self,
        render: &RenderArtifacts,
        source_file: Option<&str>,
    ) -> Result<AnalysisReport, String>;

    /// The files to analyze, in order: `files` and any file the session's
    /// analysis across the batch adds, after preparing that analysis. An
    /// error stops the run.
    fn plan_batch(
        &mut self,
        files: &[BatchFile],
        _plan: &BatchPlan<'_>,
    ) -> Result<Vec<BatchFile>, String> {
        Ok(files.to_vec())
    }

    /// Render and analyze the `index`-th file of the planned batch.
    /// `input` is its text without a byte-order mark; `had_bom` says
    /// whether one was stripped.
    fn analyze_planned(
        &mut self,
        _index: usize,
        file: &BatchFile,
        input: &str,
        _had_bom: bool,
    ) -> Result<(RenderArtifacts, AnalysisReport), FileFailure> {
        let render = self
            .render_file(Some(&file.path), input)
            .map_err(FileFailure::Render)?;
        let report = self
            .analyze(&render, Some(&file.name))
            .map_err(FileFailure::Analysis)?;
        Ok((render, report))
    }

    /// Why the `index`-th file of the planned batch, already analyzed, was
    /// not compared with its version at the range's base: a side of it did
    /// not render, so its report stands without that comparison. A strict
    /// mode fails the run on such a file. `None` where it was compared, or
    /// where the batch reviews no change.
    fn not_compared(&self, _index: usize) -> Option<String> {
        None
    }

    /// The report on a file the planned change removes, from its text at
    /// the range's base: `None` when the base holds the file and it cannot
    /// be read. The driver calls it for each changed file the range's head
    /// does not hold and its base does; `Ok(None)` lists the file as not
    /// analyzed, and an error is handled as a file that failed to render.
    fn analyze_removed(
        &mut self,
        _path: &Path,
        _base_text: Option<&str>,
    ) -> Result<Option<AnalysisReport>, String> {
        Ok(None)
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
    /// The rules the run evaluates: a policy or an exception names one by
    /// its id or a former id.
    pub rules: &'a [Rule],
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

/// One analyzed source, for [`PolicyGate::decide`].
pub struct SourceCase<'a> {
    /// The rendered text the reports describe.
    pub sql: &'a str,
    /// Every finding and context entry of the analysis, whatever
    /// `--min-severity` shows: what the policy decides on, and what the
    /// risk report written beside the decision holds, so the decision's
    /// indices resolve in it.
    pub report: &'a AnalysisReport,
    /// The file the source came from, absent for standard input.
    pub scope_path: Option<&'a str>,
}

/// One file of a batch, for [`PolicyGate::decide_in_batch`].
pub struct BatchCase<'a> {
    /// The rendered text the report describes.
    pub sql: &'a str,
    /// Every finding and context entry of the file's analysis, whatever
    /// `--min-severity` shows.
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
    /// The decision record as written to its artifact: from
    /// [`PolicyGate::decide`], and from [`PolicyGate::decide_in_batch`]
    /// when the case asks for it.
    pub record: Option<serde_json::Value>,
}

/// Evaluates a loaded policy against analysis reports, writes the decision
/// artifacts and reports each outcome to the user.
pub trait PolicyGate {
    /// Decide a single analyzed source.
    fn decide(&self, case: &SourceCase<'_>) -> PolicyOutcome;

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
    /// The run's reading of the working tree's dbt projects, by which the
    /// scan sorted its files: each project file is read once a run.
    pub projects: &'a ProjectsOnDisk,
}

/// Renders templates to the SQL text `fmt` formats.
pub trait FormatRenderer {
    /// Render `source`, read from the file at `path` (`None` where it was
    /// read from no file), so the renderer can render it as the file's
    /// location gives.
    fn render(&mut self, path: Option<&Path>, source: &str) -> Result<String, String>;
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

    /// Whether `command`, one this build defines, reads `--dialect`.
    fn reads_dialect(&self, _command: &str) -> bool {
        false
    }

    /// Print the top-level usage: every command this build offers.
    fn usage(&self, program: &str);

    /// The sentence shown with a report that ran at reduced depth.
    fn depth_note(&self, depth: &AnalysisDepth) -> String {
        depth.to_string()
    }

    /// What renders templates, said where a session that renders none
    /// analyzed some as written.
    fn rendering_offer(&self) -> String {
        "The full build renders Jinja and dbt templates: https://lexega.com".to_string()
    }

    /// What compares a change, said where a `review` session compares none.
    fn comparison_offer(&self) -> String {
        "Comparing a change is part of the full build: https://lexega.com".to_string()
    }
}
