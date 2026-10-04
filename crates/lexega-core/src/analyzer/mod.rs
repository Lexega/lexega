// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Pre-execution risk control and analysis
//!
//! This module provides risk analysis capabilities for SQL queries before execution,
//! enabling blast radius estimation, cost risk detection, and semantic change tracking.

mod config;
mod evidence_utils;
pub mod gl_sast;
mod metrics;
pub mod placeholder_classifier;
pub mod sarif;

pub use config::AnalysisConfig;
pub use evidence_utils::LineIndex;
pub use gl_sast::{to_gl_sast, GlSastReport};
pub use metrics::MetricsCollector;
pub use placeholder_classifier::{
    classify_placeholder, compute_placeholder_stats, PlaceholderStats,
};
pub use sarif::{to_sarif, SarifReport, ToolRun};

use chrono::Utc;

use serde::{Deserialize, Serialize};

/// Source of a policy signal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalSource {
    /// Built-in analyzer (YAML rules in builtin_rules.yaml)
    BuiltIn,
    /// Custom user-defined rule
    Custom,
}

/// Current schema version for risk artifacts
pub const RISK_SCHEMA_VERSION: u32 = 1;

/// Category of skipped statement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    /// Statement type not yet implemented
    UnimplementedStatementType,
    /// OpaqueContent or other unparsed construct (rare edge case)
    UnparsedConstruct,
    /// Other/unknown reason
    Other(String),
}

/// Details about a skipped statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedStatement {
    /// Why it was skipped
    pub reason: SkipReason,
    /// Line number (1-indexed) or 0 if unknown
    pub line_number: usize,
    /// Statement kind/prefix (first 50 chars)
    pub statement_prefix: String,
    /// Best-guess impact category: control, security, ddl, dml, or unknown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_category: Option<String>,
    /// Whether any signals were extracted from this statement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signals_extracted: Option<bool>,
}

impl SkippedStatement {
    /// Guess the impact category based on statement text
    pub fn guess_impact_category(statement_text: &str) -> String {
        let upper = statement_text.to_uppercase();

        // Security-related statements
        if upper.contains("POLICY")
            || upper.contains("GRANT")
            || upper.contains("REVOKE")
            || upper.contains("MASKING")
            || upper.contains("ROW ACCESS")
            || upper.contains("SECURITY")
            || upper.contains("AUTHENTICATION")
            || upper.contains("INTEGRATION")
            || upper.contains("NETWORK POLICY")
        {
            return "security".to_string();
        }

        // Control-related statements
        if upper.starts_with("ALTER SESSION")
            || upper.starts_with("SET ")
            || upper.contains("BEGIN")
            || upper.contains("COMMIT")
            || upper.contains("ROLLBACK")
            || upper.contains("TRANSACTION")
        {
            return "control".to_string();
        }

        // DDL statements
        if upper.starts_with("CREATE ")
            || upper.starts_with("ALTER ")
            || upper.starts_with("DROP ")
            || upper.starts_with("TRUNCATE")
            || upper.starts_with("RENAME")
        {
            return "ddl".to_string();
        }

        // DML statements
        if upper.starts_with("SELECT")
            || upper.starts_with("INSERT")
            || upper.starts_with("UPDATE")
            || upper.starts_with("DELETE")
            || upper.starts_with("MERGE")
            || upper.starts_with("WITH ")
        {
            // CTE-based queries
            return "dml".to_string();
        }

        "unknown".to_string()
    }
}

// ============================================================================
// Placeholder Tracking (for Jinja templates requiring runtime introspection)
// ============================================================================

/// Where in the SQL the placeholder appears (impact zone)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImpactZone {
    /// WHERE clause predicate
    Where,
    /// JOIN condition or join table
    Join,
    /// FROM clause table reference
    From,
    /// SELECT projection
    Select,
    /// GROUP BY clause
    GroupBy,
    /// HAVING clause (filter on aggregates)
    Having,
    /// QUALIFY clause (window function filter)
    Qualify,
    /// ORDER BY clause
    OrderBy,
    /// LIMIT/OFFSET clause
    Limit,
    /// DML target table (INSERT/UPDATE/DELETE/MERGE)
    DmlTarget,
    /// DDL object (CREATE/ALTER/DROP target)
    DdlObject,
    /// Could not determine zone (treated as high-impact for safety)
    Unknown,
    /// Other known but low-impact location
    Other,
}

impl ImpactZone {
    /// Whether this zone is high-impact (affects semantics significantly)
    pub fn is_high_impact(&self) -> bool {
        matches!(
            self,
            ImpactZone::Where
                | ImpactZone::Join
                | ImpactZone::From
                | ImpactZone::Having
                | ImpactZone::Qualify
                | ImpactZone::DmlTarget
                | ImpactZone::DdlObject
                | ImpactZone::Unknown // Unknown treated as high-impact for safety
        )
    }
}

/// Aggregated placeholder summary for a file or batch
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "PlaceholderSummary"))]
pub struct PlaceholderSummary {
    /// Total placeholder count
    pub total: usize,
    /// Statements that contain placeholders
    pub statements_impacted: usize,
    /// High-impact placeholders (WHERE, JOIN, FROM, DML_TARGET, DDL_OBJECT)
    pub high_impact: usize,
    /// Low-impact placeholders (SELECT, ORDER_BY, etc.)
    pub low_impact: usize,
    /// Top placeholder sources (macro name -> count)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_sources: Vec<(String, usize)>,
    /// Top placeholder kinds (kind -> count)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub top_kinds: Vec<(String, usize)>,
}

/// Render completeness level
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
#[cfg_attr(feature = "schema", schemars(rename = "RenderCompleteness"))]
pub enum RenderCompleteness {
    /// No placeholders, full resolution
    #[default]
    Full,
    /// Some placeholders inserted but only in low-impact zones (SELECT, ORDER BY, etc.)
    PartialLowImpactOnly,
    /// Some placeholders inserted including high-impact zones (WHERE, JOIN, FROM, etc.)
    Partial,
    /// A template was present but could not be rendered — analysis ran on the
    /// template text itself, so the rendered shape of the SQL is unknown
    NotRendered,
}

/// Confidence level for analysis results
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[cfg_attr(feature = "schema", schemars(rename = "ConfidenceLevel"))]
pub enum ConfidenceLevel {
    /// Low confidence - placeholders in critical zones
    Low,
    /// Medium confidence - some uncertainty
    Medium,
    /// High confidence - full resolution
    #[default]
    High,
}

/// How many of the evaluated rules ran without analysis they use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AnalysisDepth"))]
pub struct AnalysisDepth {
    /// Rules evaluated in this run.
    pub rules_total: usize,
    /// Rules among them that use analysis this build does not include.
    /// They may stay silent or report less precisely.
    pub rules_limited: usize,
}

impl std::fmt::Display for AnalysisDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} of {} rules use analysis this build does not include and may stay silent or report less precisely.",
            self.rules_limited, self.rules_total
        )
    }
}

/// Signals extracted from a single statement (for debugging custom rules)
/// Reason code for rule rejection (machine-readable)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    Disabled,
    NodetypeMismatch,
    MissingSignal,
    ConditionFailed,
    SignalPresentButDifferentQualification,
    ResolutionLimitHit,
}

/// Structured details for rule rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RejectionDetails {
    NodetypeMismatch {
        expected: Vec<String>,
        actual: String,
    },
    MissingSignal {
        missing_signals: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        present_signals_sample: Option<Vec<String>>,
        /// Phase where the signal was missing: "trigger" or "condition"
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<String>,
    },
    ConditionFailed {
        block_type: String,
        expected_conditions: usize,
        matched_conditions: usize,
    },
    Empty {},
}

/// Information about a rule that was evaluated but didn't trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluatedRule {
    /// Rule ID
    pub rule_id: String,
    /// Rule name for context
    pub rule_name: String,
    /// Machine-readable reason code
    pub reason_code: ReasonCode,
    /// Human-readable explanation
    pub reason: String,
    /// Structured details (machine-actionable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<RejectionDetails>,
    /// Whether this is a terminal condition (intentional bypass) vs a failed match
    #[serde(skip_serializing_if = "is_false")]
    pub terminal: bool,
}

/// Helper for serde skip_serializing_if
fn is_false(value: &bool) -> bool {
    !*value
}

/// Helper for serde skip_serializing_if on usize fields
fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// Resolution warning for signal tracking limitations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionWarning {
    /// Kind of resolution issue
    pub kind: String,
    /// Column or signal that couldn't be fully resolved
    pub column: String,
    /// Signal that was actually observed
    pub observed_signal: String,
    /// Signal that was expected (if known from rule context)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_signal: Option<String>,
    /// Where resolution stopped (cte, derived_table, unknown)
    pub stopped_at: String,
    /// Detailed reason
    pub reason: String,
}

/// Summary of rule evaluation for a statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSummary {
    /// Total rules evaluated
    pub evaluated: usize,
    /// Rules that matched
    pub matched: usize,
    /// Rules that were rejected
    pub rejected: usize,
    /// Whether the rejection list was truncated
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Grouped summary of rejected rules by reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedSummary {
    /// Rules rejected due to statement-type mismatch
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub node_type_mismatch: Vec<String>,
    /// Breakdown of other rejections by reason code. `BTreeMap` for
    /// deterministic key order in serialized output.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub other_rejections: std::collections::BTreeMap<String, usize>,
}

/// Simplified view of a rule that almost matched (verbose mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlmostMatchedRule {
    /// Rule identifier
    pub rule_id: String,
    /// Human-readable rule name
    pub rule_name: String,
    /// Signals that were missing
    pub missing_signals: Vec<String>,
    /// Signals that were present (sample)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub present_signals: Vec<String>,
    /// Brief explanation
    pub reason: String,
}

// ─────────────────────────────────────────────────────────────────────
// V1 diagnostic surface — populated by `analyze_risk_core` when
// `trace_mode` is on, using the v1 rules engine's introspection
// (`crate::rules::evaluate_rules_with_explain`).
// ─────────────────────────────────────────────────────────────────────

/// Per-statement explanation of v1 rule evaluation: which rules
/// matched, and for those that didn't, why (path-by-path).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StatementExplanation {
    /// Source span of the statement this explanation describes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_span: Option<crate::lexer::token::Span>,
    /// First 80 chars of the statement source for human navigation.
    pub statement_preview: String,
    /// Rule IDs that fired for this statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
    /// Rule IDs that were evaluated but didn't fire, with the typed
    /// (rendered) rejection explanation for each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_rules: Vec<RejectedRuleExplanation>,
}

/// One rule that was evaluated against a statement and didn't fire,
/// along with the explanation paths the engine recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RejectedRuleExplanation {
    pub rule_id: String,
    pub explanation: crate::rules::RuleExplanation,
}

/// Statement-level signal and rule matching information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatementSignals {
    /// Line number where statement starts
    pub line_number: usize,
    /// First 80 chars of statement
    pub statement_preview: String,
    /// Custom rules that matched this statement (empty if none)
    pub matched_rules: Vec<String>,
    /// Summary of rule evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_summary: Option<EvaluationSummary>,
    /// Rules that were evaluated but didn't match (for debugging)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluated_but_not_matched: Vec<EvaluatedRule>,
    /// Rules that almost matched (verbose mode - missing signals only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub almost_matched: Vec<AlmostMatchedRule>,
    /// Grouped summary of obvious mismatches (trace mode only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_summary: Option<RejectedSummary>,
    /// Resolution warnings (signal tracking limitations)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_warnings: Vec<ResolutionWarning>,
    /// Per-statement IR-native facts (trace mode only). The public
    /// [`crate::facts::StatementFacts`] carrier exposes everything
    /// rules can reason about: tables read/written, scopes, joins,
    /// predicates, aggregates, projections, policy / integration /
    /// privilege sub-trees, etc. Plan types (`RelPlan` and its
    /// siblings) are deliberately not surfaced here — the public
    /// schema is facts-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<crate::facts::StatementFacts>,
}

/// Explicit details about what analysis could not interpret.
///
/// This is complementary to `skipped_details`:
/// - `skipped_details` => statement types we did not implement (high-level summary).
/// - `analysis_limitations` => per-statement detail for anything we could not fully analyze,
///   including completely skipped statements and opaque inner constructs inside parsed statements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisLimitation {
    /// Line number where statement starts
    pub line_number: usize,

    /// First 80-ish chars of statement (single-line preview)
    pub statement_preview: String,

    /// Exact limitation markers emitted during semantic extraction.
    ///
    /// These are intentionally human-readable and grep-friendly.
    pub limitations: Vec<String>,
}

/// Metadata about the catalog used for analysis
///
/// Enables trust assessment: was the catalog fresh enough?
/// Are there gaps where referenced tables weren't in the catalog?
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CatalogInfo {
    /// Was a catalog provided?
    pub catalog_loaded: bool,

    /// Path to the catalog file (if loaded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_path: Option<String>,

    /// SHA-256 of the catalog snapshot content. Identifies the exact catalog
    /// state this analysis consulted, independent of path or timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_sha256: Option<String>,

    /// When the catalog was generated (ISO8601 from generated_at field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,

    /// Age of the catalog in hours (computed from generated_at)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_hours: Option<f64>,

    /// Warning if catalog is stale (>24h old)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_warning: Option<String>,

    /// Tables referenced in SQL but not found in catalog
    /// These represent gaps where FK/PK/constraint analysis was not possible
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_tables: Vec<String>,

    /// Count of tables in the catalog
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_table_count: Option<usize>,
}

/// What a run measured. Keeps pre-merge gate history and repository
/// posture history distinguishable to whatever reads the artifacts when
/// both kinds share a storage location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RunScope"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunScope {
    /// Pre-merge evaluation of a commit range (`review`, `diff`).
    Change {
        /// Base ref or commit of the compared range, as given to the CLI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base: Option<String>,
        /// Head ref or commit of the compared range, as given to the CLI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head: Option<String>,
        /// Stable identifier of the change under review (PR / MR number).
        /// From `--change-id` or detected from the CI environment. Lets
        /// consumers group repeated runs of the same change (each push to
        /// an open PR re-runs the review).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        change_id: Option<String>,
    },
    /// Evaluation of the repository state as checked out (`analyze`).
    Snapshot {
        /// Commit SHA of the analyzed state, when provided via `--commit`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit: Option<String>,
    },
    /// Evaluation of a single statement at execution time.
    Runtime,
}

/// The kind of a [`RunScope`], without its payload. Policy entries use
/// lists of these (`run_scopes:`) to state which kinds of runs they
/// apply to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RunScopeKind"))]
#[serde(rename_all = "snake_case")]
pub enum RunScopeKind {
    /// Pre-merge evaluation of a commit range (`review`, `diff`).
    Change,
    /// Evaluation of the repository state as checked out (`analyze`).
    Snapshot,
    /// Evaluation of a single statement at execution time.
    Runtime,
}

impl RunScope {
    pub fn kind(&self) -> RunScopeKind {
        match self {
            RunScope::Change { .. } => RunScopeKind::Change,
            RunScope::Snapshot { .. } => RunScopeKind::Snapshot,
            RunScope::Runtime => RunScopeKind::Runtime,
        }
    }
}

/// Semantic Analysis Report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Schema version for forward compatibility
    pub schema_version: u32,

    /// Version of the engine that produced this report
    #[serde(default)]
    pub engine_version: String,

    /// ISO 8601 timestamp when this analysis was performed
    pub timestamp: String,

    /// What this run measured: a commit range, a repository snapshot, or a
    /// single statement at execution time. Absent in reports produced by
    /// older engine versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_scope: Option<RunScope>,

    /// Repository this run analyzed (e.g. `org/repo`). From `--repo`,
    /// the CI environment, or the checkout's `origin` remote. Lets
    /// consumers aggregating several repositories in one storage location
    /// keep them apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,

    /// CI run identifier that produced this report. From `--run-id` or
    /// the CI environment. Groups artifacts written by the same run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,

    /// Full path to the source file that was analyzed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file_path: Option<String>,

    /// High-level summary
    pub summary: AnalysisSummary,

    /// Detailed signals (evidence stored directly in each signal)
    pub signals: Vec<RuleMatch>,

    /// Positive security/governance signals (non-blocking)
    pub positive_signals: Vec<PositiveSignal>,

    /// Details about skipped statements (for transparency)
    pub skipped_details: Vec<SkippedStatement>,

    /// Explicit details about what could not be fully analyzed (skipped statements and/or opaque sub-constructs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analysis_limitations: Vec<AnalysisLimitation>,

    /// Per-statement signal breakdown showing which rules matched.
    /// Only includes RELEVANT signals (governance + used by active rules) to reduce noise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_signals: Vec<StatementSignals>,
    /// Indicates which statements are included: "matched_only" (default) or "all" (trace)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_signals_mode: Option<String>,
    /// V1 rule-engine diagnostic surface — populated when `trace_mode`
    /// is on. One entry per statement with matched-rule IDs and typed
    /// rejection explanations for each rule that didn't fire.
    /// Distinct from `statement_signals`. See `StatementExplanation` doc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_explanations: Vec<StatementExplanation>,
    /// Whether trace mode was enabled (affects detail level)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_mode: Option<bool>,

    /// Catalog metadata for trust assessment
    /// Shows catalog freshness, gaps, and whether FK/PK analysis was possible
    #[serde(default)]
    pub catalog_info: CatalogInfo,

    /// Role context for this analysis (parsed from USE ROLE statements).
    /// Contains the last role in the file.
    #[serde(skip)]
    pub assumed_role: Option<String>,
}

impl AnalysisReport {
    pub fn new() -> Self {
        Self {
            schema_version: RISK_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().to_rfc3339(),
            run_scope: None,
            repo: None,
            run_id: None,
            source_file_path: None,
            summary: AnalysisSummary::default(),
            signals: Vec::new(),
            positive_signals: Vec::new(),
            skipped_details: Vec::new(),
            analysis_limitations: Vec::new(),
            statement_signals: Vec::new(),
            statement_signals_mode: None,
            statement_explanations: Vec::new(),
            trace_mode: None,
            catalog_info: CatalogInfo::default(),
            assumed_role: None,
        }
    }

    /// Get maximum risk level across all signals
    pub fn max_risk_level(&self) -> RiskLevel {
        self.signals
            .iter()
            .map(|f| f.risk_level())
            .max()
            .unwrap_or(RiskLevel::Low)
    }

    /// Add a signal (evidence is already in the signal).
    /// Also updates summary counts incrementally for performance.
    pub fn add_signal(&mut self, signal: RuleMatch) {
        // Increment count by risk level as we add (avoid 4 iterations at the end)
        match signal.risk_level() {
            RiskLevel::Critical => self.summary.critical_count += 1,
            RiskLevel::High => self.summary.high_count += 1,
            RiskLevel::Medium => self.summary.medium_count += 1,
            RiskLevel::Low => self.summary.low_count += 1,
            RiskLevel::Info => self.summary.info_count += 1,
        }
        self.summary.total_reported_signals += 1;
        self.signals.push(signal);
    }

    /// Add a positive signal (non-blocking governance improvement)
    pub fn add_positive_signal(&mut self, signal: PositiveSignal) {
        self.positive_signals.push(signal);
    }

    /// Merge another report into this one
    pub fn merge(&mut self, other: AnalysisReport) {
        // Simple: just extend everything (evidence is already in signals)
        self.signals.extend(other.signals);
        self.positive_signals.extend(other.positive_signals);
        self.skipped_details.extend(other.skipped_details);
        self.analysis_limitations.extend(other.analysis_limitations);
        self.statement_signals.extend(other.statement_signals);
        self.statement_explanations
            .extend(other.statement_explanations);

        // Merge summary counts (since add_signal() updates them incrementally)
        self.summary.total_reported_signals += other.summary.total_reported_signals;
        self.summary.critical_count += other.summary.critical_count;
        self.summary.high_count += other.summary.high_count;
        self.summary.medium_count += other.summary.medium_count;
        self.summary.low_count += other.summary.low_count;
        self.summary.info_count += other.summary.info_count;

        // Merge role context (keep existing if present, otherwise use other's)
        if self.assumed_role.is_none() && other.assumed_role.is_some() {
            self.assumed_role = other.assumed_role;
        }

        // One run evaluates one corpus at one depth, so any report's value
        // describes the whole.
        if self.summary.analysis_depth.is_none() {
            self.summary.analysis_depth = other.summary.analysis_depth;
        }
    }

    /// Deduplicate policy signals by topic_key with custom > built-in precedence
    ///
    /// Groups signals by topic_key (if present). When multiple signals share a topic:
    /// - If any custom signal exists, suppress all built-in signals for that topic
    /// - Keep the custom signal and add all rule IDs to contributors
    /// - If only built-in signals exist, keep them as-is
    pub fn deduplicate_by_topic(&mut self) {
        use std::collections::{HashMap, HashSet};

        // Build index of statement lines covered by custom rules
        let mut custom_rule_lines: HashSet<usize> = HashSet::new();
        for signal in &self.signals {
            let RuleMatch::Analysis(pf) = signal;
            if matches!(pf.source, Some(SignalSource::Custom)) {
                if let Some(line) = pf.statement_line_number {
                    custom_rule_lines.insert(line);
                }
            }
        }

        // Separate policy signals with topic_key from others
        let mut topic_groups: HashMap<String, Vec<usize>> = HashMap::new();
        let mut keep_as_is = Vec::new();

        for (idx, signal) in self.signals.iter().enumerate() {
            match signal {
                RuleMatch::Analysis(pf) if pf.topic_key.is_some() => {
                    let topic = pf.topic_key.as_ref().unwrap().clone();
                    topic_groups.entry(topic).or_default().push(idx);
                }
                _ => {
                    keep_as_is.push(idx);
                }
            }
        }

        let mut deduped_signals = Vec::new();

        // Keep non-topic signals as-is
        for idx in keep_as_is {
            deduped_signals.push(self.signals[idx].clone());
        }

        // Process each topic group
        for (_topic, indices) in topic_groups {
            let signals_in_group: Vec<_> = indices.iter().map(|&idx| &self.signals[idx]).collect();

            // Check if any custom signals exist in this group
            let has_custom = signals_in_group.iter().any(|f| {
                let RuleMatch::Analysis(pf) = f;
                matches!(pf.source, Some(SignalSource::Custom))
            });

            if has_custom {
                // Keep only custom signals, collect all rule IDs as contributors
                let mut contributors = Vec::new();
                let mut representative: Option<AnalysisSignal> = None;

                for &idx in &indices {
                    let RuleMatch::Analysis(pf) = &self.signals[idx];
                    contributors.push(pf.matched_rule.clone());

                    // Use first custom signal as representative
                    if representative.is_none() && matches!(pf.source, Some(SignalSource::Custom)) {
                        let mut merged = pf.clone();
                        merged.contributors = Some(contributors.clone());
                        representative = Some(merged);
                    }
                }

                // Update contributors on representative
                if let Some(mut rep) = representative {
                    rep.contributors = Some(contributors);
                    deduped_signals.push(RuleMatch::Analysis(rep));
                }
            } else {
                // No custom signals - keep all built-in signals
                for &idx in &indices {
                    deduped_signals.push(self.signals[idx].clone());
                }
            }
        }

        self.signals = deduped_signals;
    }

    /// Validate report invariants and evidence correctness
    ///
    /// Checks that:
    /// - Summary counts match actual signals
    /// - Cross-database boolean matches database set size
    /// - Evidence is valid (line numbers > 0, etc.)
    ///
    /// Returns `Ok(())` if valid, `Err` with all validation errors otherwise.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Invariant 1: total_reported_signals == signals.len()
        if self.summary.total_reported_signals != self.signals.len() {
            errors.push(format!(
                "total_reported_signals ({}) doesn't match signals.len() ({})",
                self.summary.total_reported_signals,
                self.signals.len()
            ));
        }

        // Invariant 2: sum of severity counts == total_reported_signals
        let severity_sum = self.summary.critical_count
            + self.summary.high_count
            + self.summary.medium_count
            + self.summary.low_count
            + self.summary.info_count;
        if severity_sum != self.summary.total_reported_signals {
            errors.push(format!(
                "Sum of severity counts ({}) doesn't match total_reported_signals ({})",
                severity_sum, self.summary.total_reported_signals
            ));
        }

        // Invariant 3: cross_database boolean matches database set
        if self.summary.cross_database && self.summary.databases_accessed.len() < 2 {
            errors.push(format!(
                "cross_database is true but databases_accessed has {} database(s)",
                self.summary.databases_accessed.len()
            ));
        }
        if !self.summary.cross_database && self.summary.databases_accessed.len() > 1 {
            errors.push(format!(
                "cross_database is false but databases_accessed has {} databases",
                self.summary.databases_accessed.len()
            ));
        }

        // Invariant 4: Validate evidence in each signal
        for (idx, signal) in self.signals.iter().enumerate() {
            for (ev_idx, evidence) in signal.evidence().iter().enumerate() {
                if let RiskEvidence::RuleMatch {
                    line_number: Some(line),
                    statement_preview,
                    ..
                } = evidence
                {
                    // Line numbers should be >= 1 (1-indexed)
                    if *line == 0 {
                        errors.push(format!(
                            "Signal #{} evidence #{}: Invalid line number 0",
                            idx, ev_idx
                        ));
                    }

                    // Statement preview should not be empty if present
                    if let Some(preview) = statement_preview {
                        if preview.trim().is_empty() {
                            errors.push(format!(
                                "Signal #{} evidence #{}: Empty statement preview",
                                idx, ev_idx
                            ));
                        }
                    }
                }
            }
        }

        // Invariant 5: Schema version should match expected
        if self.schema_version != RISK_SCHEMA_VERSION {
            errors.push(format!(
                "Schema version mismatch: expected {}, got {}",
                RISK_SCHEMA_VERSION, self.schema_version
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Deduplicate policy signals by aggregating identical rules, except
    /// those whose `id` appears in `per_statement_rules`. The set is sourced
    /// from the rule corpus's `per_statement: true` YAML flag — see
    /// [`crate::rules::engine::Rule::per_statement`]. An empty set
    /// aggregates every rule.
    pub fn deduplicate_with_per_statement_rules(
        &mut self,
        per_statement_rules: &std::collections::HashSet<String>,
    ) {
        use std::collections::HashMap;

        // Group policy signals by (matched_rule, signal_type, risk_level)
        let mut policy_groups: HashMap<(String, String, RiskLevel), Vec<usize>> = HashMap::new();
        let mut other_signals = Vec::new();

        for (idx, signal) in self.signals.iter().enumerate() {
            match signal {
                RuleMatch::Analysis(pf) => {
                    // Per-statement compliance/review rules emit one
                    // signal per occurrence and bypass dedup
                    // aggregation. Declared via `per_statement: true`
                    // in the rule's YAML; the set is built by the
                    // caller from the active rule corpus.
                    if per_statement_rules.contains(&pf.matched_rule) {
                        other_signals.push(idx);
                        continue;
                    }
                    let key = (
                        pf.matched_rule.clone(),
                        pf.signal_type.clone(),
                        pf.risk_level,
                    );
                    policy_groups.entry(key).or_default().push(idx);
                }
            }
        }

        // Build deduplicated signals list
        let mut deduped_signals = Vec::new();

        // Add non-policy signals as-is
        for idx in other_signals {
            deduped_signals.push(self.signals[idx].clone());
        }

        // Add aggregated policy signals
        for ((_matched_rule, _signal_type, _risk_level), indices) in policy_groups {
            if indices.is_empty() {
                continue;
            }

            // Get first signal as template
            let first_idx = indices[0];
            let RuleMatch::Analysis(first_signal) = &self.signals[first_idx];
            // Collect all evidence from all occurrences, deduplicating
            let mut all_evidence = Vec::new();
            // Collect all affected_tables from all occurrences, deduplicating
            let mut all_affected_tables: Vec<String> = Vec::new();
            for &idx in &indices {
                let RuleMatch::Analysis(pf) = &self.signals[idx];
                for ev in &pf.evidence {
                    if !all_evidence.contains(ev) {
                        all_evidence.push(ev.clone());
                    }
                }
                // Merge affected_tables
                if let Some(tables) = &pf.affected_tables {
                    for table in tables {
                        if !all_affected_tables.contains(table) {
                            all_affected_tables.push(table.clone());
                        }
                    }
                }
            }

            // Create aggregated signal
            let mut aggregated = first_signal.clone();
            aggregated.evidence = all_evidence;
            // Set deduplicated affected_tables (sorted for deterministic
            // output — insertion order follows the nondeterministic group
            // iteration).
            if !all_affected_tables.is_empty() {
                all_affected_tables.sort();
                aggregated.affected_tables = Some(all_affected_tables);
            }

            // Always set both counts for clarity
            let num_signals = indices.len();
            let num_evidence = aggregated.evidence.len();
            aggregated.signals_merged = Some(num_signals);
            aggregated.evidence_count = Some(num_evidence);

            // Update message if multiple signals were merged
            if num_signals > 1 {
                let base_message = &first_signal.message;
                aggregated.message = format!("{} ({} occurrences)", base_message, num_signals);
            }

            deduped_signals.push(RuleMatch::Analysis(aggregated));
        }

        // Replace signals with deduplicated list
        self.signals = deduped_signals;

        // Recalculate summary counts using centralized method
        self.summary.recalculate_from_signals(&self.signals);
    }
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Risk summary statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AnalysisSummary"))]
pub struct AnalysisSummary {
    pub total_reported_signals: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub tables_read: usize,
    pub tables_written: usize,

    /// Cross-schema access (different schemas within same database)
    pub cross_schema: bool,

    /// Cross-database access (different databases accessed)
    pub cross_database: bool,

    /// Set of databases accessed (for reporting).
    // Stored as a `BTreeSet` (not `HashSet`) so serialization is
    // deterministically ordered — a `HashSet` iterates in a per-process
    // random order, making JSON/YAML/SARIF output non-reproducible. Kept as a
    // non-doc comment so this implementation rationale does not leak into the
    // public JSON schema generated from the doc comment above.
    pub databases_accessed: std::collections::BTreeSet<String>,

    /// Base tables read across all analyzed statements — the set backing the
    /// `tables_read` count. Internal: lets the dynamic-SQL literal-body pass
    /// union the tables read inside executed literal bodies into the summary
    /// (set semantics dedupe across top-level + bodies). Not serialized; the
    /// public surface stays the count.
    #[serde(skip)]
    pub tables_read_names: std::collections::HashSet<String>,
    /// Base tables written — internal set backing the `tables_written` count.
    #[serde(skip)]
    pub tables_written_names: std::collections::HashSet<String>,

    // Coverage metrics for CI trust
    /// Total SQL statements seen, counted at every depth — top-level plus
    /// those inside procedure / function / block bodies. Equals
    /// `statements_analyzed + statements_skipped + jinja_blocks`.
    pub statements_parsed: usize,
    /// Statements the analyzer recognized and evaluated — reads, writes,
    /// DDL, security, and procedural control flow.
    pub statements_analyzed: usize,
    /// Statements the parser could not recognize, so they were not
    /// analyzed (unsupported or malformed syntax). A non-zero value lowers
    /// analysis confidence.
    pub statements_skipped: usize,
    /// Statements whose kind was recognized but whose payload could not be
    /// fully parsed — e.g. an `ALTER TABLE` action that fell through to
    /// `Unknown`, or a `GRANT`/`REVOKE` that degraded to an unparsed shape.
    /// These are a subset of `statements_analyzed` (the verb and target are
    /// known); a non-zero value lowers analysis confidence so silently-dropped
    /// payloads are visible. Omitted from serialization when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub statements_partial: usize,
    /// Jinja/template blocks that are NOT SQL ({{ config() }}, {% set %}, etc.)
    pub jinja_blocks: usize,

    // Operation counts by classification
    pub ddl_operations: usize,
    pub security_operations: usize,
    pub control_operations: usize,

    // === Procedure/Function Body Analysis ===
    /// Number of procedure/function bodies that were analyzed
    #[serde(default, skip_serializing_if = "is_zero")]
    pub procedure_bodies_analyzed: usize,

    /// Total SQL statements found inside procedure/function bodies
    #[serde(default, skip_serializing_if = "is_zero")]
    pub statements_in_bodies: usize,

    /// Role assumed for analysis (from USE ROLE statement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumed_role: Option<String>,

    // === Placeholder/Taint Tracking ===
    /// Render completeness: full (no placeholders) or partial (has placeholders)
    #[serde(default)]
    pub render_completeness: RenderCompleteness,

    /// Aggregated placeholder summary (only present when render_completeness is Partial)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<PlaceholderSummary>,

    /// Overall analysis confidence based on placeholder impact
    #[serde(default)]
    pub analysis_confidence: ConfidenceLevel,

    /// Present when this build ran without part of the analysis: how many
    /// of the rules it evaluated are affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_depth: Option<AnalysisDepth>,
}

impl AnalysisSummary {
    /// Recalculate signal counts from current signals list
    ///
    /// This is the single source of truth for count calculation.
    /// Should be called after any operation that modifies signals
    /// (add_signal, merge, deduplicate).
    pub fn recalculate_from_signals(&mut self, signals: &[RuleMatch]) {
        self.total_reported_signals = signals.len();
        self.critical_count = signals
            .iter()
            .filter(|f| matches!(f.risk_level(), RiskLevel::Critical))
            .count();
        self.high_count = signals
            .iter()
            .filter(|f| matches!(f.risk_level(), RiskLevel::High))
            .count();
        self.medium_count = signals
            .iter()
            .filter(|f| matches!(f.risk_level(), RiskLevel::Medium))
            .count();
        self.low_count = signals
            .iter()
            .filter(|f| matches!(f.risk_level(), RiskLevel::Low))
            .count();
        self.info_count = signals
            .iter()
            .filter(|f| matches!(f.risk_level(), RiskLevel::Info))
            .count();
    }
}

/// Risk signal types
///
/// NOTE: Cost signals are now unified into AnalysisSignal with enrichment fields
/// (scan_type, affected_tables). Cost/performance detection is handled by YAML rules
/// with P0xx IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleMatch {
    Analysis(AnalysisSignal),
}

impl RuleMatch {
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            RuleMatch::Analysis(f) => f.risk_level,
        }
    }

    /// Get the rule ID that generated this signal.
    /// All signals have a stable rule ID for policy matching.
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            RuleMatch::Analysis(f) => Some(&f.matched_rule),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            RuleMatch::Analysis(f) => &f.message,
        }
    }

    pub fn evidence(&self) -> &[RiskEvidence] {
        match self {
            RuleMatch::Analysis(f) => &f.evidence,
        }
    }

    /// Get the signal type as a string (for diff output)
    pub fn signal_type(&self) -> &str {
        match self {
            RuleMatch::Analysis(g) => &g.signal_type,
        }
    }

    /// Get the assumed Snowflake role at the time this signal was generated.
    /// Used for role-based exception matching.
    pub fn assumed_role(&self) -> Option<&str> {
        match self {
            RuleMatch::Analysis(f) => f.assumed_role.as_deref(),
        }
    }

    /// Get the affected tables for this signal.
    pub fn affected_tables(&self) -> Vec<String> {
        match self {
            RuleMatch::Analysis(g) => g.affected_tables.clone().unwrap_or_default(),
        }
    }

    /// Set the source file path on this signal.
    /// Called by CLI when processing files to attach file context.
    pub fn set_source_file(&mut self, path: String) {
        match self {
            RuleMatch::Analysis(f) => {
                // For Analysis signals, source_file is stored in evidence
                for ev in &mut f.evidence {
                    if let RiskEvidence::RuleMatch { source_file, .. } = ev {
                        *source_file = Some(path.clone());
                    }
                }
            }
        }
    }

    /// Get the source file path for this signal.
    /// Returns the source_file from the first evidence item that has one.
    pub fn source_file(&self) -> Option<&str> {
        self.evidence().iter().find_map(|ev| ev.source_file())
    }
}

// NOTE: Blast radius detection is handled by YAML rules DML-WRITE-UNBOUNDED, DML-WRITE-XSCHEMA, DML-WRITE-MULTITBL.
// The AnalysisSignal enrichment fields (unbounded_write, statement_cross_schema, etc.) carry the data.

// NOTE: Cost/performance detection is handled by YAML rules Q-SCAN-NOFILT, Q-JOIN-*, etc.
// The AnalysisSignal enrichment fields (scan_type, affected_tables) carry the data.

/// Policy violation signal
///
/// ## Counting Fields
///
/// - `signals_merged`: Number of raw signals that were grouped/aggregated into this one.
///   For single occurrences this is 1. For aggregated signals (scope = "multi_statement"),
///   this is the count of statements that matched the same rule.
///
/// - `evidence_count`: Number of evidence entries attached to this signal. This may differ
///   from `signals_merged` because:
///   - One signal may have multiple evidence entries (e.g., macro expansion generates multiple)
///   - Evidence entries may be deduplicated if they're identical
///
/// **Important**: Subqueries and CTEs are counted as separate signals when they
/// generate their own semantic extraction warnings.
///
/// ## Evidence
///
/// Policy signals include structured evidence showing:
/// - `RuleMatch`: Signal type, line number, preview, and the specific extraction warning(s) that triggered the rule
/// - Additional context depending on the rule type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSignal {
    pub message: String,
    pub risk_level: RiskLevel,
    pub matched_rule: String,
    pub signal_type: String,
    /// Number of raw signals merged into this aggregated signal (internal use only, not user-facing)
    #[serde(skip_serializing)]
    pub signals_merged: Option<usize>,
    /// Number of evidence entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_count: Option<usize>,
    /// Scope of this signal: "statement" for single occurrence, "multi_statement" for aggregated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Line number for single-statement signals (used for deduplication and custom rule suppression)
    /// Note: This field is actively used in deduplicate_by_topic() to track which lines
    /// have custom rules. Evidence line numbers serve a different purpose (display).
    #[serde(skip_serializing)]
    pub statement_line_number: Option<usize>,
    /// Line numbers for multi-statement aggregated signals
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_lines: Option<Vec<usize>>,
    /// Topic key for deduplication (e.g., "governance.row_policy_removed")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic_key: Option<String>,
    /// Source of this signal (BuiltIn or Custom)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SignalSource>,
    /// Rule IDs that contributed to this signal (for merged signals)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contributors: Option<Vec<String>>,
    /// Parent context if this signal is from a nested statement (e.g., "PROCEDURE my_proc")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_context: Option<String>,
    pub evidence: Vec<RiskEvidence>,

    // === Cost/Performance enrichment fields (populated unconditionally when data available) ===
    /// Scan type classification (from extraction warnings or semantic analysis)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_type: Option<ScanType>,
    /// Tables read by this statement (canonical names)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_tables: Option<Vec<String>>,

    // === Blast radius enrichment fields (populated for write statements when data available) ===
    /// Tables modified by this statement (canonical names)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables_modified: Option<Vec<String>>,
    /// True if statement writes to tables in multiple schemas
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_cross_schema: Option<bool>,
    /// True if statement writes to tables in multiple databases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_cross_database: Option<bool>,
    /// True if this is a write statement without a WHERE clause (unbounded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unbounded_write: Option<bool>,

    // === Role context ===
    /// Snowflake role assumed when this signal was generated (from USE ROLE in SQL)
    /// Used for role-scoped exception matching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumed_role: Option<String>,
}

/// Supporting evidence for signals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RiskEvidence {
    TableReference {
        table: String,
        operation: String,
    },
    PredicateInfo {
        has_where: bool,
        has_limit: bool,
    },
    /// Signal that triggered a custom rule (shows which extraction warning matched)
    RuleMatch {
        /// Type of signal (table_touched, column_ref, governance)
        signal_type: String,
        /// Resolution status for column_ref signals: "base_table" (traced), "cte", "derived_table", "unknown" (unresolved)
        /// For non-column signals, this is None
        #[serde(skip_serializing_if = "Option::is_none")]
        resolution_status: Option<String>,
        /// Full signal string (e.g., "column_ref:pii.users.ssn")
        signal_value: String,
        /// Line in rendered SQL (post-Jinja)
        #[serde(skip_serializing_if = "Option::is_none")]
        line_number: Option<usize>,
        /// Column number within the line (1-based) for distinguishing same-line occurrences
        #[serde(skip_serializing_if = "Option::is_none")]
        column_number: Option<usize>,
        /// Line in template SQL (pre-Jinja) or call site for generated content
        #[serde(skip_serializing_if = "Option::is_none")]
        template_line_number: Option<usize>,
        /// True if line was generated by macro/expression
        #[serde(skip_serializing_if = "Option::is_none")]
        is_generated: Option<bool>,
        /// Name of macro that generated this content
        #[serde(skip_serializing_if = "Option::is_none")]
        macro_name: Option<String>,
        /// First ~80 chars of statement
        #[serde(skip_serializing_if = "Option::is_none")]
        statement_preview: Option<String>,
        /// Source file path (for multi-file reports)
        #[serde(skip_serializing_if = "Option::is_none")]
        source_file: Option<String>,
        /// Clickable location in path:line:column format
        #[serde(skip_serializing_if = "Option::is_none")]
        location: Option<String>,
        /// Snowflake role active when this evidence was generated (for per-statement role tracking)
        #[serde(skip_serializing_if = "Option::is_none")]
        assumed_role: Option<String>,
    },
}

impl RiskEvidence {
    /// Get the assumed role for this evidence item (for per-evidence role-based exception matching)
    pub fn assumed_role(&self) -> Option<&str> {
        match self {
            RiskEvidence::RuleMatch { assumed_role, .. } => assumed_role.as_deref(),
            _ => None,
        }
    }

    /// Get the source file for this evidence item (for per-evidence path-based exception matching)
    pub fn source_file(&self) -> Option<&str> {
        match self {
            RiskEvidence::RuleMatch { source_file, .. } => source_file.as_deref(),
            _ => None,
        }
    }
}

/// Positive security/governance signals (non-blocking informational items)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositiveSignal {
    pub message: String,
    pub signal_type: String,
    pub details: Option<String>,
}

/// Risk severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RiskLevel"))]
pub enum RiskLevel {
    /// Informational - not a risk, just tracking/awareness
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    #[allow(clippy::should_implement_trait)] // an unknown level is `None`, not a parse error
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(RiskLevel::Info),
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

/// Scan type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "ScanType"))]
pub enum ScanType {
    FullTableScan,
    UnboundedScan,
    CartesianProduct,
    ImplicitCrossJoin,
    LeadingWildcard,
    // Subquery patterns
    RepeatedSubquery,
    CorrelatedSubquery,
    // Temporal join patterns
    UnboundedTemporalJoin,
    // Aggregate explosion patterns
    HighCardinalityAggregate,
    ManyDimensionAggregate,
    LargeTableAggregate,
    // Window function patterns
    WindowHighCardinalityPartition,
    WindowRankingNoOrder,
    WindowNoPartitionLargeTable,
    WindowUnboundedFrame,
    WindowMultiplePartitions,
}

/// Error type for risk analysis
#[derive(Debug)]
pub enum RiskError {
    ParseError(crate::error::ParseError),
    AnalysisError(String),
    BaselineError(String),
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
}

impl std::fmt::Display for RiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskError::ParseError(e) => write!(f, "Parse error: {}", e),
            RiskError::AnalysisError(msg) => write!(f, "Analysis error: {}", msg),
            RiskError::BaselineError(msg) => write!(f, "Baseline error: {}", msg),
            RiskError::IoError(e) => write!(f, "IO error: {}", e),
            RiskError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for RiskError {}

impl From<crate::error::ParseError> for RiskError {
    fn from(e: crate::error::ParseError) -> Self {
        RiskError::ParseError(e)
    }
}

impl From<std::io::Error> for RiskError {
    fn from(e: std::io::Error) -> Self {
        RiskError::IoError(e)
    }
}

impl From<serde_json::Error> for RiskError {
    fn from(e: serde_json::Error) -> Self {
        RiskError::SerializationError(e)
    }
}
