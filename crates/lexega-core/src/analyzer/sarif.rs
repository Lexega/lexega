// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SARIF (Static Analysis Results Interchange Format) output support
//!
//! Converts AnalysisReport findings to SARIF 2.1.0 format for integration with
//! GitHub Security, GitLab SAST, Azure DevOps, and other SARIF-compatible tools.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use super::{AnalysisReport, ConfidenceLevel, RenderCompleteness, RiskLevel, RuleMatch};

/// The tool run a report is written up for: what the report itself does not
/// carry.
#[derive(Debug, Clone, Copy)]
pub struct ToolRun<'a> {
    /// Name the tool that produced the report goes by.
    pub name: &'a str,
    /// Version of that tool.
    pub version: &'a str,
    /// Root that relative file paths resolve against. SARIF only.
    pub base_path: Option<&'a str>,
    /// The sentence a run at reduced depth is reported with.
    pub depth_note: Option<&'a str>,
    /// Files of a batch analyzed on their template text because it could
    /// not be rendered. A one-file report whose summary says not rendered
    /// names its own file without them.
    pub unrendered_files: &'a [String],
    /// SQL files of a batch it left unanalyzed (a template that could not be
    /// rendered, a file that could not be read or analyzed, a symbolic link
    /// the scan does not follow), each with why.
    pub skipped_files: &'a [(String, String)],
    /// SQL files of a batch it did not analyze because they hold dbt macro
    /// definitions, not statements, each with what the run says of it.
    pub macro_files: &'a [(String, String)],
    /// What the run left undone that its findings do not show (templates
    /// analyzed as written, a change not compared), a sentence each.
    pub run_notes: &'a [String],
}

/// What a report says about a file analyzed on its template text.
pub(crate) const NOT_RENDERED_NOTE: &str =
    "Template could not be rendered; analysis ran on template text.";

/// What a report says about a file of a batch it did not analyze.
pub(crate) const NOT_ANALYZED_NOTE: &str = "File was not analyzed; no finding is reported for it.";

/// The files `report` was analyzed on unrendered template text for: none
/// unless its summary says not rendered. A report that names neither those
/// nor a batch's skipped files is of one source, which it names.
pub(crate) fn unrendered_files<'r>(report: &'r AnalysisReport, run: &ToolRun<'r>) -> Vec<&'r str> {
    match report.summary.render_completeness {
        RenderCompleteness::NotRendered
            if run.unrendered_files.is_empty() && run.skipped_files.is_empty() =>
        {
            vec![report.source_file_path.as_deref().unwrap_or("input.sql")]
        }
        RenderCompleteness::NotRendered => {
            run.unrendered_files.iter().map(String::as_str).collect()
        }
        RenderCompleteness::Full
        | RenderCompleteness::PartialLowImpactOnly
        | RenderCompleteness::Partial => Vec::new(),
    }
}

/// SARIF schema version we produce
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Top-level SARIF document
#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single analysis run
#[derive(Debug, Clone, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    /// The unit every region's columns count in.
    #[serde(rename = "columnKind")]
    pub column_kind: SarifColumnKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
    #[serde(rename = "originalUriBaseIds", skip_serializing_if = "Option::is_none")]
    pub original_uri_base_ids: Option<HashMap<String, SarifArtifactLocation>>,
    /// How completely the run's templates rendered, and the confidence that
    /// leaves the analysis.
    pub properties: SarifRunProperties,
}

/// The unit a run's region columns count in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SarifColumnKind {
    /// UTF-16 code units, the unit GitHub code scanning reads.
    #[serde(rename = "utf16CodeUnits")]
    Utf16CodeUnits,
}

/// The run's property bag.
#[derive(Debug, Clone, Serialize)]
pub struct SarifRunProperties {
    /// The least complete render of the run's files: a file left unanalyzed
    /// because it did not render counts as not rendered.
    #[serde(rename = "renderCompleteness")]
    pub render_completeness: RenderCompleteness,
    /// The lowest confidence of the files analyzed.
    #[serde(rename = "analysisConfidence")]
    pub analysis_confidence: ConfidenceLevel,
}

/// Tool information
#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifToolDriver,
}

/// Tool driver (main component)
#[derive(Debug, Clone, Serialize)]
pub struct SarifToolDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    pub rules: Vec<SarifRule>,
}

/// Rule definition
#[derive(Debug, Clone, Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    /// Prior ids this rule was published under, so code-scanning tools
    /// can re-key existing alerts across a rename. Omitted when empty.
    #[serde(rename = "deprecatedIds", skip_serializing_if = "Vec::is_empty")]
    pub deprecated_ids: Vec<String>,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(
        rename = "defaultConfiguration",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_configuration: Option<SarifRuleConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

/// Rule configuration (default level)
#[derive(Debug, Clone, Serialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
}

/// Rule properties (tags, security-severity, etc.)
#[derive(Debug, Clone, Serialize)]
pub struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision: Option<String>,
}

/// Single analysis result
#[derive(Debug, Clone, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<BTreeMap<String, String>>,
    // BTreeMap: serialized key order must be deterministic run-to-run.
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "Option::is_none"
    )]
    pub partial_fingerprints: Option<BTreeMap<String, String>>,
}

/// Message with text
#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Location information
#[derive(Debug, Clone, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    /// What is said of this location in particular.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Physical location (file + region)
#[derive(Debug, Clone, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// Artifact (file) location
#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// Region within a file
#[derive(Debug, Clone, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

/// Code snippet
#[derive(Debug, Clone, Serialize)]
pub struct SarifSnippet {
    pub text: String,
}

/// Invocation information. Optional in SARIF; emitted so a consumer can
/// filter findings by `endTimeUtc`.
#[derive(Debug, Clone, Serialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    /// RFC3339 timestamp marking analysis completion. Sourced from
    /// [`AnalysisReport::timestamp`]. A consumer that filters findings by
    /// recency has nothing to filter on without it.
    #[serde(rename = "endTimeUtc", skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
    /// Notes about the run as a whole. Omitted when empty.
    #[serde(
        rename = "toolExecutionNotifications",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tool_execution_notifications: Vec<SarifNotification>,
}

/// A message from the tool about the run rather than about a result.
#[derive(Debug, Clone, Serialize)]
pub struct SarifNotification {
    pub descriptor: SarifNotificationDescriptor,
    pub level: String,
    pub message: SarifMessage,
    /// The files the notification is about. Omitted when it is about the
    /// run as a whole.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
}

/// Identifies the kind of a [`SarifNotification`].
#[derive(Debug, Clone, Serialize)]
pub struct SarifNotificationDescriptor {
    pub id: String,
}

/// `descriptor.id` of the notification a run at reduced depth carries.
pub const DEPTH_NOTIFICATION_ID: &str = "analysis-depth";

/// `descriptor.id` of the notification a file analyzed on its template text
/// carries.
pub(crate) const NOT_RENDERED_NOTIFICATION_ID: &str = "template-not-rendered";

/// `descriptor.id` of the notification naming the files of a batch it did not
/// analyze, each location saying why.
pub(crate) const NOT_ANALYZED_NOTIFICATION_ID: &str = "file-not-analyzed";

/// `descriptor.id` of each notification saying what the run left undone.
pub(crate) const RUN_LIMITED_NOTIFICATION_ID: &str = "run-limited";

/// `descriptor.id` of the notification naming a file of a batch it did not
/// analyze because it holds macro definitions.
pub(crate) const MACRO_FILE_NOTIFICATION_ID: &str = "macro-file-not-analyzed";

/// Where `path` is, as a SARIF artifact location: an absolute path as a
/// `file://` URI, a relative one against `uri_base_id`.
fn artifact_location(path: String, uri_base_id: &Option<String>) -> SarifArtifactLocation {
    if path.starts_with('/') {
        SarifArtifactLocation {
            uri: format!("file://{}", path),
            uri_base_id: None,
        }
    } else {
        SarifArtifactLocation {
            uri: path,
            uri_base_id: uri_base_id.clone(),
        }
    }
}

impl SarifMessage {
    pub fn new(text: impl Into<String>) -> Self {
        SarifMessage { text: text.into() }
    }
}

/// Versioned `partialFingerprints` key carrying Lexega's stable finding
/// identity. SARIF consumers (GitHub Code Scanning in particular) match
/// alerts across uploads on these values — bump the version suffix if the
/// hash inputs ever change, so old and new fingerprints don't false-match.
const FINDING_FINGERPRINT_KEY: &str = "lexegaFinding/v1";

/// Collapse whitespace runs to single spaces so reformatting a statement
/// doesn't change its identity.
fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Stable identity for a finding: rule + file + normalized statement text.
/// Line/column are deliberately excluded — the point of the fingerprint is
/// that alerts survive code moving up or down the file. Two findings with
/// the same inputs are disambiguated later by an ordinal suffix.
///
/// `pub`: this is the canonical finding identity, shared by the SARIF and
/// GitLab emitters and by anything that ingests their output — never
/// reimplement it.
///
/// `file_path` is the path exactly as recorded in evidence — never a
/// formatted URI (no `file://` prefix), or the surfaces stop agreeing.
pub fn finding_fingerprint(
    rule_id: &str,
    file_path: &str,
    statement: Option<&str>,
    message: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(file_path.as_bytes());
    hasher.update([0u8]);
    // Statement text is the most stable witness; the message (which carries
    // object names and specifics) is the fallback when no preview exists.
    let body = match statement {
        Some(s) => normalize_whitespace(s),
        None => normalize_whitespace(message),
    };
    hasher.update(body.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn fingerprint_map(value: String) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    map.insert(FINDING_FINGERPRINT_KEY.to_string(), value);
    Some(map)
}

/// Map RiskLevel to SARIF level
fn risk_level_to_sarif_level(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "error",
        RiskLevel::High => "error",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "note",
        RiskLevel::Info => "note",
    }
}

/// Map RiskLevel to security-severity (CVSS-like score for GitHub)
fn risk_level_to_security_severity(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "9.0",
        RiskLevel::High => "7.0",
        RiskLevel::Medium => "4.0",
        RiskLevel::Low => "1.0",
        RiskLevel::Info => "0.0",
    }
}

/// Inverse of `risk_level_to_security_severity`: recover the five-level
/// severity label from a `security-severity` score (the same thresholds
/// GitHub code scanning applies). For reading a SARIF report back in; both
/// directions of the score convention live in this module.
pub fn severity_label_from_security_score(score: f64) -> &'static str {
    if score >= 9.0 {
        "Critical"
    } else if score >= 7.0 {
        "High"
    } else if score >= 4.0 {
        "Medium"
    } else if score > 0.0 {
        "Low"
    } else {
        "Info"
    }
}

/// Extract rule ID from a finding
pub(super) fn get_rule_id(finding: &RuleMatch) -> String {
    match finding {
        RuleMatch::Analysis(g) => g.matched_rule.clone(),
    }
}

/// Get line number from a finding (template line preferred for dbt models)
pub(super) fn get_line_number(finding: &RuleMatch) -> Option<usize> {
    // First try to parse from evidence location field (path:line:column format)
    // The location field already contains template line when available
    if let Some(place) = get_location_from_evidence(finding) {
        return Some(place.line);
    }

    // Second: try template_line_number directly from evidence
    // This handles cases where location is not set but template_line_number exists
    for evidence in finding.evidence() {
        if let super::RiskEvidence::RuleMatch {
            template_line_number: Some(line),
            ..
        } = evidence
        {
            return Some(*line);
        }
    }

    // Third: try line_number from evidence (rendered line, but still better than nothing)
    for evidence in finding.evidence() {
        if let super::RiskEvidence::RuleMatch {
            line_number: Some(line),
            ..
        } = evidence
        {
            return Some(*line);
        }
    }

    // Final fallback to statement_line_number on AnalysisFinding
    match finding {
        RuleMatch::Analysis(g) => g.statement_line_number,
    }
}

/// Where an evidence item points: the file and line its `location` names,
/// the column in UTF-16 code units where the item carries its position, and
/// its statement preview.
pub(super) struct EvidencePlace {
    pub(super) path: String,
    pub(super) line: usize,
    pub(super) utf16_column: Option<usize>,
    pub(super) preview: Option<String>,
}

/// Where `evidence` points, read from its `location` (`path:line:column`)
/// and its position.
fn evidence_place(evidence: &super::RiskEvidence) -> Option<EvidencePlace> {
    let super::RiskEvidence::RuleMatch {
        location: Some(location),
        position,
        statement_preview,
        ..
    } = evidence
    else {
        return None;
    };
    let mut parts = location.rsplitn(3, ':');
    let (_column, line, path) = (parts.next()?, parts.next()?, parts.next()?);
    let line = position.map_or_else(|| line.parse().ok(), |at| Some(at.line))?;
    Some(EvidencePlace {
        path: path.to_string(),
        line,
        utf16_column: position.map(|at| at.utf16_column),
        preview: statement_preview.clone(),
    })
}

/// Where a finding's first located evidence points.
pub(super) fn get_location_from_evidence(finding: &RuleMatch) -> Option<EvidencePlace> {
    finding.evidence().iter().find_map(evidence_place)
}

/// Where each located evidence of a finding points (one per UNION branch,
/// etc.).
pub(super) fn get_all_locations_from_evidence(finding: &RuleMatch) -> Vec<EvidencePlace> {
    finding
        .evidence()
        .iter()
        .filter_map(evidence_place)
        .collect()
}

/// Get file path from finding evidence, with fallback to default
pub(super) fn get_file_path_from_evidence(finding: &RuleMatch, default: &str) -> String {
    // First try location field (has full path)
    if let Some(place) = get_location_from_evidence(finding) {
        return place.path;
    }

    // Then try source_file field
    for evidence in finding.evidence() {
        if let super::RiskEvidence::RuleMatch {
            source_file: Some(file),
            ..
        } = evidence
        {
            return file.clone();
        }
    }

    default.to_string()
}

/// Get statement preview from evidence
pub(super) fn get_statement_preview(finding: &RuleMatch) -> Option<String> {
    for evidence in finding.evidence() {
        if let super::RiskEvidence::RuleMatch {
            statement_preview, ..
        } = evidence
        {
            if statement_preview.is_some() {
                return statement_preview.clone();
            }
        }
    }
    None
}

/// Get tags for a finding type
///
/// Uses enrichment fields to determine finding category rather than rule ID prefixes.
/// This is more robust as it reflects actual finding characteristics.
fn get_finding_tags(finding: &RuleMatch) -> Vec<String> {
    match finding {
        RuleMatch::Analysis(g) => {
            // Diff findings (DIFF-* rule_ids) carry the
            // `semantic-change` / `baseline` SARIF tags. The v1 fact
            // engine routes them through `RuleMatch::Analysis`, so we
            // discriminate by rule_id prefix.
            if g.matched_rule.starts_with("DIFF-") {
                return vec!["semantic-change".to_string(), "baseline".to_string()];
            }

            let mut tags = vec!["governance".to_string()];

            // Cost/performance findings have scan_type or affected_tables populated
            if g.scan_type.is_some() || g.affected_tables.is_some() {
                tags.push("performance".to_string());
                tags.push("cost".to_string());
                tags.push("query-pattern".to_string());
            }

            // Blast radius findings have tables_modified or unbounded_write populated
            if g.tables_modified.is_some() || g.unbounded_write.is_some() {
                tags.push("blast-radius".to_string());
                tags.push("data-modification".to_string());
            }

            // Security findings - check for security-related finding types
            let sig_type = g.finding_type.to_lowercase();
            if sig_type.contains("privilege")
                || sig_type.contains("grant")
                || sig_type.contains("policy")
                || sig_type.contains("role")
                || sig_type.contains("security")
                || sig_type.contains("encryption")
            {
                tags.push("security".to_string());
                tags.push("security-policy".to_string());
            }

            // Default governance tag if no other category matched
            if tags.len() == 1 {
                tags.push("security".to_string());
            }

            tags
        }
    }
}

/// Convert an `AnalysisReport` to SARIF. A rule is named by its id: the
/// corpus gives a rule no other name.
pub fn to_sarif(report: &AnalysisReport, run: &ToolRun<'_>) -> SarifReport {
    let base_path = run.base_path;
    // Collect unique rules
    let mut rules_map: HashMap<String, SarifRule> = HashMap::new();
    let mut results: Vec<SarifResult> = Vec::new();

    // Get file path (use default if not set)
    let file_uri = report
        .source_file_path
        .as_deref()
        .unwrap_or("input.sql")
        .to_string();

    // If base_path is provided, use %SRCROOT% as the base ID for relative paths
    let uri_base_id = if base_path.is_some() {
        Some("%SRCROOT%".to_string())
    } else {
        None
    };

    for finding in &report.findings {
        let rule_id = get_rule_id(finding);
        let level = finding.risk_level();

        // Add rule if not already present
        if !rules_map.contains_key(&rule_id) {
            rules_map.insert(
                rule_id.clone(),
                SarifRule {
                    id: rule_id.clone(),
                    name: rule_id.clone(),
                    deprecated_ids: crate::rules::former_ids_for(&rule_id).to_vec(),
                    short_description: SarifMessage::new(&rule_id),
                    full_description: Some(SarifMessage::new(finding.message())),
                    default_configuration: Some(SarifRuleConfiguration {
                        level: risk_level_to_sarif_level(level).to_string(),
                    }),
                    help: None,
                    properties: Some(SarifRuleProperties {
                        tags: Some(get_finding_tags(finding)),
                        security_severity: Some(risk_level_to_security_severity(level).to_string()),
                        precision: Some("high".to_string()),
                    }),
                },
            );
        }

        // Get all locations from evidence - for findings with multiple UNION branches,
        // this will create one SARIF result per location
        let all_locations = get_all_locations_from_evidence(finding);

        if all_locations.len() > 1 {
            // Multiple locations - create one result per location
            for EvidencePlace {
                path,
                line,
                utf16_column,
                preview,
            } in all_locations
            {
                // Fingerprint the raw path, before any URI formatting: the
                // GitLab emitter hashes the path as recorded in evidence,
                // and identity must match across surfaces.
                let fingerprint =
                    finding_fingerprint(&rule_id, &path, preview.as_deref(), finding.message());

                results.push(SarifResult {
                    rule_id: rule_id.clone(),
                    level: risk_level_to_sarif_level(level).to_string(),
                    message: SarifMessage::new(finding.message()),
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: artifact_location(path, &uri_base_id),
                            region: Some(SarifRegion {
                                start_line: line,
                                start_column: utf16_column,
                                end_line: Some(line),
                                end_column: None,
                                snippet: preview.map(|s| SarifSnippet { text: s }),
                            }),
                        },
                        message: None,
                    }],
                    fingerprints: None,
                    partial_fingerprints: fingerprint_map(fingerprint),
                });
            }
        } else {
            // Single location or fallback - original behavior
            let region = if let Some(place) = get_location_from_evidence(finding) {
                Some(SarifRegion {
                    start_line: place.line,
                    start_column: place.utf16_column,
                    end_line: Some(place.line),
                    end_column: None,
                    snippet: get_statement_preview(finding).map(|s| SarifSnippet { text: s }),
                })
            } else {
                get_line_number(finding).map(|line| SarifRegion {
                    start_line: line,
                    start_column: Some(1),
                    end_line: Some(line),
                    end_column: None,
                    snippet: get_statement_preview(finding).map(|s| SarifSnippet { text: s }),
                })
            };

            // Get per-finding file path (from evidence or fallback to report-level)
            let finding_file_path = get_file_path_from_evidence(finding, &file_uri);

            // Fingerprint the raw path, before any URI formatting: identity
            // must match the GitLab emitter, which hashes the path as
            // recorded in evidence.
            let fingerprint = finding_fingerprint(
                &rule_id,
                &finding_file_path,
                get_statement_preview(finding).as_deref(),
                finding.message(),
            );

            results.push(SarifResult {
                rule_id: rule_id.clone(),
                level: risk_level_to_sarif_level(level).to_string(),
                message: SarifMessage::new(finding.message()),
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: artifact_location(finding_file_path, &uri_base_id),
                        region,
                    },
                    message: None,
                }],
                fingerprints: None,
                partial_fingerprints: fingerprint_map(fingerprint),
            });
        }
    }

    // Sort rules by ID for deterministic output
    let mut rules: Vec<SarifRule> = rules_map.into_values().collect();
    rules.sort_by(|a, b| a.id.cmp(&b.id));

    // Sort results for stable cross-machine output. Key is the
    // first location's (uri, start_line, start_column, rule_id) —
    // groups findings by file then by location within file, which
    // is the natural review order and makes SARIF diffs stable
    // regardless of walkdir traversal order, HashMap iteration, or
    // per-witness emission ordering inside the rule engine. Most
    // results have a single location; multi-location results sort
    // by their first.
    results.sort_by(|a, b| {
        let key = |r: &SarifResult| {
            let loc = r.locations.first();
            let uri = loc
                .map(|l| l.physical_location.artifact_location.uri.clone())
                .unwrap_or_default();
            let (line, col) = loc
                .and_then(|l| l.physical_location.region.as_ref())
                .map(|reg| (reg.start_line, reg.start_column.unwrap_or(0)))
                .unwrap_or((0, 0));
            (uri, line, col, r.rule_id.clone())
        };
        key(a).cmp(&key(b))
    });

    // Disambiguate genuine duplicates (same rule + file + statement text):
    // suffix an ordinal, assigned in canonical sort order so it's stable
    // run-to-run. Without this, two identical findings would merge into one
    // alert in consumers that match on the fingerprint. Runs AFTER the sort
    // so a line shift cannot reorder ordinals between otherwise-identical
    // findings... unless the duplicates themselves swap positions, which is
    // the unavoidable edge of any line-free identity.
    let mut occurrence: BTreeMap<String, usize> = BTreeMap::new();
    for result in &mut results {
        if let Some(fingerprints) = result.partial_fingerprints.as_mut() {
            if let Some(value) = fingerprints.get_mut(FINDING_FINGERPRINT_KEY) {
                let n = occurrence.entry(value.clone()).or_insert(0);
                *value = format!("{}:{}", value, *n);
                *n += 1;
            }
        }
    }

    // Build originalUriBaseIds if base_path is provided
    let original_uri_base_ids = base_path.map(|path| {
        let mut map = HashMap::new();
        map.insert(
            "%SRCROOT%".to_string(),
            SarifArtifactLocation {
                uri: if path.starts_with('/') {
                    format!("file://{}", path)
                } else {
                    path.to_string()
                },
                uri_base_id: None,
            },
        );
        map
    });

    let unrendered = unrendered_files(report, run);
    let tool_execution_notifications = run
        .depth_note
        .map(|note| SarifNotification {
            descriptor: SarifNotificationDescriptor {
                id: DEPTH_NOTIFICATION_ID.to_string(),
            },
            level: "note".to_string(),
            message: SarifMessage::new(note),
            locations: Vec::new(),
        })
        .into_iter()
        .chain(run.run_notes.iter().map(|note| SarifNotification {
            descriptor: SarifNotificationDescriptor {
                id: RUN_LIMITED_NOTIFICATION_ID.to_string(),
            },
            level: "warning".to_string(),
            message: SarifMessage::new(note),
            locations: Vec::new(),
        }))
        .chain((!unrendered.is_empty()).then(|| {
            SarifNotification {
                descriptor: SarifNotificationDescriptor {
                    id: NOT_RENDERED_NOTIFICATION_ID.to_string(),
                },
                level: "warning".to_string(),
                message: SarifMessage::new(NOT_RENDERED_NOTE),
                locations: unrendered
                    .iter()
                    .map(|path| SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: artifact_location(path.to_string(), &uri_base_id),
                            region: None,
                        },
                        message: None,
                    })
                    .collect(),
            }
        }))
        .chain((!run.skipped_files.is_empty()).then(|| {
            SarifNotification {
                descriptor: SarifNotificationDescriptor {
                    id: NOT_ANALYZED_NOTIFICATION_ID.to_string(),
                },
                level: "warning".to_string(),
                message: SarifMessage::new(NOT_ANALYZED_NOTE),
                locations: run
                    .skipped_files
                    .iter()
                    .map(|(path, reason)| SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: artifact_location(path.clone(), &uri_base_id),
                            region: None,
                        },
                        message: Some(SarifMessage::new(reason.as_str())),
                    })
                    .collect(),
            }
        }))
        .chain(
            run.macro_files
                .iter()
                .map(|(path, note)| SarifNotification {
                    descriptor: SarifNotificationDescriptor {
                        id: MACRO_FILE_NOTIFICATION_ID.to_string(),
                    },
                    level: "note".to_string(),
                    message: SarifMessage::new(note.as_str()),
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: artifact_location(path.clone(), &uri_base_id),
                            region: None,
                        },
                        message: None,
                    }],
                }),
        )
        .collect();

    SarifReport {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolDriver {
                    name: run.name.to_string(),
                    version: run.version.to_string(),
                    information_uri: Some("https://lexega.com".to_string()),
                    rules,
                },
            },
            results,
            column_kind: SarifColumnKind::Utf16CodeUnits,
            invocations: Some(vec![SarifInvocation {
                execution_successful: true,
                // The analysis report's timestamp is the closest match to
                // SARIF's `endTimeUtc` (when the analysis completed).
                end_time_utc: Some(report.timestamp.clone()),
                tool_execution_notifications,
            }]),
            original_uri_base_ids,
            properties: SarifRunProperties {
                render_completeness: report.summary.render_completeness.clone(),
                analysis_confidence: report.summary.analysis_confidence.clone(),
            },
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalysisFinding, RiskEvidence};

    const RUN: ToolRun<'static> = ToolRun {
        name: "sqlcheck",
        version: "1.0.0",
        base_path: None,
        depth_note: None,
        unrendered_files: &[],
        skipped_files: &[],
        macro_files: &[],
        run_notes: &[],
    };

    #[test]
    fn test_sarif_conversion() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/users.sql".to_string());

        // Add a governance finding
        report.findings.push(RuleMatch::Analysis(AnalysisFinding {
            message: "NULL-logic hazard: NOT IN with subquery".to_string(),
            risk_level: RiskLevel::Critical,
            matched_rule: "Q-NULL-NOTIN".to_string(),
            finding_type: "null-logic-not-in".to_string(),
            findings_merged: Some(1),
            evidence_count: Some(1),
            scope: Some("statement".to_string()),
            statement_line_number: Some(15),
            statement_lines: None,
            topic_key: Some("correctness.null_logic_not_in".to_string()),
            source: None,
            contributors: None,
            parent_context: None,
            evidence: vec![RiskEvidence::RuleMatch {
                finding_type: "SelectStatement".to_string(),
                resolution_status: None,
                rule_id: "".to_string(),
                line_number: Some(15),
                column_number: None,
                template_line_number: None,
                is_generated: None,
                macro_name: None,
                statement_preview: Some("SELECT * FROM users WHERE id NOT IN...".to_string()),
                source_file: None,
                location: None,
                position: None,
                assumed_role: None, // Test doesn't need role context
            }],
            scan_type: None,
            affected_tables: None,
            tables_modified: None,
            statement_cross_schema: None,
            statement_cross_database: None,
            unbounded_write: None,
            assumed_role: None,
        }));

        let sarif = to_sarif(&report, &RUN);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "sqlcheck");
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].rule_id, "Q-NULL-NOTIN");
        assert_eq!(sarif.runs[0].results[0].level, "error");
        let rule = &sarif.runs[0].tool.driver.rules[0];
        assert_eq!(rule.id, "Q-NULL-NOTIN");
        assert_eq!(rule.name, "Q-NULL-NOTIN");
        assert_eq!(rule.short_description.text, "Q-NULL-NOTIN");
        assert_eq!(
            sarif.runs[0].results[0].locations[0]
                .physical_location
                .region
                .as_ref()
                .unwrap()
                .start_line,
            15
        );
    }

    #[test]
    fn a_reduced_depth_run_carries_its_note_as_a_notification() {
        let report = AnalysisReport::new();
        let note = "52 of 930 rules ran without analysis they use.";

        let sarif = to_sarif(
            &report,
            &ToolRun {
                depth_note: Some(note),
                ..RUN
            },
        );
        let json = serde_json::to_value(&sarif).unwrap();
        let notifications = &json["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert_eq!(notifications.as_array().map(Vec::len), Some(1));
        assert_eq!(notifications[0]["descriptor"]["id"], DEPTH_NOTIFICATION_ID);
        assert_eq!(notifications[0]["level"], "note");
        assert_eq!(notifications[0]["message"]["text"], note);

        let full_depth = serde_json::to_value(to_sarif(&report, &RUN)).unwrap();
        assert!(full_depth["runs"][0]["invocations"][0]
            .get("toolExecutionNotifications")
            .is_none());
    }

    #[test]
    fn a_run_says_which_files_it_analyzed_on_template_text() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());

        let rendered = serde_json::to_value(to_sarif(&report, &RUN)).unwrap();
        assert_eq!(
            rendered["runs"][0]["properties"]["renderCompleteness"],
            "full"
        );
        assert_eq!(
            rendered["runs"][0]["properties"]["analysisConfidence"],
            "high"
        );
        assert!(rendered["runs"][0]["invocations"][0]
            .get("toolExecutionNotifications")
            .is_none());

        report.summary.render_completeness = RenderCompleteness::NotRendered;
        report.summary.analysis_confidence = ConfidenceLevel::Low;
        let one = serde_json::to_value(to_sarif(&report, &RUN)).unwrap();
        assert_eq!(
            one["runs"][0]["properties"]["renderCompleteness"],
            "not_rendered"
        );
        assert_eq!(one["runs"][0]["properties"]["analysisConfidence"], "low");
        let notifications = &one["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert_eq!(notifications.as_array().map(Vec::len), Some(1));
        assert_eq!(
            notifications[0]["descriptor"]["id"],
            NOT_RENDERED_NOTIFICATION_ID
        );
        assert_eq!(notifications[0]["level"], "warning");
        assert_eq!(notifications[0]["message"]["text"], NOT_RENDERED_NOTE);
        assert_eq!(
            notifications[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "models/a.sql"
        );

        let batch_files = ["models/b.sql".to_string(), "/repo/models/c.sql".to_string()];
        report.source_file_path = None;
        let batch = serde_json::to_value(to_sarif(
            &report,
            &ToolRun {
                unrendered_files: &batch_files,
                depth_note: Some("1 of 2 rules use analysis this build does not include."),
                ..RUN
            },
        ))
        .unwrap();
        let notifications = &batch["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert_eq!(notifications[0]["descriptor"]["id"], DEPTH_NOTIFICATION_ID);
        assert!(notifications[0].get("locations").is_none());
        let uris: Vec<&str> = notifications[1]["locations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                l["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(uris, ["models/b.sql", "file:///repo/models/c.sql"]);
    }

    #[test]
    fn a_batch_names_the_files_it_could_not_render_as_not_analyzed() {
        let mut report = AnalysisReport::new();
        report.summary.render_completeness = RenderCompleteness::NotRendered;
        report
            .findings
            .push(test_finding("R-1", 3, "DELETE FROM t"));
        let skipped = [(
            "/repo/models/m.sql".to_string(),
            "Jinja rendering error: Division by zero".to_string(),
        )];
        let sarif = serde_json::to_value(to_sarif(
            &report,
            &ToolRun {
                skipped_files: &skipped,
                ..RUN
            },
        ))
        .unwrap();
        let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap();
        // No file of the batch was analyzed on its template text.
        assert_eq!(notifications.len(), 1, "{notifications:?}");
        assert_eq!(
            notifications[0]["descriptor"]["id"],
            NOT_ANALYZED_NOTIFICATION_ID
        );
        assert_eq!(notifications[0]["level"], "warning");
        assert_eq!(notifications[0]["message"]["text"], NOT_ANALYZED_NOTE);
        let location = &notifications[0]["locations"][0];
        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "file:///repo/models/m.sql"
        );
        assert_eq!(
            location["message"]["text"],
            "Jinja rendering error: Division by zero"
        );
        // A finding's location says nothing of its own.
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0]["locations"][0].get("message").is_none());
    }

    // Each macro file of a batch is a note of its own, on its file, with
    // what the run says of it.
    #[test]
    fn a_batch_names_each_macro_file_it_did_not_analyze() {
        let report = AnalysisReport::new();
        let macros = [
            (
                "macros/a.sql".to_string(),
                "in a macro path of dbt_project.yml: macro definitions, not statements".to_string(),
            ),
            ("/repo/macros/b.sql".to_string(), "b's note".to_string()),
        ];
        let sarif = serde_json::to_value(to_sarif(
            &report,
            &ToolRun {
                macro_files: &macros,
                ..RUN
            },
        ))
        .unwrap();
        let notes: Vec<(&str, &str, &str, &str)> = sarif["runs"][0]["invocations"][0]
            ["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|note| {
                (
                    note["descriptor"]["id"].as_str().unwrap(),
                    note["level"].as_str().unwrap(),
                    note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap(),
                    note["message"]["text"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            notes,
            [
                (
                    MACRO_FILE_NOTIFICATION_ID,
                    "note",
                    "macros/a.sql",
                    "in a macro path of dbt_project.yml: macro definitions, not statements"
                ),
                (
                    MACRO_FILE_NOTIFICATION_ID,
                    "note",
                    "file:///repo/macros/b.sql",
                    "b's note"
                ),
            ]
        );
    }

    #[test]
    fn test_risk_level_mapping() {
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Critical), "error");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::High), "error");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Medium), "warning");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Low), "note");
    }

    fn test_finding(rule: &str, line: usize, preview: &str) -> RuleMatch {
        RuleMatch::Analysis(AnalysisFinding {
            message: format!("{} fired", rule),
            risk_level: RiskLevel::High,
            matched_rule: rule.to_string(),
            finding_type: "test-finding".to_string(),
            findings_merged: Some(1),
            evidence_count: Some(1),
            scope: Some("statement".to_string()),
            statement_line_number: Some(line),
            statement_lines: None,
            topic_key: None,
            source: None,
            contributors: None,
            parent_context: None,
            evidence: vec![RiskEvidence::RuleMatch {
                finding_type: "SelectStatement".to_string(),
                resolution_status: None,
                rule_id: "".to_string(),
                line_number: Some(line),
                column_number: None,
                template_line_number: None,
                is_generated: None,
                macro_name: None,
                statement_preview: Some(preview.to_string()),
                source_file: None,
                location: None,
                position: None,
                assumed_role: None,
            }],
            scan_type: None,
            affected_tables: None,
            tables_modified: None,
            statement_cross_schema: None,
            statement_cross_database: None,
            unbounded_write: None,
            assumed_role: None,
        })
    }

    fn fingerprint_of(sarif: &SarifReport, idx: usize) -> String {
        sarif.runs[0].results[idx]
            .partial_fingerprints
            .as_ref()
            .expect("partialFingerprints present")
            .get(FINDING_FINGERPRINT_KEY)
            .expect("versioned key present")
            .clone()
    }

    // A region's column counts UTF-16 code units, which the run declares; the
    // fingerprint holds no position.
    #[test]
    fn a_region_column_counts_utf16_code_units() {
        let placed = |position: Option<crate::analyzer::TextPosition>| {
            let mut finding = test_finding("Q-NULL-NEQ", 2, "select 1");
            let RuleMatch::Analysis(analysis) = &mut finding;
            if let RiskEvidence::RuleMatch {
                location,
                position: at,
                ..
            } = &mut analysis.evidence[0]
            {
                *location = Some("q.sql:2:36".to_string());
                *at = position;
            }
            let mut report = AnalysisReport::new();
            report.findings.push(finding);
            to_sarif(&report, &RUN)
        };
        let sarif = placed(Some(crate::analyzer::TextPosition {
            line: 2,
            column: 36,
            utf16_column: 37,
        }));
        let json = serde_json::to_value(&sarif).unwrap();
        assert_eq!(json["runs"][0]["columnKind"], "utf16CodeUnits");
        let region = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(
            (region["startLine"].as_u64(), region["startColumn"].as_u64()),
            (Some(2), Some(37))
        );
        // Without its position the item's column in UTF-16 units is not known.
        let unplaced = serde_json::to_value(placed(None)).unwrap();
        let region =
            &unplaced["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 2);
        assert!(region.get("startColumn").is_none(), "{region}");
        assert_eq!(fingerprint_of(&sarif, 0), fingerprint_of(&placed(None), 0));
    }

    #[test]
    fn fingerprint_present_with_versioned_key_and_ordinal() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .findings
            .push(test_finding("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));

        let sarif = to_sarif(&report, &RUN);
        let fp = fingerprint_of(&sarif, 0);
        assert!(fp.ends_with(":0"), "ordinal suffix expected: {}", fp);
        assert_eq!(fp.len(), 64 + 2, "sha256 hex + ':0': {}", fp);
    }

    #[test]
    fn fingerprint_stable_when_statement_moves_lines() {
        let make = |line: usize| {
            let mut report = AnalysisReport::new();
            report.source_file_path = Some("models/a.sql".to_string());
            report
                .findings
                .push(test_finding("DML-WRITE-UNBOUNDED", line, "DELETE FROM t"));
            to_sarif(&report, &RUN)
        };

        assert_eq!(fingerprint_of(&make(10), 0), fingerprint_of(&make(310), 0));
    }

    #[test]
    fn fingerprint_ignores_whitespace_reformatting() {
        let make = |preview: &str| {
            let mut report = AnalysisReport::new();
            report.source_file_path = Some("models/a.sql".to_string());
            report
                .findings
                .push(test_finding("DML-WRITE-UNBOUNDED", 10, preview));
            to_sarif(&report, &RUN)
        };

        assert_eq!(
            fingerprint_of(&make("DELETE FROM t WHERE x = 1"), 0),
            fingerprint_of(&make("DELETE  FROM\n    t\n  WHERE x = 1"), 0)
        );
    }

    #[test]
    fn duplicate_findings_get_distinct_ordinals() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .findings
            .push(test_finding("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));
        report
            .findings
            .push(test_finding("DML-WRITE-UNBOUNDED", 50, "DELETE FROM t"));

        let sarif = to_sarif(&report, &RUN);
        let a = fingerprint_of(&sarif, 0);
        let b = fingerprint_of(&sarif, 1);
        assert_ne!(a, b);
        assert_eq!(a[..64], b[..64], "same base hash, different ordinal");
        assert!(a.ends_with(":0") && b.ends_with(":1"), "{} / {}", a, b);
    }

    #[test]
    fn different_rules_and_statements_get_different_fingerprints() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .findings
            .push(test_finding("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));
        report
            .findings
            .push(test_finding("GRT-ALL-PRIV", 20, "GRANT ALL ON t TO r"));

        let sarif = to_sarif(&report, &RUN);
        assert_ne!(
            fingerprint_of(&sarif, 0)[..64],
            fingerprint_of(&sarif, 1)[..64]
        );
    }
}
