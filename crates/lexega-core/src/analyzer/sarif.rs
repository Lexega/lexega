// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SARIF (Static Analysis Results Interchange Format) output support
//!
//! Converts AnalysisReport signals to SARIF 2.1.0 format for integration with
//! GitHub Security, GitLab SAST, Azure DevOps, and other SARIF-compatible tools.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

use super::{AnalysisReport, RiskLevel, RuleMatch};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
    #[serde(rename = "originalUriBaseIds", skip_serializing_if = "Option::is_none")]
    pub original_uri_base_ids: Option<HashMap<String, SarifArtifactLocation>>,
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
}

/// Identifies the kind of a [`SarifNotification`].
#[derive(Debug, Clone, Serialize)]
pub struct SarifNotificationDescriptor {
    pub id: String,
}

/// `descriptor.id` of the notification a run at reduced depth carries.
pub const DEPTH_NOTIFICATION_ID: &str = "analysis-depth";

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

/// Extract rule ID from a signal
pub(super) fn get_rule_id(signal: &RuleMatch) -> String {
    match signal {
        RuleMatch::Analysis(g) => g.matched_rule.clone(),
    }
}

/// Get line number from a signal (template line preferred for dbt models)
pub(super) fn get_line_number(signal: &RuleMatch) -> Option<usize> {
    // First try to parse from evidence location field (path:line:column format)
    // The location field already contains template line when available
    if let Some((_, line, _)) = get_location_from_evidence(signal) {
        return Some(line);
    }

    // Second: try template_line_number directly from evidence
    // This handles cases where location is not set but template_line_number exists
    for evidence in signal.evidence() {
        if let super::RiskEvidence::RuleMatch {
            template_line_number: Some(line),
            ..
        } = evidence
        {
            return Some(*line);
        }
    }

    // Third: try line_number from evidence (rendered line, but still better than nothing)
    for evidence in signal.evidence() {
        if let super::RiskEvidence::RuleMatch {
            line_number: Some(line),
            ..
        } = evidence
        {
            return Some(*line);
        }
    }

    // Final fallback to statement_line_number on AnalysisSignal
    match signal {
        RuleMatch::Analysis(g) => g.statement_line_number,
    }
}

/// Extract file path, line, and column from signal evidence
/// Parses the location field which has format: path:line:column
pub(super) fn get_location_from_evidence(signal: &RuleMatch) -> Option<(String, usize, usize)> {
    for evidence in signal.evidence() {
        if let super::RiskEvidence::RuleMatch {
            location: Some(loc),
            ..
        } = evidence
        {
            // Parse path:line:column format
            // Find the last two colons (line and column)
            if let Some(col_pos) = loc.rfind(':') {
                if let Some(line_pos) = loc[..col_pos].rfind(':') {
                    let path = &loc[..line_pos];
                    let line_str = &loc[line_pos + 1..col_pos];
                    let col_str = &loc[col_pos + 1..];

                    if let (Ok(line), Ok(col)) =
                        (line_str.parse::<usize>(), col_str.parse::<usize>())
                    {
                        return Some((path.to_string(), line, col));
                    }
                }
            }
        }
    }
    None
}

/// Extract ALL locations from signal evidence (one per UNION branch, etc.)
/// Returns Vec of (path, line, column, statement_preview)
pub(super) fn get_all_locations_from_evidence(
    signal: &RuleMatch,
) -> Vec<(String, usize, usize, Option<String>)> {
    let mut locations = Vec::new();

    for evidence in signal.evidence() {
        if let super::RiskEvidence::RuleMatch {
            location: Some(loc),
            statement_preview,
            ..
        } = evidence
        {
            // Parse path:line:column format
            if let Some(col_pos) = loc.rfind(':') {
                if let Some(line_pos) = loc[..col_pos].rfind(':') {
                    let path = &loc[..line_pos];
                    let line_str = &loc[line_pos + 1..col_pos];
                    let col_str = &loc[col_pos + 1..];

                    if let (Ok(line), Ok(col)) =
                        (line_str.parse::<usize>(), col_str.parse::<usize>())
                    {
                        locations.push((path.to_string(), line, col, statement_preview.clone()));
                    }
                }
            }
        }
    }

    locations
}

/// Get file path from signal evidence, with fallback to default
pub(super) fn get_file_path_from_evidence(signal: &RuleMatch, default: &str) -> String {
    // First try location field (has full path)
    if let Some((path, _, _)) = get_location_from_evidence(signal) {
        return path;
    }

    // Then try source_file field
    for evidence in signal.evidence() {
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
pub(super) fn get_statement_preview(signal: &RuleMatch) -> Option<String> {
    for evidence in signal.evidence() {
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

/// Get tags for a signal type
///
/// Uses enrichment fields to determine signal category rather than rule ID prefixes.
/// This is more robust as it reflects actual signal characteristics.
fn get_signal_tags(signal: &RuleMatch) -> Vec<String> {
    match signal {
        RuleMatch::Analysis(g) => {
            // Diff signals (DIFF-* rule_ids) carry the
            // `semantic-change` / `baseline` SARIF tags. The v1 fact
            // engine routes them through `RuleMatch::Analysis`, so we
            // discriminate by rule_id prefix.
            if g.matched_rule.starts_with("DIFF-") {
                return vec!["semantic-change".to_string(), "baseline".to_string()];
            }

            let mut tags = vec!["governance".to_string()];

            // Cost/performance signals have scan_type or affected_tables populated
            if g.scan_type.is_some() || g.affected_tables.is_some() {
                tags.push("performance".to_string());
                tags.push("cost".to_string());
                tags.push("query-pattern".to_string());
            }

            // Blast radius signals have tables_modified or unbounded_write populated
            if g.tables_modified.is_some() || g.unbounded_write.is_some() {
                tags.push("blast-radius".to_string());
                tags.push("data-modification".to_string());
            }

            // Security signals - check for security-related signal types
            let sig_type = g.signal_type.to_lowercase();
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

    for signal in &report.signals {
        let rule_id = get_rule_id(signal);
        let level = signal.risk_level();

        // Add rule if not already present
        if !rules_map.contains_key(&rule_id) {
            rules_map.insert(
                rule_id.clone(),
                SarifRule {
                    id: rule_id.clone(),
                    name: rule_id.clone(),
                    deprecated_ids: crate::rules::former_ids_for(&rule_id).to_vec(),
                    short_description: SarifMessage::new(&rule_id),
                    full_description: Some(SarifMessage::new(signal.message())),
                    default_configuration: Some(SarifRuleConfiguration {
                        level: risk_level_to_sarif_level(level).to_string(),
                    }),
                    help: None,
                    properties: Some(SarifRuleProperties {
                        tags: Some(get_signal_tags(signal)),
                        security_severity: Some(risk_level_to_security_severity(level).to_string()),
                        precision: Some("high".to_string()),
                    }),
                },
            );
        }

        // Get all locations from evidence - for signals with multiple UNION branches,
        // this will create one SARIF result per location
        let all_locations = get_all_locations_from_evidence(signal);

        if all_locations.len() > 1 {
            // Multiple locations - create one result per location
            for (path, line, col, preview) in all_locations {
                // Fingerprint the raw path, before any URI formatting: the
                // GitLab emitter hashes the path as recorded in evidence,
                // and identity must match across surfaces.
                let fingerprint =
                    finding_fingerprint(&rule_id, &path, preview.as_deref(), signal.message());

                // For relative paths with base_path, use uriBaseId; for absolute paths, use file:// URI
                let (signal_file_uri, base_id) = if path.starts_with('/') {
                    (format!("file://{}", path), None)
                } else {
                    (path, uri_base_id.clone())
                };
                results.push(SarifResult {
                    rule_id: rule_id.clone(),
                    level: risk_level_to_sarif_level(level).to_string(),
                    message: SarifMessage::new(signal.message()),
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: signal_file_uri,
                                uri_base_id: base_id,
                            },
                            region: Some(SarifRegion {
                                start_line: line,
                                start_column: Some(col),
                                end_line: Some(line),
                                end_column: None,
                                snippet: preview.map(|s| SarifSnippet { text: s }),
                            }),
                        },
                    }],
                    fingerprints: None,
                    partial_fingerprints: fingerprint_map(fingerprint),
                });
            }
        } else {
            // Single location or fallback - original behavior
            let region = if let Some((_, line, col)) = get_location_from_evidence(signal) {
                Some(SarifRegion {
                    start_line: line,
                    start_column: Some(col),
                    end_line: Some(line),
                    end_column: None,
                    snippet: get_statement_preview(signal).map(|s| SarifSnippet { text: s }),
                })
            } else {
                get_line_number(signal).map(|line| SarifRegion {
                    start_line: line,
                    start_column: Some(1),
                    end_line: Some(line),
                    end_column: None,
                    snippet: get_statement_preview(signal).map(|s| SarifSnippet { text: s }),
                })
            };

            // Get per-signal file path (from evidence or fallback to report-level)
            let signal_file_path = get_file_path_from_evidence(signal, &file_uri);

            // Fingerprint the raw path, before any URI formatting: identity
            // must match the GitLab emitter, which hashes the path as
            // recorded in evidence.
            let fingerprint = finding_fingerprint(
                &rule_id,
                &signal_file_path,
                get_statement_preview(signal).as_deref(),
                signal.message(),
            );

            // For relative paths with base_path, use uriBaseId; for absolute paths, use file:// URI
            let (signal_file_uri, base_id) = if signal_file_path.starts_with('/') {
                (format!("file://{}", signal_file_path), None)
            } else {
                (signal_file_path, uri_base_id.clone())
            };
            results.push(SarifResult {
                rule_id: rule_id.clone(),
                level: risk_level_to_sarif_level(level).to_string(),
                message: SarifMessage::new(signal.message()),
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: signal_file_uri,
                            uri_base_id: base_id,
                        },
                        region,
                    },
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
            invocations: Some(vec![SarifInvocation {
                execution_successful: true,
                // The analysis report's timestamp is the closest match to
                // SARIF's `endTimeUtc` (when the analysis completed).
                end_time_utc: Some(report.timestamp.clone()),
                tool_execution_notifications: run
                    .depth_note
                    .map(|note| SarifNotification {
                        descriptor: SarifNotificationDescriptor {
                            id: DEPTH_NOTIFICATION_ID.to_string(),
                        },
                        level: "note".to_string(),
                        message: SarifMessage::new(note),
                    })
                    .into_iter()
                    .collect(),
            }]),
            original_uri_base_ids,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalysisSignal, RiskEvidence};

    const RUN: ToolRun<'static> = ToolRun {
        name: "sqlcheck",
        version: "1.0.0",
        base_path: None,
        depth_note: None,
    };

    #[test]
    fn test_sarif_conversion() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/users.sql".to_string());

        // Add a governance signal
        report.signals.push(RuleMatch::Analysis(AnalysisSignal {
            message: "NULL-logic hazard: NOT IN with subquery".to_string(),
            risk_level: RiskLevel::Critical,
            matched_rule: "Q-NULL-NOTIN".to_string(),
            signal_type: "null-logic-not-in".to_string(),
            signals_merged: Some(1),
            evidence_count: Some(1),
            scope: Some("statement".to_string()),
            statement_line_number: Some(15),
            statement_lines: None,
            topic_key: Some("correctness.null_logic_not_in".to_string()),
            source: None,
            contributors: None,
            parent_context: None,
            evidence: vec![RiskEvidence::RuleMatch {
                signal_type: "SelectStatement".to_string(),
                resolution_status: None,
                signal_value: "".to_string(),
                line_number: Some(15),
                column_number: None,
                template_line_number: None,
                is_generated: None,
                macro_name: None,
                statement_preview: Some("SELECT * FROM users WHERE id NOT IN...".to_string()),
                source_file: None,
                location: None,
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
    fn test_risk_level_mapping() {
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Critical), "error");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::High), "error");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Medium), "warning");
        assert_eq!(risk_level_to_sarif_level(RiskLevel::Low), "note");
    }

    fn test_signal(rule: &str, line: usize, preview: &str) -> RuleMatch {
        RuleMatch::Analysis(AnalysisSignal {
            message: format!("{} fired", rule),
            risk_level: RiskLevel::High,
            matched_rule: rule.to_string(),
            signal_type: "test-signal".to_string(),
            signals_merged: Some(1),
            evidence_count: Some(1),
            scope: Some("statement".to_string()),
            statement_line_number: Some(line),
            statement_lines: None,
            topic_key: None,
            source: None,
            contributors: None,
            parent_context: None,
            evidence: vec![RiskEvidence::RuleMatch {
                signal_type: "SelectStatement".to_string(),
                resolution_status: None,
                signal_value: "".to_string(),
                line_number: Some(line),
                column_number: None,
                template_line_number: None,
                is_generated: None,
                macro_name: None,
                statement_preview: Some(preview.to_string()),
                source_file: None,
                location: None,
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

    #[test]
    fn fingerprint_present_with_versioned_key_and_ordinal() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));

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
                .signals
                .push(test_signal("DML-WRITE-UNBOUNDED", line, "DELETE FROM t"));
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
                .signals
                .push(test_signal("DML-WRITE-UNBOUNDED", 10, preview));
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
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 50, "DELETE FROM t"));

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
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));
        report
            .signals
            .push(test_signal("GRT-ALL-PRIV", 20, "GRANT ALL ON t TO r"));

        let sarif = to_sarif(&report, &RUN);
        assert_ne!(
            fingerprint_of(&sarif, 0)[..64],
            fingerprint_of(&sarif, 1)[..64]
        );
    }
}
