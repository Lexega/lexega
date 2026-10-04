// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! GitLab SAST report output (`gl-sast-report.json`).
//!
//! Implements the GitLab security report schema (`sast`, v15.2.4) so
//! findings appear in GitLab's merge request security widget and
//! Vulnerability Report. GitLab validates uploaded reports against the
//! schema and rejects invalid ones, so required fields here follow the
//! schema exactly — including the timestamp format, which is ISO 8601
//! WITHOUT timezone suffix or fractional seconds.

use serde::Serialize;

use super::sarif::{
    finding_fingerprint, get_all_locations_from_evidence, get_file_path_from_evidence,
    get_line_number, get_location_from_evidence, get_rule_id, get_statement_preview, ToolRun,
};
use super::{AnalysisReport, RiskLevel, RuleMatch};

const GL_SCHEMA_VERSION: &str = "15.2.4";
/// Schema cap on `vulnerabilities[].name`.
const GL_NAME_MAX_CHARS: usize = 255;

/// Top-level report document.
#[derive(Debug, Clone, Serialize)]
pub struct GlSastReport {
    pub version: String,
    pub scan: GlScan,
    pub vulnerabilities: Vec<GlVulnerability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlScan {
    pub analyzer: GlScanner,
    pub scanner: GlScanner,
    #[serde(rename = "type")]
    pub scan_type: String,
    pub start_time: String,
    pub end_time: String,
    pub status: String,
    /// Notes about the scan as a whole. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<GlScanMessage>,
}

/// A message to whoever started the scan.
#[derive(Debug, Clone, Serialize)]
pub struct GlScanMessage {
    pub level: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlScanner {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: GlVendor,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlVendor {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlVulnerability {
    /// Unique within the report; GitLab also uses it for tracking.
    /// Lexega's stable finding fingerprint (rule + file + statement,
    /// line-independent) with an ordinal suffix for duplicates — the same
    /// identity emitted in SARIF `partialFingerprints`.
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub location: GlLocation,
    pub identifiers: Vec<GlIdentifier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub name: String,
    pub value: String,
}

fn risk_level_to_gl_severity(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "Critical",
        RiskLevel::High => "High",
        RiskLevel::Medium => "Medium",
        RiskLevel::Low => "Low",
        RiskLevel::Info => "Info",
    }
}

/// Schema timestamp: `yyyy-mm-ddThh:mm:ss`, no zone, no millis.
/// Report timestamps are RFC3339; reformat. The fallback only triggers if
/// an externally-supplied report carries a non-RFC3339 timestamp.
fn gl_time(rfc3339: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(rfc3339) {
        Ok(t) => t.format("%Y-%m-%dT%H:%M:%S").to_string(),
        Err(_) => chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
    }
}

fn lexega_scanner(run: &ToolRun<'_>) -> GlScanner {
    GlScanner {
        id: run.name.to_string(),
        name: "Lexega".to_string(),
        version: run.version.to_string(),
        vendor: GlVendor {
            name: "Lexega".to_string(),
        },
    }
}

fn build_vulnerability(
    signal: &RuleMatch,
    rule_id: &str,
    file: String,
    line: usize,
    statement: Option<&str>,
) -> GlVulnerability {
    // The schema keeps finding-specific text out of `name`; the rule id is
    // the only name a rule has.
    let name: String = rule_id.chars().take(GL_NAME_MAX_CHARS).collect();

    GlVulnerability {
        id: finding_fingerprint(rule_id, &file, statement, signal.message()),
        name,
        description: signal.message().to_string(),
        severity: risk_level_to_gl_severity(signal.risk_level()).to_string(),
        location: GlLocation {
            file,
            start_line: line,
            end_line: line,
        },
        identifiers: vec![GlIdentifier {
            identifier_type: "lexega_rule_id".to_string(),
            name: format!("Lexega {}", rule_id),
            value: rule_id.to_string(),
        }],
    }
}

/// Convert an AnalysisReport to a GitLab SAST report.
///
/// File paths are emitted as carried by the findings — run the analysis
/// from the repository root so they are repo-relative, which is what the
/// security widget links against.
pub fn to_gl_sast(report: &AnalysisReport, run: &ToolRun<'_>) -> GlSastReport {
    let file_fallback = report
        .source_file_path
        .as_deref()
        .unwrap_or("input.sql")
        .to_string();

    let mut vulnerabilities: Vec<GlVulnerability> = Vec::new();

    for signal in &report.signals {
        let rule_id = get_rule_id(signal);

        // Mirror the SARIF emitter: one vulnerability per evidence location
        // (UNION branches etc.), single-location fallback otherwise.
        let all_locations = get_all_locations_from_evidence(signal);
        if all_locations.len() > 1 {
            for (path, line, _col, preview) in all_locations {
                vulnerabilities.push(build_vulnerability(
                    signal,
                    &rule_id,
                    path,
                    line,
                    preview.as_deref(),
                ));
            }
        } else {
            let (path, line) = match get_location_from_evidence(signal) {
                Some((p, l, _)) => (p, l),
                None => (
                    get_file_path_from_evidence(signal, &file_fallback),
                    get_line_number(signal).unwrap_or(1),
                ),
            };
            vulnerabilities.push(build_vulnerability(
                signal,
                &rule_id,
                path,
                line,
                get_statement_preview(signal).as_deref(),
            ));
        }
    }

    // Same canonical order as the SARIF emitter: file, line, rule.
    vulnerabilities.sort_by(|a, b| {
        (&a.location.file, a.location.start_line, &a.id).cmp(&(
            &b.location.file,
            b.location.start_line,
            &b.id,
        ))
    });

    // Ordinal-suffix duplicate identities, in canonical order, so `id`
    // stays unique within the report (schema requirement) and stable
    // run-to-run.
    let mut occurrence: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for vulnerability in &mut vulnerabilities {
        let n = occurrence.entry(vulnerability.id.clone()).or_insert(0);
        vulnerability.id = format!("{}:{}", vulnerability.id, *n);
        *n += 1;
    }

    let time = gl_time(&report.timestamp);
    GlSastReport {
        version: GL_SCHEMA_VERSION.to_string(),
        scan: GlScan {
            analyzer: lexega_scanner(run),
            scanner: lexega_scanner(run),
            scan_type: "sast".to_string(),
            // Statement analysis completes in one pass; the report carries a
            // single completion timestamp, used for both bounds.
            start_time: time.clone(),
            end_time: time,
            status: "success".to_string(),
            messages: run
                .depth_note
                .map(|note| GlScanMessage {
                    level: "info".to_string(),
                    value: note.to_string(),
                })
                .into_iter()
                .collect(),
        },
        vulnerabilities,
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

    fn test_signal(rule: &str, line: usize, preview: &str) -> RuleMatch {
        RuleMatch::Analysis(AnalysisSignal {
            message: format!("{} fired", rule),
            risk_level: RiskLevel::Critical,
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

    #[test]
    fn schema_required_fields_present() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));

        let gl = to_gl_sast(&report, &RUN);
        let json = serde_json::to_value(&gl).unwrap();

        assert_eq!(json["version"], "15.2.4");
        assert_eq!(json["scan"]["type"], "sast");
        assert_eq!(json["scan"]["status"], "success");
        assert_eq!(json["scan"]["analyzer"]["vendor"]["name"], "Lexega");
        assert_eq!(json["scan"]["scanner"]["id"], "sqlcheck");
        assert_eq!(json["scan"]["analyzer"]["id"], "sqlcheck");

        assert!(json["scan"].get("messages").is_none());

        let v = &json["vulnerabilities"][0];
        assert!(v["id"].as_str().unwrap().ends_with(":0"));
        assert_eq!(v["name"], "DML-WRITE-UNBOUNDED");
        assert_eq!(v["severity"], "Critical");
        assert_eq!(v["location"]["file"], "models/a.sql");
        assert_eq!(v["location"]["start_line"], 10);
        assert_eq!(v["identifiers"][0]["type"], "lexega_rule_id");
        assert_eq!(v["identifiers"][0]["value"], "DML-WRITE-UNBOUNDED");
    }

    #[test]
    fn a_reduced_depth_run_carries_its_note_as_a_scan_message() {
        let report = AnalysisReport::new();
        let note = "52 of 930 rules ran without analysis they use.";

        let gl = to_gl_sast(
            &report,
            &ToolRun {
                depth_note: Some(note),
                ..RUN
            },
        );
        let json = serde_json::to_value(&gl).unwrap();
        assert_eq!(json["scan"]["messages"][0]["level"], "info");
        assert_eq!(json["scan"]["messages"][0]["value"], note);
    }

    #[test]
    fn timestamps_match_gitlab_pattern() {
        let report = AnalysisReport::new();
        let gl = to_gl_sast(&report, &RUN);

        // yyyy-mm-ddThh:mm:ss — exactly 19 chars, no zone suffix.
        let t = &gl.scan.end_time;
        assert_eq!(t.len(), 19, "got: {}", t);
        assert_eq!(t.as_bytes()[10], b'T');
        assert!(!t.ends_with('Z'), "no timezone suffix allowed: {}", t);
        assert_eq!(gl.scan.start_time, gl.scan.end_time);
    }

    #[test]
    fn fingerprint_matches_sarif_for_absolute_paths() {
        // SARIF formats absolute paths as `file://` URIs for display, but
        // identity hashes the raw path — the same finding must carry the
        // same fingerprint in both emitters.
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("/repo/models/a.sql".to_string());
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));

        let gl = to_gl_sast(&report, &RUN);
        let sarif = crate::analyzer::sarif::to_sarif(&report, &RUN);
        let sarif_fp = sarif.runs[0].results[0]
            .partial_fingerprints
            .as_ref()
            .expect("partialFingerprints present")
            .values()
            .next()
            .expect("fingerprint entry present")
            .clone();
        assert_eq!(gl.vulnerabilities[0].id, sarif_fp);
    }

    #[test]
    fn duplicate_ids_get_ordinals_and_id_is_line_independent() {
        let mut report = AnalysisReport::new();
        report.source_file_path = Some("models/a.sql".to_string());
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 10, "DELETE FROM t"));
        report
            .signals
            .push(test_signal("DML-WRITE-UNBOUNDED", 90, "DELETE FROM t"));

        let gl = to_gl_sast(&report, &RUN);
        let a = &gl.vulnerabilities[0].id;
        let b = &gl.vulnerabilities[1].id;
        assert_ne!(a, b);
        assert_eq!(a[..64], b[..64], "line number must not affect identity");
    }

    #[test]
    fn severity_mapping_matches_gitlab_enum() {
        assert_eq!(risk_level_to_gl_severity(RiskLevel::Critical), "Critical");
        assert_eq!(risk_level_to_gl_severity(RiskLevel::High), "High");
        assert_eq!(risk_level_to_gl_severity(RiskLevel::Medium), "Medium");
        assert_eq!(risk_level_to_gl_severity(RiskLevel::Low), "Low");
        assert_eq!(risk_level_to_gl_severity(RiskLevel::Info), "Info");
    }
}
