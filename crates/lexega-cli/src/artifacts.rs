// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Artifact writing utilities.
//!
//! Two format axes:
//! - [`ReportArtifactFormat`] (Json | Yaml | Sarif) — findings: risk reports,
//!   batch summaries, review reports
//! - [`DecisionArtifactFormat`] (Json | Yaml) — policy verdicts; SARIF has no
//!   schema for decisions, so it is intentionally not representable here.
//!
//! Functions:
//! - is_artifact_file_path
//! - write_artifact (decisions)
//! - write_report_artifact, write_optional_report_artifact (findings, handles
//!   SARIF transform internally)
//! - resolve_artifact_path
//! - sanitize_artifact_key

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use lexega_core::analyzer::{self, AnalysisReport, ToolRun};

use super::io::{is_cloud_uri, write_uri};

/// Format for findings artifacts (risk reports, batch summaries, review
/// reports). SARIF is allowed here because findings have a SARIF schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportArtifactFormat {
    Json,
    Yaml,
    Sarif,
}

impl ReportArtifactFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ReportArtifactFormat::Json => "json",
            ReportArtifactFormat::Yaml => "yaml",
            ReportArtifactFormat::Sarif => "sarif",
        }
    }

    pub fn from_cli_arg(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(ReportArtifactFormat::Json),
            "yaml" | "yml" => Ok(ReportArtifactFormat::Yaml),
            "sarif" => Ok(ReportArtifactFormat::Sarif),
            _ => Err("--report-artifact-format must be json, yaml, or sarif".to_string()),
        }
    }
}

/// Format for decision artifacts (policy verdicts). SARIF is not allowed here
/// because the SARIF schema has no representation for a policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionArtifactFormat {
    Json,
    Yaml,
}

impl DecisionArtifactFormat {
    pub fn extension(self) -> &'static str {
        match self {
            DecisionArtifactFormat::Json => "json",
            DecisionArtifactFormat::Yaml => "yaml",
        }
    }

    pub fn from_cli_arg(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(DecisionArtifactFormat::Json),
            "yaml" | "yml" => Ok(DecisionArtifactFormat::Yaml),
            _ => Err("--decision-artifact-format must be json or yaml".to_string()),
        }
    }
}

/// Format derived from file extension for --report-out
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFileFormat {
    Json,
    Yaml,
    Sarif,
}

impl OutputFileFormat {
    /// Derive format from file extension, returns None for directories or unknown extensions
    pub fn from_path(path: &str) -> Option<Self> {
        let p = path.trim().to_ascii_lowercase();
        if p.ends_with(".sarif") {
            Some(OutputFileFormat::Sarif)
        } else if p.ends_with(".yaml") || p.ends_with(".yml") {
            Some(OutputFileFormat::Yaml)
        } else if p.ends_with(".json") {
            Some(OutputFileFormat::Json)
        } else {
            None
        }
    }
}

pub fn is_artifact_file_path(path: &str) -> bool {
    let p = path.trim().to_ascii_lowercase();
    p.ends_with(".json") || p.ends_with(".yaml") || p.ends_with(".yml") || p.ends_with(".sarif")
}

/// Serialize-and-write helper used by all artifact write sites. JSON or YAML
/// only; SARIF goes through [`write_report_artifact`], which handles the
/// schema transform before delegating here.
fn write_serialized<T: serde::Serialize>(
    encoding: DecisionArtifactFormat,
    base: &str,
    default_name: &str,
    value: &T,
) -> String {
    let content = match encoding {
        DecisionArtifactFormat::Json => serde_json::to_string_pretty(value).unwrap_or_else(|e| {
            eprintln!("Error serializing artifact JSON: {}", e);
            process::exit(1);
        }),
        DecisionArtifactFormat::Yaml => serde_yaml_ng::to_string(value).unwrap_or_else(|e| {
            eprintln!("Error serializing artifact YAML: {}", e);
            process::exit(1);
        }),
    };

    // Special case: "-" means stdout (useful for agent/runtime integration)
    if base == "-" {
        println!("{}", content);
        return "-".to_string();
    }

    // For cloud URIs, use write_uri directly
    if is_cloud_uri(base) {
        // Cloud URIs must be full paths (can't join default_name)
        let target = if is_artifact_file_path(base) {
            base.to_string()
        } else {
            // Append default name to cloud URI path
            format!("{}/{}", base.trim_end_matches('/'), default_name)
        };

        if let Err(e) = write_uri(&target, &content) {
            eprintln!("Error writing artifact to '{}': {}", target, e);
            process::exit(1);
        }
        return target;
    }

    // Local path handling
    let target_path = resolve_artifact_path(base, default_name);

    if let Some(parent) = target_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!(
                "Error creating artifact directory '{}': {}",
                parent.display(),
                e
            );
            process::exit(1);
        }
    }

    if let Err(e) = fs::write(&target_path, &content) {
        eprintln!("Error writing artifact '{}': {}", target_path.display(), e);
        process::exit(1);
    }

    target_path.display().to_string()
}

/// Write a decision artifact (policy verdict).
pub fn write_artifact<T: serde::Serialize>(
    format: DecisionArtifactFormat,
    base: &str,
    default_name: &str,
    value: &T,
) -> String {
    write_serialized(format, base, default_name, value)
}

/// Write a findings artifact (risk report, batch summary, review report).
/// When `format` is SARIF, transforms `findings` via `analyzer::to_sarif`
/// before writing; otherwise serializes `native` directly.
///
/// `findings` carries the report data that the SARIF transform consumes;
/// `native` is the rich payload customers see in JSON/YAML form (often the
/// same object as `findings` for single-file commands). `run` is what the
/// SARIF transform says about the run.
pub fn write_report_artifact<T: serde::Serialize>(
    format: ReportArtifactFormat,
    findings: &AnalysisReport,
    native: &T,
    base: &str,
    name_prefix: &str,
    run: &ToolRun<'_>,
) -> String {
    let default_name = format!("{}.{}", name_prefix, format.extension());
    match format {
        ReportArtifactFormat::Sarif => {
            let sarif = analyzer::to_sarif(findings, run);
            write_serialized(DecisionArtifactFormat::Json, base, &default_name, &sarif)
        }
        ReportArtifactFormat::Json => {
            write_serialized(DecisionArtifactFormat::Json, base, &default_name, native)
        }
        ReportArtifactFormat::Yaml => {
            write_serialized(DecisionArtifactFormat::Yaml, base, &default_name, native)
        }
    }
}

/// Optional wrapper around [`write_report_artifact`] for sites where
/// `--report-out` may be unset.
pub fn write_optional_report_artifact<T: serde::Serialize>(
    format: ReportArtifactFormat,
    findings: &AnalysisReport,
    native: &T,
    out: Option<&str>,
    name_prefix: &str,
    run: &ToolRun<'_>,
) -> Option<String> {
    out.map(|base| write_report_artifact(format, findings, native, base, name_prefix, run))
}

pub fn resolve_artifact_path(base: &str, default_name: &str) -> PathBuf {
    let base_path = Path::new(base);
    if is_artifact_file_path(base) {
        base_path.to_path_buf()
    } else {
        base_path.join(default_name)
    }
}

pub fn sanitize_artifact_key(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => out.push(ch),
            _ => out.push('_'),
        }
    }
    // Avoid empty names
    if out.is_empty() {
        "file".to_string()
    } else {
        out
    }
}
