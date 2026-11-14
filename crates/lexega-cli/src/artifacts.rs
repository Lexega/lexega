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
//! - sanitize_artifact_key, ArtifactKeys

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use lexega_core::analyzer::{self, AnalysisReport, ToolRun};

use super::io::{is_cloud_uri, is_web_uri, write_uri};

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

    /// The format a file's extension names, or none for a directory or an
    /// extension no report has.
    pub fn from_path(path: &str) -> Option<Self> {
        let p = path.trim().to_ascii_lowercase();
        if p.ends_with(".sarif") {
            Some(ReportArtifactFormat::Sarif)
        } else if p.ends_with(".yaml") || p.ends_with(".yml") {
            Some(ReportArtifactFormat::Yaml)
        } else if p.ends_with(".json") {
            Some(ReportArtifactFormat::Json)
        } else {
            None
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

/// A `--report-artifact-format` that names another format than the
/// `--report-out` file's extension does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportFormatConflict {
    pub format: ReportArtifactFormat,
    pub target: String,
    pub by_extension: ReportArtifactFormat,
}

impl std::fmt::Display for ReportFormatConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "--report-artifact-format {} contradicts --report-out '{}', whose extension names {}; give one of them, or make them agree",
            self.format.extension(),
            self.target,
            self.by_extension.extension()
        )
    }
}

impl std::error::Error for ReportFormatConflict {}

/// The format of the `--report-out` artifact at `target`, for one file and
/// a batch alike: `explicit`, the `--report-artifact-format` given, else the
/// one `target`'s extension names, else `fallback`. An explicit format that
/// contradicts the extension is an error.
pub(crate) fn resolve_report_format(
    target: &str,
    explicit: Option<ReportArtifactFormat>,
    fallback: ReportArtifactFormat,
) -> Result<ReportArtifactFormat, ReportFormatConflict> {
    let by_extension = ReportArtifactFormat::from_path(target);
    match (explicit, by_extension) {
        (Some(format), Some(by_extension)) if format != by_extension => Err(ReportFormatConflict {
            format,
            target: target.to_string(),
            by_extension,
        }),
        (Some(format), _) => Ok(format),
        (None, Some(by_extension)) => Ok(by_extension),
        (None, None) => Ok(fallback),
    }
}

/// A `--report-out` or `--decision-out` target nothing is written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportTargetError {
    /// A web address: files are written to a path or uploaded with a cloud
    /// CLI.
    WebAddress { option: String, target: String },
    /// A name that is neither a report file nor a directory.
    UnknownFile(String),
}

impl std::fmt::Display for ReportTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportTargetError::WebAddress { option, target } => write!(
                f,
                "{option} '{target}' is a web address, which cannot be written to; use a local path, s3://, gs:// or az://"
            ),
            ReportTargetError::UnknownFile(target) => write!(
                f,
                "--report-out '{target}' names neither a report file (.json, .yaml, .yml, .sarif) nor a directory; end a directory's name with '/'"
            ),
        }
    }
}

impl std::error::Error for ReportTargetError {}

/// Refuse a web address as the target of `option` (`--report-out`,
/// `--decision-out`).
pub fn check_output_target(option: &str, target: &str) -> Result<(), ReportTargetError> {
    if is_web_uri(target.trim()) {
        return Err(ReportTargetError::WebAddress {
            option: option.to_string(),
            target: target.to_string(),
        });
    }
    Ok(())
}

/// Refuse a `--report-out` target a report is never written to: a web
/// address, or a name with an extension other than a report's that is not
/// a directory. `-` (standard output), a report file, a name ending in `/`,
/// a name with no extension and an existing directory are targets.
pub fn check_report_target(target: &str) -> Result<(), ReportTargetError> {
    check_output_target("--report-out", target)?;
    let trimmed = target.trim();
    let path = Path::new(trimmed);
    let names_a_file = trimmed != "-"
        && !trimmed.ends_with('/')
        && !is_artifact_file_path(trimmed)
        && path.extension().is_some()
        && (is_cloud_uri(trimmed) || !path.is_dir());
    if names_a_file {
        return Err(ReportTargetError::UnknownFile(target.to_string()));
    }
    Ok(())
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

/// The longest key [`sanitize_artifact_key`] returns: with a suffix such as
/// `.decision.json` it stays within the 255 bytes a file name may hold.
const MAX_ARTIFACT_KEY_BYTES: usize = 200;

/// A file-name-safe key for `input`, at most `MAX_ARTIFACT_KEY_BYTES` long.
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
        return "file".to_string();
    }
    if out.len() <= MAX_ARTIFACT_KEY_BYTES {
        return out;
    }
    // A longer key keeps its end, the file's own name, behind a 64-bit
    // FNV-1a hash of the whole input, so two long paths that end alike stay
    // apart. `out` is ASCII, so any byte index is a character boundary.
    let hash = fnv1a(input);
    let tail = &out[out.len() - (MAX_ARTIFACT_KEY_BYTES - 17)..];
    format!("{hash:016x}_{tail}")
}

/// The 64-bit FNV-1a hash of `input`: stable across runs and platforms.
fn fnv1a(input: &str) -> u64 {
    input.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The artifact key of each source a run writes artifacts for, so that no
/// two of them share one. A source keys on its [`sanitize_artifact_key`]
/// unless another source of the run has that key too, read without case as
/// a case-insensitive file system reads a file name; each such source then
/// keys on it followed by `-` and a hash of its own name.
pub(crate) struct ArtifactKeys {
    keys: std::collections::HashMap<String, String>,
}

impl ArtifactKeys {
    /// The keys of the sources `names` names.
    pub(crate) fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        use std::collections::{BTreeSet, HashMap, HashSet};
        let names: BTreeSet<&str> = names.into_iter().collect();
        let mut sharing: HashMap<String, usize> = HashMap::new();
        for name in &names {
            *sharing
                .entry(sanitize_artifact_key(name).to_ascii_lowercase())
                .or_default() += 1;
        }
        let mut keys = HashMap::with_capacity(names.len());
        let mut taken: HashSet<String> = HashSet::with_capacity(names.len());
        let mut shared = Vec::new();
        for name in names {
            let key = sanitize_artifact_key(name);
            let folded = key.to_ascii_lowercase();
            if sharing.get(&folded).is_some_and(|count| *count == 1) {
                taken.insert(folded);
                keys.insert(name.to_string(), key);
            } else {
                shared.push((name, key));
            }
        }
        for (name, key) in shared {
            let hash = fnv1a(name);
            let mut attempt = 0_u32;
            let unique = loop {
                let candidate = match attempt {
                    0 => format!("{key}-{:08x}", hash >> 32),
                    1 => format!("{key}-{hash:016x}"),
                    n => format!("{key}-{hash:016x}-{n}"),
                };
                if taken.insert(candidate.to_ascii_lowercase()) {
                    break candidate;
                }
                attempt += 1;
            };
            keys.insert(name.to_string(), unique);
        }
        Self { keys }
    }

    /// The key of the source `name` names; a source the run did not list
    /// keys on its [`sanitize_artifact_key`].
    pub(crate) fn key(&self, name: &str) -> String {
        self.keys
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_artifact_key(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_no_other_source_has_is_the_sanitized_name() {
        let keys = ArtifactKeys::new(["migrations/cleanup_orders.sql", "a/b.sql"]);
        assert_eq!(
            keys.key("migrations/cleanup_orders.sql"),
            "migrations_cleanup_orders.sql"
        );
        assert_eq!(keys.key("a/b.sql"), "a_b.sql");
    }

    #[test]
    fn sources_that_share_a_key_each_get_their_own() {
        let names = ["a/b_c.sql", "a_b/c.sql", "a_b_c.sql", "A/B_C.sql", "x.sql"];
        let keys = ArtifactKeys::new(names);
        let all: Vec<String> = names.iter().map(|name| keys.key(name)).collect();
        let distinct: std::collections::HashSet<String> =
            all.iter().map(|key| key.to_ascii_lowercase()).collect();
        assert_eq!(distinct.len(), names.len(), "{all:?}");
        assert_eq!(keys.key("x.sql"), "x.sql");
        for (name, key) in names.iter().zip(&all).take(4) {
            assert!(
                key.starts_with(&sanitize_artifact_key(name)) && key.len() == name.len() + 9,
                "{name}: {key}"
            );
        }
        // The same run names a source alike every time.
        let again = ArtifactKeys::new(names.iter().rev().copied());
        for (name, key) in names.iter().zip(&all) {
            assert_eq!(&again.key(name), key);
        }
    }

    #[test]
    fn a_hashed_key_never_takes_another_sources_key() {
        let hashed = format!("a_b.sql-{:08x}", fnv1a("a/b.sql") >> 32);
        let names = ["a/b.sql", "a_b.sql", hashed.as_str()];
        let keys = ArtifactKeys::new(names);
        let all: std::collections::HashSet<String> =
            names.iter().map(|name| keys.key(name)).collect();
        assert_eq!(all.len(), 3, "{all:?}");
        assert_eq!(keys.key(&hashed), hashed);
    }
}
