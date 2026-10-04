// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! File I/O, URI handling, and BOM stripping.
//!
//! Functions:
//! - strip_bom
//! - resolve_uri
//! - write_uri
//! - list_uri
//! - list_uri_recursive
//! - is_cloud_uri
//! - is_yaml_uri
//! - has_jinja_syntax
//! - load_variable_context
//! - yaml_to_json
//! - load_struct_from_json_or_yaml
//! - collect_sql_files
//! - collect_embedded_files

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use lexega_core::dialect::DialectRef;
use lexega_core::template::context::LexegaConfig;
use lexega_core::template::{
    CommandLineOnlyKey, SubstitutionConfig, SubstitutionSettings, SubstitutionSyntax,
    VariableContext, VariableSource,
};
use serde::de::DeserializeOwned;
use walkdir::WalkDir;

pub fn strip_bom(input: &str) -> &str {
    input.strip_prefix('\u{FEFF}').unwrap_or(input)
}

/// Canonical dialect list for user-facing "Unknown dialect" errors and
/// help text. Keep in sync with `lexega_core::dialect::dialect_from_name`.
pub const DIALECT_OPTIONS: &str =
    "snowflake, postgresql, bigquery, mysql, mssql, databricks, redshift";

/// Resolve a dialect name string to a DialectRef.
///
/// Accepts: "snowflake" (default), "postgresql"/"postgres"/"pg", "mysql", "bigquery"/"bq",
/// "mssql"/"tsql"/"sqlserver", "redshift"/"rs".
/// Returns None for unrecognized values (caller should print error and exit).
pub fn resolve_dialect(name: &str) -> Option<DialectRef> {
    lexega_core::dialect::dialect_from_name(name)
}

/// Resolve a URI to file content.
///
/// Supports multiple URI schemes:
/// - Local paths (default): Read directly from filesystem
/// - `s3://bucket/key`: Fetch via AWS CLI (`aws s3 cp`)
/// - `gs://bucket/key`: Fetch via Google Cloud CLI (`gsutil cp`)
/// - `az://container/blob`: Fetch via Azure CLI (`az storage blob download`)
/// - `https://...`: Fetch via curl (supports pre-signed URLs)
///
/// Cloud URIs require the respective CLI to be installed and authenticated.
/// This is the standard pattern for CI/CD where runners are pre-configured.
pub fn resolve_uri(uri: &str) -> Result<String, Box<dyn std::error::Error>> {
    // S3 URI: s3://bucket/path/to/file.yaml
    if uri.starts_with("s3://") {
        let output = Command::new("aws")
            .args(["s3", "cp", uri, "-"])
            .output()
            .map_err(|e| format!("Failed to execute 'aws s3 cp'. Is AWS CLI installed? {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("aws s3 cp failed for '{}': {}", uri, stderr).into());
        }
        return Ok(String::from_utf8(output.stdout)?);
    }

    // GCS URI: gs://bucket/path/to/file.yaml
    if uri.starts_with("gs://") {
        let output = Command::new("gsutil")
            .args(["cp", uri, "-"])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'gsutil cp'. Is Google Cloud SDK installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("gsutil cp failed for '{}': {}", uri, stderr).into());
        }
        return Ok(String::from_utf8(output.stdout)?);
    }

    // Azure Blob URI: az://container/path/to/file.yaml
    // Note: Azure uses different URL formats; we support az:// as a shorthand
    if let Some(path) = uri.strip_prefix("az://") {
        // Parse az://container/blob/path -> container and blob path
        let (container, blob_path) = path.split_once('/').ok_or_else(|| {
            format!(
                "Invalid Azure URI '{}': expected az://container/blob/path",
                uri
            )
        })?;

        let output = Command::new("az")
            .args([
                "storage",
                "blob",
                "download",
                "--container-name",
                container,
                "--name",
                blob_path,
                "--file",
                "/dev/stdout",
                "--no-progress",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'az storage blob download'. Is Azure CLI installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(
                format!("az storage blob download failed for '{}': {}", uri, stderr).into(),
            );
        }
        return Ok(String::from_utf8(output.stdout)?);
    }

    // HTTPS URL: Use curl for pre-signed URLs and public endpoints
    if uri.starts_with("https://") || uri.starts_with("http://") {
        let output = Command::new("curl")
            .args(["-sS", "-f", uri])
            .output()
            .map_err(|e| format!("Failed to execute 'curl'. Is curl installed? {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("curl failed for '{}': {}", uri, stderr).into());
        }
        return Ok(String::from_utf8(output.stdout)?);
    }

    // Default: local file path
    fs::read_to_string(uri).map_err(|e| format!("Failed to read '{}': {}", uri, e).into())
}

/// Load a CatalogIndex from a URI (local path or cloud storage).
///
/// This handles all URI schemes supported by `resolve_uri` and automatically
/// detects JSON vs YAML format based on extension or content.
///
/// An optional `provider_name` can be given to override the provider stored in the
/// snapshot.  When `None`, the provider is auto-detected from the snapshot's
/// `provider` field, falling back to Snowflake.
pub fn load_catalog_index_from_uri(
    uri: &str,
    provider_name: Option<&str>,
) -> Result<lexega_core::catalog::CatalogIndex, String> {
    load_catalog_index_from_uri_with_overlay(uri, provider_name, &[])
}

/// Like [`load_catalog_index_from_uri`], but adds the column tags in
/// `tag_overlay` to the snapshot before the index is built.
pub fn load_catalog_index_from_uri_with_overlay(
    uri: &str,
    provider_name: Option<&str>,
    tag_overlay: &[lexega_core::catalog::ColumnTagOverlay],
) -> Result<lexega_core::catalog::CatalogIndex, String> {
    let content = resolve_uri(uri).map_err(|e| e.to_string())?;

    // Detect format by extension or content
    let is_yaml = uri.ends_with(".yaml")
        || uri.ends_with(".yml")
        || content.trim_start().starts_with("schema_version:");

    let mut snapshot: lexega_core::catalog::CatalogSnapshot = if is_yaml {
        serde_yaml_ng::from_str(&content)
            .map_err(|e| format!("YAML parse error for '{}': {}", uri, e))?
    } else {
        serde_json::from_str(&content)
            .map_err(|e| format!("JSON parse error for '{}': {}", uri, e))?
    };

    snapshot
        .validate_version()
        .map_err(|e| format!("Catalog version error for '{}': {}", uri, e))?;

    if !tag_overlay.is_empty() {
        snapshot.enrich_column_tags(tag_overlay);
    }

    if let Some(pname) = provider_name {
        let provider = lexega_core::catalog_provider_by_name(pname).ok_or_else(|| {
            let valid = lexega_core::builtin_catalog_provider_names().join(", ");
            format!(
                "Unknown catalog provider '{}'. Valid providers: {}",
                pname, valid
            )
        })?;
        lexega_core::catalog::CatalogIndex::from_snapshot_with_provider(snapshot, provider)
            .map_err(|e| format!("Catalog index error for '{}': {}", uri, e))
    } else {
        lexega_core::catalog::CatalogIndex::from_snapshot(snapshot)
            .map_err(|e| format!("Catalog index error for '{}': {}", uri, e))
    }
}

/// Write content to a URI.
///
/// Supports multiple URI schemes:
/// - Local paths (default): Write directly to filesystem
/// - `s3://bucket/key`: Upload via AWS CLI (`aws s3 cp`)
/// - `gs://bucket/key`: Upload via Google Cloud CLI (`gsutil cp`)
/// - `az://container/blob`: Upload via Azure CLI (`az storage blob upload`)
///
/// Cloud URIs require the respective CLI to be installed and authenticated.
pub fn write_uri(uri: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    // S3 URI: s3://bucket/path/to/file.json
    if uri.starts_with("s3://") {
        let mut child = Command::new("aws")
            .args(["s3", "cp", "-", uri])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to execute 'aws s3 cp'. Is AWS CLI installed? {}", e))?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(content.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("aws s3 cp failed for '{}': {}", uri, stderr).into());
        }
        return Ok(());
    }

    // GCS URI: gs://bucket/path/to/file.json
    if uri.starts_with("gs://") {
        let mut child = Command::new("gsutil")
            .args(["cp", "-", uri])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to execute 'gsutil cp'. Is Google Cloud SDK installed? {}",
                    e
                )
            })?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(content.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("gsutil cp failed for '{}': {}", uri, stderr).into());
        }
        return Ok(());
    }

    // Azure Blob URI: az://container/path/to/file.json
    if let Some(path) = uri.strip_prefix("az://") {
        // Parse az://container/blob/path -> container and blob path
        let (container, blob_path) = path.split_once('/').ok_or_else(|| {
            format!(
                "Invalid Azure URI '{}': expected az://container/blob/path",
                uri
            )
        })?;

        // Azure CLI requires a file, so write to temp and upload
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("lexega-upload-{}.tmp", std::process::id()));
        fs::write(&temp_file, content)?;

        // `az storage blob upload --file` takes a path string; surface a
        // typed error when the system temp dir resolves to non-UTF-8 bytes
        // rather than crashing inside the argv builder.
        let temp_file_str = temp_file.to_str().ok_or_else(|| {
            format!(
                "Temp file path is not valid UTF-8 (cannot pass to `az`): {}",
                temp_file.display()
            )
        })?;

        let output = Command::new("az")
            .args([
                "storage",
                "blob",
                "upload",
                "--container-name",
                container,
                "--name",
                blob_path,
                "--file",
                temp_file_str,
                "--overwrite",
                "--no-progress",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'az storage blob upload'. Is Azure CLI installed? {}",
                    e
                )
            })?;

        // Clean up temp file
        let _ = fs::remove_file(&temp_file);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("az storage blob upload failed for '{}': {}", uri, stderr).into());
        }
        return Ok(());
    }

    // Default: local file path
    // Create parent directories if needed
    let path = Path::new(uri);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory '{}': {}", parent.display(), e))?;
        }
    }
    fs::write(uri, content).map_err(|e| format!("Failed to write '{}': {}", uri, e).into())
}

/// Check if a URI is a cloud storage URI (not a local path)
pub fn is_cloud_uri(uri: &str) -> bool {
    uri.starts_with("s3://") || uri.starts_with("gs://") || uri.starts_with("az://")
}

/// List files in a URI (cloud storage or local directory).
///
/// Returns a list of filenames (not full paths) in the directory/prefix.
/// For cloud storage, only lists files matching the optional suffix filter.
///
/// Supports:
/// - Local paths: Uses std::fs::read_dir
/// - `s3://bucket/prefix/`: Uses `aws s3 ls`
/// - `gs://bucket/prefix/`: Uses `gsutil ls`
/// - `az://container/prefix/`: Uses `az storage blob list`
pub fn list_uri(
    uri: &str,
    suffix_filter: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Ensure URI ends with / for directory listing
    let uri = if uri.ends_with('/') {
        uri.to_string()
    } else {
        format!("{}/", uri)
    };

    // S3 URI: s3://bucket/path/
    if uri.starts_with("s3://") {
        let output = Command::new("aws")
            .args(["s3", "ls", &uri])
            .output()
            .map_err(|e| format!("Failed to execute 'aws s3 ls'. Is AWS CLI installed? {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("aws s3 ls failed for '{}': {}", uri, stderr).into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        let files: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // aws s3 ls output format: "2024-01-15 10:30:00    12345 filename.json"
                // or for directories: "                           PRE dirname/"
                let parts: Vec<&str> = line.split_whitespace().collect();
                parts.last().map(|s| s.to_string())
            })
            .filter(|name| !name.ends_with('/')) // Skip directories
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // GCS URI: gs://bucket/path/
    if uri.starts_with("gs://") {
        let output = Command::new("gsutil")
            .args(["ls", &uri])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'gsutil ls'. Is Google Cloud SDK installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("gsutil ls failed for '{}': {}", uri, stderr).into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        let files: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // gsutil ls returns full paths: gs://bucket/path/filename.json
                line.rsplit('/').next().map(|s| s.to_string())
            })
            .filter(|name| !name.is_empty())
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // Azure Blob URI: az://container/prefix/
    if let Some(path_with_slash) = uri.strip_prefix("az://") {
        let path = path_with_slash.trim_end_matches('/');
        let (container, prefix) = path.split_once('/').unwrap_or((path, ""));

        let output = Command::new("az")
            .args([
                "storage",
                "blob",
                "list",
                "--container-name",
                container,
                "--prefix",
                prefix,
                "--query",
                "[].name",
                "-o",
                "tsv",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'az storage blob list'. Is Azure CLI installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("az storage blob list failed for '{}': {}", uri, stderr).into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        let prefix_len = if prefix.is_empty() {
            0
        } else {
            prefix.len() + 1
        }; // +1 for trailing /
        let files: Vec<String> = stdout
            .lines()
            .map(|line| {
                // Azure returns full blob paths, strip prefix to get filename
                if line.len() > prefix_len {
                    line[prefix_len..].to_string()
                } else {
                    line.to_string()
                }
            })
            .filter(|name| !name.contains('/')) // Only direct children, not nested
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // Default: local directory
    let path = Path::new(uri.trim_end_matches('/'));
    if !path.exists() {
        return Ok(Vec::new());
    }

    let files: Vec<String> = fs::read_dir(path)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if suffix_filter.is_none_or(|s| name.ends_with(s)) {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    Ok(files)
}

/// List files recursively in a URI (cloud storage or local directory).
///
/// Returns a list of relative paths from the base URI.
/// For cloud storage, lists ALL files under the prefix recursively.
///
/// Supports:
/// - Local paths: Uses walkdir for recursive traversal
/// - `s3://bucket/prefix/`: Uses `aws s3 ls --recursive`
/// - `gs://bucket/prefix/`: Uses `gsutil ls -r`
/// - `az://container/prefix/`: Uses `az storage blob list` (inherently recursive)
pub fn list_uri_recursive(
    uri: &str,
    suffix_filter: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Normalize URI - ensure no trailing slash for consistent handling
    let base_uri = uri.trim_end_matches('/');

    // S3 URI: s3://bucket/path/
    if let Some(without_scheme) = base_uri.strip_prefix("s3://") {
        // aws s3 ls --recursive s3://bucket/prefix/
        let ls_uri = format!("{}/", base_uri);
        let output = Command::new("aws")
            .args(["s3", "ls", "--recursive", &ls_uri])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'aws s3 ls --recursive'. Is AWS CLI installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Empty prefix returns error, treat as empty
            if stderr.contains("NoSuchKey")
                || stderr.contains("does not exist")
                || stderr.is_empty()
            {
                return Ok(Vec::new());
            }
            return Err(
                format!("aws s3 ls --recursive failed for '{}': {}", ls_uri, stderr).into(),
            );
        }

        let stdout = String::from_utf8(output.stdout)?;
        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        // Recursive output format: "2024-01-15 10:30:00      12345 prefix/team-a/file.json"
        // The path is the 4th whitespace-separated field (0-indexed: date, time, size, path)
        // `without_scheme` was bound at the outer `if let` above and holds
        // the URI with the `s3://` prefix already stripped (e.g. `bucket/prefix`).
        let bucket_end = without_scheme.find('/').unwrap_or(without_scheme.len());
        let key_prefix = if bucket_end < without_scheme.len() {
            &without_scheme[bucket_end + 1..]
        } else {
            ""
        };

        let files: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                // Use split_whitespace and take the 4th element (the object key)
                line.split_whitespace().nth(3).map(|s| s.to_string())
            })
            .filter(|path| !path.is_empty())
            .filter_map(|path| {
                // Strip the key prefix to get relative path
                if key_prefix.is_empty() {
                    Some(path)
                } else {
                    // A path outside the expected prefix is skipped.
                    path.strip_prefix(key_prefix)
                        .map(|relative| relative.trim_start_matches('/').to_string())
                }
            })
            .filter(|name| !name.is_empty())
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // GCS URI: gs://bucket/path/
    if base_uri.starts_with("gs://") {
        // gsutil ls -r gs://bucket/path/ for recursive listing
        let ls_uri = format!("{}/", base_uri);
        let output = Command::new("gsutil")
            .args(["ls", "-r", &ls_uri])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'gsutil ls -r'. Is Google Cloud SDK installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Empty/non-existent prefix - treat as empty
            if stderr.contains("matched no objects")
                || stderr.contains("CommandException")
                || stderr.contains("NotFoundError")
            {
                return Ok(Vec::new());
            }
            return Err(format!("gsutil ls -r failed for '{}': {}", ls_uri, stderr).into());
        }

        let stdout = String::from_utf8(output.stdout)?;
        // gsutil ls -r returns full paths: gs://bucket/path/subdir/filename.json
        // Also returns directory markers ending with : or /
        let base_with_slash = format!("{}/", base_uri);
        let files: Vec<String> = stdout
            .lines()
            .filter(|line| !line.ends_with('/') && !line.ends_with(':')) // Skip directories
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                // Strip base URI to get relative path
                if let Some(relative) = line.strip_prefix(&base_with_slash) {
                    Some(relative.to_string())
                } else {
                    line.strip_prefix(base_uri)
                        .map(|relative| relative.trim_start_matches('/').to_string())
                }
            })
            .filter(|name| !name.is_empty())
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // Azure Blob URI: az://container/prefix/
    // Azure blob list is inherently recursive (returns all blobs with prefix)
    if let Some(path) = base_uri.strip_prefix("az://") {
        let (container, prefix) = path.split_once('/').unwrap_or((path, ""));

        // Ensure prefix ends with / for proper prefix matching (if not empty)
        let prefix_with_slash = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };

        let output = Command::new("az")
            .args([
                "storage",
                "blob",
                "list",
                "--container-name",
                container,
                "--prefix",
                &prefix_with_slash,
                "--query",
                "[].name",
                "-o",
                "tsv",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'az storage blob list'. Is Azure CLI installed? {}",
                    e
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(
                format!("az storage blob list failed for '{}': {}", base_uri, stderr).into(),
            );
        }

        let stdout = String::from_utf8(output.stdout)?;
        let prefix_len = prefix_with_slash.len();
        let files: Vec<String> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                // Azure returns full blob paths (relative to container), strip prefix
                if prefix_len > 0 && line.starts_with(&prefix_with_slash) {
                    Some(line[prefix_len..].to_string())
                } else if prefix_len == 0 {
                    Some(line.to_string())
                } else {
                    None
                }
            })
            .filter(|name| !name.is_empty())
            .filter(|name| suffix_filter.is_none_or(|s| name.ends_with(s)))
            .collect();
        return Ok(files);
    }

    // Default: local directory - use walkdir for recursive traversal
    let base_path = Path::new(base_uri);
    if !base_path.exists() {
        return Ok(Vec::new());
    }

    let files: Vec<String> = WalkDir::new(base_path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.path();
            let relative = path.strip_prefix(base_path).ok()?;
            let name = relative.to_string_lossy().to_string();
            if suffix_filter.is_none_or(|s| name.ends_with(s)) {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    Ok(files)
}

/// Check if content looks like YAML based on URI extension
pub fn is_yaml_uri(uri: &str) -> bool {
    let lower = uri.to_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Detect Jinja template syntax — the single detection predicate for every
/// render surface (see `template::has_jinja_syntax`).
pub use lexega_core::template::has_jinja_syntax;

/// Load variable context from CLI arguments, files, and the environment
/// allowlist (`--var-env`).
pub fn load_variable_context(
    cli_vars: &[(String, String)],
    var_files: &[String],
    snowsql_configs: &[String],
    env_allowlist: &[String],
) -> Result<VariableContext, Box<dyn std::error::Error>> {
    let mut context = VariableContext::new();

    // Load from files first (lower priority)
    for file_path in var_files {
        let content = fs::read_to_string(file_path)?;

        // Detect format by extension
        if file_path.ends_with(".json") {
            let vars: serde_json::Value = serde_json::from_str(&content)?;
            if let serde_json::Value::Object(map) = vars {
                for (key, value) in map {
                    context.set(key, value, VariableSource::VarFile);
                }
            }
        } else if file_path.ends_with(".yaml") || file_path.ends_with(".yml") {
            let vars: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content)?;
            if let serde_yaml_ng::Value::Mapping(map) = vars {
                for (key, value) in map {
                    if let serde_yaml_ng::Value::String(k) = key {
                        // Convert YAML value to JSON value
                        let json_value = yaml_to_json(value);
                        context.set(k, json_value, VariableSource::VarFile);
                    }
                }
            }
        }
    }

    // Load SnowSQL config `[variables]` sections (priority below --var/--var-file,
    // above .lexega.toml; precedence resolved by VariableSource).
    for config_path in snowsql_configs {
        context.load_from_snowsql_config(std::path::Path::new(config_path))?;
    }

    // Allowlisted environment values (priority between --var-file and the
    // SnowSQL config; precedence resolved by VariableSource).
    context.load_from_env_allowlist(env_allowlist);

    // Load CLI vars (higher priority)
    for (key, value) in cli_vars {
        // Try to parse as JSON first, fall back to string
        let json_value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
        context.set(key.clone(), json_value, VariableSource::Cli);
    }

    Ok(context)
}

/// Resolve the deployment-variable substitution setup. The marker syntaxes
/// are the presets `.lexega.toml` `[template.substitution]` selects (walk-up
/// discovered; the default preset set when it selects none) followed by the
/// `--var-syntax` values. The environment allowlist is the `--var-env` names
/// and nothing else.
pub fn resolve_substitution(
    cli_syntaxes: &[String],
    cli_env: &[String],
) -> Result<(SubstitutionConfig, Vec<String>), String> {
    let settings = discover_substitution_settings()?;
    let mut syntaxes: Vec<SubstitutionSyntax> = Vec::new();
    match settings.as_ref().and_then(|s| s.presets.as_ref()) {
        Some(names) => {
            for name in names {
                syntaxes
                    .push(SubstitutionSyntax::from_preset_name(name).map_err(|e| e.to_string())?);
            }
        }
        None => syntaxes.extend(SubstitutionConfig::default().syntaxes),
    }
    for value in cli_syntaxes {
        let syntax = SubstitutionSyntax::from_cli_value(value).map_err(|e| e.to_string())?;
        if !syntaxes.contains(&syntax) {
            syntaxes.push(syntax);
        }
    }
    let mut env: Vec<String> = Vec::new();
    for name in cli_env {
        if !env.contains(name) {
            env.push(name.clone());
        }
    }
    Ok((SubstitutionConfig { syntaxes }, env))
}

/// Walk up from the current directory for `.lexega.toml` and read its
/// `[template.substitution]` table, if any. A missing file is `Ok(None)`;
/// an unreadable or malformed file is an error — the user wrote config
/// that must load. So is a table that sets a command-line-only key: the
/// file sits in the tree being analyzed, and a run that ignored the key
/// would analyze something other than what its author configured.
fn discover_substitution_settings() -> Result<Option<SubstitutionSettings>, String> {
    let mut current =
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;
    loop {
        let config_path = current.join(".lexega.toml");
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;
            let config: LexegaConfig = toml::from_str(&content)
                .map_err(|e| format!("Failed to parse {}: {}", config_path.display(), e))?;
            let settings = config.template.and_then(|t| t.substitution);
            if let Some(key) = settings
                .as_ref()
                .and_then(|s| s.command_line_only_keys().into_iter().next())
            {
                return Err(format!(
                    "{}: [template.substitution] `{}` is not read from a configuration file. {}",
                    config_path.display(),
                    key.name(),
                    command_line_spelling(key)
                ));
            }
            return Ok(settings);
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

/// How to give on the command line what `key` would have set.
fn command_line_spelling(key: CommandLineOnlyKey) -> &'static str {
    match key {
        CommandLineOnlyKey::Env => {
            "Name each environment variable with --var-env NAME on the command line."
        }
        CommandLineOnlyKey::Custom => {
            "Give each delimiter pair as a marker shape on the command line, e.g. --var-syntax '%%NAME%%'."
        }
    }
}

/// Convert YAML value to JSON value
fn yaml_to_json(yaml: serde_yaml_ng::Value) -> serde_json::Value {
    match yaml {
        serde_yaml_ng::Value::Null => serde_json::Value::Null,
        serde_yaml_ng::Value::Bool(b) => serde_json::Value::Bool(b),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml_ng::Value::String(s) => serde_json::Value::String(s),
        serde_yaml_ng::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.into_iter().map(yaml_to_json).collect())
        }
        serde_yaml_ng::Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                if let serde_yaml_ng::Value::String(key) = k {
                    obj.insert(key, yaml_to_json(v));
                }
            }
            serde_json::Value::Object(obj)
        }
        serde_yaml_ng::Value::Tagged(tagged) => yaml_to_json(tagged.value),
    }
}

pub fn load_struct_from_json_or_yaml<T: DeserializeOwned>(
    uri: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let content = resolve_uri(uri)?;

    if is_yaml_uri(uri) {
        // Parse to YAML Value first, then convert to JSON value.
        // This avoids relying on serde_yaml_ng generic parsing support.
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&content)?;
        let json_value = yaml_to_json(value);
        Ok(serde_json::from_value(json_value)?)
    } else {
        Ok(serde_json::from_str(&content)?)
    }
}

/// Why a file a scan found is left unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The file is under a `macros` directory, where Jinja macro definitions
    /// live; they are not statements.
    MacroDirectory,
    /// The entry is a symbolic link. A scan reads the files that live in
    /// the directory it was given, wherever a link in it points.
    SymbolicLink,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::MacroDirectory => {
                write!(
                    f,
                    "in a macros directory: macro definitions, not statements"
                )
            }
            SkipReason::SymbolicLink => {
                write!(f, "symbolic link: a directory scan does not follow links")
            }
        }
    }
}

/// A file a scan found and left unread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFile {
    pub path: PathBuf,
    pub reason: SkipReason,
}

/// What a scan found: the files to read and the files it will not read.
/// Every file the scan matches is in one of the two, so nothing it leaves
/// unread goes unreported.
#[derive(Debug, Default)]
pub struct FoundFiles {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<SkippedFile>,
}

impl FoundFiles {
    fn skip(&mut self, path: PathBuf, reason: SkipReason) {
        self.skipped.push(SkippedFile { path, reason });
    }

    /// Whether the scan matched nothing at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.skipped.is_empty()
    }
}

/// Whether `path` names a SQL file. The extension matches in any case.
pub(crate) fn has_sql_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
}

/// Whether a directory named `macros` lies on `relative`, a file path taken
/// from the root of a scan or of a repository.
pub(crate) fn in_macros_directory(relative: &Path) -> bool {
    relative
        .parent()
        .is_some_and(|dir| dir.components().any(|c| c.as_os_str() == "macros"))
}

/// Absolute form of a file a scan will read (dunce strips `\\?\` on Windows).
fn absolute(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The SQL files under `path`: a glob pattern, a directory or a single file.
///
/// A scan never follows a symbolic link it comes across — the link is listed
/// as skipped — so it reads nothing outside the directory it was given. A
/// path named outright is the caller's own choice and is followed.
pub fn collect_sql_files(path: &str, recursive: bool) -> FoundFiles {
    let mut found = FoundFiles::default();
    let path_obj = Path::new(path);

    if path.contains('*') || path.contains('?') {
        match glob::glob(path) {
            Ok(paths) => {
                for entry in paths.filter_map(Result::ok) {
                    if !has_sql_extension(&entry) {
                        continue;
                    }
                    match fs::symlink_metadata(&entry) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            found.skip(entry, SkipReason::SymbolicLink)
                        }
                        Ok(meta) if meta.is_file() => found.files.push(absolute(&entry)),
                        Ok(_) | Err(_) => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("Invalid glob pattern: {}", e);
            }
        }
    } else if path_obj.is_dir() {
        if recursive {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                let entry_path = entry.path();
                if !has_sql_extension(entry_path) {
                    continue;
                }
                let file_type = entry.file_type();
                if file_type.is_symlink() {
                    found.skip(entry_path.to_path_buf(), SkipReason::SymbolicLink);
                } else if file_type.is_file() {
                    let relative = entry_path.strip_prefix(path_obj).unwrap_or(entry_path);
                    if in_macros_directory(relative) {
                        found.skip(entry_path.to_path_buf(), SkipReason::MacroDirectory);
                    } else {
                        found.files.push(absolute(entry_path));
                    }
                }
            }
        } else if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let entry_path = entry.path();
                if !has_sql_extension(&entry_path) {
                    continue;
                }
                match entry.file_type() {
                    Ok(file_type) if file_type.is_symlink() => {
                        found.skip(entry_path, SkipReason::SymbolicLink)
                    }
                    Ok(file_type) if file_type.is_file() => found.files.push(absolute(&entry_path)),
                    Ok(_) | Err(_) => {}
                }
            }
        }
    } else if path_obj.is_file() {
        found.files.push(absolute(path_obj));
    }

    found
}

/// Whether `path` is a Python source or notebook file.
fn has_embedded_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "py" || ext == "ipynb")
}

/// Python and notebook files for embedded SQL extraction (`--scan-embedded`):
/// the `.py` / `.ipynb` files under a directory, or a single such file.
/// Symbolic links are treated as in [`collect_sql_files`].
pub fn collect_embedded_files(path: &str, recursive: bool) -> FoundFiles {
    let mut found = FoundFiles::default();
    let path_obj = Path::new(path);

    if path_obj.is_dir() {
        if recursive {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                let entry_path = entry.path();
                if !has_embedded_extension(entry_path) {
                    continue;
                }
                // Skip common virtual environments and build directories
                if let Some(path_str) = entry_path.to_str() {
                    if path_str.contains("/.venv/")
                        || path_str.contains("/venv/")
                        || path_str.contains("/node_modules/")
                        || path_str.contains("/__pycache__/")
                        || path_str.contains("/.ipynb_checkpoints/")
                    {
                        continue;
                    }
                }
                let file_type = entry.file_type();
                if file_type.is_symlink() {
                    found.skip(entry_path.to_path_buf(), SkipReason::SymbolicLink);
                } else if file_type.is_file() {
                    found.files.push(absolute(entry_path));
                }
            }
        } else if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let entry_path = entry.path();
                if !has_embedded_extension(&entry_path) {
                    continue;
                }
                match entry.file_type() {
                    Ok(file_type) if file_type.is_symlink() => {
                        found.skip(entry_path, SkipReason::SymbolicLink)
                    }
                    Ok(file_type) if file_type.is_file() => found.files.push(absolute(&entry_path)),
                    Ok(_) | Err(_) => {}
                }
            }
        }
    } else if path_obj.is_file() && has_embedded_extension(path_obj) {
        found.files.push(absolute(path_obj));
    }

    found
}
/// Load a customer `--custom-rules` file as a classified v1 rule
/// corpus. Only the YAML schema served by `load_v1_rules` is accepted
/// (the v1 loader is YAML-only). The returned
/// [`lexega_core::rules::LoadedRuleset`] carries both full rules and
/// partial overrides — built-in merging, partial-override resolution,
/// and `--no-builtin` handling happen at the CLI seam via
/// `rules::build_v1_rule_corpus`.
pub fn load_custom_rules(uri: &str) -> Result<lexega_core::rules::LoadedRuleset, String> {
    let content = resolve_uri(uri)
        .map_err(|e| format!("Failed to load custom rules from '{}': {}", uri, e))?;

    let lower = uri.to_lowercase();
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        lexega_core::rules::load_v1_rules(&content)
            .map_err(|e| format!("Failed to parse v1 rules from '{}': {}", uri, e))
    } else {
        Err("Custom rules file must have .yaml or .yml extension (v1 schema)".to_string())
    }
}
