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
use std::sync::Arc;

use lexega_core::catalog::{
    CatalogColumn, CatalogError, CatalogIndex, CatalogProvider, CatalogSnapshot, ColumnTagOverlay,
};
use lexega_core::dialect::DialectRef;
use lexega_core::ir::SessionContext;
use lexega_core::template::context::LexegaConfig;
use lexega_core::template::{
    lexically_normal, macro_path_owner, CommandLineOnlyKey, MacroPathOwner, ProjectTree,
    ProjectsOnDisk, SnowsqlConfigRead, SubstitutionConfig, SubstitutionSettings,
    SubstitutionSyntax, VariableContext, VariableSource, PROJECT_FILE,
};
use serde::de::DeserializeOwned;
use walkdir::WalkDir;

/// A SQL file's text, read as its byte-order mark says (UTF-8, or UTF-16
/// of either byte order), and the encoding to write it back in.
pub fn read_sql_file(path: &Path) -> Result<lexega_core::extract::SourceText, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    lexega_core::extract::decode_source(&bytes).map_err(|e| format!("the file is {}", e))
}

pub use lexega_core::extract::strip_bom;

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
///
/// The text comes back without a leading UTF-8 byte-order mark.
pub fn resolve_uri(uri: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(strip_bom(&fetch_uri(uri)?).to_string())
}

fn fetch_uri(uri: &str) -> Result<String, Box<dyn std::error::Error>> {
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

    // A web address: a pre-signed URL or a public endpoint.
    if is_web_uri(uri) {
        let response = shared_http_client()
            .send(&HttpRequest {
                method: HttpMethod::Get,
                url: uri,
                headers: &[],
                body: None,
                timeout: None,
                body_limit: None,
            })
            .map_err(|e| format!("Cannot fetch '{}': {}", uri, e))?;
        let status = response.status;
        if !(200..=299).contains(&status) {
            return Err(format!("Cannot fetch '{}': HTTP {}", uri, status).into());
        }
        let body = response
            .read_body()
            .map_err(|e| format!("Cannot fetch '{}': {}", uri, e))?;
        return Ok(String::from_utf8(body)?);
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
///
/// `dialect` is the one the run analyses under (Snowflake when `None`):
/// the index is built under it, so the catalog's names are keyed as the
/// run's statements look them up.
pub fn load_catalog_index_from_uri(
    uri: &str,
    provider_name: Option<&str>,
    dialect: &Option<DialectRef>,
) -> Result<CatalogIndex, String> {
    load_catalog_index_from_uri_with_overlay(uri, provider_name, &[], dialect)
}

/// Like [`load_catalog_index_from_uri`], but adds the column tags in
/// `tag_overlay` to the snapshot before the index is built.
pub fn load_catalog_index_from_uri_with_overlay(
    uri: &str,
    provider_name: Option<&str>,
    tag_overlay: &[ColumnTagOverlay],
    dialect: &Option<DialectRef>,
) -> Result<CatalogIndex, String> {
    let mut snapshot = read_catalog_snapshot(uri)?;
    let named = provider_name.map(catalog_provider_named).transpose()?;
    let provider = index_provider(named, snapshot.provider.as_deref());

    // The overlay and the index fold the catalog's names.
    let _dialect = lexega_core::Engine::recognition().apply_dialect(dialect);
    if !tag_overlay.is_empty() {
        snapshot.enrich_column_tags(tag_overlay, &*provider);
    }

    CatalogIndex::from_snapshot_with_provider(snapshot, provider)
        .map_err(|e| format!("Catalog index error for '{}': {}", uri, e))
}

/// The catalog snapshot at `uri`, JSON or YAML by extension or content,
/// checked for its schema version.
fn read_catalog_snapshot(uri: &str) -> Result<CatalogSnapshot, String> {
    let content = resolve_uri(uri).map_err(|e| e.to_string())?;

    // Detect format by extension or content
    let is_yaml = uri.ends_with(".yaml")
        || uri.ends_with(".yml")
        || content.trim_start().starts_with("schema_version:");

    let snapshot: CatalogSnapshot = if is_yaml {
        serde_yaml_ng::from_str(&content)
            .map_err(|e| format!("YAML parse error for '{}': {}", uri, e))?
    } else {
        serde_json::from_str(&content)
            .map_err(|e| format!("JSON parse error for '{}': {}", uri, e))?
    };

    snapshot
        .validate_version()
        .map_err(|e| format!("Catalog version error for '{}': {}", uri, e))?;
    Ok(snapshot)
}

/// The catalog provider named `name`.
fn catalog_provider_named(name: &str) -> Result<Arc<dyn CatalogProvider>, String> {
    lexega_core::catalog_provider_by_name(name).ok_or_else(|| {
        let valid = lexega_core::builtin_catalog_provider_names().join(", ");
        format!(
            "Unknown catalog provider '{}'. Valid providers: {}",
            name, valid
        )
    })
}

/// The provider a catalog is indexed with and its column tags are matched
/// with: `named`, else the one the snapshot names (`snapshot_names`), else
/// the default, as [`CatalogIndex::from_snapshot`] picks it.
fn index_provider(
    named: Option<Arc<dyn CatalogProvider>>,
    snapshot_names: Option<&str>,
) -> Arc<dyn CatalogProvider> {
    named
        .or_else(|| snapshot_names.and_then(lexega_core::catalog_provider_by_name))
        .unwrap_or_else(lexega_core::default_catalog_provider)
}

/// A session's catalog, indexed under each dialect the session analyses in.
///
/// The catalog is read once. A dialect's index is built from it the first
/// time that dialect is selected, under that dialect, with any column tags
/// matched as that dialect reads names. Without column tags every index
/// shares the catalog as read; with them the loaded dialect's index shares
/// it and each other dialect's index holds its own copy. An index is read
/// only under the dialect it was built under.
pub struct SessionCatalogs {
    source: CatalogSource,
    /// The provider every index is built with and its tags matched with.
    provider: Arc<dyn CatalogProvider>,
    /// The dialect the catalog was loaded under, and its index.
    loaded_under: String,
    loaded: Arc<CatalogIndex>,
    /// The index of each other dialect selected, or why it cannot be built.
    others: Vec<(String, Result<Arc<CatalogIndex>, String>)>,
    /// Which of `others` is selected; `None` is `loaded`.
    current: Option<usize>,
}

/// What a session's catalog is made from.
enum CatalogSource {
    /// A catalog as read with `tag_overlay`'s tags added as the loaded
    /// dialect reads names; `tagged_columns` holds each column they were
    /// added to and how many tags it had as read.
    Snapshot {
        snapshot: Arc<CatalogSnapshot>,
        tag_overlay: Vec<ColumnTagOverlay>,
        tagged_columns: Vec<(ColumnAt, usize)>,
    },
    /// A catalog of the tagged columns alone; a two-part table name is
    /// placed in `default_database`.
    ColumnTags {
        tag_overlay: Vec<ColumnTagOverlay>,
        default_database: Option<String>,
    },
}

impl SessionCatalogs {
    /// The catalog at `uri` (any scheme [`resolve_uri`] reads), with
    /// `tag_overlay`'s tags added, indexed under `dialect` (Snowflake when
    /// `None`) with the provider named `provider_name`, else the one the
    /// snapshot names.
    pub fn load(
        uri: &str,
        provider_name: Option<&str>,
        tag_overlay: &[ColumnTagOverlay],
        dialect: &Option<DialectRef>,
    ) -> Result<Self, String> {
        let mut snapshot = read_catalog_snapshot(uri)?;
        let named = provider_name.map(catalog_provider_named).transpose()?;
        let provider = index_provider(named, snapshot.provider.as_deref());
        let tagged_columns = {
            let _dialect = lexega_core::Engine::recognition().apply_dialect(dialect);
            add_column_tags(&mut snapshot, tag_overlay, &*provider)
        };
        let source = CatalogSource::Snapshot {
            snapshot: Arc::new(snapshot),
            tag_overlay: tag_overlay.to_vec(),
            tagged_columns,
        };
        let loaded = build_index(&source, &provider, dialect_key(dialect), dialect)
            .map_err(|e| format!("Catalog index error for '{}': {}", uri, e))?;
        Ok(Self::loaded(source, provider, loaded, dialect))
    }

    /// A catalog of only the columns `tag_overlay` tags, with their tags,
    /// indexed as [`Self::load`] indexes one.
    pub fn from_column_tags(
        tag_overlay: &[ColumnTagOverlay],
        default_database: Option<&str>,
        provider_name: Option<&str>,
        dialect: &Option<DialectRef>,
    ) -> Result<Self, String> {
        let source = CatalogSource::ColumnTags {
            tag_overlay: tag_overlay.to_vec(),
            default_database: default_database.map(str::to_string),
        };
        // A catalog made from tags names no provider of its own.
        let named = provider_name.map(catalog_provider_named).transpose()?;
        let provider = index_provider(named, None);
        let loaded = build_index(&source, &provider, dialect_key(dialect), dialect)
            .map_err(|e| format!("Synthesized catalog index error: {}", e))?;
        Ok(Self::loaded(source, provider, loaded, dialect))
    }

    fn loaded(
        source: CatalogSource,
        provider: Arc<dyn CatalogProvider>,
        loaded: CatalogIndex,
        dialect: &Option<DialectRef>,
    ) -> Self {
        Self {
            source,
            provider,
            loaded_under: dialect_key(dialect).to_string(),
            loaded: Arc::new(loaded),
            others: Vec::new(),
            current: None,
        }
    }

    /// Make `dialect`'s index the one [`Self::current`] hands out, building
    /// it the first time that dialect is selected.
    pub fn select(&mut self, dialect: &Option<DialectRef>) {
        let name = dialect_key(dialect);
        if name == self.loaded_under {
            self.current = None;
            return;
        }
        let at = match self.others.iter().position(|(other, _)| other == name) {
            Some(at) => at,
            None => {
                let index = build_index(&self.source, &self.provider, &self.loaded_under, dialect)
                    .map(Arc::new)
                    .map_err(|e| {
                        format!(
                            "Failed to load catalog: Catalog index error under {}: {}",
                            name, e
                        )
                    });
                self.others.push((name.to_string(), index));
                self.others.len() - 1
            }
        };
        self.current = Some(at);
    }

    /// The index of the dialect last selected (the one loaded under until
    /// another is), or why it cannot be built.
    pub fn current(&self) -> Result<&Arc<CatalogIndex>, String> {
        match self.current.and_then(|at| self.others.get(at)) {
            Some((_, index)) => index.as_ref().map_err(String::clone),
            None => Ok(&self.loaded),
        }
    }
}

/// The name a dialect's index is kept under; `None` reads as Snowflake.
fn dialect_key(dialect: &Option<DialectRef>) -> &str {
    dialect.as_ref().map_or("snowflake", |d| d.name())
}

/// `source`'s catalog indexed under `dialect` with `provider`, its column
/// tags matched there too; `loaded_under` is the dialect a catalog's tags
/// were added under when it was read.
fn build_index(
    source: &CatalogSource,
    provider: &Arc<dyn CatalogProvider>,
    loaded_under: &str,
    dialect: &Option<DialectRef>,
) -> Result<CatalogIndex, CatalogError> {
    let _dialect = lexega_core::Engine::recognition().apply_dialect(dialect);
    let snapshot = match source {
        CatalogSource::Snapshot {
            snapshot,
            tag_overlay,
            tagged_columns,
        } => {
            if tag_overlay.is_empty() || dialect_key(dialect) == loaded_under {
                Arc::clone(snapshot)
            } else {
                let mut tagged = CatalogSnapshot::clone(snapshot);
                remove_added_tags(&mut tagged, tagged_columns);
                tagged.enrich_column_tags(tag_overlay, &**provider);
                Arc::new(tagged)
            }
        }
        CatalogSource::ColumnTags {
            tag_overlay,
            default_database,
        } => Arc::new(CatalogSnapshot::from_source_column_tags(
            tag_overlay,
            default_database.as_deref(),
            &**provider,
        )),
    };
    CatalogIndex::from_snapshot_with_provider(snapshot, Arc::clone(provider))
}

/// A column's place in a catalog: database, schema, table and column, each
/// by its position in its parent.
type ColumnAt = (usize, usize, usize, usize);

/// Every column of `snapshot`, with its place.
fn columns_of(snapshot: &CatalogSnapshot) -> impl Iterator<Item = (ColumnAt, &CatalogColumn)> {
    snapshot
        .databases
        .iter()
        .enumerate()
        .flat_map(|(d, database)| {
            database
                .schemas
                .iter()
                .enumerate()
                .flat_map(move |(s, schema)| {
                    schema
                        .tables
                        .iter()
                        .enumerate()
                        .flat_map(move |(t, table)| {
                            table
                                .columns
                                .iter()
                                .enumerate()
                                .map(move |(c, column)| ((d, s, t, c), column))
                        })
                })
        })
}

/// Adds `tag_overlay`'s tags to `snapshot` as an index built with
/// `provider` under the thread's dialect finds names. Returns each column a
/// tag was added to, with how many tags it had before: matching only
/// appends.
fn add_column_tags(
    snapshot: &mut CatalogSnapshot,
    tag_overlay: &[ColumnTagOverlay],
    provider: &dyn CatalogProvider,
) -> Vec<(ColumnAt, usize)> {
    if tag_overlay.is_empty() {
        return Vec::new();
    }
    let before: Vec<usize> = columns_of(snapshot)
        .map(|(_, column)| column.tags.len())
        .collect();
    snapshot.enrich_column_tags(tag_overlay, provider);
    columns_of(snapshot)
        .zip(before)
        .filter(|((_, column), before)| column.tags.len() > *before)
        .map(|((at, _), before)| (at, before))
        .collect()
}

/// Gives each column of `tagged_columns` back the tags it had before
/// [`add_column_tags`] added to it.
fn remove_added_tags(snapshot: &mut CatalogSnapshot, tagged_columns: &[(ColumnAt, usize)]) {
    for &((d, s, t, c), before) in tagged_columns {
        let column = snapshot
            .databases
            .get_mut(d)
            .and_then(|database| database.schemas.get_mut(s))
            .and_then(|schema| schema.tables.get_mut(t))
            .and_then(|table| table.columns.get_mut(c));
        if let Some(column) = column {
            column.tags.truncate(before);
        }
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

        // Azure CLI requires a file, so stage the content in one.
        let staged = StagedUpload::new()?;
        let staged_file = staged.write("report", content.as_bytes())?;

        // `az storage blob upload --file` takes a path string; surface a
        // typed error when the system temp dir resolves to non-UTF-8 bytes
        // rather than crashing inside the argv builder.
        let temp_file_str = staged_file.to_str().ok_or_else(|| {
            format!(
                "Temp file path is not valid UTF-8 (cannot pass to `az`): {}",
                staged_file.display()
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

/// What [`write_new_uri`] found at its URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewObject {
    /// Nothing was there, and the content now is.
    Written,
    /// Something was already there, and is left as it was.
    AlreadyThere,
}

/// Write `content` at `uri` only where nothing is there yet: an object or
/// file already at `uri` is never replaced. The schemes are those of
/// [`write_uri`]; S3 takes a conditional write, Cloud Storage `cp -n`, and
/// Azure an upload that does not overwrite.
pub fn write_new_uri(uri: &str, content: &str) -> Result<NewObject, Box<dyn std::error::Error>> {
    if is_web_uri(uri) {
        return Err(format!("'{}' is a web address; nothing is written to one", uri).into());
    }
    let staged_path = |staged: &StagedUpload| -> Result<String, Box<dyn std::error::Error>> {
        let file = staged.write("object", content.as_bytes())?;
        Ok(file
            .to_str()
            .ok_or_else(|| {
                format!(
                    "Temp file path is not valid UTF-8 (cannot pass to the CLI): {}",
                    file.display()
                )
            })?
            .to_string())
    };

    if let Some(path) = uri.strip_prefix("s3://") {
        let (bucket, key) = path
            .split_once('/')
            .ok_or_else(|| format!("Invalid S3 URI '{}': expected s3://bucket/key", uri))?;
        let staged = StagedUpload::new()?;
        let file = staged_path(&staged)?;
        let output = Command::new("aws")
            .args([
                "s3api",
                "put-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--body",
                &file,
                "--if-none-match",
                "*",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'aws s3api put-object'. Is AWS CLI installed? {}",
                    e
                )
            })?;
        if output.status.success() {
            return Ok(NewObject::Written);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("PreconditionFailed") || stderr.contains("(412)") {
            return Ok(NewObject::AlreadyThere);
        }
        return Err(format!("aws s3api put-object failed for '{}': {}", uri, stderr).into());
    }

    if uri.starts_with("gs://") {
        let staged = StagedUpload::new()?;
        let file = staged_path(&staged)?;
        let output = Command::new("gsutil")
            .args(["cp", "-n", &file, uri])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'gsutil cp'. Is Google Cloud SDK installed? {}",
                    e
                )
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(format!("gsutil cp -n failed for '{}': {}", uri, stderr).into());
        }
        return Ok(if stderr.contains("Skipping existing item") {
            NewObject::AlreadyThere
        } else {
            NewObject::Written
        });
    }

    if let Some(path) = uri.strip_prefix("az://") {
        let (container, blob_path) = path.split_once('/').ok_or_else(|| {
            format!(
                "Invalid Azure URI '{}': expected az://container/blob/path",
                uri
            )
        })?;
        let staged = StagedUpload::new()?;
        let file = staged_path(&staged)?;
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
                &file,
                "--overwrite",
                "false",
                "--no-progress",
            ])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute 'az storage blob upload'. Is Azure CLI installed? {}",
                    e
                )
            })?;
        if output.status.success() {
            return Ok(NewObject::Written);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("BlobAlreadyExists") || stderr.contains("already exists") {
            return Ok(NewObject::AlreadyThere);
        }
        return Err(format!("az storage blob upload failed for '{}': {}", uri, stderr).into());
    }

    let path = Path::new(uri);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory '{}': {}", parent.display(), e))?;
        }
    }
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(content.as_bytes())
                .map_err(|e| format!("Failed to write '{}': {}", uri, e))?;
            Ok(NewObject::Written)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(NewObject::AlreadyThere),
        Err(e) => Err(format!("Failed to write '{}': {}", uri, e).into()),
    }
}

/// Whether `uri` is a web address, which inputs are fetched from and
/// outputs are never written to.
pub(crate) fn is_web_uri(uri: &str) -> bool {
    ["https://", "http://"].iter().any(|scheme| {
        uri.get(..scheme.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(scheme))
    })
}

/// A private directory for the files a command reads or writes by path. It
/// has an unpredictable name and only its owner can enter it, and the files
/// in it are created exclusively, so a link planted at a name is never
/// followed. It and what it holds are removed when this is dropped, whether
/// the command succeeded or not.
pub(crate) struct StagedUpload {
    dir: PathBuf,
}

impl StagedUpload {
    pub(crate) fn new() -> std::io::Result<Self> {
        use std::hash::{BuildHasher, Hasher};

        let root = std::env::temp_dir();
        for _ in 0..16 {
            // `RandomState` is seeded from the system's randomness.
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u32(std::process::id());
            let dir = root.join(format!("lexega-upload-{:016x}", hasher.finish()));
            match private_directory().create(&dir) {
                Ok(()) => return Ok(StagedUpload { dir }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no private staging directory could be made",
        ))
    }

    /// Where a file called `name` is, or will be made by a command.
    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Make the file `name` holding `content`; it must not exist.
    pub(crate) fn write(&self, name: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        use std::io::Write;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let path = self.path(name);
        options.open(&path)?.write_all(content)?;
        Ok(path)
    }
}

/// A builder of a directory only its owner can use, where the platform has
/// such modes.
#[cfg(unix)]
fn private_directory() -> fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

#[cfg(not(unix))]
fn private_directory() -> fs::DirBuilder {
    fs::DirBuilder::new()
}

impl Drop for StagedUpload {
    fn drop(&mut self) {
        // Nothing to report: a directory already gone is the aim.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The method of an HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// One HTTP request.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    pub method: HttpMethod,
    pub url: &'a str,
    /// Header fields, each a name and its value.
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    /// The longest the whole exchange may take; `None` sets no limit.
    pub timeout: Option<std::time::Duration>,
    /// The most body bytes read before reading fails; `None` sets no limit.
    pub body_limit: Option<u64>,
}

/// Makes HTTP requests. TLS is rustls's, certificates are checked against
/// the operating system's store, and requests go through the proxy that
/// `ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` names (HTTP or SOCKS), except
/// for the hosts `NO_PROXY` lists and for this machine, which is always
/// reached directly. Redirects are not followed. Clones share one pool of
/// kept-alive connections.
#[derive(Clone)]
pub struct HttpClient {
    /// Through the environment's proxy, when one is named.
    proxied: ureq::Agent,
    /// For this machine: a proxy would carry its traffic elsewhere.
    direct: ureq::Agent,
}

/// How long making a connection may take.
const HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    pub fn new() -> Self {
        Self::with_proxy(ureq::Proxy::try_from_env())
    }

    fn with_proxy(proxy: Option<ureq::Proxy>) -> Self {
        HttpClient {
            proxied: Self::agent(proxy),
            direct: Self::agent(None),
        }
    }

    fn agent(proxy: Option<ureq::Proxy>) -> ureq::Agent {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::PlatformVerifier)
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .build();
        ureq::Agent::config_builder()
            .tls_config(tls)
            .proxy(proxy)
            // A status is the caller's to judge.
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_connect(Some(HTTP_CONNECT_TIMEOUT))
            .user_agent(concat!("lexega/", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent()
    }

    /// Send `request` and return once the response's status and headers
    /// have arrived.
    pub fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse, String> {
        let agent = if is_this_machine(request.url) {
            &self.direct
        } else {
            &self.proxied
        };
        let response = match request.method {
            HttpMethod::Get => self.without_body(agent.get(request.url), request),
            HttpMethod::Delete => self.without_body(agent.delete(request.url), request),
            HttpMethod::Post => self.with_body(agent.post(request.url), request),
            HttpMethod::Put => self.with_body(agent.put(request.url), request),
            HttpMethod::Patch => self.with_body(agent.patch(request.url), request),
        }
        .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let (parts, body) = response.into_parts();
        let body = match request.body_limit {
            Some(limit) => body.into_with_config().limit(limit).reader(),
            None => body.into_reader(),
        };
        Ok(HttpResponse {
            status,
            headers: parts.headers,
            body,
        })
    }

    fn without_body(
        &self,
        mut builder: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
        request: &HttpRequest<'_>,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        // Names go out as written: some servers compare them by case.
        for (name, value) in request.headers {
            builder = builder.header_raw(name, value.as_bytes());
        }
        if let Some(timeout) = request.timeout {
            builder = builder.config().timeout_global(Some(timeout)).build();
        }
        builder.call()
    }

    fn with_body(
        &self,
        mut builder: ureq::RequestBuilder<ureq::typestate::WithBody>,
        request: &HttpRequest<'_>,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        // Names go out as written: some servers compare them by case.
        for (name, value) in request.headers {
            builder = builder.header_raw(name, value.as_bytes());
        }
        if let Some(timeout) = request.timeout {
            builder = builder.config().timeout_global(Some(timeout)).build();
        }
        builder.send(request.body.unwrap_or_default())
    }
}

/// Whether `url` names this machine: `localhost` or a loopback address.
fn is_this_machine(url: &str) -> bool {
    let Ok(uri) = url.parse::<ureq::http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// One client for the process, so its requests share kept-alive
/// connections.
pub fn shared_http_client() -> &'static HttpClient {
    static CLIENT: std::sync::OnceLock<HttpClient> = std::sync::OnceLock::new();
    CLIENT.get_or_init(HttpClient::new)
}

/// A response whose status and headers have arrived. Reading it reads the
/// body as it arrives.
pub struct HttpResponse {
    pub status: u16,
    headers: ureq::http::HeaderMap,
    body: ureq::BodyReader<'static>,
}

impl HttpResponse {
    /// The value of the header `name`, matched without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The whole body.
    pub fn read_body(mut self) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let mut body = Vec::new();
        self.body
            .read_to_end(&mut body)
            .map_err(|e| format!("cannot read the response body: {}", e))?;
        Ok(body)
    }
}

impl std::io::Read for HttpResponse {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.body.read(buf)
    }
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
        let content = fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read variable file '{}': {}", file_path, e))?;
        let content = strip_bom(&content);
        let not_an_object = || {
            format!(
                "Variable file '{}' must be an object of NAME: value pairs",
                file_path
            )
        };

        // Detect format by extension
        let lower = file_path.to_lowercase();
        if lower.ends_with(".json") {
            let vars: serde_json::Value = serde_json::from_str(content)
                .map_err(|e| format!("Variable file '{}' is not valid JSON: {}", file_path, e))?;
            let serde_json::Value::Object(map) = vars else {
                return Err(not_an_object().into());
            };
            for (key, value) in map {
                context.set(key, value, VariableSource::VarFile);
            }
        } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            let vars: serde_yaml_ng::Value = serde_yaml_ng::from_str(content)
                .map_err(|e| format!("Variable file '{}' is not valid YAML: {}", file_path, e))?;
            let serde_yaml_ng::Value::Mapping(map) = vars else {
                return Err(not_an_object().into());
            };
            for (key, value) in map {
                let serde_yaml_ng::Value::String(name) = key else {
                    let written = serde_yaml_ng::to_string(&key).unwrap_or_default();
                    return Err(format!(
                        "Variable file '{}' has a name that is not a string: {}",
                        file_path,
                        written.trim_end()
                    )
                    .into());
                };
                // Convert YAML value to JSON value
                context.set(name, yaml_to_json(value), VariableSource::VarFile);
            }
        } else {
            return Err(format!(
                "Variable file '{}' must be a .json, .yaml or .yml file holding an object of NAME: value pairs",
                file_path
            )
            .into());
        }
    }

    // Load SnowSQL config `[variables]` sections (priority below --var/--var-file,
    // above .lexega.toml; precedence resolved by VariableSource).
    for config_path in snowsql_configs {
        let read = context.load_from_snowsql_config(std::path::Path::new(config_path))?;
        if read == SnowsqlConfigRead::NoVariablesSection {
            eprintln!(
                "Warning: SnowSQL config '{}' has no [variables] section: it supplies no variables",
                config_path
            );
        }
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
    let Some((config_path, config)) = discover_lexega_config()? else {
        return Ok(None);
    };
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
    Ok(settings)
}

/// The `.lexega.toml` nearest the current directory, walking up, and what
/// it says; `None` where there is none. An unreadable or malformed file is
/// an error.
fn discover_lexega_config() -> Result<Option<(std::path::PathBuf, LexegaConfig)>, String> {
    let mut current =
        std::env::current_dir().map_err(|e| format!("Failed to get current directory: {}", e))?;
    loop {
        let config_path = current.join(".lexega.toml");
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;
            let config: LexegaConfig = toml::from_str(&content)
                .map_err(|e| format!("Failed to parse {}: {}", config_path.display(), e))?;
            return Ok(Some((config_path, config)));
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

/// The database and schema a table named without them is looked for in,
/// until the script's own `USE` or `SET search_path` changes them:
/// `--default-schema`'s value (`flag`), else `.lexega.toml`'s `[session]
/// default_schema`; each `SCHEMA` or `DATABASE.SCHEMA`. `None` where
/// neither gives one: a dbt profile's, else the dialect's default, holds.
pub fn resolve_default_schema(flag: Option<&str>) -> Result<Option<SessionContext>, String> {
    let named = |written: &str, from: &str| {
        SessionContext::named(written).ok_or_else(|| {
            format!("{from} takes SCHEMA or DATABASE.SCHEMA; '{written}' is neither")
        })
    };
    if let Some(written) = flag {
        return named(written, "--default-schema").map(Some);
    }
    let Some((config_path, config)) = discover_lexega_config()? else {
        return Ok(None);
    };
    config
        .session
        .and_then(|session| session.default_schema)
        .map(|written| {
            named(
                &written,
                &format!("{}: [session] default_schema", config_path.display()),
            )
        })
        .transpose()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// A dbt project's path makes the file a macro file
    /// ([`macro_path_owner`]): it holds Jinja macro definitions, not
    /// statements. The project's root is as reports name it.
    MacroDirectory(MacroPathOwner),
    /// The entry is a symbolic link. A scan reads the files that live in
    /// the directory it was given, wherever a link in it points.
    SymbolicLink,
    /// A directory the scan could not list: it may hold SQL the run does
    /// not read.
    UnreadableDirectory,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::MacroDirectory(owner) => {
                let project = slash_separated(&owner.root().join(PROJECT_FILE));
                match owner {
                    MacroPathOwner::Project(_) => write!(f, "in a macro path of {project}")?,
                    MacroPathOwner::InstalledPackage(_) => {
                        write!(f, "in the macro path of a package {project} installs")?
                    }
                }
                write!(f, ": macro definitions, not statements")
            }
            SkipReason::SymbolicLink => {
                write!(f, "symbolic link: a directory scan does not follow links")
            }
            SkipReason::UnreadableDirectory => write!(f, "a directory the scan could not read"),
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

    /// The files and the skipped files in path order, whatever order the
    /// file system listed them in.
    fn in_path_order(mut self) -> Self {
        self.files.sort();
        self.skipped.sort_by(|a, b| a.path.cmp(&b.path));
        self
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

/// Absolute form of a file a scan will read (dunce strips `\\?\` on Windows).
pub(crate) fn absolute(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Names files by the path every report, decision and policy exception
/// names them by: from the run's one root, the root SARIF declares as
/// `%SRCROOT%`.
pub(crate) struct ReportedPaths {
    /// The working directory, absolute; `None` where it cannot be read.
    cwd: Option<PathBuf>,
    /// The root of the git repository the working directory is in, else
    /// the working directory; absolute.
    root: Option<PathBuf>,
}

impl ReportedPaths {
    pub(crate) fn new() -> Self {
        let cwd = std::env::current_dir().ok().map(|dir| absolute(&dir));
        let root = cwd.as_deref().map(|cwd| {
            super::git::repository_root_of(cwd)
                .map(|root| absolute(&root))
                .unwrap_or_else(|| cwd.to_path_buf())
        });
        Self { cwd, root }
    }

    /// The path `path` is reported by, `/`-separated and without `.` or
    /// `..` parts: its path from the run's root (the root of the git
    /// repository the working directory is in, as `review` names a changed
    /// file, else the working directory) when it lies under it, whatever
    /// repository or project of its own it is in; its absolute path
    /// otherwise. The path is read as written, then with its directory
    /// resolved; a symbolic link it names is never followed.
    pub(crate) fn name(&self, path: &Path) -> String {
        let (Some(cwd), Some(root)) = (self.cwd.as_deref(), self.root.as_deref()) else {
            return slash_separated(&lexically_normal(path));
        };
        let written = lexically_normal(&cwd.join(path));
        let resolved = match (written.parent(), written.file_name()) {
            (Some(dir), Some(name)) => Some(absolute(dir).join(name)),
            (None, _) | (_, None) => None,
        };
        let under = |file: &Path| {
            file.strip_prefix(root)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(Path::to_path_buf)
        };
        let shown = under(&written)
            .or_else(|| resolved.as_deref().and_then(under))
            .unwrap_or(written);
        slash_separated(&shown)
    }
}

/// `path` as text with `/` between its parts on every platform.
fn slash_separated(path: &Path) -> String {
    let text = path.display().to_string();
    if std::path::MAIN_SEPARATOR == '/' {
        text
    } else {
        text.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

/// A directory walk's `entry` under `root`, or none, with the directory it
/// could not read listed as skipped.
fn walked(
    entry: walkdir::Result<walkdir::DirEntry>,
    root: &Path,
    found: &mut FoundFiles,
) -> Option<walkdir::DirEntry> {
    entry
        .map_err(|e| {
            let unread = e.path().unwrap_or(root).to_path_buf();
            found.skip(unread, SkipReason::UnreadableDirectory);
        })
        .ok()
}

/// The entries of `dir`, or none, with `dir` listed as skipped, where it
/// cannot be read.
fn list_directory(dir: &Path, found: &mut FoundFiles) -> Vec<fs::DirEntry> {
    match fs::read_dir(dir).and_then(|entries| entries.collect::<Result<Vec<_>, _>>()) {
        Ok(entries) => entries,
        Err(_) => {
            found.skip(dir.to_path_buf(), SkipReason::UnreadableDirectory);
            Vec::new()
        }
    }
}

/// The SQL files under each of `paths`, in their order: each a glob
/// pattern, a directory or a single file.
///
/// A scan never follows a symbolic link it comes across — the link is listed
/// as skipped — so it reads nothing outside the directory it was given. A
/// path named outright is the caller's own choice and is followed. A
/// directory scanned recursively lists as skipped the macro files
/// ([`macro_path_owner`]) of the dbt projects `projects`, the run's
/// reading, holds. Every project a path reaches, those above it and those
/// its walk meets, is read before any file is sorted, so the order of
/// `paths` does not matter.
pub fn collect_sql_files(
    paths: &[&str],
    recursive: bool,
    projects: &ProjectsOnDisk,
) -> Vec<FoundFiles> {
    let walks: Vec<(FoundFiles, Vec<WalkedFile>)> = paths
        .iter()
        .map(|path| walk_sql_files(path, recursive, projects))
        .collect();
    let names = ReportedPaths::new();
    walks
        .into_iter()
        .map(|(mut found, walked)| {
            for WalkedFile { path, file } in walked {
                match macro_path_owner(projects, &file) {
                    Some(owner) => {
                        let owner = reported_owner(owner, &names);
                        found.skip(path, SkipReason::MacroDirectory(owner));
                    }
                    None => found.files.push(file),
                }
            }
            found.in_path_order()
        })
        .collect()
}

/// `owner` with its project's root as reports name it ([`ReportedPaths`]).
fn reported_owner(owner: MacroPathOwner, names: &ReportedPaths) -> MacroPathOwner {
    let reported = |root: &Path| {
        let file = PathBuf::from(names.name(&root.join(PROJECT_FILE)));
        file.parent().map(Path::to_path_buf).unwrap_or_default()
    };
    match owner {
        MacroPathOwner::Project(root) => MacroPathOwner::Project(reported(&root)),
        MacroPathOwner::InstalledPackage(root) => MacroPathOwner::InstalledPackage(reported(&root)),
    }
}

/// A SQL file a recursive walk met: the path walked, and the file's
/// absolute path.
struct WalkedFile {
    path: PathBuf,
    file: PathBuf,
}

/// The SQL files under `path`, and apart from them the files a recursive
/// walk of it met, to be sorted once every path is walked; each
/// `dbt_project.yml` above the walked directory or met by the walk is read
/// into `projects`.
fn walk_sql_files(
    path: &str,
    recursive: bool,
    projects: &ProjectsOnDisk,
) -> (FoundFiles, Vec<WalkedFile>) {
    let mut found = FoundFiles::default();
    let mut walked_files = Vec::new();
    let path_obj = Path::new(path);

    if path.contains('*') || path.contains('?') {
        match glob::glob(path) {
            Ok(paths) => {
                for entry in paths {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            found.skip(e.path().to_path_buf(), SkipReason::UnreadableDirectory);
                            continue;
                        }
                    };
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
            for dir in absolute(path_obj).ancestors().skip(1) {
                projects.project_at(dir);
            }
            for entry in WalkDir::new(path).follow_links(false) {
                let Some(entry) = walked(entry, path_obj, &mut found) else {
                    continue;
                };
                let entry_path = entry.path();
                if entry_path.file_name() == Some(std::ffi::OsStr::new(PROJECT_FILE)) {
                    if let Some(dir) = entry_path.parent() {
                        projects.project_at(&absolute(dir));
                    }
                    continue;
                }
                if !has_sql_extension(entry_path) {
                    continue;
                }
                let file_type = entry.file_type();
                if file_type.is_symlink() {
                    found.skip(entry_path.to_path_buf(), SkipReason::SymbolicLink);
                } else if file_type.is_file() {
                    walked_files.push(WalkedFile {
                        path: entry_path.to_path_buf(),
                        file: absolute(entry_path),
                    });
                }
            }
        } else {
            for entry in list_directory(path_obj, &mut found) {
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

    (found, walked_files)
}

/// Whether `path` is a Python source or notebook file.
pub(crate) fn has_embedded_extension(path: &Path) -> bool {
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
            for entry in WalkDir::new(path).follow_links(false) {
                let Some(entry) = walked(entry, path_obj, &mut found) else {
                    continue;
                };
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
        } else {
            for entry in list_directory(path_obj, &mut found) {
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

    found.in_path_order()
}

/// The strict mode a run uses: `flag`, the `--strict` option as given, or
/// else `LEXEGA_STRICT`. Exit with code 1 when the variable names no mode.
pub fn strict_mode_or_exit(flag: Option<lexega_core::StrictMode>) -> lexega_core::StrictMode {
    flag.unwrap_or_else(|| {
        lexega_core::strict_mode_from_env().unwrap_or_else(|value| {
            eprintln!(
                "Error: LEXEGA_STRICT='{}' is not a strict mode (off|strict|pedantic)",
                value
            );
            std::process::exit(1);
        })
    })
}

/// The rules a run evaluates: the built-in rules when `builtins`, with the
/// custom rules `custom` holds, loaded from the file it names, layered over
/// them. Says on stderr what each custom entry under a former id does: it
/// applies to the built-in rule that absorbed the id, or, with no built-in
/// rules, is reported under that rule's id.
pub fn rule_corpus(
    custom: Option<(&str, lexega_core::rules::LoadedRuleset)>,
    builtins: bool,
) -> Result<Vec<lexega_core::rules::Rule>, lexega_core::rules::MergeError> {
    let Some((uri, loaded)) = custom else {
        return lexega_core::rules::build_v1_rule_corpus(Default::default(), builtins);
    };
    let overrides = loaded.former_id_overrides().to_vec();
    let corpus = lexega_core::rules::build_v1_rule_corpus(loaded, builtins)?;
    for entry in &overrides {
        if builtins {
            eprintln!(
                "{} is now {}; the override in {} applies to it",
                entry.former_id, entry.canonical_id, uri
            );
        } else {
            eprintln!(
                "{} is now {}; the rule in {} is reported as {}",
                entry.former_id, entry.canonical_id, uri, entry.canonical_id
            );
        }
    }
    Ok(corpus)
}

/// Load a customer `--custom-rules` file as a classified v1 rule
/// corpus: the one rule-file schema, written as YAML (`.yaml`, `.yml`),
/// JSON (`.json`) or TOML (`.toml`) as the extension says. The returned
/// [`lexega_core::rules::LoadedRuleset`] carries both full rules and
/// partial overrides — built-in merging, partial-override resolution,
/// and `--no-builtin` handling happen at the CLI seam via [`rule_corpus`].
pub fn load_custom_rules(uri: &str) -> Result<lexega_core::rules::LoadedRuleset, String> {
    use lexega_core::rules::{load_v1_rules, load_v1_rules_from_json, load_v1_rules_from_toml};

    let lower = uri.to_lowercase();
    let load: fn(&str) -> Result<_, _> = if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        load_v1_rules
    } else if lower.ends_with(".json") {
        |text| load_v1_rules_from_json(text.as_bytes())
    } else if lower.ends_with(".toml") {
        load_v1_rules_from_toml
    } else {
        return Err(
            "Custom rules file must have a .yaml, .yml, .json or .toml extension".to_string(),
        );
    };
    let content = resolve_uri(uri)
        .map_err(|e| format!("Failed to load custom rules from '{}': {}", uri, e))?;
    load(&content).map_err(|e| format!("Failed to parse v1 rules from '{}': {}", uri, e))
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_new_write_never_replaces_what_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("day/record.json");
        let uri = path.to_str().unwrap();
        assert_eq!(write_new_uri(uri, "first").unwrap(), NewObject::Written);
        assert_eq!(
            write_new_uri(uri, "second").unwrap(),
            NewObject::AlreadyThere
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        assert!(write_new_uri("https://example.com/x", "x").is_err());
    }
    use super::*;

    /// One table, declared with a quoted mixed-case name.
    const QUOTED_NAME_CATALOG: &str = r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": {"name": "MyTable", "case_sensitive": true}, "kind": "Table", "columns": [{"name": "ID", "data_type": "NUMBER", "nullable": false}]}]}]}]}"#;

    fn catalog_file() -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("catalog.json");
        fs::write(&path, QUOTED_NAME_CATALOG).expect("write catalog");
        let uri = path.to_str().expect("utf-8 path").to_string();
        (dir, uri)
    }

    /// Every tag on every column of `index`'s catalog.
    fn column_tags(index: &CatalogIndex) -> Vec<String> {
        index
            .snapshot()
            .databases
            .iter()
            .flat_map(|database| &database.schemas)
            .flat_map(|schema| &schema.tables)
            .flat_map(|table| &table.columns)
            .flat_map(|column| column.tags.iter().map(|tag| tag.tag_name.clone()))
            .collect()
    }

    #[test]
    fn every_dialects_index_shares_the_catalog_as_read() {
        let (_dir, uri) = catalog_file();
        let snowflake = resolve_dialect("snowflake");
        let mut catalogs =
            SessionCatalogs::load(&uri, None, &[], &snowflake).expect("catalog loads");
        let loaded = Arc::clone(catalogs.current().expect("loaded index"));

        catalogs.select(&resolve_dialect("databricks"));
        let databricks = Arc::clone(catalogs.current().expect("databricks index"));
        assert!(!Arc::ptr_eq(&loaded, &databricks));
        assert!(std::ptr::eq(loaded.snapshot(), databricks.snapshot()));

        catalogs.select(&snowflake);
        assert!(Arc::ptr_eq(
            &loaded,
            catalogs.current().expect("loaded index")
        ));
    }

    #[test]
    fn column_tags_are_matched_as_each_indexs_dialect_reads_names() {
        let (_dir, uri) = catalog_file();
        let overlay = [ColumnTagOverlay {
            full_ref: "analytics.public.mytable".to_string(),
            column: "id".to_string(),
            tag_names: vec!["pii".to_string()],
        }];
        // A tag lands where the dialect's index finds the table: Databricks
        // finds `mytable` as the catalog's `"MyTable"`, PostgreSQL does not.
        let postgresql = resolve_dialect("postgresql");
        let databricks = resolve_dialect("databricks");
        let mut catalogs =
            SessionCatalogs::load(&uri, None, &overlay, &postgresql).expect("catalog loads");
        for (dialect, found) in [
            (&postgresql, false),
            (&databricks, true),
            (&postgresql, false),
        ] {
            catalogs.select(dialect);
            let index = catalogs.current().expect("index");
            let _scope = lexega_core::Engine::recognition().apply_dialect(dialect);
            assert_eq!(
                index
                    .get_table_by_name("analytics", "public", "mytable")
                    .is_some(),
                found
            );
            let expected: &[&str] = if found { &["pii"] } else { &[] };
            assert_eq!(column_tags(index), expected);
        }
    }

    #[test]
    fn a_column_tag_is_matched_to_a_case_sensitive_name_as_the_index_finds_it() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("catalog.json");
        fs::write(&path, QUOTED_NAME_CATALOG.replace("MyTable", "MYTABLE")).expect("write catalog");
        let uri = path.to_str().expect("utf-8 path");
        let overlay = [ColumnTagOverlay {
            full_ref: "analytics.public.MYTABLE".to_string(),
            column: "id".to_string(),
            tag_names: vec!["pii".to_string()],
        }];
        for name in [
            "snowflake",
            "postgresql",
            "databricks",
            "mysql",
            "bigquery",
            "mssql",
        ] {
            let dialect = resolve_dialect(name);
            let catalogs =
                SessionCatalogs::load(uri, None, &overlay, &dialect).expect("catalog loads");
            let index = catalogs.current().expect("index");
            let _scope = lexega_core::Engine::recognition().apply_dialect(&dialect);
            assert!(
                index
                    .get_table_by_name("analytics", "public", "MYTABLE")
                    .is_some(),
                "{name}"
            );
            assert_eq!(column_tags(index), ["pii"], "{name}");
        }
    }

    #[test]
    fn with_column_tags_the_loaded_index_shares_the_sessions_catalog() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("catalog.json");
        fs::write(&path, QUOTED_NAME_CATALOG.replace("MyTable", "MYTABLE")).expect("write catalog");
        let uri = path.to_str().expect("utf-8 path");
        let overlay = [ColumnTagOverlay {
            full_ref: "analytics.public.mytable".to_string(),
            column: "id".to_string(),
            tag_names: vec!["pii".to_string()],
        }];
        let catalogs = SessionCatalogs::load(uri, None, &overlay, &resolve_dialect("snowflake"))
            .expect("catalog loads");
        let loaded = catalogs.current().expect("loaded index");
        assert_eq!(column_tags(loaded), ["pii"]);
        let CatalogSource::Snapshot { snapshot, .. } = &catalogs.source else {
            panic!("a catalog read from a file is a snapshot");
        };
        assert!(std::ptr::eq(&**snapshot, loaded.snapshot()));
    }

    #[test]
    fn another_dialects_index_holds_only_the_tags_it_matches() {
        let (_dir, uri) = catalog_file();
        // Databricks reads `"mytable"` as the catalog's `"MyTable"`;
        // Snowflake does not.
        let overlay = [ColumnTagOverlay {
            full_ref: "analytics.public.\"mytable\"".to_string(),
            column: "id".to_string(),
            tag_names: vec!["pii".to_string()],
        }];
        let databricks = resolve_dialect("databricks");
        let mut catalogs =
            SessionCatalogs::load(&uri, None, &overlay, &databricks).expect("catalog loads");
        assert_eq!(
            column_tags(catalogs.current().expect("loaded index")),
            ["pii"]
        );

        catalogs.select(&resolve_dialect("snowflake"));
        assert!(column_tags(catalogs.current().expect("snowflake index")).is_empty());

        catalogs.select(&databricks);
        assert_eq!(
            column_tags(catalogs.current().expect("loaded index")),
            ["pii"]
        );
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;

    #[test]
    fn this_machine_is_localhost_or_a_loopback_address() {
        for url in [
            "http://localhost:8080/mcp",
            "http://LOCALHOST/",
            "http://127.0.0.1/",
            "http://127.9.9.9:1/x",
            "http://[::1]:9000/mcp",
        ] {
            assert!(is_this_machine(url), "{url}");
        }
        for url in [
            "https://example.com/",
            "http://127.0.0.1.example.com/",
            "http://localhost.example.com/",
            "http://10.0.0.1/",
            "not a url",
        ] {
            assert!(!is_this_machine(url), "{url}");
        }
    }

    #[test]
    fn this_machine_is_reached_directly_whatever_the_proxy() {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                line.clear();
            }
            (&stream)
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        // A proxy that notes each connection and closes it.
        let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let proxied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&proxied);
        std::thread::spawn(move || {
            for stream in proxy_listener.incoming() {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let proxy = ureq::Proxy::new(&format!("http://127.0.0.1:{proxy_port}")).unwrap();
        let client = HttpClient::with_proxy(Some(proxy));
        let get = |url: &str| {
            client.send(&HttpRequest {
                method: HttpMethod::Get,
                url,
                headers: &[],
                body: None,
                timeout: Some(std::time::Duration::from_secs(10)),
                body_limit: None,
            })
        };
        let local = get(&format!("http://127.0.0.1:{port}/")).expect("reached directly");
        assert_eq!(local.read_body().unwrap(), b"ok");
        assert_eq!(proxied.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(get("http://lexega.invalid/").is_err());
        assert_eq!(
            proxied.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "another host goes through the proxy"
        );
    }
}
