// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Catalog command handler.
//!
//! Handles catalog operations: pull (generate snapshot), inspect (show summary), diff (compare snapshots).
//!
//! Functions:
//! - handle_catalog_command
//! - resolve_default_catalog_sidecar
//! - maybe_rebuild_go_sidecar

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use lexega_core::catalog;

use super::io::resolve_uri;
use super::usage::print_catalog_usage;

fn resolve_default_catalog_sidecar(provider_name: Option<&str>) -> String {
    let base_name = provider_name
        .and_then(lexega_core::catalog_provider_by_name)
        .unwrap_or_else(lexega_core::default_catalog_provider)
        .sidecar_binary()
        .to_string();

    let sidecar_exe = if cfg!(windows) {
        if base_name.ends_with(".exe") {
            base_name
        } else {
            format!("{base_name}.exe")
        }
    } else {
        base_name
    };

    // 1) Prefer a sibling binary next to the running executable (best for packaged installs).
    if let Ok(exe_path) = env::current_exe() {
        let sibling = exe_path.with_file_name(&sidecar_exe);
        if sibling.is_file() {
            return sibling.to_string_lossy().to_string();
        }
    }

    // 2) In development builds, prefer the Go sidecar source beside this crate.
    //    This uses CARGO_MANIFEST_DIR which embeds the build machine's absolute
    //    path into the binary — only include it in debug builds.
    //    The module directory is named after the sidecar binary's base name
    //    (e.g. `sidecars/lexega-sf-catalog/` for Snowflake,
    //    `sidecars/lexega-mssql-catalog/` for SQL Server), so each provider's
    //    sidecar lives in its own Go module.
    #[cfg(debug_assertions)]
    {
        // Module dir is the binary's base name (no `.exe` suffix on Windows).
        let module_dir_name = sidecar_exe.strip_suffix(".exe").unwrap_or(&sidecar_exe);
        let workspace_sidecar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("sidecars")
            .join(module_dir_name)
            .join(&sidecar_exe);
        if workspace_sidecar
            .parent()
            .is_some_and(|p| p.join("go.mod").is_file())
        {
            return workspace_sidecar.to_string_lossy().to_string();
        }
    }

    // 3) Fall back to PATH.
    sidecar_exe
}

/// Catalog providers Lexega ships a first-party `catalog pull` extractor for.
/// Other registered providers (see `builtin_catalog_provider_names`) can still
/// analyze a supplied snapshot, but `pull` needs an external `--sidecar`. This
/// list feeds the help text and the not-found error message — it is never the
/// gate (a user may install their own extractor on PATH for any provider).
pub(crate) const BUNDLED_PULL_PROVIDERS: &[&str] = &["snowflake", "databricks", "mssql"];

/// Whether a resolved catalog sidecar can actually be run: a concrete file, a
/// not-yet-built binary inside a Go module (built on demand by
/// `maybe_rebuild_go_sidecar`), or a bare name resolvable on PATH.
fn catalog_sidecar_is_runnable(sidecar: &str) -> bool {
    let p = Path::new(sidecar);

    // A concrete path (absolute, or relative with a separator).
    if p.is_absolute() || p.components().count() > 1 {
        if p.is_file() {
            return true;
        }
        // A sidecar inside a Go module is buildable on demand, so treat it as
        // runnable even before the first build.
        return p.parent().is_some_and(|dir| dir.join("go.mod").is_file());
    }

    // Bare name: look it up on PATH.
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            if dir.join(sidecar).is_file() {
                return true;
            }
        }
    }
    false
}

fn maybe_rebuild_go_sidecar(sidecar: &str) -> Result<(), String> {
    use std::time::SystemTime;

    let sidecar_path = PathBuf::from(sidecar);

    // If it's not a concrete path, it's probably coming from PATH; don't guess.
    if !sidecar_path.is_absolute() {
        return Ok(());
    }

    let Some(module_dir) = sidecar_path.parent() else {
        return Ok(());
    };

    // Only auto-build when the sidecar lives inside a Go module (go.mod present).
    if !module_dir.join("go.mod").is_file() {
        return Ok(());
    }

    fn newest_go_source_mtime(dir: &Path) -> Option<SystemTime> {
        fn visit_dir(dir: &Path, newest: &mut Option<SystemTime>) {
            let entries = match fs::read_dir(dir) {
                Ok(v) => v,
                Err(_) => return,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Keep the walk tight and deterministic.
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        if name == ".git" || name == "vendor" || name == "target" {
                            continue;
                        }
                    }
                    visit_dir(&path, newest);
                    continue;
                }

                let is_go = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("go"));
                let is_go_mod_or_sum = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n == "go.mod" || n == "go.sum");

                if !is_go && !is_go_mod_or_sum {
                    continue;
                }

                if let Ok(m) = fs::metadata(&path).and_then(|m| m.modified()) {
                    if newest.is_none_or(|cur| m > cur) {
                        *newest = Some(m);
                    }
                }
            }
        }

        let mut newest: Option<SystemTime> = None;
        visit_dir(dir, &mut newest);
        newest
    }

    let sidecar_mtime = fs::metadata(&sidecar_path).and_then(|m| m.modified()).ok();
    let newest_src = newest_go_source_mtime(module_dir);

    let needs_rebuild = match (sidecar_mtime, newest_src) {
        (None, Some(_)) => true,
        (Some(bin), Some(src)) => src > bin,
        // If we can't determine timestamps, be conservative and don't rebuild.
        _ => false,
    };

    if !needs_rebuild {
        return Ok(());
    }

    eprintln!(
        "Building catalog sidecar (Go): {}",
        sidecar_path.to_string_lossy()
    );

    let status = Command::new("go")
        .current_dir(module_dir)
        .arg("build")
        .arg("-o")
        .arg(&sidecar_path)
        .arg(".")
        .status()
        .map_err(|e| format!("Failed to run 'go build' for sidecar: {e}"))?;

    if !status.success() {
        return Err(format!(
            "Go sidecar build failed with exit code {:?}",
            status.code()
        ));
    }

    Ok(())
}

pub fn handle_catalog_command(args: &[String]) {
    // Check for help flag first
    if args.len() >= 3 && matches!(args[2].as_str(), "-h" | "--help" | "help") {
        print_catalog_usage(&args[0]);
        return;
    }

    if args.len() < 3 {
        print_catalog_usage(&args[0]);
        process::exit(1);
    }

    /// Load a catalog snapshot from a URI (local path or cloud storage).
    fn load_catalog_from_uri(uri: &str) -> Result<catalog::CatalogSnapshot, String> {
        let content = resolve_uri(uri).map_err(|e| e.to_string())?;

        // Detect format by extension or content
        let is_yaml = uri.ends_with(".yaml")
            || uri.ends_with(".yml")
            || content.trim_start().starts_with("schema_version:");

        let snapshot: catalog::CatalogSnapshot = if is_yaml {
            serde_yaml_ng::from_str(&content).map_err(|e| format!("YAML parse error: {e}"))?
        } else {
            serde_json::from_str(&content).map_err(|e| format!("JSON parse error: {e}"))?
        };

        snapshot.validate_version().map_err(|e| e.to_string())?;
        Ok(snapshot)
    }

    match args[2].as_str() {
        "-h" | "--help" | "help" => {
            print_catalog_usage(&args[0]);
        }
        "inspect" => {
            if args.len() < 4 {
                eprintln!("Error: catalog inspect requires a file path or URI");
                print_catalog_usage(&args[0]);
                process::exit(1);
            }

            let uri = &args[3];
            let snapshot = match load_catalog_from_uri(uri) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: failed to load snapshot: {e}");
                    process::exit(1);
                }
            };

            // Same content identity recorded in reports (catalog_sha256),
            // so auditors can verify a catalog file against a decision.
            let sha256 = match snapshot.sha256_hex() {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Error: failed to hash snapshot: {e}");
                    process::exit(1);
                }
            };

            let mut schema_count: usize = 0;
            let mut table_count: usize = 0;
            let mut column_count: usize = 0;
            let mut tables_with_row_count: usize = 0;
            let mut tables_with_bytes: usize = 0;
            let mut constraint_count: usize = 0;

            for db in &snapshot.databases {
                schema_count += db.schemas.len();
                for s in &db.schemas {
                    table_count += s.tables.len();
                    for t in &s.tables {
                        column_count += t.columns.len();
                        if t.row_count_estimate.is_some() {
                            tables_with_row_count += 1;
                        }
                        if t.bytes_estimate.is_some() {
                            tables_with_bytes += 1;
                        }
                        constraint_count += t.constraints.len();
                    }
                }
            }

            println!("Catalog Snapshot");
            println!("  URI: {}", uri);
            println!("  SHA-256: {}", sha256);
            println!("  Schema version: {}", snapshot.schema_version);
            if let Some(ts) = snapshot.generated_at {
                println!("  Generated at: {}", ts.to_rfc3339());
            }
            if let Some(src) = snapshot.source {
                println!("  Source: {}", src);
            }
            println!("  Databases: {}", snapshot.databases.len());
            println!("  Schemas: {}", schema_count);
            println!("  Tables: {}", table_count);
            println!("  Columns: {}", column_count);
            println!("  Tables w/ row_count: {}", tables_with_row_count);
            println!("  Tables w/ bytes: {}", tables_with_bytes);
            println!("  Constraints: {}", constraint_count);
        }
        "diff" => {
            if args.len() < 5 {
                eprintln!("Error: catalog diff requires <old> and <new> file paths or URIs");
                print_catalog_usage(&args[0]);
                process::exit(1);
            }
            let old_uri = &args[3];
            let new_uri = &args[4];

            let old = match load_catalog_from_uri(old_uri) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: failed to load old snapshot: {e}");
                    process::exit(1);
                }
            };
            let new = match load_catalog_from_uri(new_uri) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: failed to load new snapshot: {e}");
                    process::exit(1);
                }
            };

            use std::collections::BTreeSet;

            fn collect_tables(s: &catalog::CatalogSnapshot) -> BTreeSet<String> {
                let mut out = BTreeSet::new();
                for db in &s.databases {
                    for schema in &db.schemas {
                        for table in &schema.tables {
                            out.insert(format!(
                                "{}.{}.{}",
                                db.name.name, schema.name.name, table.name.name
                            ));
                        }
                    }
                }
                out
            }

            fn collect_columns(s: &catalog::CatalogSnapshot) -> BTreeSet<String> {
                let mut out = BTreeSet::new();
                for db in &s.databases {
                    for schema in &db.schemas {
                        for table in &schema.tables {
                            for col in &table.columns {
                                out.insert(format!(
                                    "{}.{}.{}.{}",
                                    db.name.name, schema.name.name, table.name.name, col.name.name
                                ));
                            }
                        }
                    }
                }
                out
            }

            fn collect_constraints(s: &catalog::CatalogSnapshot) -> BTreeSet<String> {
                let mut out = BTreeSet::new();
                for db in &s.databases {
                    for schema in &db.schemas {
                        for table in &schema.tables {
                            for c in &table.constraints {
                                // Deterministic string key for diffing.
                                // Note: keep this stable across versions.
                                let cols = c
                                    .columns
                                    .iter()
                                    .map(|i| i.name.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",");
                                let ref_table = c.ref_table.as_ref().map(|t| {
                                    format!("{}.{}.{}", t.database.name, t.schema.name, t.name.name)
                                });
                                let ref_cols = c
                                    .ref_columns
                                    .iter()
                                    .map(|i| i.name.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",");
                                out.insert(format!(
                                    "{}.{}.{}|{:?}|{}|{}|{}|{}",
                                    db.name.name,
                                    schema.name.name,
                                    table.name.name,
                                    c.kind,
                                    c.name.clone().unwrap_or_default(),
                                    cols,
                                    ref_table.unwrap_or_default(),
                                    ref_cols
                                ));
                            }
                        }
                    }
                }
                out
            }

            let old_tables = collect_tables(&old);
            let new_tables = collect_tables(&new);
            let old_cols = collect_columns(&old);
            let new_cols = collect_columns(&new);
            let old_constraints = collect_constraints(&old);
            let new_constraints = collect_constraints(&new);

            let tables_added = new_tables.difference(&old_tables).count();
            let tables_removed = old_tables.difference(&new_tables).count();
            let cols_added = new_cols.difference(&old_cols).count();
            let cols_removed = old_cols.difference(&new_cols).count();
            let constraints_added = new_constraints.difference(&old_constraints).count();
            let constraints_removed = old_constraints.difference(&new_constraints).count();

            println!("Catalog Diff Summary");
            println!("  Old: {}", old_uri);
            println!("  New: {}", new_uri);
            println!("  Tables added: {}", tables_added);
            println!("  Tables removed: {}", tables_removed);
            println!("  Columns added: {}", cols_added);
            println!("  Columns removed: {}", cols_removed);
            println!("  Constraints added: {}", constraints_added);
            println!("  Constraints removed: {}", constraints_removed);
        }
        "pull" => {
            let mut out: Option<String> = None;
            let mut sidecar: Option<String> = None;
            let mut provider_name: Option<String> = None;
            let mut pass_through: Vec<String> = Vec::new();

            let mut i = 3; // start after "catalog pull"
            while i < args.len() {
                match args[i].as_str() {
                    "--out" => {
                        if i + 1 >= args.len() {
                            eprintln!("Error: --out requires a file path");
                            process::exit(1);
                        }
                        out = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--sidecar" => {
                        if i + 1 >= args.len() {
                            eprintln!("Error: --sidecar requires a command path");
                            process::exit(1);
                        }
                        sidecar = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--provider" => {
                        if i + 1 >= args.len() {
                            let valid = lexega_core::builtin_catalog_provider_names().join(", ");
                            eprintln!("Error: --provider requires a value ({})", valid);
                            process::exit(1);
                        }
                        let pname = args[i + 1].clone();
                        // Validate provider name and resolve sidecar binary
                        match lexega_core::catalog_provider_by_name(&pname) {
                            Some(_) => provider_name = Some(pname),
                            None => {
                                let valid =
                                    lexega_core::builtin_catalog_provider_names().join(", ");
                                eprintln!(
                                    "Error: Unknown catalog provider '{}'. Valid: {}",
                                    pname, valid
                                );
                                process::exit(1);
                            }
                        }
                        i += 2;
                    }
                    "--" => {
                        pass_through.extend_from_slice(&args[(i + 1)..]);
                        break;
                    }
                    other => {
                        pass_through.push(other.to_string());
                        i += 1;
                    }
                }
            }

            let out = match out {
                Some(v) => v,
                None => {
                    eprintln!("Error: catalog pull requires --out <file>");
                    print_catalog_usage(&args[0]);
                    process::exit(1);
                }
            };

            // An explicit --sidecar is trusted as-is (a wrong path surfaces the
            // usual exec error). For the default resolution, fail early with an
            // actionable message when no extractor is actually present, rather
            // than letting Command::new emit a raw OS "not found".
            let sidecar = match sidecar {
                Some(s) => s,
                None => {
                    let resolved = resolve_default_catalog_sidecar(provider_name.as_deref());
                    if !catalog_sidecar_is_runnable(&resolved) {
                        let provider = provider_name.as_deref().unwrap_or("snowflake");
                        eprintln!(
                            "Error: no catalog extractor is available to pull a '{provider}' snapshot."
                        );
                        eprintln!(
                            "  Lexega bundles 'catalog pull' extractors for: {}.",
                            BUNDLED_PULL_PROVIDERS.join(", ")
                        );
                        eprintln!(
                            "  To pull anyway, provide your own extractor: catalog pull --sidecar <path> ..."
                        );
                        eprintln!(
                            "  If you already have a snapshot, attach it directly: analyze --catalog <file> ..."
                        );
                        process::exit(1);
                    }
                    resolved
                }
            };

            // Ensure the output directory exists (skip for cloud URIs).
            let is_cloud =
                out.starts_with("s3://") || out.starts_with("gs://") || out.starts_with("az://");
            let out_path = PathBuf::from(&out);
            if !is_cloud {
                if let Some(parent) = out_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            eprintln!(
                                "Error: failed to create output directory '{}': {}",
                                parent.display(),
                                e
                            );
                            process::exit(1);
                        }
                    }
                }
            }

            // Avoid duplicated/contradictory sidecar args.
            let mut filtered: Vec<String> = Vec::new();
            let mut j = 0;
            while j < pass_through.len() {
                if pass_through[j] == "--out" {
                    j += 2;
                    continue;
                }
                filtered.push(pass_through[j].clone());
                j += 1;
            }

            if let Some(ref provider_name) = provider_name {
                filtered.push("--provider".to_string());
                filtered.push(provider_name.clone());
            }

            if let Err(e) = maybe_rebuild_go_sidecar(&sidecar) {
                eprintln!("Error: {e}");
                process::exit(1);
            }

            if let Some(ref provider_name) = provider_name {
                eprintln!("Catalog provider: {}", provider_name);
            }

            // Print a small fingerprint to make it obvious which binary is being executed
            // (useful when multiple copies exist on PATH).
            {
                let sidecar_path = PathBuf::from(&sidecar);
                if sidecar_path.is_file() {
                    let meta = fs::metadata(&sidecar_path);
                    match meta {
                        Ok(m) => {
                            let size = m.len();
                            let mtime = m
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| format!("{}.{:09}s", d.as_secs(), d.subsec_nanos()))
                                .unwrap_or_else(|| "unknown".to_string());

                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                eprintln!(
                                    "Using catalog sidecar: {} (mtime={}, size={}, dev={}, inode={})",
                                    sidecar,
                                    mtime,
                                    size,
                                    m.dev(),
                                    m.ino()
                                );
                            }

                            #[cfg(not(unix))]
                            {
                                eprintln!(
                                    "Using catalog sidecar: {} (mtime={}, size={})",
                                    sidecar, mtime, size
                                );
                            }
                        }
                        Err(_) => {
                            eprintln!("Using catalog sidecar: {}", sidecar);
                        }
                    }
                } else {
                    eprintln!("Using catalog sidecar: {}", sidecar);
                }
            }

            // Check if output is a cloud URI - if so, stream via stdout
            let is_cloud_uri =
                out.starts_with("s3://") || out.starts_with("gs://") || out.starts_with("az://");

            if is_cloud_uri {
                // Stream directly to cloud storage via pipe
                eprintln!("Streaming catalog to cloud storage: {}", out);

                // Build the upload command based on URI scheme
                let (upload_cmd, upload_args): (&str, Vec<&str>) = if out.starts_with("s3://") {
                    ("aws", vec!["s3", "cp", "-", &out])
                } else if out.starts_with("gs://") {
                    ("gsutil", vec!["cp", "-", &out])
                } else if out.starts_with("az://") {
                    // Azure requires more complex handling - use temp file
                    eprintln!(
                        "Error: Azure streaming not yet supported. Use local file then upload."
                    );
                    process::exit(1);
                } else {
                    unreachable!()
                };

                // Spawn sidecar with stdout piped
                let sidecar_child = Command::new(&sidecar)
                    .arg("pull")
                    .arg("--out")
                    .arg("-") // Write to stdout
                    .args(&filtered)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit())
                    .spawn();

                let sidecar_child = match sidecar_child {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error: failed to run sidecar '{sidecar}': {e}");
                        process::exit(1);
                    }
                };

                // Spawn upload command with stdin from sidecar stdout
                let upload_child = Command::new(upload_cmd)
                    .args(&upload_args)
                    .stdin(sidecar_child.stdout.unwrap())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .spawn();

                let upload_output = match upload_child {
                    Ok(c) => c.wait_with_output(),
                    Err(e) => {
                        eprintln!("Error: failed to run '{}': {}", upload_cmd, e);
                        eprintln!(
                            "Is {} CLI installed and authenticated?",
                            if out.starts_with("s3://") {
                                "AWS"
                            } else {
                                "Google Cloud"
                            }
                        );
                        process::exit(1);
                    }
                };

                match upload_output {
                    Ok(output) if output.status.success() => {
                        eprintln!("Catalog snapshot uploaded to: {}", out);
                    }
                    Ok(output) => {
                        eprintln!(
                            "Error: upload failed with exit code {:?}",
                            output.status.code()
                        );
                        process::exit(output.status.code().unwrap_or(1));
                    }
                    Err(e) => {
                        eprintln!("Error: upload command failed: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                // Local file - use existing flow
                let status = Command::new(&sidecar)
                    .arg("pull")
                    .arg("--out")
                    .arg(&out)
                    .args(&filtered)
                    .status();

                match status {
                    Ok(s) if s.success() => {}
                    Ok(s) => process::exit(s.code().unwrap_or(1)),
                    Err(e) => {
                        eprintln!("Error: failed to run sidecar '{sidecar}': {e}");
                        process::exit(1);
                    }
                }

                // Sanity check the produced snapshot. If it's older than our current version,
                // it's usually because an older sidecar binary was used.
                match catalog::CatalogSnapshot::load_from_path(&out_path) {
                    Ok(snapshot) => {
                        if snapshot.schema_version != catalog::CATALOG_SCHEMA_VERSION {
                            eprintln!(
                                "Error: catalog snapshot schema_version={} (expected {}).\n  This usually means an older sidecar was used.\n  Using sidecar: {}\n  Tip: override with: catalog pull --sidecar <path> ...",
                                snapshot.schema_version,
                                catalog::CATALOG_SCHEMA_VERSION,
                                sidecar
                            );
                            process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: wrote catalog snapshot but failed to re-load it for validation: {e}"
                        );
                    }
                }
            }
        }
        other => {
            eprintln!("Error: unknown catalog subcommand '{other}'");
            print_catalog_usage(&args[0]);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The providers `pull` claims an extractor for are exactly the ones
    /// whose extractor source sits in this crate.
    #[test]
    fn bundled_providers_match_the_extractor_modules() {
        let bundled: BTreeSet<String> = BUNDLED_PULL_PROVIDERS
            .iter()
            .map(|name| {
                lexega_core::catalog_provider_by_name(name)
                    .expect("bundled provider is registered")
                    .sidecar_binary()
                    .to_string()
            })
            .collect();

        let sidecars = Path::new(env!("CARGO_MANIFEST_DIR")).join("sidecars");
        let modules: BTreeSet<String> = fs::read_dir(&sidecars)
            .expect("sidecars directory")
            .flatten()
            .filter(|entry| entry.path().join("go.mod").is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(bundled, modules);
    }
}
