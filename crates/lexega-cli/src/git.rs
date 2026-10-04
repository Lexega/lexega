// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Git operations for the commands that read a commit range.
//!
//! Functions:
//! - get_git_repo_root
//! - make_absolute_path
//! - get_changed_sql_files
//! - get_file_at_commit
//! - repo_slug_from_remote

use std::path::{Path, PathBuf};

use super::io::{has_sql_extension, in_macros_directory, SkipReason, SkippedFile};

/// Repository slug (`owner/repo`) derived from the `origin` remote.
/// Handles `git@host:owner/repo.git` and `http(s)://host/owner/repo[.git]`.
/// Used as the last-resort repo identity for artifact stamping when neither
/// `--repo` nor a CI environment provides one.
pub fn repo_slug_from_remote() -> Option<String> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8(output.stdout).ok()?;
    slug_from_remote_url(url.trim())
}

fn slug_from_remote_url(url: &str) -> Option<String> {
    // scp-like: git@host:owner/repo(.git) — path follows the first ':'.
    // URL forms: scheme://[user@]host[:port]/owner/repo(.git).
    let path = if let Some(rest) = url.split_once("://").map(|(_, r)| r) {
        rest.split_once('/').map(|(_, p)| p)?
    } else {
        url.split_once(':').map(|(_, p)| p)?
    };
    let path = path.trim_matches('/').trim_end_matches(".git");
    // Keep the last two segments: deep paths (GitLab subgroups, ADO
    // collection/project/_git/repo) still end in something repo-like.
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != "_git")
        .collect();
    match segments.as_slice() {
        [] => None,
        [single] => Some((*single).to_string()),
        [.., owner, name] => Some(format!("{}/{}", owner, name)),
    }
}

#[cfg(test)]
mod git_tests {
    use super::slug_from_remote_url;

    #[test]
    fn slug_parses_common_remote_forms() {
        assert_eq!(
            slug_from_remote_url("git@github.com:acme/data-models.git"),
            Some("acme/data-models".to_string())
        );
        assert_eq!(
            slug_from_remote_url("https://github.com/acme/data-models"),
            Some("acme/data-models".to_string())
        );
        assert_eq!(
            slug_from_remote_url("https://gitlab.com/acme/platform/data-models.git"),
            Some("platform/data-models".to_string())
        );
        assert_eq!(
            slug_from_remote_url("https://dev.azure.com/acme/Data/_git/models"),
            Some("Data/models".to_string())
        );
        assert_eq!(slug_from_remote_url(""), None);
    }

    #[test]
    fn every_changed_sql_file_is_read_or_listed_as_skipped() {
        let names = "models/plain.sql\0models/café.sql\0models/quo\"te.sql\0models/upper.SQL\0\
                     tests/assert_positive.sql\0dbt_packages/pkg/models/m.sql\0\
                     macros/grants.sql\0models/macros/helper.sql\0README.md\0";
        let changed = super::changed_sql_files(names.as_bytes()).expect("names are UTF-8");
        assert_eq!(
            changed.files,
            [
                "models/plain.sql",
                "models/café.sql",
                "models/quo\"te.sql",
                "models/upper.SQL",
                "tests/assert_positive.sql",
                "dbt_packages/pkg/models/m.sql",
            ]
        );
        let skipped: Vec<_> = changed
            .skipped
            .iter()
            .map(|s| (s.path.to_string_lossy().into_owned(), s.reason))
            .collect();
        assert_eq!(
            skipped,
            [
                (
                    "macros/grants.sql".to_string(),
                    crate::io::SkipReason::MacroDirectory
                ),
                (
                    "models/macros/helper.sql".to_string(),
                    crate::io::SkipReason::MacroDirectory
                ),
            ]
        );
    }

    #[test]
    fn a_changed_name_that_is_not_utf8_is_an_error() {
        let error = super::changed_sql_files(b"models/\xff.sql\0").expect_err("not UTF-8");
        assert!(error.contains("not valid UTF-8"), "{error}");
    }
}

pub fn get_git_repo_root() -> Option<PathBuf> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let path = stdout.trim();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Convert a git-relative path to an absolute path using the repo root
pub fn make_absolute_path(relative_path: &str, git_root: Option<&Path>) -> String {
    if let Some(root) = git_root {
        root.join(relative_path).display().to_string()
    } else {
        // Fallback: try to use current dir
        if let Ok(cwd) = std::env::current_dir() {
            cwd.join(relative_path).display().to_string()
        } else {
            relative_path.to_string()
        }
    }
}

/// The SQL files a commit range changes, as paths from the repository root:
/// those to read, and those under a `macros` directory, which are listed as
/// skipped. Every changed SQL file is in one of the two.
#[derive(Debug, Default)]
pub struct ChangedSqlFiles {
    pub files: Vec<String>,
    pub skipped: Vec<SkippedFile>,
}

impl ChangedSqlFiles {
    /// Whether the range changes no SQL file at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.skipped.is_empty()
    }
}

/// The SQL files changed between two commits.
pub fn get_changed_sql_files(
    base: &str,
    head: &str,
    paths: &[String],
    _recursive: bool,
) -> Result<ChangedSqlFiles, String> {
    use std::process::Command;

    // `-z` makes git print each name as it is, NUL-terminated. Without it a
    // name with a non-ASCII byte, a quote or a backslash comes back quoted
    // and escaped, which is not the name of the file.
    let mut cmd = Command::new("git");
    cmd.args([
        "diff",
        "--name-only",
        "-z",
        &format!("{}..{}", base, head),
        "--",
    ]);

    for path in paths {
        cmd.arg(path);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff failed: {}", stderr));
    }

    changed_sql_files(&output.stdout)
}

/// Sort the NUL-terminated names `git diff --name-only -z` printed into the
/// SQL files to read and the ones to list as skipped.
fn changed_sql_files(names: &[u8]) -> Result<ChangedSqlFiles, String> {
    let mut changed = ChangedSqlFiles::default();
    for name in names.split(|byte| *byte == 0).filter(|n| !n.is_empty()) {
        let name = std::str::from_utf8(name).map_err(|_| {
            format!(
                "changed file name is not valid UTF-8: {}",
                String::from_utf8_lossy(name)
            )
        })?;
        let path = Path::new(name);
        if !has_sql_extension(path) {
            continue;
        }
        if in_macros_directory(path) {
            changed.skipped.push(SkippedFile {
                path: path.to_path_buf(),
                reason: SkipReason::MacroDirectory,
            });
        } else {
            changed.files.push(name.to_string());
        }
    }
    Ok(changed)
}

/// Get file content at a specific commit
pub fn get_file_at_commit(commit: &str, file_path: &str) -> Result<String, String> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["show", &format!("{}:{}", commit, file_path)])
        .output()
        .map_err(|e| format!("Failed to run git show: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git show failed: {}", stderr));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in file: {}", e))
}
