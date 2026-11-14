// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Git operations for the commands that read a commit range.
//!
//! Functions:
//! - get_git_repo_root
//! - repository_root_of
//! - make_absolute_path
//! - get_changed_sql_files
//! - sql_files_at_commit_under
//! - get_file_at_commit
//! - read_file_at_commit
//! - repo_slug_from_remote

use std::path::{Path, PathBuf};

use lexega_core::template::{
    macro_path_owner, macro_path_owners, MacroPathOwner, ProjectPaths, ProjectTree, PROJECT_FILE,
};

use super::io::{has_embedded_extension, has_sql_extension, SkipReason, SkippedFile};

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

    /// The files a `git diff --name-status -z` listing changes, sorted, in
    /// a repository whose root is a dbt project of dbt's default paths.
    fn changed_files(listing: &[u8]) -> Result<super::ChangedFiles, String> {
        let projects = super::ProjectsAtCommit::of_files(&[("dbt_project.yml", "name: 'p'\n")]);
        changed_files_among(listing, &projects)
    }

    /// The files a listing changes, sorted, among `projects`.
    fn changed_files_among(
        listing: &[u8],
        projects: &super::ProjectsAtCommit,
    ) -> Result<super::ChangedFiles, String> {
        let macro_owner =
            |path: &std::path::Path| lexega_core::template::macro_path_owner(projects, path);
        super::listed(listing)
            .and_then(|entries| super::sort_changed(entries, &macro_owner))
            .map_err(|e| e.to_string())
    }

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
        let names = "M\0models/plain.sql\0M\0models/café.sql\0A\0models/quo\"te.sql\0\
                     M\0models/upper.SQL\0M\0tests/assert_positive.sql\0\
                     M\0dbt_packages/pkg/models/m.sql\0M\0macros/grants.sql\0\
                     D\0models/macros/helper.sql\0M\0README.md\0M\0jobs/load.py\0";
        let changed = changed_files(names.as_bytes()).expect("names are UTF-8");
        assert_eq!(changed.embedded, ["jobs/load.py"]);
        let changed = changed.sql;
        assert_eq!(
            changed.files,
            [
                "models/plain.sql",
                "models/café.sql",
                "models/quo\"te.sql",
                "models/upper.SQL",
                "tests/assert_positive.sql",
                "dbt_packages/pkg/models/m.sql",
                // A folder named `macros` under the model path holds models.
                "models/macros/helper.sql",
            ]
        );
        let skipped: Vec<_> = changed
            .skipped
            .iter()
            .map(|s| (s.path.to_string_lossy().into_owned(), s.reason.to_string()))
            .collect();
        assert_eq!(
            skipped,
            [(
                "macros/grants.sql".to_string(),
                "in a macro path of dbt_project.yml: macro definitions, not statements".to_string()
            )]
        );
    }

    // A changed file is a macro file where a dbt project the commit holds
    // says: under its `macro-paths`, wherever they point, an installed
    // package's own read from the package's `dbt_project.yml`, a project
    // nested in a package its own. A file no project's macro path holds is
    // none.
    #[test]
    fn a_changed_file_is_a_macro_file_where_its_project_says() {
        let projects = super::ProjectsAtCommit::of_files(&[
            (
                "transform/shop/dbt_project.yml",
                "name: 'shop'\nmacro-paths: [\"my_macros\", \"./shared/macros/\", \"../common/macros\"]\npackages-install-path: vendor\n",
            ),
            (
                "transform/shop/vendor/pkg/dbt_project.yml",
                "name: 'pkg'\nmacro-paths: [\"pmacros\"]\n",
            ),
            (
                "transform/shop/vendor/pkg/integration_tests/dbt_project.yml",
                "name: 'pkg_tests'\n",
            ),
        ]);
        let names = "M\0transform/shop/my_macros/a.sql\0M\0transform/shop/shared/macros/b.sql\0\
                     M\0transform/shop/macros/c.sql\0M\0transform/shop/vendor/pkg/pmacros/d.sql\0\
                     M\0transform/shop/vendor/pkg/macros/e.sql\0M\0transform/shop/vendor/bare/macros/f.sql\0\
                     M\0transform/shop/models/g.sql\0M\0scripts/macros/h.sql\0\
                     M\0transform/shop/vendor/pkg/integration_tests/macros/i.sql\0\
                     M\0transform/common/macros/j.sql\0M\0transform/common/models/k.sql\0";
        let changed = changed_files_among(names.as_bytes(), &projects).expect("names are UTF-8");
        let skipped: Vec<_> = changed
            .sql
            .skipped
            .iter()
            .map(|s| s.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            skipped,
            [
                "transform/shop/my_macros/a.sql",
                "transform/shop/shared/macros/b.sql",
                "transform/shop/vendor/pkg/pmacros/d.sql",
                // A package without a `dbt_project.yml` has dbt's default.
                "transform/shop/vendor/bare/macros/f.sql",
                "transform/shop/vendor/pkg/integration_tests/macros/i.sql",
                "transform/common/macros/j.sql",
            ]
        );
        assert_eq!(
            changed.sql.files,
            [
                "transform/shop/macros/c.sql",
                "transform/shop/vendor/pkg/macros/e.sql",
                "transform/shop/models/g.sql",
                "scripts/macros/h.sql",
                "transform/common/models/k.sql",
            ]
        );
    }

    // A commit's project whose macro path is `..` takes no file another
    // project is around, nor a file in no project: it holds only its own
    // project's files, and the skip names it.
    #[test]
    fn a_parent_macro_path_at_a_commit_claims_only_its_own_projects_files() {
        let names = "A\0tools/dbt_project.yml\0M\0shop/models/m.sql\0M\0shop/macros/a.sql\0\
                     M\0scripts/load.sql\0M\0tools/t.sql\0";
        let projects = super::ProjectsAtCommit::of_files(&[
            ("shop/dbt_project.yml", "name: 'shop'\n"),
            (
                "tools/dbt_project.yml",
                "name: 'tools'\nmacro-paths: [\"..\"]\n",
            ),
        ]);
        let changed = changed_files_among(names.as_bytes(), &projects).expect("names are UTF-8");
        assert_eq!(changed.sql.files, ["shop/models/m.sql", "scripts/load.sql"]);
        let skipped: Vec<_> = changed
            .sql
            .skipped
            .iter()
            .map(|s| format!("{}: {}", s.path.display(), s.reason))
            .collect();
        assert_eq!(
            skipped,
            [
                "shop/macros/a.sql: in a macro path of shop/dbt_project.yml: macro definitions, not statements",
                "tools/t.sql: in a macro path of tools/dbt_project.yml: macro definitions, not statements",
            ]
        );
    }

    #[test]
    fn a_changed_name_that_is_not_utf8_is_an_error() {
        let error = changed_files(b"M\0models/\xff.sql\0").expect_err("not UTF-8");
        assert!(error.contains("not valid UTF-8"), "{error}");
        let error = changed_files(b"M\0jobs/\xff.py\0").expect_err("not UTF-8");
        assert!(error.contains("not valid UTF-8"), "{error}");
    }

    #[test]
    fn a_name_that_is_not_utf8_of_a_file_no_run_reads_is_passed_over() {
        let changed = changed_files(b"M\0assets/caf\xe9.png\0A\0x.sq\xff\0M\0models/a.sql\0")
            .expect("only names of files read must be UTF-8");
        assert_eq!(changed.sql.files, ["models/a.sql"]);
        assert!(changed.sql.skipped.is_empty());
        assert!(changed.embedded.is_empty());
    }

    #[test]
    fn a_moved_sql_file_keeps_its_former_path_and_a_file_moved_off_sql_is_removed() {
        let listing = b"R100\0legacy.sql\0archive/legacy.sql\0\
                        R087\0q.sql\0q.txt\0\
                        R100\0notes.txt\0n.sql\0\
                        R095\0macros/m.sql\0models/m.sql\0\
                        C090\0a.sql\0b.sql\0";
        let changed = changed_files(listing).expect("names are UTF-8");
        assert_eq!(
            changed.sql.files,
            [
                "archive/legacy.sql",
                "q.sql",
                "n.sql",
                "models/m.sql",
                "b.sql"
            ]
        );
        assert_eq!(
            changed.sql.renamed_from.into_iter().collect::<Vec<_>>(),
            [("archive/legacy.sql".to_string(), "legacy.sql".to_string())]
        );
        let skipped: Vec<_> = changed
            .sql
            .skipped
            .iter()
            .map(|s| s.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(skipped, ["macros/m.sql"]);
    }
}

/// The root of the git repository the working directory is in.
pub fn get_git_repo_root() -> Option<PathBuf> {
    repository_root_of(Path::new("."))
}

/// The root of the git repository `dir` is in, as git names it; `None`
/// outside any repository or where git cannot be run.
pub(crate) fn repository_root_of(dir: &Path) -> Option<PathBuf> {
    use std::process::Command;

    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
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

/// The two commits a `base..head` or `base...head` argument names, as git
/// reads it: a side left empty is `HEAD`, and `base...head` is the range
/// from the merge base of the two to `head`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRange {
    pub base: String,
    pub head: String,
}

/// Why a commit range, or what it changes, could not be read from git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeError {
    /// The argument is not `base..head` or `base...head`.
    Malformed(String),
    /// The command does not run in a git repository.
    NotARepository,
    /// A side names no commit the repository holds; `shallow` when the
    /// repository is a shallow clone, which holds only part of its history.
    MissingCommit { rev: String, shallow: bool },
    /// Git could not give the merge base of a `base...head` range.
    MergeBase {
        base: String,
        head: String,
        reason: String,
    },
    /// A path argument matches no file at either commit of the range.
    PathMatchesNothing {
        path: String,
        base: String,
        head: String,
    },
    /// The name of a changed file a run reads is not UTF-8.
    NameNotUtf8(String),
    /// Git could not be run, or failed.
    Git(String),
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeError::Malformed(range) => write!(
                f,
                "commit range must be in format 'base..head' or 'base...head' (e.g., main..HEAD), not '{}'",
                range
            ),
            RangeError::NotARepository => f.write_str(
                "not a git repository: a commit range is read from the repository the command runs in",
            ),
            RangeError::MissingCommit { rev, shallow: true } => write!(
                f,
                "'{}' is not a commit in this clone, which is shallow: fetch the history the range needs (GitHub actions/checkout: `fetch-depth: 0`; GitLab CI: `GIT_DEPTH: 0`; Bitbucket Pipelines: `clone: depth: full`; Azure Pipelines checkout: `fetchDepth: 0`)",
                rev
            ),
            RangeError::MissingCommit {
                rev,
                shallow: false,
            } => write!(
                f,
                "'{}' names no commit in this repository: fetch it (`git fetch origin <branch>`) or name a commit the repository holds",
                rev
            ),
            RangeError::PathMatchesNothing { path, base, head } => write!(
                f,
                "'{}' matches no file at {} or {}",
                path, base, head
            ),
            RangeError::NameNotUtf8(name) => {
                write!(f, "changed file name is not valid UTF-8: {}", name)
            }
            RangeError::Git(reason) => f.write_str(reason),
            RangeError::MergeBase { base, head, reason } => write!(
                f,
                "no merge base of '{}' and '{}': {}",
                base, head, reason
            ),
        }
    }
}

impl std::error::Error for RangeError {}

impl CommitRange {
    /// The range `range` names.
    pub fn resolve(range: &str) -> Result<Self, RangeError> {
        let (base, head, symmetric) = match range.split_once("...") {
            Some((base, head)) => (base, head, true),
            None => match range.split_once("..") {
                Some((base, head)) => (base, head, false),
                None => return Err(RangeError::Malformed(range.to_string())),
            },
        };
        if base.is_empty() && head.is_empty() {
            return Err(RangeError::Malformed(range.to_string()));
        }
        let side = |rev: &str| if rev.is_empty() { "HEAD" } else { rev }.to_string();
        let (base, head) = (side(base), side(head));
        if !git_succeeds(&["rev-parse", "--git-dir"])? {
            return Err(RangeError::NotARepository);
        }
        for rev in [&base, &head] {
            if !holds_commit(rev)? {
                return Err(RangeError::MissingCommit {
                    rev: rev.clone(),
                    shallow: is_shallow()?,
                });
            }
        }
        let base = if symmetric {
            merge_base(&base, &head)?
        } else {
            base
        };
        Ok(CommitRange { base, head })
    }

    /// Refuse the first of `paths` that matches no file the range holds at
    /// its base or its head, read as `git diff` reads a path argument.
    pub fn check_paths(&self, paths: &[String]) -> Result<(), RangeError> {
        if paths.is_empty() {
            return Ok(());
        }
        let empty = empty_tree()?;
        for path in paths {
            if !holds_under(&empty, &self.head, path)? && !holds_under(&empty, &self.base, path)? {
                return Err(RangeError::PathMatchesNothing {
                    path: path.clone(),
                    base: self.base.clone(),
                    head: self.head.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A git failure, from what it wrote on stderr.
fn git_failed(command: &str, stderr: &[u8]) -> RangeError {
    RangeError::Git(format!(
        "git {} failed: {}",
        command,
        String::from_utf8_lossy(stderr)
    ))
}

/// A git process that could not be started.
fn git_not_run(e: std::io::Error) -> RangeError {
    RangeError::Git(format!("Failed to run git: {}", e))
}

/// Whether `rev` names a commit the repository holds.
pub fn holds_commit(rev: &str) -> Result<bool, RangeError> {
    let commit = format!("{}^{{commit}}", rev);
    git_succeeds(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &commit,
    ])
}

/// Whether git exits with success on `args`, its output discarded.
fn git_succeeds(args: &[&str]) -> Result<bool, RangeError> {
    use std::process::{Command, Stdio};

    Command::new("git")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(git_not_run)
}

/// Whether the repository is a shallow clone.
fn is_shallow() -> Result<bool, RangeError> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["rev-parse", "--is-shallow-repository"])
        .output()
        .map_err(git_not_run)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

/// The commit `git merge-base` gives for `base` and `head`.
fn merge_base(base: &str, head: &str) -> Result<String, RangeError> {
    use std::process::Command;

    let failed = |reason: String| RangeError::MergeBase {
        base: base.to_string(),
        head: head.to_string(),
        reason,
    };
    let output = Command::new("git")
        .args(["merge-base", "--end-of-options", base, head])
        .output()
        .map_err(|e| failed(format!("Failed to run git: {}", e)))?;
    let found = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || found.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(failed(if stderr.is_empty() {
            "the two share no history".to_string()
        } else {
            stderr
        }));
    }
    Ok(found)
}

/// The SQL files a commit range changes, as paths from the repository root:
/// those to read, and the macro files of the dbt projects the commits hold
/// ([`macro_path_owner`]), which are listed as skipped. Every changed SQL file is in one of the two. A file of `files`
/// the range moves from another SQL file's path has that path at the base
/// in `renamed_from`.
#[derive(Debug, Default)]
pub struct ChangedSqlFiles {
    pub files: Vec<String>,
    pub skipped: Vec<SkippedFile>,
    pub renamed_from: std::collections::BTreeMap<String, String>,
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
) -> Result<ChangedSqlFiles, RangeError> {
    get_changed_files(base, head, paths).map(|changed| changed.sql)
}

/// Whether the range changes a SQL file under `paths`, a macro file among
/// them, read from the listing alone.
pub fn changes_sql_files(base: &str, head: &str, paths: &[String]) -> Result<bool, RangeError> {
    let listing = name_status(base, head, paths, None)?;
    Ok(listed(&listing)?.iter().any(|entry| {
        std::iter::once(entry.name)
            .chain(entry.from)
            .any(|name| has_sql_extension(Path::new(String::from_utf8_lossy(name).as_ref())))
    }))
}

/// The files a commit range changes that a review reads: its SQL files, and
/// the Python and notebook files `--scan-embedded` extracts SQL from.
#[derive(Debug, Default)]
pub(crate) struct ChangedFiles {
    pub(crate) sql: ChangedSqlFiles,
    pub(crate) embedded: Vec<String>,
}

/// The files changed between two commits, as [`ChangedFiles`] sorts them.
pub(crate) fn get_changed_files(
    base: &str,
    head: &str,
    paths: &[String],
) -> Result<ChangedFiles, RangeError> {
    let listing = name_status(base, head, paths, None)?;
    let mut entries = listed(&listing)?;
    // A file moved into the paths from outside them is listed there as
    // added; the moves of the whole tree give the path it had at the base.
    // A listing of the whole tree holds every move already.
    let moves = if entries
        .iter()
        .any(|entry| entry.status == ListedStatus::Added)
        && !names_whole_tree(paths)?
    {
        name_status(base, head, &[], Some("--diff-filter=R"))?
    } else {
        Vec::new()
    };
    let moved_from: std::collections::BTreeMap<&[u8], &[u8]> = listed(&moves)?
        .into_iter()
        .filter_map(|entry| Some((entry.name, entry.from?)))
        .collect();
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.status == ListedStatus::Added)
    {
        entry.from = moved_from.get(entry.name).copied();
    }
    // A file is a macro file where it is one at either commit.
    let sql: Vec<PathBuf> = entries
        .iter()
        .flat_map(|entry| std::iter::once(entry.name).chain(entry.from))
        .map(|name| PathBuf::from(String::from_utf8_lossy(name).as_ref()))
        .filter(|path| has_sql_extension(path))
        .collect();
    let at_base = ProjectsAtCommit::read(base, &sql)?;
    let at_head = ProjectsAtCommit::read(head, &sql)?;
    let macro_owner =
        |path: &Path| macro_path_owner(&at_base, path).or_else(|| macro_path_owner(&at_head, path));
    sort_changed(entries, &macro_owner)
}

/// The roots of the dbt projects `commit` holds whose paths make one of the
/// SQL files of `files` a macro file ([`macro_path_owners`]); each file and
/// root a path from the repository root. No tree is read where `files`
/// holds no SQL file.
pub fn projects_holding_macros(
    commit: &str,
    files: &[PathBuf],
) -> Result<Vec<PathBuf>, RangeError> {
    let sql: Vec<PathBuf> = files
        .iter()
        .filter(|file| has_sql_extension(file))
        .cloned()
        .collect();
    let projects = ProjectsAtCommit::read(commit, &sql)?;
    let mut roots: Vec<PathBuf> = sql
        .iter()
        .flat_map(|file| macro_path_owners(&projects, file))
        .map(|owner| owner.root().to_path_buf())
        .collect();
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// The dbt projects of a commit: the paths each `dbt_project.yml` it holds
/// names, by its directory, from the repository root.
pub(crate) struct ProjectsAtCommit {
    projects: std::collections::BTreeMap<PathBuf, ProjectPaths>,
}

impl ProjectsAtCommit {
    /// The projects `commit` holds, read where one of `files` may be a
    /// macro file of one; none where `files` is empty. A `dbt_project.yml`
    /// the commit holds and that cannot be read makes a project of dbt's
    /// default paths.
    fn read(commit: &str, files: &[PathBuf]) -> Result<Self, RangeError> {
        use std::process::Command;

        let mut projects = std::collections::BTreeMap::new();
        if files.is_empty() {
            return Ok(ProjectsAtCommit { projects });
        }
        // Each entry `<mode> <type> <object>\t<path>` of the whole tree: a
        // macro path may point anywhere in it.
        let output = Command::new("git")
            .args(["ls-tree", "--full-tree", "-r", "-z", commit])
            .output()
            .map_err(git_not_run)?;
        if !output.status.success() {
            return Err(git_failed("ls-tree", &output.stderr));
        }
        for name in output
            .stdout
            .split(|byte| *byte == 0)
            .filter_map(|entry| std::str::from_utf8(entry).ok())
            .filter_map(|entry| entry.split_once('\t'))
            .filter(|(object, _)| object.split(' ').nth(1) == Some("blob"))
            .map(|(_, name)| name)
            .filter(|name| Path::new(name).file_name() == Some(std::ffi::OsStr::new(PROJECT_FILE)))
        {
            let Some(dir) = Path::new(name).parent() else {
                continue;
            };
            let text = read_file_at_commit(commit, name).ok();
            projects.insert(dir.to_path_buf(), ProjectPaths::read(text.as_deref()));
        }
        Ok(ProjectsAtCommit { projects })
    }

    /// The projects of `files`, each a path from the repository root and
    /// its text.
    #[cfg(test)]
    fn of_files(files: &[(&str, &str)]) -> Self {
        let projects = files
            .iter()
            .filter_map(|(name, text)| {
                let dir = Path::new(name).parent()?;
                Some((dir.to_path_buf(), ProjectPaths::read(Some(text))))
            })
            .collect();
        ProjectsAtCommit { projects }
    }
}

impl ProjectTree for ProjectsAtCommit {
    fn project_at(&self, dir: &Path) -> Option<ProjectPaths> {
        self.projects.get(dir).cloned()
    }

    fn projects(&self) -> Vec<(PathBuf, ProjectPaths)> {
        self.projects
            .iter()
            .map(|(root, paths)| (root.clone(), paths.clone()))
            .collect()
    }
}

/// What `git diff --name-status -z` prints for the range under `paths`,
/// with `filter` its `--diff-filter` option where one is given.
fn name_status(
    base: &str,
    head: &str,
    paths: &[String],
    filter: Option<&str>,
) -> Result<Vec<u8>, RangeError> {
    use std::process::Command;

    // `-z` makes git print each name as it is, NUL-terminated. Without it a
    // name with a non-ASCII byte, a quote or a backslash comes back quoted
    // and escaped, which is not the name of the file. A moved file is listed
    // with the path it had at the base, whatever the user's git config.
    let mut cmd = Command::new("git");
    cmd.args(["diff", "--name-status", "--find-renames", "-z"]);
    cmd.args(filter);
    cmd.args([&format!("{}..{}", base, head), "--"]);
    cmd.args(paths);

    let output = cmd.output().map_err(git_not_run)?;
    if !output.status.success() {
        return Err(git_failed("diff", &output.stderr));
    }
    Ok(output.stdout)
}

/// Whether `paths` name the whole tree: none, or `.` alone run from the
/// repository's top directory.
fn names_whole_tree(paths: &[String]) -> Result<bool, RangeError> {
    use std::process::Command;

    if paths.iter().any(|path| path != ".") {
        return Ok(false);
    }
    if paths.is_empty() {
        return Ok(true);
    }
    let output = Command::new("git")
        .args(["rev-parse", "--show-prefix"])
        .output()
        .map_err(git_not_run)?;
    if !output.status.success() {
        return Err(git_failed("rev-parse", &output.stderr));
    }
    Ok(output.stdout.trim_ascii().is_empty())
}

/// The SQL files `commit` holds under `paths`, as paths from the
/// repository root. Path arguments are read as `git diff` reads them, and
/// a macro file of a dbt project is left out, as a commit range's listing
/// leaves it unread. An error where git cannot list the commit, or
/// where a SQL file's name is not UTF-8.
pub fn sql_files_at_commit_under(
    commit: &str,
    paths: &[String],
) -> Result<std::collections::BTreeSet<String>, RangeError> {
    get_changed_files(&empty_tree()?, commit, paths)
        .map(|listed| listed.sql.files.into_iter().collect())
}

/// The tree that holds no file: every file a commit holds is a change from
/// it.
fn empty_tree() -> Result<String, RangeError> {
    use std::process::Command;

    let empty = Command::new("git")
        .args(["hash-object", "-t", "tree", "--stdin"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(git_not_run)?;
    if !empty.status.success() {
        return Err(git_failed("hash-object", &empty.stderr));
    }
    Ok(String::from_utf8_lossy(&empty.stdout).trim().to_string())
}

/// Whether `commit` holds a file `path` matches; `empty` is the empty tree.
fn holds_under(empty: &str, commit: &str, path: &str) -> Result<bool, RangeError> {
    use std::process::{Command, Stdio};

    // `--quiet` exits 1 where the path holds a file and 0 where it holds
    // none, listing nothing.
    let output = Command::new("git")
        .args(["diff", "--quiet", empty, commit, "--", path])
        .stdout(Stdio::null())
        .output()
        .map_err(git_not_run)?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        Some(_) | None => Err(git_failed("diff", &output.stderr)),
    }
}

/// What a review makes of a changed file, by its name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChangedKind {
    /// A SQL file to read.
    Sql,
    /// A macro file of the dbt project whose path decided, listed as
    /// skipped.
    Macro(MacroPathOwner),
    /// A Python or notebook file `--scan-embedded` reads.
    Embedded,
    /// Any other file, passed over.
    Other,
}

impl ChangedKind {
    /// The kind of the file `name`, a macro file where `macro_owner` names
    /// the project whose path makes it one.
    fn of(name: &[u8], macro_owner: &dyn Fn(&Path) -> Option<MacroPathOwner>) -> Self {
        // An extension that is not UTF-8 is none of these, so the lossy form
        // tells the files read from the rest.
        let lossy = String::from_utf8_lossy(name);
        let path = Path::new(lossy.as_ref());
        if has_embedded_extension(path) {
            ChangedKind::Embedded
        } else if !has_sql_extension(path) {
            ChangedKind::Other
        } else {
            macro_owner(path).map_or(ChangedKind::Sql, ChangedKind::Macro)
        }
    }

    /// Whether `self` and `other` are the same kind, whichever project
    /// owns a macro file.
    fn is_kind_of(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl ChangedFiles {
    /// List `name`, a file of `kind`, where its kind belongs. A file listed
    /// whose name is not UTF-8 is an error.
    fn push(&mut self, name: &[u8], kind: ChangedKind) -> Result<(), RangeError> {
        match kind {
            ChangedKind::Sql => self.sql.files.push(utf8_name(name)?.to_string()),
            ChangedKind::Macro(owner) => self.sql.skipped.push(SkippedFile {
                path: Path::new(utf8_name(name)?).to_path_buf(),
                reason: SkipReason::MacroDirectory(owner),
            }),
            ChangedKind::Embedded => self.embedded.push(utf8_name(name)?.to_string()),
            ChangedKind::Other => {}
        }
        Ok(())
    }
}

fn utf8_name(name: &[u8]) -> Result<&str, RangeError> {
    std::str::from_utf8(name)
        .map_err(|_| RangeError::NameNotUtf8(String::from_utf8_lossy(name).into_owned()))
}

/// How `git diff --name-status` says an entry changed, as far as a run
/// reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListedStatus {
    /// `A`: the head adds the file.
    Added,
    /// `R`: the file moved from another path.
    Renamed,
    /// `C`: the file was copied from another path, which keeps it.
    Copied,
    /// Any other: modified, deleted, its type changed, unmerged.
    Changed,
}

impl ListedStatus {
    fn of(field: &[u8]) -> Self {
        match field.first() {
            Some(b'A') => ListedStatus::Added,
            Some(b'R') => ListedStatus::Renamed,
            Some(b'C') => ListedStatus::Copied,
            Some(_) | None => ListedStatus::Changed,
        }
    }
}

/// One entry `git diff --name-status -z` prints: its status, its path, and
/// for a moved file the path it had at the base.
struct Listed<'a> {
    status: ListedStatus,
    from: Option<&'a [u8]>,
    name: &'a [u8],
}

/// The entries of a `git diff --name-status -z` listing.
fn listed(listing: &[u8]) -> Result<Vec<Listed<'_>>, RangeError> {
    let mut entries = Vec::new();
    let mut fields = listing.split(|byte| *byte == 0).filter(|f| !f.is_empty());
    while let Some(status) = fields.next() {
        let mut path = || {
            fields
                .next()
                .ok_or_else(|| RangeError::Git("git diff listing ends inside an entry".to_string()))
        };
        let status = ListedStatus::of(status);
        // A move names its former path first; a copy leaves its source
        // where it was.
        let (from, name) = match status {
            ListedStatus::Renamed => (Some(path()?), path()?),
            ListedStatus::Copied => {
                path()?;
                (None, path()?)
            }
            ListedStatus::Added | ListedStatus::Changed => (None, path()?),
        };
        entries.push(Listed { status, from, name });
    }
    Ok(entries)
}

/// Sort `entries` into the SQL files to read, the ones to list as skipped
/// (the macro files `macro_owner` names a project for), and the Python and
/// notebook files. Any other file is passed over, whatever its name; a SQL,
/// Python or notebook file whose name is not UTF-8 is an error. A SQL file
/// moved from another SQL file's path is read at the base under that path;
/// a file moved to a name of another kind leaves its former path removed.
fn sort_changed(
    entries: Vec<Listed<'_>>,
    macro_owner: &dyn Fn(&Path) -> Option<MacroPathOwner>,
) -> Result<ChangedFiles, RangeError> {
    let mut changed = ChangedFiles::default();
    for Listed { from, name, .. } in entries {
        let kind = ChangedKind::of(name, macro_owner);
        let Some(from) = from else {
            changed.push(name, kind)?;
            continue;
        };
        let from_kind = ChangedKind::of(from, macro_owner);
        if kind == ChangedKind::Sql && from_kind == ChangedKind::Sql {
            changed
                .sql
                .renamed_from
                .insert(utf8_name(name)?.to_string(), utf8_name(from)?.to_string());
        }
        let moved_across_kinds = !kind.is_kind_of(&from_kind);
        changed.push(name, kind)?;
        if moved_across_kinds {
            changed.push(from, from_kind)?;
        }
    }
    Ok(changed)
}

/// Get file content at a specific commit
pub fn get_file_at_commit(commit: &str, file_path: &str) -> Result<String, String> {
    read_file_at_commit(commit, file_path).map_err(|e| e.to_string())
}

/// Why a file could not be read at a commit.
#[derive(Debug)]
pub enum FileAtCommitError {
    /// The commit does not hold the file.
    Absent(String),
    /// The commit holds something at the path and it could not be read as
    /// a file: not UTF-8, a symbolic link (not followed) or a submodule
    /// (whose files are not in the repository), or git failed.
    Unreadable(String),
}

impl std::fmt::Display for FileAtCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileAtCommitError::Absent(reason) | FileAtCommitError::Unreadable(reason) => {
                f.write_str(reason)
            }
        }
    }
}

impl std::error::Error for FileAtCommitError {}

/// The text of `file_path` as of `commit`, telling a file the commit does
/// not hold from one it holds and cannot read. A symbolic link and a
/// submodule are held and not read: the text of a link is its target's
/// path, and a submodule's files are not in this repository.
pub fn read_file_at_commit(commit: &str, file_path: &str) -> Result<String, FileAtCommitError> {
    read_source_at_commit(commit, file_path).map(|source| source.text)
}

/// [`read_file_at_commit`], with the encoding the committed bytes are in.
pub(crate) fn read_source_at_commit(
    commit: &str,
    file_path: &str,
) -> Result<lexega_core::extract::SourceText, FileAtCommitError> {
    use std::process::Command;

    // What the commit holds at the path, by its mode: `<mode> <type>
    // <object>\t<path>`, nothing when it holds nothing there. The path is
    // taken as written, not as a pattern.
    let listed = Command::new("git")
        .args([
            "--literal-pathspecs",
            "ls-tree",
            "--full-tree",
            "-z",
            commit,
            "--",
            file_path,
        ])
        .output()
        .map_err(|e| FileAtCommitError::Unreadable(format!("Failed to run git ls-tree: {}", e)))?;
    if !listed.status.success() {
        return Err(FileAtCommitError::Unreadable(format!(
            "git ls-tree failed: {}",
            String::from_utf8_lossy(&listed.stderr)
        )));
    }
    let entry = String::from_utf8_lossy(&listed.stdout);
    match entry.split(' ').next().filter(|mode| !mode.is_empty()) {
        None => {
            return Err(FileAtCommitError::Absent(format!(
                "{} does not hold {}",
                commit, file_path
            )))
        }
        // A directory stands where the file was.
        Some("040000") => {
            return Err(FileAtCommitError::Absent(format!(
                "{} holds a directory at {}",
                commit, file_path
            )))
        }
        Some("120000") => {
            return Err(FileAtCommitError::Unreadable(
                "symbolic link: a committed link is not followed".to_string(),
            ))
        }
        Some("160000") => {
            return Err(FileAtCommitError::Unreadable(
                "submodule: its files are not in this repository".to_string(),
            ))
        }
        Some(_) => {}
    }

    let object = format!("{}:{}", commit, file_path);
    let output = Command::new("git")
        .args(["show", &object])
        .output()
        .map_err(|e| FileAtCommitError::Unreadable(format!("Failed to run git show: {}", e)))?;

    if !output.status.success() {
        return Err(FileAtCommitError::Unreadable(format!(
            "git show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    lexega_core::extract::decode_source(&output.stdout)
        .map_err(|e| FileAtCommitError::Unreadable(format!("The file is {}", e)))
}
