// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CI-provided run identity for artifact stamping.
//!
//! Reads the run, repository, change, and commit identifiers the CI
//! platform already exposes as environment variables, so artifacts carry
//! their provenance without per-pipeline flag plumbing. Explicit flags
//! (`--run-id`, `--repo`, `--change-id`, `--commit`) always win over
//! detection.
//!
//! Platform detection lives here, once: [`detect_ci_platform`] is the
//! single marker check that `pr_comment.rs` and `cmd_ci.rs` also consume.

use std::env;

/// Identity of the CI run that invoked the CLI, if any.
pub struct CiRunContext {
    /// Platform run/pipeline/build identifier.
    pub run_id: Option<String>,
    /// Repository slug as the platform names it (e.g. `org/repo`).
    pub repo: Option<String>,
    /// PR / MR number when the run is a change evaluation.
    pub change_id: Option<String>,
    /// Commit SHA the run checked out.
    pub commit: Option<String>,
}

/// Run/repo/change identity after precedence resolution. This is the ONLY
/// place the precedence rule lives: explicit flags > CI environment > git
/// `origin` remote (repository only).
pub struct RunMetadata {
    pub run_id: Option<String>,
    pub repo: Option<String>,
    pub change_id: Option<String>,
    pub commit: Option<String>,
}

/// Resolve artifact identity once per command from flag values and the
/// environment.
pub fn resolve_run_metadata(
    run_id_flag: Option<String>,
    repo_flag: Option<String>,
    change_id_flag: Option<String>,
    commit_flag: Option<String>,
) -> RunMetadata {
    let ci = detect_ci_run_context();
    RunMetadata {
        run_id: run_id_flag.or(ci.run_id),
        repo: repo_flag
            .or(ci.repo)
            .or_else(super::git::repo_slug_from_remote),
        change_id: change_id_flag.or(ci.change_id),
        commit: commit_flag.or(ci.commit),
    }
}

/// The resolved identity of this invocation, stamped onto every report
/// artifact the run produces. `apply` is the single stamping mechanism —
/// scope, repository, and run always travel together, so an artifact can
/// never be partially stamped. Decisions inherit these fields from the
/// report.
#[derive(Clone)]
pub struct RunIdentity {
    pub scope: lexega_core::analyzer::RunScope,
    pub repo: Option<String>,
    pub run_id: Option<String>,
}

impl RunIdentity {
    pub fn apply(&self, report: &mut lexega_core::analyzer::AnalysisReport) {
        report.run_scope = Some(self.scope.clone());
        report.repo = self.repo.clone();
        report.run_id = self.run_id.clone();
    }
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// True when `LEXEGA_CI` marks this as a gating CI run. Opt-in (a truthy
/// value) so local development is never surprised by enforcement. Defined
/// once here so every command shares one notion of strict CI.
fn ci_strict_enabled() -> bool {
    match env::var("LEXEGA_CI") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// In a strict CI run, a missing policy is a hard error — the gate must not
/// be silently bypassable. `has_gate` says whether the build has a policy
/// gate at all; `hint` is the command-specific invocation example. No-op
/// outside strict CI or when a policy is present.
pub fn enforce_policy_required_in_ci(policy_present: bool, has_gate: bool, hint: &str) {
    if !ci_strict_enabled() || policy_present {
        return;
    }
    if has_gate {
        eprintln!(
            "Error: CI mode requires --policy (set LEXEGA_CI=0 to disable).\n\
             Hint: {}",
            hint
        );
    } else {
        eprintln!(
            "Error: LEXEGA_CI marks this run as gated by a policy, and this build has no policy gate (set LEXEGA_CI=0 to disable)."
        );
    }
    std::process::exit(1);
}

/// The CI platform this process runs under, keyed by each platform's
/// marker environment variable. The one platform-detection type: run
/// identity (here), PR comments (`pr_comment.rs`), and mode selection
/// (`cmd_ci.rs`) all match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiPlatform {
    /// GitHub Actions (`GITHUB_ACTIONS`)
    GitHub,
    /// GitLab CI (`GITLAB_CI`)
    GitLab,
    /// Bitbucket Pipelines (`BITBUCKET_PIPELINE_UUID`)
    Bitbucket,
    /// Azure DevOps Pipelines (`TF_BUILD`)
    AzureDevOps,
}

/// The single marker check. `None` outside CI (or on an unrecognized
/// platform).
pub fn detect_ci_platform() -> Option<CiPlatform> {
    if env::var("GITHUB_ACTIONS").is_ok() {
        return Some(CiPlatform::GitHub);
    }
    if env::var("GITLAB_CI").is_ok() {
        return Some(CiPlatform::GitLab);
    }
    if env::var("BITBUCKET_PIPELINE_UUID").is_ok() {
        return Some(CiPlatform::Bitbucket);
    }
    if env::var("TF_BUILD").is_ok() {
        return Some(CiPlatform::AzureDevOps);
    }
    None
}

/// Detect run identity from the current CI platform's environment.
/// All fields `None` outside CI (or on an unrecognized platform).
pub fn detect_ci_run_context() -> CiRunContext {
    match detect_ci_platform() {
        Some(CiPlatform::GitHub) => CiRunContext {
            run_id: var("GITHUB_RUN_ID"),
            repo: var("GITHUB_REPOSITORY"),
            change_id: github_pr_number(),
            // On pull_request events this is the synthetic merge commit —
            // GitHub's own convention for "what the run checked out".
            commit: var("GITHUB_SHA"),
        },
        Some(CiPlatform::GitLab) => CiRunContext {
            run_id: var("CI_PIPELINE_ID"),
            repo: var("CI_PROJECT_PATH"),
            change_id: var("CI_MERGE_REQUEST_IID"),
            commit: var("CI_COMMIT_SHA"),
        },
        Some(CiPlatform::Bitbucket) => CiRunContext {
            run_id: var("BITBUCKET_BUILD_NUMBER"),
            repo: var("BITBUCKET_REPO_FULL_NAME"),
            change_id: var("BITBUCKET_PR_ID"),
            commit: var("BITBUCKET_COMMIT"),
        },
        Some(CiPlatform::AzureDevOps) => CiRunContext {
            run_id: var("BUILD_BUILDID"),
            // Repository NAME, not the GUID `BUILD_REPOSITORY_ID` used for
            // API URLs — artifacts are read by humans and dashboards.
            repo: var("BUILD_REPOSITORY_NAME"),
            change_id: var("SYSTEM_PULLREQUEST_PULLREQUESTID"),
            commit: var("BUILD_SOURCEVERSION"),
        },
        None => CiRunContext {
            run_id: None,
            repo: None,
            change_id: None,
            commit: None,
        },
    }
}

/// PR number from `GITHUB_REF` (`refs/pull/<N>/merge` on pull_request runs).
fn github_pr_number() -> Option<String> {
    pr_number_from_ref(&var("GITHUB_REF")?)
}

fn pr_number_from_ref(github_ref: &str) -> Option<String> {
    let rest = github_ref.strip_prefix("refs/pull/")?;
    let number = rest.split('/').next()?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(number.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_stamps_scope_repo_and_run_together() {
        let identity = RunIdentity {
            scope: lexega_core::analyzer::RunScope::Change {
                base: Some("main".to_string()),
                head: Some("abc".to_string()),
                change_id: Some("41".to_string()),
            },
            repo: Some("org/repo".to_string()),
            run_id: Some("run-9".to_string()),
        };
        let mut report = lexega_core::analyzer::AnalysisReport::new();
        identity.apply(&mut report);
        assert_eq!(report.run_scope, Some(identity.scope.clone()));
        assert_eq!(report.repo.as_deref(), Some("org/repo"));
        assert_eq!(report.run_id.as_deref(), Some("run-9"));
    }

    // Env-var manipulation is process-global; detection branches are
    // covered by CLI-level usage. This exercises the pure ref parser.
    #[test]
    fn pr_number_parses_pull_refs_only() {
        assert_eq!(
            pr_number_from_ref("refs/pull/41/merge"),
            Some("41".to_string())
        );
        assert_eq!(pr_number_from_ref("refs/heads/main"), None);
        assert_eq!(pr_number_from_ref("refs/pull//merge"), None);
        assert_eq!(pr_number_from_ref("refs/pull/4x/merge"), None);
    }
}
