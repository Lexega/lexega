// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `ci` — CI entry point that selects the analysis scope from
//! the pipeline's own event context.
//!
//! Pull/merge-request events run a change-scoped `review` against the
//! detected base; push and scheduled events run a snapshot `analyze`.
//! Options are forwarded verbatim to the underlying command, so `ci`
//! supports exactly what those commands support and can never lag them.
//! Outside CI it exits with guidance instead of guessing.

use super::ci_env::CiPlatform;
use super::extension::Extension;
use std::env;
use std::process;

/// What the CI event tells us to measure.
enum CiMode {
    /// PR/MR event — review `base..HEAD`.
    Change { range: String, detail: String },
    /// Push/schedule — snapshot of the checked-out tree.
    Snapshot { detail: String },
}

pub fn handle_ci_command(args: &[String], ext: &dyn Extension) {
    let rest = &args[2..];
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        super::usage::print_ci_usage(&args[0], ext);
        return;
    }

    // ci-only overrides — consumed here, never forwarded.
    let mut forced_snapshot = false;
    let mut forced_range: Option<String> = None;
    let mut remaining: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--snapshot" => {
                forced_snapshot = true;
                i += 1;
            }
            "--range" => {
                if i + 1 >= rest.len() {
                    eprintln!("Error: --range requires a value (BASE..HEAD)");
                    process::exit(1);
                }
                forced_range = Some(rest[i + 1].clone());
                i += 2;
            }
            _ => {
                remaining.push(rest[i].clone());
                i += 1;
            }
        }
    }
    if forced_snapshot && forced_range.is_some() {
        eprintln!("Error: --snapshot and --range are mutually exclusive");
        process::exit(1);
    }

    let (paths, options, defaulted) = split_paths_and_options(&remaining);

    // A path after the options started would be forwarded as an EXTRA
    // positional and double-analyze the tree — refuse instead of guessing.
    if let Some(stray) = find_misplaced_positional(&options) {
        eprintln!(
            "Error: '{}' looks like a path but appears after the options started.",
            stray
        );
        eprintln!(
            "Paths must come before options: {} ci [PATHS...] [OPTIONS]",
            args[0]
        );
        process::exit(1);
    }

    let mode = if forced_snapshot {
        CiMode::Snapshot {
            detail: "--snapshot".to_string(),
        }
    } else if let Some(range) = forced_range {
        CiMode::Change {
            range,
            detail: "--range".to_string(),
        }
    } else {
        match detect_ci_mode() {
            Some(mode) => mode,
            None => {
                eprintln!("Error: no CI environment detected.");
                eprintln!();
                eprintln!("`ci` selects between change review and snapshot analysis from the");
                eprintln!("pipeline's event context (GitHub Actions, GitLab CI, Azure DevOps,");
                eprintln!("Bitbucket Pipelines). Outside CI, run the underlying command:");
                eprintln!("  {} review <BASE..HEAD> [PATHS...]    # changes", args[0]);
                eprintln!(
                    "  {} analyze [PATHS...]                # current state",
                    args[0]
                );
                eprintln!("Or force a mode here with --snapshot / --range <BASE..HEAD>.");
                process::exit(1);
            }
        }
    };

    match mode {
        CiMode::Change { range, detail } => {
            eprintln!("ci: {} → reviewing {}", detail, range);
            let mut forwarded = vec![args[0].clone(), "review".to_string(), range];
            forwarded.extend(paths);
            if defaulted {
                forwarded.push("-r".to_string());
            }
            forwarded.extend(options);
            crate::dispatch(&forwarded, ext);
        }
        CiMode::Snapshot { detail } => {
            eprintln!("ci: {} → analyzing current state", detail);
            let mut forwarded = vec![args[0].clone(), "analyze".to_string()];
            forwarded.extend(paths);
            if defaulted {
                forwarded.push("-r".to_string());
            }
            let (options, dropped) = strip_review_only_options(options);
            for flag in dropped {
                eprintln!("ci: no pull request on this run — ignoring {}", flag);
            }
            forwarded.extend(options);
            crate::dispatch(&forwarded, ext);
        }
    }
}

/// PR-only flags that `analyze` rejects. A dual-trigger workflow carries
/// one `ci` line for both legs, so on a snapshot run these are dropped
/// (with a note) instead of failing the push build over a flag that only
/// means something on a pull request. Bare flags only — none take a value.
const REVIEW_ONLY_FLAGS: &[&str] = &["--pr-comment"];

/// Remove review-only flags from a snapshot run's forwarded options.
/// Returns the surviving options and the flags that were dropped.
fn strip_review_only_options(options: Vec<String>) -> (Vec<String>, Vec<&'static str>) {
    let dropped: Vec<&'static str> = REVIEW_ONLY_FLAGS
        .iter()
        .copied()
        .filter(|f| options.iter().any(|o| o == f))
        .collect();
    let kept = options
        .into_iter()
        .filter(|o| !REVIEW_ONLY_FLAGS.contains(&o.as_str()))
        .collect();
    (kept, dropped)
}

/// Leading non-flag arguments are paths; everything from the first flag
/// onward is forwarded verbatim, so flag VALUES are never misread as
/// paths. With no paths given, default to the whole tree recursively
/// (returned bool = defaults were injected).
fn split_paths_and_options(args: &[String]) -> (Vec<String>, Vec<String>, bool) {
    let split = args
        .iter()
        .position(|a| a.starts_with('-'))
        .unwrap_or(args.len());
    let (paths, options) = args.split_at(split);
    if paths.is_empty() {
        (vec![".".to_string()], options.to_vec(), true)
    } else {
        (paths.to_vec(), options.to_vec(), false)
    }
}

/// A token that neither starts with `-` nor directly follows a flag can't
/// be a flag value — it's a misplaced positional. (Every value-taking
/// option in `analyze`/`review` takes exactly one value, so a legitimate
/// value always has a `-`-leading predecessor.)
fn find_misplaced_positional(options: &[String]) -> Option<&str> {
    options.windows(2).find_map(|w| {
        if !w[0].starts_with('-') && !w[1].starts_with('-') {
            Some(w[1].as_str())
        } else {
            None
        }
    })
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Detect the run mode from the CI platform's event context. Platform
/// detection is shared (`ci_env::detect_ci_platform`); only the event
/// interpretation lives here.
fn detect_ci_mode() -> Option<CiMode> {
    match super::ci_env::detect_ci_platform()? {
        CiPlatform::GitHub => {
            let event = var("GITHUB_EVENT_NAME").unwrap_or_else(|| "push".to_string());
            if event == "pull_request" || event == "pull_request_target" {
                let base = github_base_sha()
                    .or_else(|| var("GITHUB_BASE_REF").map(|b| format!("origin/{}", b)));
                return match base {
                    Some(base) => Some(CiMode::Change {
                        range: format!("{}..HEAD", base),
                        detail: format!("GitHub Actions {} event", event),
                    }),
                    None => {
                        eprintln!(
                        "Error: GitHub Actions {} event but neither the event payload nor GITHUB_BASE_REF provides a base ref.",
                        event
                    );
                        process::exit(1);
                    }
                };
            }
            Some(CiMode::Snapshot {
                detail: format!("GitHub Actions {} event", event),
            })
        }
        CiPlatform::GitLab => {
            if var("CI_MERGE_REQUEST_IID").is_some() {
                // The diff-base SHA is an ancestor of the fetched MR head, so
                // it exists even though GitLab runners fetch a narrow refspec
                // (origin/<target-branch> usually is NOT fetched).
                let base = var("CI_MERGE_REQUEST_DIFF_BASE_SHA").or_else(|| {
                    var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME").map(|b| format!("origin/{}", b))
                });
                return match base {
                    Some(base) => Some(CiMode::Change {
                        range: format!("{}..HEAD", base),
                        detail: "GitLab CI merge-request pipeline".to_string(),
                    }),
                    None => {
                        eprintln!("Error: GitLab merge-request pipeline without CI_MERGE_REQUEST_DIFF_BASE_SHA.");
                        process::exit(1);
                    }
                };
            }
            Some(CiMode::Snapshot {
                detail: "GitLab CI branch pipeline".to_string(),
            })
        }
        CiPlatform::Bitbucket => {
            if var("BITBUCKET_PR_ID").is_some() {
                return match var("BITBUCKET_PR_DESTINATION_BRANCH") {
                    Some(branch) => Some(CiMode::Change {
                        range: format!("origin/{}..HEAD", branch),
                        detail: "Bitbucket Pipelines pull request".to_string(),
                    }),
                    None => {
                        eprintln!(
                            "Error: Bitbucket PR pipeline without BITBUCKET_PR_DESTINATION_BRANCH."
                        );
                        process::exit(1);
                    }
                };
            }
            Some(CiMode::Snapshot {
                detail: "Bitbucket Pipelines branch build".to_string(),
            })
        }
        CiPlatform::AzureDevOps => {
            if var("SYSTEM_PULLREQUEST_PULLREQUESTID").is_some() {
                return match var("SYSTEM_PULLREQUEST_TARGETBRANCH") {
                    Some(target) => Some(CiMode::Change {
                        range: format!("origin/{}..HEAD", strip_refs_heads(&target)),
                        detail: "Azure DevOps pull request build".to_string(),
                    }),
                    None => {
                        eprintln!(
                            "Error: Azure DevOps PR build without SYSTEM_PULLREQUEST_TARGETBRANCH."
                        );
                        process::exit(1);
                    }
                };
            }
            Some(CiMode::Snapshot {
                detail: "Azure DevOps branch build".to_string(),
            })
        }
    }
}

/// Exact base commit of the PR from the GitHub event payload — more
/// precise than `origin/<base-branch>`, which may have advanced past the
/// recorded merge base since the event fired.
fn github_base_sha() -> Option<String> {
    let event_path = var("GITHUB_EVENT_PATH")?;
    let content = std::fs::read_to_string(&event_path).ok()?;
    let event: serde_json::Value = serde_json::from_str(&content).ok()?;
    event
        .get("pull_request")
        .and_then(|pr| pr.get("base"))
        .and_then(|b| b.get("sha"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/// `refs/heads/main` → `main`; already-bare branch names pass through.
fn strip_refs_heads(branch_ref: &str) -> &str {
    branch_ref.strip_prefix("refs/heads/").unwrap_or(branch_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn split_defaults_to_recursive_whole_tree() {
        let (paths, options, defaulted) = split_paths_and_options(&v(&["--policy", "p.yml"]));
        assert_eq!(paths, v(&["."]));
        assert_eq!(options, v(&["--policy", "p.yml"]));
        assert!(defaulted);
    }

    #[test]
    fn split_keeps_leading_paths_and_forwards_flag_values_untouched() {
        let (paths, options, defaulted) =
            split_paths_and_options(&v(&["models/", "macros/", "--env", "prod"]));
        assert_eq!(paths, v(&["models/", "macros/"]));
        assert_eq!(options, v(&["--env", "prod"]));
        assert!(!defaulted);
    }

    #[test]
    fn split_never_reads_flag_values_as_paths() {
        // `prod` is --env's value; it must stay in the forwarded options.
        let (paths, options, defaulted) =
            split_paths_and_options(&v(&["--env", "prod", "models/"]));
        assert_eq!(paths, v(&["."]));
        assert_eq!(options, v(&["--env", "prod", "models/"]));
        assert!(defaulted);
    }

    #[test]
    fn misplaced_path_after_options_is_caught() {
        // `models/` after --env's value would double-analyze — flagged.
        assert_eq!(
            find_misplaced_positional(&v(&["--env", "prod", "models/"])),
            Some("models/")
        );
        // Flag values and repeated flag/value pairs are legitimate.
        assert_eq!(
            find_misplaced_positional(&v(&["--var", "a=1", "--var", "b=2", "--env", "prod"])),
            None
        );
    }

    #[test]
    fn strip_refs_heads_handles_both_forms() {
        assert_eq!(strip_refs_heads("refs/heads/main"), "main");
        assert_eq!(strip_refs_heads("main"), "main");
    }

    #[test]
    fn snapshot_runs_drop_pr_comment_but_keep_everything_else() {
        let (kept, dropped) =
            strip_review_only_options(v(&["--pr-comment", "--policy", "p.yml", "--env", "prod"]));
        assert_eq!(kept, v(&["--policy", "p.yml", "--env", "prod"]));
        assert_eq!(dropped, ["--pr-comment"]);

        let (kept, dropped) = strip_review_only_options(v(&["--policy", "p.yml"]));
        assert_eq!(kept, v(&["--policy", "p.yml"]));
        assert!(dropped.is_empty());
    }
}
