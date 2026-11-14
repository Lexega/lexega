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
                if let Some(first) = forced_range.as_ref().filter(|first| **first != rest[i + 1]) {
                    eprintln!(
                        "Error: --range is given twice, as '{}' and as '{}'; give it once",
                        first,
                        rest[i + 1]
                    );
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

    let (paths, options) = split_paths_and_options(&remaining);
    let recursion = recursion_flag(&options);

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
            forwarded.extend(recursion);
            forwarded.extend(options);
            crate::dispatch(&forwarded, ext);
        }
        CiMode::Snapshot { detail } => {
            eprintln!("ci: {} → analyzing current state", detail);
            let mut forwarded = vec![args[0].clone(), "analyze".to_string()];
            forwarded.extend(paths);
            forwarded.extend(recursion);
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

/// `-r` unless the options already ask for recursion: a directory `ci` is
/// given is read with everything under it, on a change and a snapshot run
/// alike.
fn recursion_flag(options: &[String]) -> Option<String> {
    let given = options.iter().any(|o| o == "-r" || o == "--recursive");
    (!given).then(|| "-r".to_string())
}

/// Leading non-flag arguments are paths; everything from the first flag
/// onward is forwarded verbatim, so flag VALUES are never misread as
/// paths. With no paths given, the whole tree.
fn split_paths_and_options(args: &[String]) -> (Vec<String>, Vec<String>) {
    let split = args
        .iter()
        .position(|a| a.starts_with('-'))
        .unwrap_or(args.len());
    let (paths, options) = args.split_at(split);
    // Paths after `--` are explicit; nothing is defaulted around them.
    let explicit_after_dashes = options
        .iter()
        .position(|a| a == "--")
        .is_some_and(|at| at + 1 < options.len());
    if paths.is_empty() && !explicit_after_dashes {
        (vec![".".to_string()], options.to_vec())
    } else {
        (paths.to_vec(), options.to_vec())
    }
}

/// A token that neither starts with `-` nor directly follows a flag can't
/// be a flag value — it's a misplaced positional. (Every value-taking
/// option in `analyze`/`review` takes exactly one value, so a legitimate
/// value always has a `-`-leading predecessor.)
fn find_misplaced_positional(options: &[String]) -> Option<&str> {
    let end = options
        .iter()
        .position(|a| a == "--")
        .unwrap_or(options.len());
    options[..end].windows(2).find_map(|w| {
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
                let pull_request = github_pull_request();
                let base = pull_request
                    .as_ref()
                    .and_then(|pr| pull_request_sha(pr, "base"))
                    .or_else(|| var("GITHUB_BASE_REF").map(|b| format!("origin/{}", b)));
                let Some(base) = base else {
                    eprintln!(
                        "Error: GitHub Actions {} event but neither the event payload nor GITHUB_BASE_REF provides a base ref.",
                        event
                    );
                    process::exit(1);
                };
                // On `pull_request_target` the workflow checks out the base
                // branch: the pull request's head is the commit the event
                // names, read from git whatever is checked out.
                let head = if event == "pull_request_target" {
                    let Some(pr) = pull_request.as_ref() else {
                        refuse_target_without_head();
                    };
                    let Some(head) = pull_request_sha(pr, "head") else {
                        refuse_target_without_head();
                    };
                    // A fork's head is fetched by no checkout of the base
                    // repository's branches: it is under the pull request's
                    // own ref.
                    let held = super::git::holds_commit(&head).unwrap_or_else(|e| {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    });
                    if !held {
                        let fetch = pr
                            .get("number")
                            .and_then(|n| n.as_u64())
                            .map_or_else(|| head.clone(), |n| format!("pull/{}/head", n));
                        eprintln!(
                            "Error: the pull request's head commit {} is not in this clone: on pull_request_target the checkout is the base branch. Fetch the head before `ci`: `git fetch origin {}`.",
                            head, fetch
                        );
                        process::exit(1);
                    }
                    head
                } else {
                    "HEAD".to_string()
                };
                return Some(CiMode::Change {
                    range: format!("{}..{}", base, head),
                    detail: format!("GitHub Actions {} event", event),
                });
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

/// The `pull_request` object of the GitHub event payload.
fn github_pull_request() -> Option<serde_json::Value> {
    let event_path = var("GITHUB_EVENT_PATH")?;
    let content = std::fs::read_to_string(&event_path).ok()?;
    let mut event: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(event.get_mut("pull_request")?.take())
}

/// The commit of the pull request's `side` (`base` or `head`). Its base is
/// more precise than `origin/<base-branch>`, which may have advanced past
/// the recorded merge base since the event fired.
fn pull_request_sha(pull_request: &serde_json::Value, side: &str) -> Option<String> {
    pull_request
        .get(side)
        .and_then(|b| b.get("sha"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/// Stop a `pull_request_target` run whose payload names no head commit.
fn refuse_target_without_head() -> ! {
    eprintln!(
        "Error: GitHub Actions pull_request_target event but the event payload gives no pull_request.head.sha: on this event the checkout is the base branch, and the pull request's head is the commit the payload names."
    );
    process::exit(1);
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
    fn split_defaults_to_the_whole_tree() {
        let (paths, options) = split_paths_and_options(&v(&["--policy", "p.yml"]));
        assert_eq!(paths, v(&["."]));
        assert_eq!(options, v(&["--policy", "p.yml"]));
    }

    #[test]
    fn every_path_is_read_recursively_unless_the_options_say_so() {
        assert_eq!(
            recursion_flag(&v(&["--env", "prod"])),
            Some("-r".to_string())
        );
        assert_eq!(recursion_flag(&v(&["-r", "--env", "prod"])), None);
        assert_eq!(recursion_flag(&v(&["--recursive"])), None);
    }

    #[test]
    fn split_keeps_leading_paths_and_forwards_flag_values_untouched() {
        let (paths, options) =
            split_paths_and_options(&v(&["models/", "macros/", "--env", "prod"]));
        assert_eq!(paths, v(&["models/", "macros/"]));
        assert_eq!(options, v(&["--env", "prod"]));
    }

    #[test]
    fn split_never_reads_flag_values_as_paths() {
        // `prod` is --env's value; it must stay in the forwarded options.
        let (paths, options) = split_paths_and_options(&v(&["--env", "prod", "models/"]));
        assert_eq!(paths, v(&["."]));
        assert_eq!(options, v(&["--env", "prod", "models/"]));
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
