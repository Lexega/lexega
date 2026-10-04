// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `lexega` binary, end to end.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_in(dir: &Path, args: &[&str], stdin: Option<&str>) -> Run {
    run_env(dir, args, stdin, &[])
}

fn run_env(dir: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lexega"))
        .args(args)
        .current_dir(dir)
        .envs(env.iter().copied())
        // A pull-request context in the environment would turn
        // `--pr-comment` into a network call.
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITLAB_CI")
        .env_remove("TF_BUILD")
        .env_remove("BITBUCKET_BUILD_NUMBER")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lexega");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write stdin");
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn run(args: &[&str], stdin: Option<&str>) -> Run {
    run_in(Path::new("."), args, stdin)
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(["-c", "user.name=test", "-c", "user.email=test@example.com"])
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn rule_ids(signals: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = signals
        .as_array()
        .expect("signals array")
        .iter()
        .map(|s| s["matched_rule"].as_str().expect("rule id").to_string())
        .collect();
    ids.sort();
    ids
}

/// A procedure whose dynamic statement only deeper analysis can prove
/// harmless, so recognition reports it.
const DYNAMIC_SQL: &str = "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN LET stmt := 'SELECT 1'; EXECUTE IMMEDIATE :stmt; END $$;";

#[test]
fn version_names_the_build() {
    let out = run(&["--version"], None);
    assert_eq!(out.code, 0);
    assert_eq!(
        out.stdout.trim(),
        format!("lexega {} (recognition)", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn licenses_prints_the_notices_for_this_binary() {
    let out = run(&["--licenses"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout
            .contains("This software (lexega) includes the following third-party dependencies."),
        "{}",
        &out.stdout[..out.stdout.len().min(400)]
    );
    for dependency in ["serde_json", "rayon"] {
        assert!(
            out.stdout.contains(dependency),
            "{dependency} is not listed"
        );
    }
}

#[test]
fn analyze_reports_findings_and_its_depth() {
    let out = run(
        &["analyze", "--stdin"],
        Some("DELETE FROM orders WHERE 1 = 1;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("DML-WRITE-UNBOUNDED"), "{}", out.stdout);
    assert!(
        out.stdout
            .contains("rules use analysis this build does not include and may stay silent or report less precisely."),
        "{}",
        out.stdout
    );
}

#[test]
fn analyze_json_matches_the_recognition_engine() {
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--format",
            "json",
            "--min-severity",
            "info",
        ],
        Some(DYNAMIC_SQL),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");

    let expected = lexega_core::Engine::recognition()
        .analyze_risk(DYNAMIC_SQL)
        .expect("analysis succeeds");
    let depth = expected
        .summary
        .analysis_depth
        .clone()
        .expect("depth is reported");
    assert_eq!(
        report["summary"]["analysis_depth"],
        serde_json::json!({
            "rules_total": depth.rules_total,
            "rules_limited": depth.rules_limited,
        })
    );
    let expected_signals = serde_json::to_value(&expected.signals).expect("signals serialize");
    let ids = rule_ids(&report["signals"]);
    assert_eq!(ids, rule_ids(&expected_signals));
    assert!(ids.iter().any(|id| id == "DYNSQL"), "{ids:?}");
}

#[test]
fn features_outside_this_build_are_refused_by_name() {
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--policy",
            "policy.yaml",
            "--cross-script",
            "--dbt-project",
            ".",
            "--mode",
            "runtime",
        ],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 1);
    for label in [
        "policy enforcement and decision records",
        "cross-script analysis",
        "runtime policy gate for agent-generated SQL",
        "Jinja / dbt template rendering",
    ] {
        assert!(out.stderr.contains(label), "{label}: {}", out.stderr);
    }
    assert!(out.stderr.contains("full build"), "{}", out.stderr);
}

#[test]
fn help_lists_no_option_this_build_refuses() {
    let refused = [
        "--policy",
        "--decision-out",
        "--exceptions",
        "--cross-script",
        "--dbt-project",
        "--dbt-profile",
        "--load-macros",
        "--render-jinja",
    ];
    for command in ["analyze", "review", "ci", "fmt"] {
        let out = run(&[command, "--help"], None);
        assert_eq!(out.code, 0, "{command}: {}", out.stderr);
        let help = format!("{}{}", out.stdout, out.stderr);
        assert!(help.contains("Usage:"), "{command}: {help}");
        for option in refused {
            assert!(!help.contains(option), "{command} --help lists {option}");
        }
    }
}

#[test]
fn a_gated_ci_run_is_refused_without_naming_a_refused_option() {
    let out = run_env(
        Path::new("."),
        &["analyze", "--stdin"],
        Some("SELECT 1;"),
        &[("LEXEGA_CI", "1")],
    );
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(out.stderr.contains("LEXEGA_CI"), "{}", out.stderr);
    assert!(out.stderr.contains("no policy gate"), "{}", out.stderr);
    assert!(!out.stderr.contains("--policy"), "{}", out.stderr);
}

#[test]
fn the_rule_primer_names_real_rules_and_its_example_fires() {
    let out = run(&["analyze", "--list-signals"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let primer = out.stdout.as_str();
    assert!(
        primer.contains("https://lexega.com/docs/rule-reference"),
        "{primer}"
    );
    assert!(!primer.contains("examples/"), "{primer}");

    let (introduction, rest) = primer
        .split_once("Authoring custom rules:")
        .expect("authoring section");
    let builtin = lexega_core::rules::all_builtin_rules().expect("corpus loads");
    let named: Vec<&str> = introduction
        .split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .filter(|word| word.len() > 3 && word.contains('-') && !word.starts_with('-'))
        .collect();
    assert!(!named.is_empty(), "{introduction}");
    for id in named {
        assert!(
            builtin.iter().any(|rule| rule.id == id),
            "{id} is not a built-in rule"
        );
    }

    let (example, _) = rest.split_once("TRIGGERS").expect("triggers section");
    let dir = TempDir::new().expect("temp dir");
    let rules = dir.path().join("rules.yaml");
    std::fs::write(&rules, format!("rules:\n{example}")).expect("write rules");
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--no-builtin",
            "--custom-rules",
            rules.to_str().expect("utf-8 path"),
            "--format",
            "json",
            "--min-severity",
            "info",
        ],
        Some("SELECT * FROM orders;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(rule_ids(&report["signals"]), ["MY-CUSTOM-001"]);
}

/// The sentence a report of this build says its depth with.
const DEPTH_NOTE: &str =
    "rules use analysis this build does not include and may stay silent or report less precisely.";

fn assert_sarif_names_rules_and_says_its_depth(sarif: &serde_json::Value) {
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    assert!(!rules.is_empty(), "{sarif}");
    for rule in rules {
        assert_eq!(rule["name"], rule["id"]);
        assert_eq!(rule["shortDescription"]["text"], rule["id"]);
    }
    let notes = run["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("notifications");
    assert_eq!(notes.len(), 1, "{sarif}");
    assert_eq!(notes[0]["descriptor"]["id"], "analysis-depth");
    assert!(
        notes[0]["message"]["text"]
            .as_str()
            .is_some_and(|text| text.ends_with(DEPTH_NOTE)),
        "{sarif}"
    );
}

#[test]
fn sarif_names_each_rule_by_its_id_and_says_its_depth() {
    let out = run(
        &["analyze", "--stdin", "--format", "sarif"],
        Some("DELETE FROM orders WHERE 1 = 1;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    assert_sarif_names_rules_and_says_its_depth(&sarif);
    assert_eq!(
        sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"],
        "DML-WRITE-UNBOUNDED"
    );
}

#[test]
fn gl_sast_names_each_finding_by_its_rule_and_says_its_depth() {
    let out = run(
        &["analyze", "--stdin", "--format", "gl-sast"],
        Some("DELETE FROM orders WHERE 1 = 1;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("gl-sast");
    let finding = &report["vulnerabilities"][0];
    assert_eq!(finding["name"], "DML-WRITE-UNBOUNDED");
    assert_eq!(finding["name"], finding["identifiers"][0]["value"]);
    let messages = report["scan"]["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1, "{report}");
    assert_eq!(messages[0]["level"], "info");
    assert!(
        messages[0]["value"]
            .as_str()
            .is_some_and(|text| text.ends_with(DEPTH_NOTE)),
        "{report}"
    );
}

#[test]
fn reports_name_the_tool_by_this_binary() {
    let sql = Some("DELETE FROM orders WHERE 1 = 1;");
    let out = run(&["analyze", "--stdin", "--format", "sarif"], sql);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "lexega");

    let out = run(&["analyze", "--stdin", "--format", "gl-sast"], sql);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("gl-sast");
    assert_eq!(report["scan"]["scanner"]["id"], "lexega");
    assert_eq!(report["scan"]["analyzer"]["id"], "lexega");
}

#[test]
fn templates_are_analyzed_as_written() {
    let out = run(
        &["analyze", "--stdin", "--format", "json"],
        Some("SELECT * FROM {{ ref('orders') }};"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(report["summary"]["render_completeness"], "not_rendered");
    assert_eq!(report["summary"]["analysis_confidence"], "low");
}

#[test]
fn deployment_variables_are_substituted() {
    let out = run(
        &[
            "analyze", "--stdin", "--var", "ENV=prod", "--format", "json",
        ],
        Some("DELETE FROM ${ENV}_db.public.orders;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(report["summary"]["render_completeness"], "full");
    assert!(
        out.stdout.to_lowercase().contains("prod_db"),
        "{}",
        out.stdout
    );
}

#[test]
fn a_catalog_snapshot_is_loaded() {
    let dir = TempDir::new().expect("temp dir");
    let catalog = dir.path().join("catalog.json");
    std::fs::write(
        &catalog,
        r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": []}"#,
    )
    .expect("write catalog");
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--format",
            "json",
            "--catalog",
            catalog.to_str().expect("utf-8 path"),
        ],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(report["catalog_info"]["catalog_loaded"], true);
}

/// A rule over a fact this build leaves at its default.
const RULE_ON_AN_UNFILLED_FACT: &str = r#"rules:
  - id: MY-STALE-REF
    risk_level: high
    message: "Reads a table an earlier statement dropped."
    triggers:
      query.stale_table_refs:
        count: { gt: 0 }
"#;

#[test]
fn a_custom_rule_sees_the_facts_a_built_in_rule_sees() {
    let dir = TempDir::new().expect("temp dir");
    let rules = dir.path().join("rules.yaml");
    std::fs::write(&rules, RULE_ON_AN_UNFILLED_FACT).expect("write rules");
    let sql = "DROP TABLE staging.t1;\nSELECT id FROM staging.t1 WHERE id = 1;";

    let report = |extra: &[&str]| -> serde_json::Value {
        let mut args = vec![
            "analyze",
            "--stdin",
            "--format",
            "json",
            "--min-severity",
            "info",
        ];
        args.extend_from_slice(extra);
        let out = run(&args, Some(sql));
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
        serde_json::from_str(&out.stdout).expect("json report")
    };
    let built_in = report(&[]);
    let with_rule = report(&["--custom-rules", rules.to_str().expect("utf-8 path")]);

    // The rule has nothing to match, and the report counts it among the
    // rules that ran without analysis they use.
    assert!(
        !rule_ids(&with_rule["signals"]).contains(&"MY-STALE-REF".to_string()),
        "{}",
        with_rule["signals"]
    );
    let depth = |report: &serde_json::Value, count: &str| -> u64 {
        report["summary"]["analysis_depth"][count]
            .as_u64()
            .expect("a count")
    };
    assert_eq!(
        depth(&with_rule, "rules_total"),
        depth(&built_in, "rules_total") + 1
    );
    assert_eq!(
        depth(&with_rule, "rules_limited"),
        depth(&built_in, "rules_limited") + 1
    );
}

#[test]
fn rules_are_fetched_from_a_remote_location() {
    // Nothing listens on port 1: the run gets as far as fetching the rules.
    let rules = "http://127.0.0.1:1/rules.yaml";
    let out = run(
        &["analyze", "--stdin", "--custom-rules", rules],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 1);
    assert!(
        out.stderr
            .contains(&format!("Failed to load custom rules from '{rules}'")),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("full build"), "{}", out.stderr);
}

#[test]
fn catalog_help_names_every_provider_and_the_bundled_extractors() {
    let out = run(&["catalog", "--help"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    for provider in lexega_core::builtin_catalog_provider_names() {
        assert!(out.stderr.contains(provider), "{provider}: {}", out.stderr);
    }
    assert!(
        out.stderr
            .contains("Extractors are bundled for snowflake, databricks, mssql"),
        "{}",
        out.stderr
    );
}

#[test]
fn fmt_formats_standard_input() {
    let out = run(&["fmt", "--stdin"], Some("select a from t"));
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("SELECT"), "{}", out.stdout);
}

#[test]
fn fmt_refuses_to_render_templates() {
    let out = run(
        &["fmt", "--stdin", "--var", "x=1"],
        Some("select {{ var('x') }}"),
    );
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("Jinja / dbt template rendering"),
        "{}",
        out.stderr
    );
}

#[test]
fn commands_of_other_builds_are_unknown() {
    let out = run(&["diff", "main..HEAD"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("Unknown command: diff"),
        "{}",
        out.stderr
    );
}

/// A repository whose last commit adds an unbounded delete to `a.sql`
/// and leaves `b.sql` untouched.
fn repo_with_a_change() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    std::fs::write(root.join("b.sql"), "DROP TABLE prod.orders;\n").expect("write b.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(root.join("a.sql"), "DELETE FROM orders WHERE 1 = 1;\n").expect("write a.sql");
    git(root, &["commit", "-q", "-am", "change"]);
    dir
}

#[test]
fn review_analyzes_the_changed_files_at_the_head_commit() {
    let repo = repo_with_a_change();
    // The working tree moves on; the review still reads the commit.
    std::fs::write(repo.path().join("a.sql"), "SELECT 2;\n").expect("write a.sql");

    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    let files = batch["files"].as_array().expect("files");
    assert_eq!(files.len(), 1, "{}", out.stdout);
    assert_eq!(files[0]["file"], "a.sql");
    let report = &files[0]["result"]["report"];
    assert_eq!(rule_ids(&report["signals"]), ["DML-WRITE-UNBOUNDED"]);
    assert_eq!(report["run_scope"]["kind"], "change");
    assert_eq!(report["run_scope"]["base"], "HEAD~1");
    assert!(batch["batch_summary"]["analysis_depth"]["rules_limited"]
        .as_u64()
        .is_some_and(|n| n > 0));
}

#[test]
fn review_reports_in_markdown_with_per_file_detail() {
    let repo = repo_with_a_change();
    let out = run_in(repo.path(), &["review", "HEAD~1..HEAD", "--quiet"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout.contains("Batch Analysis Summary"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("#### `a.sql`"), "{}", out.stdout);
    assert!(out.stdout.contains("**Note**:"), "{}", out.stdout);
}

#[test]
fn review_without_a_pull_request_prints_the_comment_once() {
    let repo = repo_with_a_change();
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--quiet", "--pr-comment"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(out.stdout.matches("Batch Analysis Summary").count(), 1);
    assert!(
        out.stderr.contains("Cannot post PR comment"),
        "{}",
        out.stderr
    );
}

#[test]
fn review_of_a_range_without_sql_changes_does_nothing() {
    let repo = repo_with_a_change();
    std::fs::write(repo.path().join("notes.txt"), "x\n").expect("write notes");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "docs"]);
    let out = run_in(repo.path(), &["review", "HEAD~1..HEAD"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(
        out.stderr.contains("No SQL files changed"),
        "{}",
        out.stderr
    );
}

#[test]
fn ci_range_runs_the_review() {
    let repo = repo_with_a_change();
    let out = run_in(
        repo.path(),
        &[
            "ci",
            "--range",
            "HEAD~1..HEAD",
            "--format",
            "json",
            "--quiet",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(batch["files"].as_array().map(Vec::len), Some(1));
}

#[test]
fn ci_snapshot_analyzes_the_tree() {
    let repo = repo_with_a_change();
    let out = run_in(
        repo.path(),
        &["ci", "--snapshot", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(batch["files"].as_array().map(Vec::len), Some(2));
}

#[test]
fn a_batch_says_its_depth_in_sarif_on_stdout_and_in_the_report_file() {
    let repo = repo_with_a_change();
    let out = run_in(
        repo.path(),
        &["analyze", ".", "-r", "--format", "sarif", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    assert_sarif_names_rules_and_says_its_depth(&sarif);

    let out = run_in(
        repo.path(),
        &["analyze", ".", "-r", "--report-out", "out.sarif", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let written = std::fs::read_to_string(repo.path().join("out.sarif")).expect("read out.sarif");
    let sarif: serde_json::Value = serde_json::from_str(&written).expect("sarif");
    assert_sarif_names_rules_and_says_its_depth(&sarif);
}

#[test]
fn a_batch_summary_lists_matched_rules_by_id_alone() {
    let repo = repo_with_a_change();
    let out = run_in(repo.path(), &["analyze", ".", "-r"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stderr
            .contains("Top Matched Rules:\n  DML-WRITE-UNBOUNDED - 1 occurrence(s)"),
        "{}",
        out.stderr
    );

    let out = run_in(repo.path(), &["review", "HEAD~1..HEAD", "--quiet"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout.contains(
            "| Rule | Occurrences |\n|------|-------------|\n| `DML-WRITE-UNBOUNDED` | 1 |"
        ),
        "{}",
        out.stdout
    );
}

/// A directory holding `.lexega.toml` with `config` and `q.sql` with `sql`.
fn project_with_config(config: &str, sql: &str) -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join(".lexega.toml"), config).expect("write config");
    std::fs::write(dir.path().join("q.sql"), sql).expect("write q.sql");
    dir
}

#[test]
fn a_config_file_cannot_name_environment_variables() {
    let project = project_with_config(
        "[template.substitution]\nenv = [\"LEXEGA_TEST_SECRET\"]\n",
        "SELECT a FROM t WHERE \"${LEXEGA_TEST_SECRET}\" NOT IN (SELECT b FROM u);\n",
    );
    let out = run_env(
        project.path(),
        &["analyze", "q.sql", "--min-severity", "info"],
        None,
        &[("LEXEGA_TEST_SECRET", "s3cr3t-value")],
    );
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr
            .contains("`env` is not read from a configuration file"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("--var-env"), "{}", out.stderr);
    assert!(!out.stdout.contains("s3cr3t-value"), "{}", out.stdout);
    assert!(!out.stderr.contains("s3cr3t-value"), "{}", out.stderr);
}

#[test]
fn a_config_file_cannot_define_delimiters() {
    let project = project_with_config(
        "[[template.substitution.custom]]\nprefix = \"%%\"\nsuffix = \"%%\"\n",
        "SELECT 1;\n",
    );
    let out = run_in(project.path(), &["analyze", "q.sql"], None);
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr
            .contains("`custom` is not read from a configuration file"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("--var-syntax"), "{}", out.stderr);
}

#[test]
fn a_config_file_selects_among_the_presets() {
    let project = project_with_config(
        "[template.substitution]\npresets = [\"dollar-paren\"]\n",
        "DELETE FROM $(ENV)_db.public.orders;\n",
    );
    let out = run_in(
        project.path(),
        &["analyze", "q.sql", "--var", "ENV=prod", "--format", "json"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout.to_lowercase().contains("prod_db"),
        "{}",
        out.stdout
    );
}

#[test]
fn a_marker_shape_on_the_command_line_is_substituted() {
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--var-syntax",
            "%%NAME%%",
            "--var",
            "ENV=prod",
            "--format",
            "json",
        ],
        Some("DELETE FROM %%ENV%%_db.public.orders;"),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(report["summary"]["render_completeness"], "full");
    assert!(
        out.stdout.to_lowercase().contains("prod_db"),
        "{}",
        out.stdout
    );
}

/// A repository whose last commit adds the same unbounded delete under five
/// names: plain, non-ASCII, upper-case extension, a `tests` directory and a
/// `macros` directory.
fn repo_with_awkward_names() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("base.sql"), "SELECT 1;\n").expect("write base.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    for name in [
        "models/plain.sql",
        "models/caf\u{e9}.sql",
        "models/upper.SQL",
        "tests/check.sql",
        "macros/helper.sql",
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "DELETE FROM orders WHERE 1 = 1;\n").expect("write sql");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "change"]);
    dir
}

#[test]
fn review_reads_every_changed_sql_file_or_lists_it_as_skipped() {
    let repo = repo_with_awkward_names();
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");

    let files = batch["files"].as_array().expect("files");
    let mut analyzed: Vec<&str> = files
        .iter()
        .map(|f| f["file"].as_str().expect("file name"))
        .collect();
    analyzed.sort_unstable();
    assert_eq!(analyzed.len(), 4, "{analyzed:?}");
    assert!(analyzed.contains(&"models/plain.sql"), "{analyzed:?}");
    assert!(analyzed.contains(&"models/upper.SQL"), "{analyzed:?}");
    assert!(analyzed.contains(&"tests/check.sql"), "{analyzed:?}");
    assert!(
        analyzed.iter().any(|name| name.starts_with("models/caf")),
        "{analyzed:?}"
    );
    for file in files {
        assert_eq!(
            rule_ids(&file["result"]["report"]["signals"]),
            ["DML-WRITE-UNBOUNDED"],
            "{}",
            file["file"]
        );
    }

    assert_eq!(batch["batch_summary"]["files_total"], 5);
    assert_eq!(batch["batch_summary"]["files_skipped"], 1);
    let skipped = batch["skipped_files"].as_array().expect("skipped files");
    assert_eq!(skipped.len(), 1, "{}", out.stdout);
    assert_eq!(skipped[0]["path"], "macros/helper.sql");
    assert!(
        skipped[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("macros directory")),
        "{}",
        skipped[0]
    );
}

#[test]
fn review_markdown_says_when_a_changed_file_was_not_analyzed() {
    let repo = repo_with_awkward_names();
    let out = run_in(repo.path(), &["review", "HEAD~1..HEAD", "--quiet"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout.contains("**1 file(s) not analyzed**"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("`helper.sql`"), "{}", out.stdout);
}

#[test]
fn review_of_a_range_that_only_changes_skipped_files_still_reports_them() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("base.sql"), "SELECT 1;\n").expect("write base.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::create_dir_all(root.join("macros")).expect("create dir");
    std::fs::write(root.join("macros/helper.sql"), "DROP TABLE prod.orders;\n").expect("write sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "change"]);

    let out = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(batch["batch_summary"]["files_processed"], 0);
    assert_eq!(batch["skipped_files"][0]["path"], "macros/helper.sql");
}

/// A tree whose `repo/` holds `ok.sql` and `leak.sql`, a symbolic link to
/// a file outside `repo/`.
#[cfg(unix)]
fn tree_with_a_link_out(outside_name: &str, outside_text: &str) -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    std::fs::create_dir_all(root.join("repo")).expect("create repo");
    std::fs::create_dir_all(root.join("outside")).expect("create outside");
    std::fs::write(root.join("outside").join(outside_name), outside_text).expect("write outside");
    std::fs::write(root.join("repo/ok.sql"), "select  1;\n").expect("write ok.sql");
    std::os::unix::fs::symlink(
        Path::new("../outside").join(outside_name),
        root.join("repo/leak.sql"),
    )
    .expect("symlink");
    dir
}

#[cfg(unix)]
#[test]
fn a_directory_scan_does_not_follow_symbolic_links() {
    let tree = tree_with_a_link_out("secret.txt", "db_password=Sup3rS3cret\n");
    let out = run_in(
        tree.path(),
        &[
            "analyze",
            "repo",
            "-r",
            "--format",
            "json",
            "--quiet",
            "--min-severity",
            "info",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(!out.stdout.contains("Sup3rS3cret"), "{}", out.stdout);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(batch["files"].as_array().map(Vec::len), Some(1));
    assert_eq!(batch["batch_summary"]["files_skipped"], 1);
    let skipped = &batch["skipped_files"][0];
    assert!(
        skipped["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("leak.sql")),
        "{skipped}"
    );
    assert!(
        skipped["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("symbolic link")),
        "{skipped}"
    );
}

#[cfg(unix)]
#[test]
fn fmt_does_not_write_through_a_symbolic_link_it_finds() {
    let tree = tree_with_a_link_out("target.sql", "select  1;\n");
    let out = run_in(tree.path(), &["fmt", "repo", "-r", "-w"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let outside = std::fs::read_to_string(tree.path().join("outside/target.sql")).expect("read");
    assert_eq!(outside, "select  1;\n");
    let inside = std::fs::read_to_string(tree.path().join("repo/ok.sql")).expect("read");
    assert_ne!(inside, "select  1;\n");
    assert!(out.stderr.contains("symbolic link"), "{}", out.stderr);
}
