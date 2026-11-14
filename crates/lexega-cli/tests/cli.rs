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
        let written = child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(input.as_bytes());
        // A run refused before it reads its input may exit first.
        if let Err(e) = written {
            assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "write stdin: {e}");
        }
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

fn rule_ids(findings: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = findings
        .as_array()
        .expect("findings array")
        .iter()
        .map(|s| s["matched_rule"].as_str().expect("rule id").to_string())
        .collect();
    ids.sort();
    ids
}

/// A procedure whose dynamic statement only deeper analysis can prove
/// harmless, so recognition reports it.
const DYNAMIC_SQL: &str = "CREATE PROCEDURE p() RETURNS STRING LANGUAGE SQL EXECUTE AS CALLER AS $$ BEGIN LET stmt := 'SELECT 1'; EXECUTE IMMEDIATE :stmt; END $$;";

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
fn analyze_names_itself_in_an_unknown_argument_error() {
    let out = run(&["analyze", "--stdin", "--bogus"], Some("SELECT 1;"));
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(
        out.stderr
            .contains("Error: Unknown analyze argument '--bogus'"),
        "stderr: {}",
        out.stderr
    );
}

#[test]
fn a_bare_double_dash_ends_the_options_of_analyze_review_and_ci() {
    let dir = TempDir::new().expect("temp dir");
    git(dir.path(), &["init", "-q"]);
    std::fs::write(dir.path().join("a.sql"), "SELECT 1;\n").expect("write");
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-q", "-m", "base"]);
    std::fs::write(dir.path().join("a.sql"), "DROP TABLE t;\n").expect("write");
    git(dir.path(), &["commit", "-q", "-am", "head"]);
    let ci_range = ["ci", "--range", "HEAD~1..HEAD"];
    for command in [&["analyze"][..], &["review", "HEAD~1..HEAD"], &ci_range] {
        let mut named = command.to_vec();
        named.extend(["--format", "json", "--", "a.sql"]);
        let out = run_in(dir.path(), &named, None);
        assert_eq!(out.code, 0, "{named:?}\nstderr: {}", out.stderr);
        let mut weird = command.to_vec();
        weird.extend(["--", "--weird.sql"]);
        let out = run_in(dir.path(), &weird, None);
        assert_eq!(out.code, 1, "{weird:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains("--weird.sql"),
            "{weird:?}\n{}",
            out.stderr
        );
    }
}

#[test]
fn built_in_rules_off_and_no_custom_rules_run_no_rule() {
    for off in [&["--no-builtin"][..], &["--builtin-rules", "false"]] {
        let mut args = vec!["analyze", "--stdin", "--format", "json"];
        args.extend_from_slice(off);
        let out = run(&args, Some("DELETE FROM orders;"));
        assert_eq!(out.code, 0, "{off:?} stderr: {}", out.stderr);
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
        assert_eq!(
            rule_ids(&report["findings"]),
            Vec::<String>::new(),
            "{off:?}"
        );
        assert!(
            out.stderr.contains("no rule runs"),
            "{off:?} stderr: {}",
            out.stderr
        );
    }
}

/// A directory holding an `aws` that records each upload it is asked for:
/// its arguments in `calls.log`, what it reads in `upload.txt`.
#[cfg(unix)]
fn recording_aws() -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let bin = TempDir::new().expect("temp dir");
    let aws = bin.path().join("aws");
    std::fs::write(
        &aws,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{dir}/calls.log'\ncat > '{dir}/upload.txt'\n",
            dir = bin.path().display()
        ),
    )
    .expect("write aws");
    std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

// A SARIF report `--report-out` sends to a cloud URI is uploaded, as every
// other report is, not written to a local directory named after the URI.
#[cfg(unix)]
#[test]
fn a_sarif_report_out_to_a_cloud_uri_is_uploaded() {
    let bin = recording_aws();
    let dir = TempDir::new().expect("temp dir");
    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = run_env(
        dir.path(),
        &[
            "analyze",
            "--stdin",
            "--format",
            "sarif",
            "--report-out",
            "s3://bkt/out/",
        ],
        Some("DELETE FROM orders;"),
        &[("PATH", path.as_str())],
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let calls = std::fs::read_to_string(bin.path().join("calls.log")).unwrap_or_default();
    assert_eq!(calls.trim(), "s3 cp - s3://bkt/out/analysis_report.sarif");
    let uploaded: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(bin.path().join("upload.txt")).expect("upload"),
    )
    .expect("sarif json");
    assert!(uploaded["runs"].is_array(), "{uploaded}");
    assert!(!dir.path().join("s3:").exists());
}

// A batch's `--report-out` to a cloud URI is uploaded and one of `-` is
// printed; neither leaves a local directory named after it.
#[cfg(unix)]
#[test]
fn a_batch_report_out_to_a_cloud_uri_or_stdout_makes_no_local_directory() {
    let bin = recording_aws();
    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let repo = repo_with_a_change();
    let entries = || {
        let mut names: Vec<String> = std::fs::read_dir(repo.path())
            .expect("read repo")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort_unstable();
        names
    };
    let before = entries();
    for command in [
        &["review", "HEAD~1..HEAD"][..],
        &["ci", "--range", "HEAD~1..HEAD"],
        &["analyze", ".", "-r"],
    ] {
        for out in ["s3://bkt/out/", "-"] {
            let mut args = command.to_vec();
            args.extend_from_slice(&["--format", "sarif", "--report-out", out]);
            let run = run_env(repo.path(), &args, None, &[("PATH", path.as_str())]);
            assert_eq!(run.code, 0, "{args:?}\nstderr: {}", run.stderr);
            assert_eq!(entries(), before, "{args:?}");
            if out == "-" {
                assert!(run.stdout.contains("\"runs\""), "{args:?}\n{}", run.stdout);
            } else {
                let calls =
                    std::fs::read_to_string(bin.path().join("calls.log")).unwrap_or_default();
                assert_eq!(
                    calls.lines().last(),
                    Some("s3 cp - s3://bkt/out/batch_summary.sarif"),
                    "{args:?}"
                );
                std::fs::remove_file(bin.path().join("calls.log")).expect("clear calls");
            }
        }
    }
}

// A batch's local `--report-out` is written into a directory it names,
// new (with its parents) or existing, or to the file it names.
#[test]
fn a_batch_report_out_is_written_to_the_local_directory_or_file_it_names() {
    let repo = repo_with_a_change();
    for command in [&["review", "HEAD~1..HEAD"][..], &["analyze", ".", "-r"]] {
        let out = TempDir::new().expect("temp dir");
        std::fs::create_dir(out.path().join("existing")).expect("existing dir");
        for (target, written) in [
            ("new/nested/", "new/nested/batch_summary.sarif"),
            ("existing", "existing/batch_summary.sarif"),
            ("deep/dir/report.sarif", "deep/dir/report.sarif"),
        ] {
            let target = out.path().join(target);
            let mut args = command.to_vec();
            args.extend_from_slice(&[
                "--format",
                "sarif",
                "--report-out",
                target.to_str().expect("utf-8 path"),
            ]);
            let run = run_in(repo.path(), &args, None);
            assert_eq!(run.code, 0, "{args:?}\nstderr: {}", run.stderr);
            let report: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(out.path().join(written)).expect("report written"),
            )
            .expect("sarif json");
            assert!(report["runs"].is_array(), "{args:?}");
        }
    }
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
    let expected_findings = serde_json::to_value(&expected.findings).expect("findings serialize");
    let ids = rule_ids(&report["findings"]);
    assert_eq!(ids, rule_ids(&expected_findings));
    // The procedure's one dynamic call is reported once, where it runs.
    assert_eq!(ids, ["PROC-DYNSQL"]);
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
fn the_former_flag_spellings_run_the_same_flags_and_help_lists_the_current_ones() {
    let primer = run(&["analyze", "--rule-syntax"], None);
    let listed = run(&["analyze", "--list-signals"], None);
    assert_eq!(primer.code, 0, "stderr: {}", primer.stderr);
    assert_eq!((listed.code, &listed.stdout), (primer.code, &primer.stdout));

    let sql = "DELETE FROM orders;";
    let explained = run(&["analyze", "--stdin", "--explain-findings"], Some(sql));
    let former = run(&["analyze", "--stdin", "--explain-signals"], Some(sql));
    assert!(
        explained.stdout.contains("DML-WRITE-UNBOUNDED"),
        "stdout: {} stderr: {}",
        explained.stdout,
        explained.stderr
    );
    assert_eq!(
        (former.code, &former.stdout),
        (explained.code, &explained.stdout)
    );

    let help = run(&["analyze", "--help"], None);
    for flag in ["--rule-syntax", "--explain-findings"] {
        assert!(help.stdout.contains(flag), "{flag}: {}", help.stdout);
    }
    for flag in ["--list-signals", "--explain-signals"] {
        assert!(!help.stdout.contains(flag), "{flag}: {}", help.stdout);
    }
}

#[test]
fn the_rule_primer_names_real_rules_and_its_example_fires() {
    let out = run(&["analyze", "--rule-syntax"], None);
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
    assert_eq!(rule_ids(&report["findings"]), ["MY-CUSTOM-001"]);
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
fn info_level_rules_are_context_shown_only_at_min_severity_info() {
    let sql = "UNDROP SCHEMA app; DELETE FROM orders;";
    let context_message = "Schema recovered using UNDROP";
    let json = |extra: &[&str]| -> serde_json::Value {
        let mut args = vec!["analyze", "--stdin", "--format", "json"];
        args.extend_from_slice(extra);
        let out = run(&args, Some(sql));
        assert_eq!(out.code, 0, "{extra:?} stderr: {}", out.stderr);
        serde_json::from_str(&out.stdout).expect("json report")
    };

    let default = json(&[]);
    assert!(default.get("context").is_none(), "{default:#}");
    let all = json(&["--min-severity", "info"]);
    assert_eq!(rule_ids(&all["context"]), ["INFO-SCHEMA-UNDROP"]);
    assert_eq!(rule_ids(&all["findings"]), ["DML-WRITE-UNBOUNDED"]);
    assert_eq!(all["summary"]["total_reported_findings"], 1);
    assert_eq!(all["summary"]["info_count"], 1);

    let text = run(&["analyze", "--stdin", "--min-severity", "info"], Some(sql));
    let context_at = text.stdout.find("Context:\n").expect("a Context heading");
    assert!(
        text.stdout[context_at..].contains(context_message),
        "{}",
        text.stdout
    );
    let quiet = run(&["analyze", "--stdin"], Some(sql));
    assert!(!quiet.stdout.contains(context_message), "{}", quiet.stdout);

    let markdown = run(
        &[
            "analyze",
            "--stdin",
            "--format",
            "markdown",
            "--min-severity",
            "info",
        ],
        Some(sql),
    );
    assert!(
        markdown.stdout.contains("### ℹ️ Context (1)"),
        "{}",
        markdown.stdout
    );

    let sarif = run(
        &[
            "analyze",
            "--stdin",
            "--format",
            "sarif",
            "--min-severity",
            "info",
        ],
        Some(sql),
    );
    let sarif: serde_json::Value = serde_json::from_str(&sarif.stdout).expect("sarif");
    let results: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|result| result["ruleId"].as_str().expect("rule id"))
        .collect();
    assert_eq!(results, ["DML-WRITE-UNBOUNDED"]);
}

// Re-indenting a statement longer than its preview leaves the finding's
// fingerprint as it was.
#[test]
fn a_reindented_long_statement_keeps_its_fingerprint() {
    let fingerprint = |sql: &str| -> String {
        let out = run(&["analyze", "--stdin", "--format", "sarif"], Some(sql));
        let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
        sarif["runs"][0]["results"][0]["partialFingerprints"]["lexegaFinding/v1"]
            .as_str()
            .expect("a fingerprint")
            .to_string()
    };
    let flat = "UPDATE analytics.customer_lifetime_value SET segment = 'archived', updated_at = CURRENT_TIMESTAMP;";
    let indented = "UPDATE\n        analytics.customer_lifetime_value\n    SET\n        segment = 'archived',\n        updated_at = CURRENT_TIMESTAMP;";
    assert_eq!(fingerprint(flat), fingerprint(indented));
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

// A secret a template writes into, analyzed as written, is masked whole in
// every CI format.
#[test]
fn a_partly_templated_secret_is_masked() {
    let mut leaks = Vec::new();
    for (dialect, sql) in [
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ var(\"x\") }}';",
        ),
        (
            "mssql",
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Zq9TmplPart{{ var(\"x\") }}';",
        ),
        (
            "bigquery",
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             password='Zq9TmplPart{{ var(\"x\") }}Zq9TmplPart') AS SELECT 1",
        ),
        (
            "mssql",
            "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'Zq9TmplPart{{ var(\"x\") }}';",
        ),
        (
            "redshift",
            "UNLOAD ('SELECT 1') TO 's3://b/p' ACCESS_KEY_ID 'Zq9TmplPart' \
             SECRET_ACCESS_KEY 'Zq9TmplPart{{ var(\"x\") }}';",
        ),
        // A doubled quote before a template does not close the string.
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ a }}x''{{ b }}Zq9TmplPart';",
        ),
        (
            "mssql",
            "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = \
             'Zq9TmplPart{{ a }}x''{{ b }}Zq9TmplPart';",
        ),
        // A template comment is part of the string.
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ a }}x''{# c #}Zq9TmplPart';",
        ),
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{# c #}Zq9TmplPart';",
        ),
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ a }}Zq9TmplPart{# c #}Zq9TmplPart';",
        ),
        (
            "mssql",
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Zq9TmplPart{# c #}Zq9TmplPart';",
        ),
        // MySQL joins strings written one after another into one password.
        (
            "mysql",
            "CREATE USER 'u'@'h' IDENTIFIED BY 'Zq9TmplPart{{ a }}' 'Zq9TmplPart';",
        ),
        // A prefix the lexer gives as a word before the string.
        (
            "mysql",
            "CREATE USER 'u'@'h' IDENTIFIED BY N'Zq9TmplPart{{ a }}Zq9TmplPart';",
        ),
        (
            "mysql",
            "CREATE USER 'u'@'h' IDENTIFIED BY N'Zq9TmplPart{# c #}Zq9TmplPart';",
        ),
        (
            "mysql",
            "CREATE USER 'u'@'h' IDENTIFIED BY N'Zq9TmplPart{{ a }}' 'Zq9TmplPart';",
        ),
        (
            "mysql",
            "CREATE USER 'u'@'h' IDENTIFIED BY X'Zq9TmplPart{{ a }}Zq9TmplPart';",
        ),
        (
            "bigquery",
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             password=r'Zq9TmplPart{{ a }}Zq9TmplPart') AS SELECT 1",
        ),
        (
            "postgresql",
            "CREATE USER u PASSWORD U&'Zq9TmplPart{{ a }}Zq9TmplPart';",
        ),
        // Strings written one after another: PostgreSQL and Redshift join
        // them across a newline, Snowflake and T-SQL do not.
        (
            "postgresql",
            "CREATE USER u PASSWORD 'Zq9TmplPart{{ a }}'\n'Zq9TmplPart';",
        ),
        (
            "postgresql",
            "CREATE USER u PASSWORD 'Zq9TmplPart'\n'Zq9TmplPart{{ a }}';",
        ),
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ a }}' 'Zq9TmplPart';",
        ),
        (
            "redshift",
            "CREATE USER u PASSWORD 'Zq9TmplPart{{ a }}'\n'Zq9TmplPart';",
        ),
        (
            "mssql",
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Zq9TmplPart{{ a }}'\n'Zq9TmplPart';",
        ),
        // A string nothing closes runs to the end of the text.
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{# c Zq9TmplPart';",
        ),
        (
            "snowflake",
            "CREATE USER u PASSWORD = 'Zq9TmplPart{{ a Zq9TmplPart';",
        ),
        (
            "mssql",
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Zq9TmplPart{{ a Zq9TmplPart';",
        ),
        (
            "mssql",
            "CREATE LOGIN l WITH PASSWORD = N'Zq9TmplPart Zq9TmplPart",
        ),
    ] {
        for format in ["text", "json", "sarif", "markdown"] {
            let out = run(
                &[
                    "analyze",
                    "--stdin",
                    "--dialect",
                    dialect,
                    "--min-severity",
                    "info",
                    "--format",
                    format,
                ],
                Some(sql),
            );
            if out.stdout.contains("Zq9Tmpl") {
                leaks.push(format!("[{dialect} {format}] {sql}"));
            }
        }
    }
    assert!(leaks.is_empty(), "secrets printed:\n{}", leaks.join("\n"));
}

// The password of a URL written in any string literal, holding `/`, `?` or
// `#` or not, is masked in every CI format.
#[test]
fn a_url_password_in_any_string_literal_is_masked() {
    let mut leaks = Vec::new();
    for (dialect, sql) in [
        (
            "snowflake",
            "COPY INTO 's3://AKIAX:wJalr/K7MDENG/Zq9UrlPw@bucket/p/' FROM t;",
        ),
        ("snowflake", "COPY INTO 's3://u:pre?Zq9UrlPw@b/p/' FROM t;"),
        ("snowflake", "COPY INTO 's3://u:pre#Zq9UrlPw@b/p/' FROM t;"),
        (
            "redshift",
            "UNLOAD ('SELECT * FROM t') TO 's3://AKIAX:wJalr/Zq9UrlPw@bucket/o/' IAM_ROLE default;",
        ),
        (
            "bigquery",
            "EXPORT DATA OPTIONS(uri='gs://u:pre/Zq9UrlPw@b/*.csv',format='CSV') \
             AS SELECT * FROM d.t;",
        ),
        (
            "databricks",
            "COMMENT ON STORAGE CREDENTIAL sc IS 'jdbc://a:Zq9UrlPw@h';",
        ),
        (
            "databricks",
            "CREATE EXTERNAL LOCATION el URL 'abfss://a:Zq9UrlPw@h/p' WITH (STORAGE CREDENTIAL sc);",
        ),
        (
            "snowflake",
            "CREATE EXTERNAL TABLE et LOCATION=@s COMMENT='pg://a:Zq9UrlPw@h' \
             FILE_FORMAT=(TYPE=CSV);",
        ),
        (
            "snowflake",
            "COPY INTO @s FROM (SELECT 'ftp://a:Zq9UrlPw@h' FROM t);",
        ),
        (
            "postgresql",
            "SELECT * FROM dblink('pg://a:Zq9UrlPw@h/db','SELECT 1') t(a int);",
        ),
        ("postgresql", "COMMENT ON TABLE t IS $$see pg://a:Zq9UrlPw@h$$;"),
        ("postgresql", "COMMENT ON TABLE t IS $c$see pg://a:Zq9UrlPw@h$c$;"),
        ("redshift", "COMMENT ON TABLE t IS $$see pg://a:Zq9UrlPw@h$$;"),
        ("snowflake", "COMMENT ON TABLE t IS $$see pg://a:Zq9UrlPw@h$$;"),
        (
            "snowflake",
            "CREATE EXTERNAL TABLE et LOCATION=@s COMMENT=$$pg://a:Zq9UrlPw@h$$ \
             FILE_FORMAT=(TYPE=CSV);",
        ),
        (
            "snowflake",
            "COPY INTO @st FROM (SELECT $$ftp://a:Zq9UrlPw@h$$ AS u FROM t);",
        ),
    ] {
        for format in ["text", "json", "sarif", "markdown"] {
            let out = run(
                &[
                    "analyze",
                    "--stdin",
                    "--dialect",
                    dialect,
                    "--min-severity",
                    "info",
                    "--format",
                    format,
                ],
                Some(sql),
            );
            if out.stdout.contains("Zq9UrlPw") {
                leaks.push(format!("[{dialect} {format}] {sql}"));
            }
        }
    }
    assert!(leaks.is_empty(), "secrets printed:\n{}", leaks.join("\n"));
}

// A T-SQL statement whose secret a template writes into, analyzed as
// written, is read whole: `--strict` reports no unparsed construct, no
// statement is skipped, and the secret stays masked. The run still exits 1,
// as every unrendered template does in this build (`E_STRICT_NOT_ANALYZED`).
#[test]
fn a_tsql_secret_a_template_writes_into_leaves_no_unparsed_construct() {
    let mut failures = Vec::new();
    for value in ["'{{ secrets.pw }}'", "'Zq9TmplPart{{ x }}Zq9TmplPart'"] {
        for statement in [
            format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = {value};"),
            format!("OPEN MASTER KEY DECRYPTION BY PASSWORD = {value};"),
            format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = {value};"),
            format!(
                "RESTORE MASTER KEY FROM FILE = 'f' DECRYPTION BY PASSWORD = {value} \
                 ENCRYPTION BY PASSWORD = {value};"
            ),
            format!("ADD SIGNATURE TO dbo.p BY CERTIFICATE c WITH PASSWORD = {value};"),
            format!("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = {value};"),
            format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = {value};"),
            format!("ALTER MASTER KEY ADD ENCRYPTION BY PASSWORD = {value};"),
            format!("CREATE CERTIFICATE c ENCRYPTION BY PASSWORD = {value} WITH SUBJECT = 's';"),
            format!(
                "CREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256 ENCRYPTION BY PASSWORD = {value};"
            ),
            format!("CREATE CREDENTIAL c WITH IDENTITY = 'i', SECRET = {value};"),
            format!("CREATE DATABASE SCOPED CREDENTIAL c WITH IDENTITY = 'i', SECRET = {value};"),
            format!("CREATE LOGIN l WITH PASSWORD = {value};"),
        ] {
            let out = run(
                &[
                    "analyze",
                    "--stdin",
                    "--dialect",
                    "mssql",
                    "--min-severity",
                    "info",
                    "--format",
                    "json",
                    "--strict",
                ],
                Some(&statement),
            );
            // A run that fails `--strict` on the parse prints no report.
            let report: Option<serde_json::Value> = serde_json::from_str(&out.stdout).ok();
            let skipped = report
                .as_ref()
                .and_then(|report| report["summary"]["statements_skipped"].as_u64());
            if out.stderr.contains("E_STRICT_OPAQUE")
                || skipped != Some(0)
                || out.stdout.contains("Zq9Tmpl")
            {
                failures.push(format!(
                    "{statement}: skipped={skipped:?} stderr={}",
                    out.stderr
                        .lines()
                        .filter(|l| l.contains("E_STRICT"))
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "read in part:\n{}",
        failures.join("\n")
    );
}

// A T-SQL key password written as a template reference, analyzed as
// written, is neither a leak nor a dummy.
#[test]
fn a_tsql_template_password_reference_is_no_leak() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("open_key.sql"),
        "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = '{{ secrets.pw }}';\n",
    )
    .expect("write sql");
    let out = run_in(
        dir.path(),
        &[
            "analyze",
            "--dialect",
            "mssql",
            "--min-severity",
            "info",
            "--format",
            "json",
            "open_key.sql",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert_eq!(report["summary"]["render_completeness"], "not_rendered");
    let findings = rule_ids(&report["findings"]);
    let context = rule_ids(&report["context"]);
    assert!(
        context.iter().any(|id| id == "INFO-MSSQL-KEY-MANAGEMENT"),
        "statement not analyzed: {context:?}"
    );
    for id in findings.iter().chain(&context) {
        assert!(
            id != "MSSQL-KEY-OPEN-INLINE-PASSWORD" && id != "CRED-DUMMY-VALUE",
            "{id} raised: findings {findings:?}, context {context:?}"
        );
    }
}

// Every T-SQL key password, a doubled quote and an `N` prefix included, and
// each password of an `OPEN … KEY` that writes two, is masked in every CI
// format and in the facts.
#[test]
fn open_binary_masks_tsql_password_literals() {
    let quoted = "N'Zq''7xPw'";
    let dir = TempDir::new().expect("temp dir");
    let mut leaks = Vec::new();
    for (sql, rule) in [
        (
            format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = {quoted}, PASSWORD = 'Mn4!vT'"),
            "MSSQL-KEY-OPEN-INLINE-PASSWORD",
        ),
        (
            format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = {quoted}"),
            "MSSQL-KEY-BACKUP-INLINE-PASSWORD",
        ),
        (
            format!("ADD SIGNATURE TO p BY CERTIFICATE c WITH PASSWORD = {quoted}"),
            "MSSQL-SIGNATURE-INLINE-PASSWORD",
        ),
        (
            format!("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = {quoted}"),
            "MSSQL-SERVICE-MASTER-KEY-INLINE-PASSWORD",
        ),
    ] {
        std::fs::write(dir.path().join("key.sql"), &sql).expect("write sql");
        let outputs: [&[&str]; 5] = [
            &["--format", "text"],
            &["--format", "json"],
            &["--format", "sarif"],
            &["--format", "markdown"],
            &["--explain-facts"],
        ];
        for output in outputs {
            let args: Vec<&str> = ["analyze", "--dialect", "mssql", "--min-severity", "info"]
                .into_iter()
                .chain(output.iter().copied())
                .chain(["key.sql"])
                .collect();
            let out = run_in(dir.path(), &args, None);
            assert_eq!(out.code, 0, "{output:?}: {sql}\nstderr: {}", out.stderr);
            if output == ["--format", "json"] {
                let report: serde_json::Value =
                    serde_json::from_str(&out.stdout).expect("json report");
                assert_eq!(report["summary"]["statements_skipped"], 0, "{sql}");
                let findings = rule_ids(&report["findings"]);
                assert!(findings.iter().any(|id| id == rule), "{sql}: {findings:?}");
            }
            let printed = format!("{}{}", out.stdout, out.stderr);
            for secret in ["Zq'7xPw", "Zq''7xPw", "Mn4!vT"] {
                if printed.contains(secret) {
                    leaks.push(format!("{output:?} printed {secret}: {sql}"));
                }
            }
        }
    }
    assert!(leaks.is_empty(), "secrets printed:\n{}", leaks.join("\n"));
}

// A batch is as completely rendered as its least rendered file: a template
// analyzed as written makes the batch `not_rendered` beside a plain file,
// in JSON and in YAML.
#[test]
fn a_batch_is_as_complete_as_its_least_rendered_file() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("a.sql"),
        "DELETE FROM orders WHERE id = 1;\n",
    )
    .expect("write a.sql");
    std::fs::write(
        dir.path().join("b.sql"),
        "SELECT * FROM {{ ref('orders') }};\n",
    )
    .expect("write b.sql");
    for format in ["json", "yaml"] {
        let out = run_in(
            dir.path(),
            &["analyze", ".", "-r", "--format", format, "--quiet"],
            None,
        );
        assert_eq!(out.code, 0, "{format}\nstderr: {}", out.stderr);
        let batch: serde_json::Value = if format == "json" {
            serde_json::from_str(&out.stdout).expect("json batch")
        } else {
            serde_yaml_ng::from_str(&out.stdout).expect("yaml batch")
        };
        let completeness: Vec<(&str, &str)> = batch["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|file| {
                let path = file["file"].as_str().expect("file name");
                let report = &file["result"]["report"]["summary"];
                (
                    &path[path.len() - "a.sql".len()..],
                    report["render_completeness"]
                        .as_str()
                        .expect("completeness"),
                )
            })
            .collect();
        assert_eq!(
            completeness,
            [("a.sql", "full"), ("b.sql", "not_rendered")],
            "{format}\n{}",
            out.stdout
        );
        assert_eq!(
            batch["batch_summary"]["rendering"]["completeness"], "not_rendered",
            "{format}\n{}",
            out.stdout
        );
    }
}

// SARIF and GitLab SAST say which files were analyzed on their template
// text, for one file and for a batch, so a gate reading only them does not
// read the run as clean.
#[test]
fn sarif_and_gl_sast_name_the_files_analyzed_on_template_text() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("a.sql"),
        "DELETE FROM orders WHERE id = 1;\n",
    )
    .expect("write a.sql");
    std::fs::write(
        dir.path().join("b.sql"),
        "SELECT * FROM {{ ref('orders') }};\n",
    )
    .expect("write b.sql");
    let note = "Template could not be rendered; analysis ran on template text.";
    let sarif_unrendered = |sarif: &serde_json::Value| -> Vec<String> {
        let notifications = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        notifications
            .as_array()
            .into_iter()
            .flatten()
            .filter(|n| n["descriptor"]["id"] == "template-not-rendered")
            .flat_map(|n| {
                assert_eq!(n["level"], "warning");
                assert_eq!(n["message"]["text"], note);
                n["locations"].as_array().expect("locations").clone()
            })
            .map(|l| {
                let uri = l["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .expect("uri");
                uri.rsplit('/').next().expect("file name").to_string()
            })
            .collect()
    };
    let gl_unrendered = |report: &serde_json::Value| -> Vec<String> {
        report["scan"]["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|m| m["level"] == "warn")
            .map(|m| {
                let value = m["value"].as_str().expect("value");
                let path = value.strip_suffix(&format!(": {note}")).expect("note");
                path.rsplit('/').next().expect("file name").to_string()
            })
            .collect()
    };

    for (args, unrendered) in [
        (vec!["analyze", "b.sql"], vec!["b.sql"]),
        (vec!["analyze", "a.sql"], vec![]),
        (vec!["analyze", ".", "-r", "--quiet"], vec!["b.sql"]),
    ] {
        let sarif_args: Vec<&str> = args.iter().copied().chain(["--format", "sarif"]).collect();
        let out = run_in(dir.path(), &sarif_args, None);
        assert_eq!(out.code, 0, "{args:?}\nstderr: {}", out.stderr);
        let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
        assert_eq!(
            sarif_unrendered(&sarif),
            unrendered,
            "{args:?}\n{}",
            out.stdout
        );
        let (completeness, confidence) = if unrendered.is_empty() {
            ("full", "high")
        } else {
            ("not_rendered", "low")
        };
        assert_eq!(
            sarif["runs"][0]["properties"]["renderCompleteness"],
            completeness
        );
        assert_eq!(
            sarif["runs"][0]["properties"]["analysisConfidence"],
            confidence
        );

        let gl_args: Vec<&str> = args
            .iter()
            .copied()
            .chain(["--format", "gl-sast"])
            .collect();
        let out = run_in(dir.path(), &gl_args, None);
        assert_eq!(out.code, 0, "{args:?}\nstderr: {}", out.stderr);
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("gl-sast");
        assert_eq!(
            gl_unrendered(&report),
            unrendered,
            "{args:?}\n{}",
            out.stdout
        );
    }

    let out = run_in(
        dir.path(),
        &[
            "analyze",
            ".",
            "-r",
            "--quiet",
            "--format",
            "sarif",
            "--report-out",
            "out/",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let written = std::fs::read_to_string(dir.path().join("out/batch_summary.sarif"))
        .expect("batch_summary.sarif");
    let sarif: serde_json::Value = serde_json::from_str(&written).expect("sarif");
    assert_eq!(sarif_unrendered(&sarif), ["b.sql"]);
    assert_eq!(
        sarif["runs"][0]["properties"]["renderCompleteness"],
        "not_rendered"
    );
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

/// A catalog of one table, declared with a quoted mixed-case name.
const QUOTED_NAME_CATALOG: &str = r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": {"name": "MyTable", "case_sensitive": true}, "kind": "Table", "columns": [{"name": "ID", "data_type": "NUMBER", "nullable": false}]}]}]}]}"#;

/// The tables `sql` names that a run under `dialect` does not find in
/// [`QUOTED_NAME_CATALOG`].
fn missing_from_the_quoted_name_catalog(dialect: &str, sql: &str) -> Vec<String> {
    let dir = TempDir::new().expect("temp dir");
    let catalog = dir.path().join("catalog.json");
    std::fs::write(&catalog, QUOTED_NAME_CATALOG).expect("write catalog");
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--dialect",
            dialect,
            "--format",
            "json",
            "--catalog",
            catalog.to_str().expect("utf-8 path"),
        ],
        Some(sql),
    );
    assert_eq!(out.code, 0, "{dialect}: stderr: {}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    report["catalog_info"]["missing_tables"]
        .as_array()
        .expect("missing tables")
        .iter()
        .map(|table| table.as_str().expect("a name").to_string())
        .collect()
}

// The catalog is read as the run's dialect reads names: where quoting a name
// does not make its case significant, a quoted table is found in whatever
// case the catalog declares it.
#[test]
fn a_catalogued_table_is_found_by_a_quoted_name_as_the_dialect_reads_it() {
    assert_eq!(
        missing_from_the_quoted_name_catalog(
            "databricks",
            "SELECT id FROM analytics.public.`MyTable`; SELECT id FROM analytics.public.`mytable`; SELECT id FROM analytics.public.nosuch;"
        ),
        ["analytics.public.nosuch"]
    );
    // Where it does, only the declared spelling is the table.
    assert_eq!(
        missing_from_the_quoted_name_catalog(
            "snowflake",
            "SELECT id FROM analytics.public.\"MyTable\"; SELECT id FROM analytics.public.\"mytable\";"
        ),
        ["analytics.public.\"mytable\""]
    );
    assert_eq!(
        missing_from_the_quoted_name_catalog(
            "mysql",
            "SELECT id FROM analytics.public.`MyTable`; SELECT id FROM analytics.public.`mytable`;"
        ),
        ["analytics.public.`mytable`"]
    );
}

/// Two files with context entries (one with a finding too) and one with
/// none, in a fresh directory.
fn context_directory() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    for (name, sql) in [
        ("a_context.sql", "UNDROP SCHEMA app;\n"),
        ("b_both.sql", "UNDROP SCHEMA app; DELETE FROM orders;\n"),
        ("c_plain.sql", "SELECT 1 AS n;\n"),
    ] {
        std::fs::write(dir.path().join(name), sql).expect("write");
    }
    dir
}

#[test]
fn a_batch_text_report_lists_each_files_context_at_min_severity_info() {
    let dir = context_directory();
    let path = dir.path().to_str().expect("utf-8 path");
    let message = "Schema recovered using UNDROP";
    let info = run(&["analyze", "-r", path, "--min-severity", "info"], None);
    assert_eq!(info.code, 0, "stderr: {}", info.stderr);
    assert!(info.stdout.contains("Context: 2\n"), "{}", info.stdout);
    let details_at = info.stdout.find("Per-File Details").expect("details");
    let details = &info.stdout[details_at..];
    assert_eq!(details.matches(message).count(), 2, "{details}");
    assert_eq!(
        details.matches("INFO-SCHEMA-UNDROP").count(),
        2,
        "{details}"
    );
    let context_only = details.find("a_context.sql").expect("context-only file");
    let both = details.find("b_both.sql").expect("file with both");
    assert!(context_only < both, "{details}");
    assert!(!details.contains("c_plain.sql"), "{details}");
    let both_section = &details[both..];
    let findings_at = both_section.find("DML-WRITE-UNBOUNDED").expect("finding");
    let context_at = both_section.find("Context:").expect("context heading");
    assert!(findings_at < context_at, "{both_section}");
    assert!(
        both_section.find(message).expect("context message") > context_at,
        "{both_section}"
    );

    let default = run(&["analyze", "-r", path], None);
    assert!(!default.stdout.contains("Context"), "{}", default.stdout);
    assert!(!default.stdout.contains(message), "{}", default.stdout);
    assert!(
        !default.stdout.contains("a_context.sql"),
        "{}",
        default.stdout
    );
}

#[test]
fn a_batch_markdown_report_lists_each_files_context_at_min_severity_info() {
    let dir = context_directory();
    let path = dir.path().to_str().expect("utf-8 path");
    let message = "Schema recovered using UNDROP";
    let info = run(
        &[
            "analyze",
            "-r",
            path,
            "--format",
            "markdown",
            "--min-severity",
            "info",
        ],
        None,
    );
    assert_eq!(info.code, 0, "stderr: {}", info.stderr);
    assert!(
        info.stdout.contains("| ℹ️ Context | 2 |"),
        "{}",
        info.stdout
    );
    let details_at = info.stdout.find("### Per-File Details").expect("details");
    let details = &info.stdout[details_at..];
    assert_eq!(details.matches(message).count(), 2, "{details}");
    // Each file is named by the path the text report gives it.
    let root = dunce::canonicalize(dir.path()).expect("canonical dir");
    let heading = |name: &str| format!("#### `{}`", root.join(name).display());
    assert!(details.contains(&heading("a_context.sql")), "{details}");
    assert!(!details.contains("c_plain.sql"), "{details}");
    let both = details
        .find(&heading("b_both.sql"))
        .expect("file with both");
    let both_section = &details[both..];
    let findings_at = both_section.find("DML-WRITE-UNBOUNDED").expect("finding");
    let context_at = both_section
        .find("**ℹ️ Context (1)**")
        .expect("context heading");
    assert!(findings_at < context_at, "{both_section}");
    assert!(
        both_section[context_at..].contains("INFO-SCHEMA-UNDROP"),
        "{both_section}"
    );
    assert!(
        details.contains("| Level | Context | Evidence |"),
        "{details}"
    );
    assert_eq!(
        details.matches("**ℹ️ Context (1)**").count(),
        2,
        "{details}"
    );
    assert_eq!(
        details.matches("INFO-SCHEMA-UNDROP").count(),
        2,
        "{details}"
    );

    let default = run(&["analyze", "-r", path, "--format", "markdown"], None);
    assert!(!default.stdout.contains("Context"), "{}", default.stdout);
    assert!(!default.stdout.contains(message), "{}", default.stdout);
    assert!(
        default.stdout.contains("### Per-File Finding Details"),
        "{}",
        default.stdout
    );
}

#[test]
fn a_batch_markdown_report_of_only_context_shows_the_context_total() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("only.sql"), "UNDROP SCHEMA app;\n").expect("write");
    let path = dir.path().to_str().expect("utf-8 path");
    let out = run(
        &[
            "analyze",
            "-r",
            path,
            "--format",
            "markdown",
            "--min-severity",
            "info",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("| ℹ️ Context | 1 |"), "{}", out.stdout);
    assert!(
        out.stdout.contains("### Per-File Details"),
        "{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("Per-File Finding Details"),
        "{}",
        out.stdout
    );
}

#[test]
fn a_batch_markdown_report_counts_the_occurrences_beyond_the_one_listed() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("a_four.sql"),
        "DELETE FROM orders;\nDELETE FROM users;\nDELETE FROM archive;\nDELETE FROM accounts;\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("b_two.sql"),
        "DELETE FROM orders;\nDELETE FROM users;\n",
    )
    .expect("write");
    let out = run(
        &[
            "analyze",
            "-r",
            dir.path().to_str().expect("utf-8 path"),
            "--format",
            "markdown",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let root = dunce::canonicalize(dir.path()).expect("canonical dir");
    let heading = |name: &str| format!("#### `{}`", root.join(name).display());
    let four = out.stdout.find(&heading("a_four.sql")).expect("a_four");
    let two = out.stdout.find(&heading("b_two.sql")).expect("b_two");
    assert!(
        out.stdout[four..two].contains("`DML-WRITE-UNBOUNDED`; +3 more"),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout[two..].contains("`DML-WRITE-UNBOUNDED`; +1 more"),
        "{}",
        out.stdout
    );
}

#[test]
fn a_batch_text_report_shows_a_multi_line_preview_on_one_line() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("a.sql"), "DELETE\n  FROM orders;\n").expect("write");
    let path = dir.path().to_str().expect("utf-8 path");
    let batch = run(&["analyze", "-r", path], None);
    let single = run(
        &[
            "analyze",
            dir.path().join("a.sql").to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert!(
        batch.stdout.contains("\"DELETE FROM orders\""),
        "{}",
        batch.stdout
    );
    assert!(
        single.stdout.contains("\"DELETE FROM orders\""),
        "{}",
        single.stdout
    );
}

// A directory's files are analysed and reported in path order, whatever order
// the file system lists them in: name by name down the tree, so `a/b.sql`
// comes before `a-b.sql`.
#[test]
fn a_directory_is_analysed_in_path_order() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::create_dir(dir.path().join("sub")).expect("sub dir");
    std::fs::create_dir(dir.path().join("a")).expect("a dir");
    let names = [
        "m_mid.sql",
        "b_load.sql",
        "z_last.sql",
        "a-b.sql",
        "a_report.sql",
        "c_three.sql",
        "k_eleven.sql",
        "sub/a_nested.sql",
        "a/b.sql",
        "y_two.sql",
    ];
    for (n, name) in names.iter().enumerate() {
        std::fs::write(dir.path().join(name), format!("SELECT {n} AS n;\n")).expect("write");
    }
    let out = run(
        &[
            "analyze",
            "-r",
            dir.path().to_str().expect("utf-8 path"),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    let root = dunce::canonicalize(dir.path()).expect("canonical dir");
    let listed: Vec<String> = batch["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|file| {
            let path = std::path::Path::new(file["file"].as_str().expect("a path"));
            let relative = path.strip_prefix(&root).expect("under the directory");
            relative.to_string_lossy().replace('\\', "/")
        })
        .collect();
    assert_eq!(
        listed,
        [
            "a/b.sql",
            "a-b.sql",
            "a_report.sql",
            "b_load.sql",
            "c_three.sql",
            "k_eleven.sql",
            "m_mid.sql",
            "sub/a_nested.sql",
            "y_two.sql",
            "z_last.sql",
        ]
    );
}

/// Every name listed in a `missing_tables` anywhere in `value`.
fn missing_tables_in(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                match (key.as_str(), field) {
                    ("missing_tables", serde_json::Value::Array(names)) => found.extend(
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_string)),
                    ),
                    _ => missing_tables_in(field, found),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                missing_tables_in(item, found);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

/// Every rule id matched anywhere in `value`.
fn matched_rules_in(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                match (key.as_str(), field) {
                    ("matched_rule", serde_json::Value::String(id)) => found.push(id.clone()),
                    _ => matched_rules_in(field, found),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                matched_rules_in(item, found);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

// Every fragment `--scan-embedded` finds, whatever call or cell holds it, is
// read in the run's dialect: it misses the tables the same statement misses
// when analysed on its own under that dialect.
#[test]
fn an_embedded_fragment_is_read_in_the_runs_dialect() {
    const QUOTED: &str = "SELECT id FROM analytics.public.\"MyTable\"";
    const QUOTED_OTHER_CASE: &str = "SELECT id FROM analytics.public.\"mytable\"";
    const BACK_QUOTED: &str = "SELECT id FROM analytics.public.`MyTable`";
    const BACK_QUOTED_OTHER_CASE: &str = "SELECT id FROM analytics.public.`mytable`";
    const BY_KEYWORD: &str = "SELECT id FROM analytics.public.by_keyword";
    const IN_A_PYTHON_CELL: &str = "SELECT id FROM analytics.public.in_a_python_cell";
    const IN_A_SQL_CELL: &str = "SELECT id FROM analytics.public.in_a_sql_cell";

    let dir = TempDir::new().expect("temp dir");
    let catalog = dir.path().join("catalog.json");
    std::fs::write(&catalog, QUOTED_NAME_CATALOG).expect("write catalog");
    let jobs = dir.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs dir");
    std::fs::write(
        jobs.join("job.py"),
        format!(
            "spark.sql('{QUOTED}')\ncursor.execute('{QUOTED_OTHER_CASE}')\nspark.sql('{BACK_QUOTED}')\ncursor.execute('{BACK_QUOTED_OTHER_CASE}')\nspark.sql(sqlQuery='{BY_KEYWORD}')\n"
        ),
    )
    .expect("write job");
    std::fs::write(
        jobs.join("notebook.py"),
        format!(
            "# Databricks notebook source\n\nspark.sql('{IN_A_PYTHON_CELL}')\n\n# COMMAND ----------\n\n# MAGIC %sql\n# MAGIC {IN_A_SQL_CELL}\n"
        ),
    )
    .expect("write notebook");

    let statements = [
        QUOTED,
        QUOTED_OTHER_CASE,
        BACK_QUOTED,
        BACK_QUOTED_OTHER_CASE,
        BY_KEYWORD,
        IN_A_PYTHON_CELL,
        IN_A_SQL_CELL,
    ];
    for dialect in [
        "snowflake",
        "postgresql",
        "databricks",
        "mysql",
        "bigquery",
        "mssql",
    ] {
        let out = run(
            &[
                "analyze",
                "--scan-embedded",
                "--dialect",
                dialect,
                "--format",
                "json",
                "--catalog",
                catalog.to_str().expect("utf-8 path"),
                "-r",
                jobs.to_str().expect("utf-8 path"),
            ],
            None,
        );
        assert_eq!(out.code, 0, "{dialect}: stderr: {}", out.stderr);
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
        let mut missing = Vec::new();
        missing_tables_in(&report, &mut missing);
        missing.sort();
        missing.dedup();

        let mut on_their_own = Vec::new();
        for sql in statements {
            let alone = run(
                &[
                    "analyze",
                    "--stdin",
                    "--dialect",
                    dialect,
                    "--format",
                    "json",
                    "--catalog",
                    catalog.to_str().expect("utf-8 path"),
                ],
                Some(sql),
            );
            assert_eq!(alone.code, 0, "{dialect} {sql}: stderr: {}", alone.stderr);
            let report: serde_json::Value =
                serde_json::from_str(&alone.stdout).expect("json report");
            missing_tables_in(&report, &mut on_their_own);
        }
        on_their_own.sort();
        on_their_own.dedup();
        assert_eq!(missing, on_their_own, "{dialect}");
        for shape in ["by_keyword", "in_a_python_cell", "in_a_sql_cell"] {
            assert!(
                missing.iter().any(|table| table.ends_with(shape)),
                "{dialect}: {shape} not analysed: {missing:?}"
            );
        }
    }
}

/// A catalog that declares two tables whose quoted names differ only in case.
const CASE_TWIN_CATALOG: &str = r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": {"name": "MyTable", "case_sensitive": true}, "kind": "Table", "columns": [{"name": "ID", "data_type": "NUMBER", "nullable": false}]}, {"name": {"name": "MYTABLE", "case_sensitive": true}, "kind": "Table", "columns": [{"name": "ID", "data_type": "NUMBER", "nullable": false}]}]}]}]}"#;

// A catalog either loads for the run's dialect, and every fragment is
// analysed against it, or it does not, and the run stops.
#[test]
fn a_catalog_that_cannot_be_read_in_the_runs_dialect_stops_an_embedded_run() {
    let dir = TempDir::new().expect("temp dir");
    let catalog = dir.path().join("catalog.json");
    std::fs::write(&catalog, CASE_TWIN_CATALOG).expect("write catalog");
    let jobs = dir.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs dir");
    std::fs::write(jobs.join("job.py"), "spark.sql('DELETE FROM zz_x')\n").expect("write job");
    for dialect in [
        "snowflake",
        "postgresql",
        "databricks",
        "mysql",
        "bigquery",
        "mssql",
    ] {
        let out = run(
            &[
                "analyze",
                "--scan-embedded",
                "--dialect",
                dialect,
                "--format",
                "json",
                "--catalog",
                catalog.to_str().expect("utf-8 path"),
                "-r",
                jobs.to_str().expect("utf-8 path"),
            ],
            None,
        );
        if matches!(dialect, "databricks" | "mssql") {
            assert_eq!(out.code, 1, "{dialect}: stdout: {}", out.stdout);
            assert!(
                out.stderr.contains("Failed to load catalog"),
                "{dialect}: stderr: {}",
                out.stderr
            );
        } else {
            assert_eq!(out.code, 0, "{dialect}: stderr: {}", out.stderr);
            let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
            let mut rules = Vec::new();
            matched_rules_in(&report, &mut rules);
            assert!(
                rules.iter().any(|id| id == "DML-WRITE-UNBOUNDED"),
                "{dialect}: {rules:?}; stderr: {}",
                out.stderr
            );
        }
    }
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
        !rule_ids(&with_rule["findings"]).contains(&"MY-STALE-REF".to_string()),
        "{}",
        with_rule["findings"]
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

/// Each form and the text its tokens must keep as written.
const FORMS_THAT_MUST_READ_THE_SAME: [(&str, &str, &str); 4] = [
    ("mssql", "SELECT 0x41 FROM t;\n", "0x41"),
    ("mssql", "UPDATE t SET c = 0x4142 WHERE id = 1;\n", "0x4142"),
    ("mysql", "SELECT X'41' FROM t;\n", "X'41'"),
    (
        "snowflake",
        "SELECT * FROM {{ s }}_t WHERE a = 1;\n",
        "{{ s }}_t",
    ),
];

#[test]
fn fmt_never_writes_or_verifies_text_that_reads_differently() {
    for (dialect, sql, kept) in FORMS_THAT_MUST_READ_THE_SAME {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("a.sql"), sql).expect("write");
        let verified = run_in(
            dir.path(),
            &[
                "fmt",
                "a.sql",
                "--dialect",
                dialect,
                "--verify",
                "-o",
                "out.sql",
            ],
            None,
        );
        match std::fs::read_to_string(dir.path().join("out.sql")) {
            Ok(out) => {
                assert_eq!(verified.code, 0, "{sql:?}: {}", verified.stderr);
                assert!(out.contains(kept), "--verify wrote {out:?} for {sql:?}");
            }
            Err(_) => assert_eq!(verified.code, 1, "{sql:?}: nothing written, exit 0"),
        }

        let written = run_in(
            dir.path(),
            &["fmt", "a.sql", "--dialect", dialect, "--write"],
            None,
        );
        let text = std::fs::read_to_string(dir.path().join("a.sql")).expect("read");
        assert!(text.contains(kept), "--write wrote {text:?} for {sql:?}");
        assert_eq!(
            written.code,
            if text == sql { 1 } else { 0 },
            "{sql:?}: {}",
            written.stderr
        );

        let batch = TempDir::new().expect("tempdir");
        std::fs::create_dir(batch.path().join("models")).expect("mkdir");
        std::fs::write(batch.path().join("models/m.sql"), sql).expect("write");
        let out = run_in(
            batch.path(),
            &["fmt", "models", "--dialect", dialect, "-w"],
            None,
        );
        let text = std::fs::read_to_string(batch.path().join("models/m.sql")).expect("read");
        assert!(text.contains(kept), "a batch -w wrote {text:?} for {sql:?}");
        assert_eq!(
            out.code,
            if text == sql { 1 } else { 0 },
            "{sql:?}: {}",
            out.stderr
        );
    }

    // Text that formats as written is still formatted, alone and in a batch.
    let batch = TempDir::new().expect("tempdir");
    std::fs::create_dir(batch.path().join("models")).expect("mkdir");
    std::fs::write(batch.path().join("models/m.sql"), "select  a from t;\n").expect("write");
    let out = run_in(batch.path(), &["fmt", "models", "-w"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let text = std::fs::read_to_string(batch.path().join("models/m.sql")).expect("read");
    assert!(text.starts_with("SELECT a"), "{text:?}");
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
fn a_full_build_command_is_refused_by_name() {
    let out = run(&["diff", "main..HEAD"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr
            .contains("Error: `diff` is not a command of this build."),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains(
            "Semantic diff between two commits is part of the full build: https://lexega.com"
        ),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Unknown command"), "{}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);

    let dir = TempDir::new().expect("temp dir");
    let out = run_in(dir.path(), &["init"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr
            .contains("Error: `init` is not a command of this build."),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("is part of the full build: https://lexega.com"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Unknown command"), "{}", out.stderr);
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);

    for command in ["policy", "policy-lint", "dashboard", "mcp"] {
        let out = run_in(dir.path(), &[command], None);
        assert_eq!(out.code, 1, "{command}");
        assert!(
            out.stderr.contains(&format!(
                "Error: `{command}` is not a command of this build."
            )),
            "{command}: {}",
            out.stderr
        );
        assert!(!out.stderr.contains("Unknown command"), "{}", out.stderr);
    }
}

#[test]
fn a_command_no_build_defines_is_unknown() {
    let out = run(&["frobnicate"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("Unknown command: frobnicate"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("Usage:"), "{}", out.stderr);
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
    assert_eq!(rule_ids(&report["findings"]), ["DML-WRITE-UNBOUNDED"]);
    assert_eq!(report["run_scope"]["kind"], "change");
    assert_eq!(report["run_scope"]["base"], "HEAD~1");
    assert!(batch["batch_summary"]["analysis_depth"]["rules_limited"]
        .as_u64()
        .is_some_and(|n| n > 0));
}

// `--dialect` without a value lists every dialect the build knows.
#[test]
fn a_dialect_option_without_a_value_lists_every_dialect() {
    let repo = repo_with_a_change();
    for args in [
        &["analyze", "a.sql", "--dialect"][..],
        &["review", "HEAD~1..HEAD", "--dialect"],
        &["fmt", "a.sql", "--dialect"],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains(
                "--dialect requires a value (snowflake, postgresql, bigquery, mysql, mssql, databricks, redshift)"
            ),
            "{args:?}\nstderr: {}",
            out.stderr
        );
    }
}

// A dialect the build does not know stops a batch as it stops one file:
// the batch is not read as the default dialect instead.
#[test]
fn a_batch_refuses_a_dialect_it_does_not_know() {
    let repo = repo_with_a_change();
    for args in [
        &["analyze", ".", "-r", "--dialect", "bogus"][..],
        &["review", "HEAD~1..HEAD", "--dialect", "bogus"][..],
        &["analyze", "a.sql", "--dialect", "bogus"][..],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains("Error: Unknown dialect 'bogus'"),
            "{args:?}\nstderr: {}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "{args:?}\nstdout: {}", out.stdout);
    }
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
fn review_lists_each_changed_files_context_under_its_own_section() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    std::fs::write(root.join("b.sql"), "SELECT 2;\n").expect("write b.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(root.join("a.sql"), "UNDROP SCHEMA app;\n").expect("write a.sql");
    std::fs::write(root.join("b.sql"), "DELETE FROM orders;\n").expect("write b.sql");
    git(root, &["commit", "-q", "-am", "change"]);

    let out = run_in(
        root,
        &[
            "review",
            "HEAD~1..HEAD",
            "--quiet",
            "--min-severity",
            "info",
        ],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let a = out.stdout.find("#### `a.sql`").expect("a.sql section");
    let b = out.stdout.find("#### `b.sql`").expect("b.sql section");
    assert!(a < b, "{}", out.stdout);
    let (a_section, b_section) = (&out.stdout[a..b], &out.stdout[b..]);
    assert!(a_section.contains("**ℹ️ Context (1)**"), "{a_section}");
    assert!(a_section.contains("INFO-SCHEMA-UNDROP"), "{a_section}");
    assert!(!a_section.contains("DML-WRITE-UNBOUNDED"), "{a_section}");
    assert!(b_section.contains("DML-WRITE-UNBOUNDED"), "{b_section}");
    assert!(!b_section.contains("INFO-SCHEMA-UNDROP"), "{b_section}");
    assert!(!b_section.contains("Context ("), "{b_section}");
    assert!(out.stdout.contains("| ℹ️ Context | 1 |"), "{}", out.stdout);
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

// A SQL file whose name is not UTF-8, held unchanged where the review reads
// nothing, leaves the range reviewed: a range that changes a README, and
// one that changes SQL outside the review's paths, say nothing changed.
#[cfg(unix)]
#[test]
fn a_sql_file_named_in_bytes_not_utf8_that_no_review_reads_leaves_the_range_reviewed() {
    use std::os::unix::ffi::OsStrExt;

    let repo = TempDir::new().expect("temp dir");
    let root = repo.path();
    for dir in ["sub", "other"] {
        std::fs::create_dir_all(root.join(dir)).expect("make dir");
    }
    std::fs::write(
        root.join("sub")
            .join(std::ffi::OsStr::from_bytes(b"caf\xe9.sql")),
        "SELECT 1;\n",
    )
    .expect("write sub/caf\\xe9.sql");
    std::fs::write(root.join("other").join("y.sql"), "SELECT 1;\n").expect("write y.sql");
    std::fs::write(root.join("README.md"), "a\n").expect("write README.md");
    git(root, &["init", "-q"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(root.join("README.md"), "b\n").expect("write README.md");
    git(root, &["commit", "-q", "-am", "readme"]);
    std::fs::write(root.join("other").join("y.sql"), "SELECT 2;\n").expect("write y.sql");
    git(root, &["commit", "-q", "-am", "other"]);

    let mut wrong = Vec::new();
    for (range, paths) in [("HEAD~2..HEAD~1", &[][..]), ("HEAD~1..HEAD", &["sub"][..])] {
        for command in [
            &["review", range][..],
            &["review", range, "--strict"],
            &["ci", "--range", range],
        ] {
            let mut args = command.to_vec();
            args.extend_from_slice(paths);
            let out = run_in(root, &args, None);
            if out.code != 0 || !out.stderr.contains("No SQL files changed") {
                wrong.push(format!(
                    "{args:?}: exit {}\nstdout: {}\nstderr: {}",
                    out.code, out.stdout, out.stderr
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
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
fn ci_reads_a_directory_it_is_given_with_its_subdirectories() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::create_dir_all(root.join("migrations/v1")).expect("mkdir");
    std::fs::write(root.join("migrations/v1/a.sql"), "SELECT 1;\n").expect("write a.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(root.join("migrations/v1/a.sql"), "DELETE FROM orders;\n").expect("write");
    git(root, &["commit", "-q", "-am", "change"]);

    for args in [
        vec!["ci", ".", "--snapshot", "--format", "json", "--quiet"],
        vec![
            "ci",
            ".",
            "--range",
            "HEAD~1..HEAD",
            "--format",
            "json",
            "--quiet",
        ],
        vec!["ci", ".", "-r", "--snapshot", "--format", "json", "--quiet"],
    ] {
        let out = run_in(root, &args, None);
        assert_eq!(out.code, 0, "{args:?}: stderr: {}", out.stderr);
        let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
        assert_eq!(batch["files"].as_array().map(Vec::len), Some(1), "{args:?}");
    }
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
        out.stdout
            .contains("Top Matched Rules:\n  DML-WRITE-UNBOUNDED - 1 occurrence(s)"),
        "{}",
        out.stdout
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

// Two changed files of one base name are two sections of the Markdown
// review, each named by the path the text report gives it, as are the
// risky files and the files not analyzed.
#[test]
fn a_markdown_review_names_each_file_by_its_path_from_the_root() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    for folder in ["mssql", "redshift"] {
        std::fs::create_dir(root.join(folder)).expect("make dir");
    }
    std::fs::write(root.join("mssql/001.sql"), "SELECT 1;\n").expect("write");
    git(root, &["init", "-q"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(
        root.join("mssql/002_purge.sql"),
        "GRANT SELECT ON dbo.orders TO public;\nDELETE FROM dbo.orders;\n",
    )
    .expect("write");
    std::fs::write(
        root.join("redshift/002_purge.sql"),
        "DELETE FROM public.events;\n",
    )
    .expect("write");
    std::fs::write(root.join("redshift/bad.sql"), b"SELECT \xff\xfe 1;\n").expect("write");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "change"]);

    let md = run_in(root, &["review", "HEAD~1..HEAD", "--quiet"], None);
    let text = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--quiet", "--format", "text"],
        None,
    );
    for out in [&md, &text] {
        assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    }
    for path in ["mssql/002_purge.sql", "redshift/002_purge.sql"] {
        assert!(
            text.stdout.contains(&format!("── {path} (")),
            "{}",
            text.stdout
        );
        assert_eq!(
            md.stdout.matches(&format!("#### `{path}`")).count(),
            1,
            "{}",
            md.stdout
        );
        assert!(
            md.stdout.contains(&format!("| `{path}` |")),
            "{}",
            md.stdout
        );
    }
    assert!(
        text.stdout.contains("  - redshift/bad.sql: "),
        "{}",
        text.stdout
    );
    assert!(
        md.stdout.contains("- `redshift/bad.sql`: "),
        "{}",
        md.stdout
    );
    assert!(!md.stdout.contains("`002_purge.sql`"), "{}", md.stdout);
}

// A block's statement the parser keeps as written (`EXEC q @v` in a MySQL
// block) is not analysed: it is counted as skipped and listed in
// `skipped_details`, in every format, a file's and a batch's.
#[test]
fn a_block_statement_kept_as_written_is_counted_as_skipped() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("proc.sql"),
        "CREATE PROCEDURE p()\nBEGIN\n  EXEC q @v;\n  DELETE FROM orders;\nEND;\n",
    )
    .expect("write");
    let file = dir.path().join("proc.sql");
    let file = file.to_str().expect("utf-8 path");
    let path = dir.path().to_str().expect("utf-8 path");
    let mysql = ["--dialect", "mysql"];

    let json = run(
        &[&["analyze", file, "--format", "json"][..], &mysql].concat(),
        None,
    );
    assert_eq!(json.code, 0, "stderr: {}", json.stderr);
    let report: serde_json::Value = serde_json::from_str(&json.stdout).expect("json report");
    assert_eq!(report["summary"]["statements_analyzed"], 2, "{report}");
    assert_eq!(report["summary"]["statements_skipped"], 1, "{report}");
    let skipped = report["skipped_details"].as_array().expect("skipped");
    assert_eq!(skipped.len(), 1, "{report}");
    assert_eq!(skipped[0]["line_number"], 3, "{report}");

    let text = run(&[&["analyze", file][..], &mysql].concat(), None);
    assert!(
        text.stdout
            .contains("Analyzed: 2 SQL statements\n  Unrecognized: 1 (could not parse"),
        "{}",
        text.stdout
    );
    let batch = run(&[&["analyze", "-r", path][..], &mysql].concat(), None);
    assert!(
        batch
            .stdout
            .contains("Analyzed: 2 SQL statements\nUnrecognized: 1 (could not parse"),
        "{}",
        batch.stdout
    );
    let md = run(
        &[&["analyze", "-r", path, "--format", "markdown"][..], &mysql].concat(),
        None,
    );
    assert!(
        md.stdout
            .contains("| SQL Statements | 2 |\n| Unrecognized (opaque) | 1 |"),
        "{}",
        md.stdout
    );
    let batch_json = run(
        &[&["analyze", "-r", path, "--format", "json"][..], &mysql].concat(),
        None,
    );
    let batch_json: serde_json::Value =
        serde_json::from_str(&batch_json.stdout).expect("json batch");
    let statements = &batch_json["batch_summary"]["statements"];
    assert_eq!(statements["sql_analyzed"], 2, "{batch_json}");
    assert_eq!(statements["sql_unrecognized"], 1, "{batch_json}");
}

// "Top Matched Rules" counts each occurrence the per-file lines count, in
// every format: two files with four and two unbounded deletes are six.
#[test]
fn top_matched_rules_count_occurrences_in_every_format() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("a_four.sql"),
        "DELETE FROM orders;\nDELETE FROM users;\nDELETE FROM archive;\nDELETE FROM accounts;\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("b_two.sql"),
        "DELETE FROM orders;\nDELETE FROM users;\n",
    )
    .expect("write");
    let path = dir.path().to_str().expect("utf-8 path");

    let text = run(&["analyze", "-r", path], None);
    assert_eq!(text.code, 0, "stderr: {}", text.stderr);
    assert!(
        text.stdout
            .contains("Top Matched Rules:\n  DML-WRITE-UNBOUNDED - 6 occurrence(s)"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("(4 occurrences)"), "{}", text.stdout);
    assert!(text.stdout.contains("(2 occurrences)"), "{}", text.stdout);

    let md = run(&["analyze", "-r", path, "--format", "markdown"], None);
    assert_eq!(md.code, 0, "stderr: {}", md.stderr);
    assert!(
        md.stdout.contains(
            "| Rule | Occurrences |\n|------|-------------|\n| `DML-WRITE-UNBOUNDED` | 6 |"
        ),
        "{}",
        md.stdout
    );

    let json = run(&["analyze", "-r", path, "--format", "json"], None);
    assert_eq!(json.code, 0, "stderr: {}", json.stderr);
    let batch: serde_json::Value = serde_json::from_str(&json.stdout).expect("json batch");
    assert_eq!(
        batch["top_matched_rules"][0]["rule"], "DML-WRITE-UNBOUNDED",
        "{}",
        json.stdout
    );
    assert_eq!(batch["top_matched_rules"][0]["count"], 6, "{}", json.stdout);
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

/// A repository, a dbt project, whose last commit adds the same unbounded
/// delete under five names: plain, non-ASCII, upper-case extension, a
/// `tests` directory and the project's `macros` directory.
fn repo_with_awkward_names() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("base.sql"), "SELECT 1;\n").expect("write base.sql");
    std::fs::write(root.join("dbt_project.yml"), "name: 'p'\n").expect("write project");
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
            rule_ids(&file["result"]["report"]["findings"]),
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
    assert_eq!(
        skipped[0]["reason"],
        "in a macro path of dbt_project.yml: macro definitions, not statements"
    );
}

// Under `--strict`, a changed file the review could not read fails the run
// and is named; a file the range removes and a macro file of the dbt project
// are listed beside a file it analyzes, and fail nothing.
#[test]
fn a_strict_review_fails_on_a_changed_file_it_did_not_analyze() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    std::fs::write(root.join("dbt_project.yml"), "name: 'p'\n").expect("write project");
    std::fs::write(root.join("gone.sql"), "SELECT 2;\n").expect("write gone.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::remove_file(root.join("gone.sql")).expect("remove gone.sql");
    std::fs::create_dir_all(root.join("macros")).expect("create macros");
    std::fs::write(
        root.join("macros/m.sql"),
        "{% macro m() %}1{% endmacro %}\n",
    )
    .expect("write macro");
    std::fs::write(root.join("b.sql"), "SELECT 3;\n").expect("write b.sql");
    git(root, &["add", "-A"]);
    git(
        root,
        &["commit", "-q", "-m", "remove, add a macro and a file"],
    );
    // Bytes that are no text: neither UTF-8 nor marked UTF-16.
    std::fs::write(root.join("a.sql"), b"DELETE \xFF FROM t;\n").expect("write a.sql");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "break the encoding"]);

    for command in [&["review"][..], &["ci", "--range"]] {
        let run_with = |range: &str, extra: &[&str]| {
            let mut args = command.to_vec();
            args.push(range);
            args.extend_from_slice(extra);
            args.extend_from_slice(&["--format", "json", "--quiet"]);
            run_in(root, &args, None)
        };
        // The range that removes a file, adds a macro and a file passes.
        let out = run_with("HEAD~2..HEAD~1", &["--strict"]);
        assert_eq!(out.code, 0, "{command:?}\nstderr: {}", out.stderr);
        let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
        assert_eq!(batch["batch_summary"]["files_skipped"], 2, "{}", out.stdout);

        // The re-encoded file fails it.
        let out = run_with("HEAD~1..HEAD", &[]);
        assert_eq!(out.code, 0, "{command:?}\nstderr: {}", out.stderr);
        let out = run_with("HEAD~1..HEAD", &["--strict"]);
        assert_eq!(out.code, 1, "{command:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains(
                "a.sql: [E_STRICT_NOT_ANALYZED] not analyzed: The file is not UTF-8 text"
            ),
            "{command:?}\nstderr: {}",
            out.stderr
        );
    }
}

// A committed symbolic link and a submodule a range changes are not read as
// SQL or Python: each is listed as not analyzed, with what it is, and fails
// `--strict`, as a directory scan treats a link.
#[cfg(unix)]
#[test]
fn a_review_lists_a_committed_link_or_submodule_as_not_analyzed() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::create_dir_all(root.join("models")).expect("models");
    std::fs::create_dir_all(root.join("jobs")).expect("jobs");
    std::fs::write(root.join("models/dim.sql"), "SELECT 1;\n").expect("write sql");
    std::fs::write(root.join("jobs/real.py"), "spark.sql('SELECT 1')\n").expect("write py");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::os::unix::fs::symlink("models/dim.sql", root.join("link.sql")).expect("sql link");
    std::os::unix::fs::symlink("real.py", root.join("jobs/link.py")).expect("py link");
    git(root, &["add", "."]);
    git(
        root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,vendor.sql",
        ],
    );
    git(root, &["commit", "-q", "-m", "links and a submodule"]);

    for command in [&["review"][..], &["ci", "--range"]] {
        let mut args = command.to_vec();
        args.extend_from_slice(&[
            "HEAD~1..HEAD",
            "--scan-embedded",
            "--format",
            "json",
            "--quiet",
        ]);
        let out = run_in(root, &args, None);
        assert_eq!(out.code, 0, "{command:?}\nstderr: {}", out.stderr);
        let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
        assert!(
            batch["files"].as_array().expect("files").is_empty(),
            "{command:?}\n{}",
            out.stdout
        );
        let mut skipped: Vec<(&str, &str)> = batch["skipped_files"]
            .as_array()
            .expect("skipped files")
            .iter()
            .map(|file| {
                (
                    file["path"].as_str().expect("path"),
                    file["reason"].as_str().expect("reason"),
                )
            })
            .collect();
        skipped.sort_unstable();
        let paths: Vec<&str> = skipped.iter().map(|(path, _)| *path).collect();
        assert_eq!(
            paths,
            ["jobs/link.py", "link.sql", "vendor.sql"],
            "{command:?}\n{}",
            out.stdout
        );
        assert!(skipped[0].1.starts_with("symbolic link"), "{skipped:?}");
        assert!(skipped[1].1.starts_with("symbolic link"), "{skipped:?}");
        assert!(skipped[2].1.starts_with("submodule"), "{skipped:?}");

        args.push("--strict");
        let out = run_in(root, &args, None);
        assert_eq!(out.code, 1, "{command:?}\nstdout: {}", out.stdout);
        for path in paths {
            assert!(
                out.stderr
                    .contains(&format!("{path}: [E_STRICT_NOT_ANALYZED] not analyzed: ")),
                "{command:?}\nstderr: {}",
                out.stderr
            );
        }
    }
}

// A batch's SARIF and GitLab SAST reports name the symbolic link its scan
// does not follow, and the file it cannot read, as not analyzed, each by its
// path from the working directory and with its reason.
#[cfg(unix)]
#[test]
fn a_batchs_sarif_and_gitlab_name_a_link_and_an_unreadable_file_as_not_analyzed() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    std::fs::write(root.join("ok.sql"), "DELETE FROM t;\n").expect("write sql");
    std::fs::write(root.join("bad.sql"), b"SELECT \xff 1;\n").expect("write bytes");
    std::os::unix::fs::symlink("ok.sql", root.join("link.sql")).expect("sql link");
    let expected = [("link.sql", "symbolic link"), ("bad.sql", "not UTF-8")];

    let out = run_in(root, &["analyze", ".", "-r", "--format", "sarif"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("notifications");
    let not_analyzed = notifications
        .iter()
        .find(|n| n["descriptor"]["id"] == "file-not-analyzed")
        .unwrap_or_else(|| panic!("{notifications:?}"));
    let locations: Vec<(&str, &str)> = not_analyzed["locations"]
        .as_array()
        .expect("locations")
        .iter()
        .map(|l| {
            (
                l["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .expect("uri"),
                l["message"]["text"].as_str().expect("reason"),
            )
        })
        .collect();
    assert_eq!(locations.len(), expected.len(), "{locations:?}");
    for (file, reason) in expected {
        assert!(
            locations
                .iter()
                .any(|(uri, why)| *uri == file && why.contains(reason)),
            "{file}: {locations:?}"
        );
    }

    let out = run_in(root, &["analyze", ".", "-r", "--format", "gl-sast"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let gitlab: serde_json::Value = serde_json::from_str(&out.stdout).expect("gl-sast");
    let messages: Vec<&str> = gitlab["scan"]["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .filter(|m| m["level"] == "warn")
        .map(|m| m["value"].as_str().expect("value"))
        .collect();
    assert_eq!(messages.len(), expected.len(), "{messages:?}");
    for (file, reason) in expected {
        assert!(
            messages
                .iter()
                .any(|m| m.starts_with(&format!("{file}: File was not analyzed"))
                    && m.contains(reason)),
            "{file}: {messages:?}"
        );
    }
}

// Under `--strict`, a file of a directory or a Python file `--scan-embedded`
// could not read fails the run and is named.
#[test]
fn a_strict_batch_fails_on_a_file_it_could_not_read() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    // Bytes that are no text: neither UTF-8 nor marked UTF-16.
    std::fs::write(dir.path().join("b.sql"), [0x41, 0xFF, 0x42]).expect("write b.sql");
    std::fs::write(dir.path().join("job.py"), [0x41, 0xFF, 0x42]).expect("write job.py");
    for (extra, unread) in [
        (&[][..], &["b.sql"][..]),
        (&["--scan-embedded"][..], &["b.sql", "job.py"][..]),
    ] {
        let mut args = vec!["analyze", ".", "-r", "--format", "json", "--quiet"];
        args.extend_from_slice(extra);
        let out = run_in(dir.path(), &args, None);
        assert_eq!(out.code, 0, "{extra:?}\nstderr: {}", out.stderr);
        let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
        let mut skipped: Vec<&str> = batch["skipped_files"]
            .as_array()
            .expect("skipped files")
            .iter()
            .map(|file| {
                Path::new(file["path"].as_str().expect("path"))
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("file name")
            })
            .collect();
        skipped.sort_unstable();
        assert_eq!(skipped, unread, "{extra:?}\n{}", out.stdout);

        args.push("--strict");
        let out = run_in(dir.path(), &args, None);
        assert_eq!(out.code, 1, "{extra:?}\nstdout: {}", out.stdout);
        for name in unread {
            assert!(
                out.stderr
                    .contains(&format!("{name}: [E_STRICT_NOT_ANALYZED] not analyzed: ")),
                "{extra:?}\nstderr: {}",
                out.stderr
            );
        }
    }
}

// A template this build does not render is analyzed as its template text,
// its findings reported; under `--strict` it fails the run as a file not
// analyzed, alone, from standard input or in a batch, and a plain file
// beside it does not.
#[test]
fn a_strict_run_fails_on_a_template_it_did_not_render() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("tpl.sql"), "DELETE FROM {{ 'jt' }};\n").expect("write tpl.sql");
    std::fs::write(dir.path().join("plain.sql"), "DELETE FROM users;\n").expect("write plain.sql");
    let reason = ": [E_STRICT_NOT_ANALYZED] not analyzed: this build does not render templates";
    for (args, stdin, code) in [
        (&["analyze", "tpl.sql"][..], None, 1),
        (
            &["analyze", "--stdin"][..],
            Some("DELETE FROM {{ 'jt' }};\n"),
            1,
        ),
        (&["analyze", "plain.sql"][..], None, 0),
    ] {
        let mut args = args.to_vec();
        args.extend_from_slice(&["--format", "json", "--strict"]);
        let out = run_in(dir.path(), &args, stdin);
        assert_eq!(out.code, code, "{args:?}\nstderr: {}", out.stderr);
        assert_eq!(
            out.stderr.contains(reason),
            code == 1,
            "{args:?}\n{}",
            out.stderr
        );
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
        assert_eq!(
            rule_ids(&report["findings"]),
            ["DML-WRITE-UNBOUNDED"],
            "{args:?}"
        );
    }

    let out = run_in(
        dir.path(),
        &[
            "analyze", ".", "-r", "--format", "json", "--quiet", "--strict",
        ],
        None,
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains(&format!("tpl.sql{reason}")),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("plain.sql:"), "{}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(
        batch["files"].as_array().map(Vec::len),
        Some(2),
        "{}",
        out.stdout
    );
}

// `review` reads the files a range changes: `--stdin` is refused with the
// usage.
#[test]
fn review_refuses_stdin() {
    let repo = repo_with_a_change();
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--stdin"],
        Some("DELETE FROM t;"),
    );
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr
            .contains("Error: --stdin does not apply to review"),
        "{}",
        out.stderr
    );
    assert!(out.stdout.contains("Usage:"), "{}", out.stdout);
}

// With `--scan-embedded`, `review` analyzes the SQL of the Python files the
// range changes, as of its head; a Python file the range removes has none.
#[test]
fn review_scans_the_python_files_a_range_changes_when_asked() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    std::fs::write(root.join("job.py"), "spark.sql('SELECT 1')\n").expect("write job.py");
    std::fs::write(root.join("old.py"), "spark.sql('SELECT 2')\n").expect("write old.py");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(root.join("job.py"), "spark.sql('DELETE FROM orders')\n").expect("write job.py");
    std::fs::remove_file(root.join("old.py")).expect("remove old.py");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "change"]);
    // The working tree moves on; the review reads the head commit.
    std::fs::write(root.join("job.py"), "spark.sql('SELECT 3')\n").expect("write job.py");

    let review = |extra: &[&str]| {
        let mut args = vec!["review", "HEAD~1..HEAD", "--format", "json", "--quiet"];
        args.extend_from_slice(extra);
        let out = run_in(root, &args, None);
        assert_eq!(out.code, 0, "{extra:?}\nstderr: {}", out.stderr);
        serde_json::from_str::<serde_json::Value>(&out.stdout).expect("json batch")
    };
    let batch = review(&["--scan-embedded"]);
    let files = batch["files"].as_array().expect("files");
    assert_eq!(files.len(), 1, "{batch}");
    // A fragment is named by its file, and the line and column its SQL
    // begins at.
    assert_eq!(files[0]["file"], "job.py:1:12", "{batch}");
    assert_eq!(files[0]["result"]["embedded"], true, "{batch}");
    assert_eq!(
        rule_ids(&files[0]["result"]["report"]["findings"]),
        ["DML-WRITE-UNBOUNDED"]
    );
    assert_eq!(batch["batch_summary"]["files_skipped"], 0, "{batch}");

    // Without it, a range that changes no SQL file reviews nothing.
    let out = run_in(root, &["review", "HEAD~1..HEAD", "--quiet"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
}

// The Markdown a review prints shows the placeholders `--render-diagnostics`
// asks for, as the text summary does.
#[test]
fn review_markdown_shows_the_render_diagnostics_asked_for() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    std::fs::write(
        root.join("a.sql"),
        "DELETE FROM ${ENV}_db.public.orders WHERE id = ${ID};\n",
    )
    .expect("write a.sql");
    git(root, &["commit", "-q", "-am", "change"]);

    let markdown = |extra: &[&str]| {
        let mut args = vec!["review", "HEAD~1..HEAD", "--quiet"];
        args.extend_from_slice(extra);
        let out = run_in(root, &args, None);
        assert_eq!(out.code, 0, "{extra:?}\nstderr: {}", out.stderr);
        out.stdout
    };
    let plain = markdown(&[]);
    assert!(!plain.contains("Top impacted files"), "{plain}");
    let summary = markdown(&["--render-diagnostics", "summary"]);
    assert!(summary.contains("_To reduce placeholders"), "{summary}");
    assert!(!summary.contains("Top impacted files"), "{summary}");
    let all = markdown(&["--render-diagnostics", "all"]);
    assert!(
        all.contains("**Top impacted files:**\n- `a.sql`: 2 (high 2, low 0)"),
        "{all}"
    );
    assert!(all.contains("**Top placeholder sources:**"), "{all}");
    assert!(all.contains("**Top placeholder kinds:**"), "{all}");
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
    assert!(
        out.stdout.contains("- `macros/helper.sql`: "),
        "{}",
        out.stdout
    );
}

#[test]
fn review_of_a_range_that_only_changes_skipped_files_still_reports_them() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("base.sql"), "SELECT 1;\n").expect("write base.sql");
    std::fs::write(root.join("dbt_project.yml"), "name: 'p'\n").expect("write project");
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

// A symbolic link to a SQL file the scan does not follow is SQL left
// unanalyzed: under `--strict` it fails the run and is named. A macro file
// of a dbt project is listed too, and fails nothing.
#[cfg(unix)]
#[test]
fn a_strict_scan_fails_on_a_symbolic_link_it_did_not_follow() {
    let tree = tree_with_a_link_out("q.sql", "SELECT 1;\n");
    std::fs::write(tree.path().join("repo/dbt_project.yml"), "name: 'p'\n").expect("write project");
    std::fs::create_dir_all(tree.path().join("repo/macros")).expect("create macros");
    std::fs::write(
        tree.path().join("repo/macros/m.sql"),
        "{% macro m() %}1{% endmacro %}\n",
    )
    .expect("write macro");
    let mut args = vec!["analyze", "repo", "-r", "--format", "json", "--quiet"];
    let out = run_in(tree.path(), &args, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(batch["batch_summary"]["files_skipped"], 2, "{}", out.stdout);

    args.push("--strict");
    let out = run_in(tree.path(), &args, None);
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr
            .contains("leak.sql: [E_STRICT_NOT_ANALYZED] not analyzed: symbolic link"),
        "stderr: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("m.sql: [E_STRICT_NOT_ANALYZED]"),
        "stderr: {}",
        out.stderr
    );
}

// Which SQL files hold macros is read from the dbt project each is in: its
// `macro-paths`, and an installed package's own. A folder named `macros`
// under the model paths, or in no project, holds SQL that is analyzed. A
// scan and a review agree, and a scan started inside a macro path finds its
// project above it.
#[test]
fn a_file_holds_macros_where_its_dbt_project_says() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("base.sql"), "SELECT 1;\n").expect("write base.sql");
    for (path, text) in [
        (
            "proj/dbt_project.yml",
            "name: 'p'\nmacro-paths: [\"my_macros\"]\n",
        ),
        (
            "proj/dbt_packages/pkg/dbt_project.yml",
            "name: 'pkg'\nmacro-paths: [\"pmacros\"]\n",
        ),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, text).expect("write project");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    for name in [
        "proj/my_macros/m.sql",
        "proj/dbt_packages/pkg/pmacros/p.sql",
        "proj/dbt_packages/pkg/macros/not_a_macro_path.sql",
        "proj/models/macros/helper.sql",
        "other/macros/x.sql",
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "DELETE FROM orders WHERE 1 = 1;\n").expect("write sql");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "change"]);

    let sorted = |batch: &serde_json::Value, key: &str, field: &str| -> Vec<String> {
        let mut paths: Vec<String> = batch[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key}: {batch}"))
            .iter()
            .filter_map(|entry| entry[field].as_str().map(str::to_string))
            .collect();
        paths.sort();
        paths
    };
    let skipped = [
        "proj/dbt_packages/pkg/pmacros/p.sql",
        "proj/my_macros/m.sql",
    ];
    let analyzed = [
        "other/macros/x.sql",
        "proj/dbt_packages/pkg/macros/not_a_macro_path.sql",
        "proj/models/macros/helper.sql",
    ];
    let scan = run_in(
        root,
        &["analyze", ".", "-r", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(scan.code, 0, "stderr: {}", scan.stderr);
    let review = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(review.code, 0, "stderr: {}", review.stderr);
    for out in [&scan, &review] {
        let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
        assert_eq!(
            sorted(&batch, "skipped_files", "path"),
            skipped,
            "{}",
            out.stdout
        );
        let files: Vec<String> = sorted(&batch, "files", "file")
            .into_iter()
            .filter(|file| file != "base.sql")
            .collect();
        assert_eq!(files, analyzed, "{}", out.stdout);
    }

    let inside = run_in(
        &root.join("proj/my_macros"),
        &["analyze", ".", "-r", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(inside.code, 0, "stderr: {}", inside.stderr);
    let batch: serde_json::Value = serde_json::from_str(&inside.stdout).expect("json batch");
    assert_eq!(
        batch["batch_summary"]["files_skipped"], 1,
        "{}",
        inside.stdout
    );
    assert_eq!(
        batch["batch_summary"]["files_processed"], 0,
        "{}",
        inside.stdout
    );
}

// A macro path holds macros wherever it points, outside its project's root
// among them: a scan, whatever order its paths are named in (a path below
// the project's root among them), a review and `fmt` skip the files it
// holds, naming the project, and analyze the files beside it.
#[test]
fn a_macro_path_outside_its_project_holds_macros_wherever_it_points() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    let project = root.join("proj/dbt_project.yml");
    std::fs::create_dir_all(project.parent().expect("parent")).expect("create dir");
    std::fs::write(
        &project,
        "name: 'p'\nmacro-paths: [\"macros\", \"../shared/macros\"]\n",
    )
    .expect("write project");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    for name in [
        "shared/macros/s.sql",
        "shared/scripts/x.sql",
        "proj/models/m.sql",
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "DELETE FROM orders WHERE 1 = 1;\n").expect("write sql");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "change"]);

    let listed = |out: &Run, key: &str, field: &str| -> Vec<String> {
        let batch: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}\n{}", out.stdout, out.stderr));
        let mut paths: Vec<String> = batch[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key}: {batch}"))
            .iter()
            .filter_map(|entry| entry[field].as_str().map(str::to_string))
            .collect();
        paths.sort();
        paths
    };
    for args in [
        &["analyze", ".", "-r", "--format", "json", "--quiet"][..],
        &[
            "analyze", "shared", "proj", "-r", "--format", "json", "--quiet",
        ],
        &[
            "analyze",
            "shared",
            "proj/models",
            "-r",
            "--format",
            "json",
            "--quiet",
        ],
        &[
            "analyze",
            "proj/models",
            "shared",
            "-r",
            "--format",
            "json",
            "--quiet",
        ],
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
    ] {
        let out = run_in(root, args, None);
        assert_eq!(out.code, 0, "{args:?}\nstderr: {}", out.stderr);
        assert_eq!(
            listed(&out, "skipped_files", "path"),
            ["shared/macros/s.sql"],
            "{args:?}"
        );
        assert_eq!(
            listed(&out, "skipped_files", "reason"),
            ["in a macro path of proj/dbt_project.yml: macro definitions, not statements"],
            "{args:?}"
        );
        assert_eq!(
            listed(&out, "files", "file"),
            ["proj/models/m.sql", "shared/scripts/x.sql"],
            "{args:?}"
        );
    }
    for args in [
        &["fmt", "-r", ".", "--check"][..],
        &["fmt", "-r", "shared", "proj/models", "--check"],
        &["fmt", "-r", "proj/models", "shared", "--check"],
    ] {
        let fmt = run_in(root, args, None);
        assert!(
            fmt.stderr
                .contains("shared/macros/s.sql - skipped (in a macro path of proj/dbt_project.yml"),
            "{args:?}\nstderr: {}",
            fmt.stderr
        );
        assert!(
            fmt.stderr.contains("Formatting 2 file(s)"),
            "{args:?}\nstderr: {}",
            fmt.stderr
        );
    }
}

// The files a project's macro path leaves unread are one line of the text
// report and of the progress, with how many; `--detail` lists each, and the
// JSON report names every one.
#[test]
fn macro_files_skipped_for_one_reason_are_said_once() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    for (path, text) in [
        (
            "dbt_project.yml",
            "name: 'shop'\nmacro-paths: [\"macros\"]\n",
        ),
        ("macros/a.sql", "{% macro a() %}1{% endmacro %}\n"),
        ("macros/b.sql", "{% macro b() %}2{% endmacro %}\n"),
        ("macros/c.sql", "{% macro c() %}3{% endmacro %}\n"),
        ("models/m.sql", "SELECT id FROM t;\n"),
    ] {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    }
    let reason = "in a macro path of dbt_project.yml: macro definitions, not statements";

    let out = run_in(root, &["analyze", ".", "-r"], None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stdout.contains(&format!("  - 3 files: {reason}")),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("macros/a.sql"), "{}", out.stdout);
    assert!(
        out.stderr
            .contains(&format!("  - 3 files skipped ({reason})")),
        "{}",
        out.stderr
    );

    let detail = run_in(root, &["analyze", ".", "-r", "--detail"], None);
    for file in ["macros/a.sql", "macros/b.sql", "macros/c.sql"] {
        assert!(
            detail.stdout.contains(&format!("  - {file}: {reason}")),
            "{}",
            detail.stdout
        );
    }

    let json = run_in(root, &["analyze", ".", "-r", "--format", "json"], None);
    let report: serde_json::Value = serde_json::from_str(&json.stdout).expect("json report");
    let skipped: Vec<&str> = report["skipped_files"]
        .as_array()
        .expect("skipped files")
        .iter()
        .filter_map(|file| file["path"].as_str())
        .collect();
    assert_eq!(
        skipped,
        ["macros/a.sql", "macros/b.sql", "macros/c.sql"],
        "{}",
        json.stdout
    );
}

// A file skipped as a dbt macro file is named in every format, SARIF and
// GitLab SAST among them. A run that analyzes nothing because each of its
// SQL files is a macro file is not reported at high confidence, says so in
// a note, and fails --strict; a run that analyzes a file beside a macro
// file stays as it was. A change with no SQL file passes --strict.
#[test]
fn a_run_of_macro_files_alone_is_named_and_not_all_clear() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    for (name, text) in [
        ("dbt_project.yml", "name: 'shop'\n"),
        (
            "macros/cents.sql",
            "{% macro cents(c) %}{{ c }} / 100{% endmacro %}\n",
        ),
        ("models/m.sql", "SELECT 1 AS a\n"),
        ("README.md", "shop\n"),
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, text).expect("write file");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    let edit = |name: &str, text: &str, message: &str| {
        std::fs::write(root.join(name), text).expect("write file");
        git(root, &["commit", "-q", "-am", message]);
    };
    edit(
        "macros/cents.sql",
        "{% macro cents(c) %}{{ c }} / 1000{% endmacro %}\n",
        "macro",
    );
    let reason = "in a macro path of dbt_project.yml: macro definitions, not statements";
    let nothing = "No SQL file was analyzed";

    let json = |out: &Run| -> serde_json::Value {
        serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}\n{}", out.stdout, out.stderr))
    };
    // Each SARIF note on a macro file: its file and its message.
    let macro_notes = |sarif: &serde_json::Value| -> Vec<(String, String)> {
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|note| note["descriptor"]["id"] == "macro-file-not-analyzed")
            .map(|note| {
                (
                    note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    note["message"]["text"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect()
    };
    let notes_text = |sarif: &serde_json::Value| -> String {
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"].to_string()
    };
    let gl_messages = |gl: &serde_json::Value| -> Vec<String> {
        gl["scan"]["messages"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|message| message["value"].as_str().map(str::to_string))
            .collect()
    };

    // A scan of the macro folder, and a review of the change to the macro.
    for args in [
        &["analyze", "macros", "-r"][..],
        &["review", "HEAD~1..HEAD"][..],
    ] {
        let with = |extra: &[&str]| -> Run {
            let mut all = args.to_vec();
            all.extend_from_slice(extra);
            run_in(root, &all, None)
        };
        let sarif_run = with(&["--format", "sarif"]);
        assert_eq!(sarif_run.code, 0, "{args:?}: {}", sarif_run.stderr);
        let sarif = json(&sarif_run);
        assert_eq!(
            macro_notes(&sarif),
            [("macros/cents.sql".to_string(), reason.to_string())],
            "{args:?}: {sarif}"
        );
        assert_eq!(
            sarif["runs"][0]["properties"]["analysisConfidence"], "low",
            "{args:?}"
        );
        assert!(notes_text(&sarif).contains(nothing), "{args:?}: {sarif}");

        let gl = json(&with(&["--format", "gl-sast"]));
        let messages = gl_messages(&gl);
        assert!(
            messages.contains(&format!("macros/cents.sql: {reason}")),
            "{args:?}: {messages:?}"
        );
        assert!(
            messages.iter().any(|message| message.contains(nothing)),
            "{args:?}: {messages:?}"
        );

        let batch = json(&with(&["--format", "json"]));
        assert_eq!(batch["skipped_files"][0]["path"], "macros/cents.sql");
        assert_eq!(batch["skipped_files"][0]["reason"], reason);
        assert!(
            batch["batch_summary"]["notes"]
                .to_string()
                .contains(nothing),
            "{args:?}: {}",
            batch["batch_summary"]
        );

        let text = with(&["--format", "text"]);
        assert!(
            text.stdout.contains(&format!("macros/cents.sql: {reason}")),
            "{args:?}: {}",
            text.stdout
        );
        assert!(
            text.stdout
                .contains("Highest risk level: none found in what was checked"),
            "{args:?}: {}",
            text.stdout
        );

        let strict = with(&["--format", "json", "--strict"]);
        assert_eq!(strict.code, 1, "{args:?}: {}", strict.stderr);
        assert!(
            strict
                .stderr
                .contains("macros/cents.sql: [E_STRICT_NOT_ANALYZED] not analyzed: "),
            "{args:?}: {}",
            strict.stderr
        );
    }

    // A change to the macro and a model: the model is analyzed, the macro
    // file still named.
    std::fs::write(
        root.join("macros/cents.sql"),
        "{% macro cents(c) %}{{ c }} / 10{% endmacro %}\n",
    )
    .expect("write file");
    edit("models/m.sql", "SELECT 2 AS a\n", "macro and model");
    let sarif = json(&run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "sarif"],
        None,
    ));
    assert_eq!(
        macro_notes(&sarif),
        [("macros/cents.sql".to_string(), reason.to_string())]
    );
    assert_eq!(sarif["runs"][0]["properties"]["analysisConfidence"], "high");
    assert!(!notes_text(&sarif).contains(nothing), "{sarif}");
    let strict = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "json", "--strict"],
        None,
    );
    assert_eq!(strict.code, 0, "{}", strict.stderr);

    // A change with no SQL file has nothing to analyze.
    edit("README.md", "shop, again\n", "readme");
    let strict = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "json", "--strict"],
        None,
    );
    assert_eq!(strict.code, 0, "{}", strict.stderr);
}

// The dbt project a file is in decides it alone. Another project's macro
// path that names its folder (`../b/models/common`), or the folder above
// (`..`), leaves its models analyzed, in a scan and at a commit; a project's
// own tests and analyses are SQL whatever its macro paths say; a macro path
// or packages install path at its project's root or above (`..`) holds no
// file outside the project. A change that adds a project whose macro path is `..` beside a project's
// changed model and a loose changed script leaves both reviewed, in SARIF
// and GitLab SAST too.
#[test]
fn a_macro_path_never_takes_another_projects_files() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    for (name, text) in [
        (
            "cross/a/dbt_project.yml",
            "name: 'a'\nmacro-paths: [\"macros\", \"../b/models/common\"]\n",
        ),
        ("cross/b/dbt_project.yml", "name: 'b'\n"),
        (
            "dotdot/p/dbt_project.yml",
            "name: 'p'\nmacro-paths: [\"macros\", \"..\"]\n",
        ),
        ("dotdot/q/dbt_project.yml", "name: 'q'\n"),
        (
            "dotdot/k/dbt_project.yml",
            "name: 'k'\npackages-install-path: \"..\"\n",
        ),
        ("shop/dbt_project.yml", "name: 'shop'\n"),
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, text).expect("write project");
    }
    let sql = [
        "cross/b/models/common/c.sql",
        "dotdot/p/models/pm.sql",
        "dotdot/p/macros/pmac.sql",
        "dotdot/p/tests/pt.sql",
        "dotdot/p/analyses/pa.sql",
        "dotdot/q/models/qm.sql",
        "dotdot/loose.sql",
        "dotdot/loosepkg/macros/lp.sql",
        "shop/models/m.sql",
    ];
    for name in sql {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "DELETE FROM orders WHERE 1 = 1;\n").expect("write sql");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);

    let entries = |out: &Run, key: &str, field: &str| -> Vec<String> {
        let batch: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}\n{}", out.stdout, out.stderr));
        let mut values: Vec<String> = batch[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key}: {batch}"))
            .iter()
            .filter_map(|entry| entry[field].as_str().map(str::to_string))
            .collect();
        values.sort();
        values
    };
    let skipped_reasons =
        ["in a macro path of dotdot/p/dbt_project.yml: macro definitions, not statements"];
    let scan = run_in(
        root,
        &["analyze", ".", "-r", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(scan.code, 0, "stderr: {}", scan.stderr);
    assert_eq!(
        entries(&scan, "files", "file"),
        [
            "cross/b/models/common/c.sql",
            "dotdot/loose.sql",
            "dotdot/loosepkg/macros/lp.sql",
            "dotdot/p/analyses/pa.sql",
            "dotdot/p/models/pm.sql",
            "dotdot/p/tests/pt.sql",
            "dotdot/q/models/qm.sql",
            "shop/models/m.sql",
        ]
    );
    assert_eq!(
        entries(&scan, "skipped_files", "path"),
        ["dotdot/p/macros/pmac.sql"]
    );
    assert_eq!(entries(&scan, "skipped_files", "reason"), skipped_reasons);

    // Every changed file at once, at a commit.
    for name in sql {
        std::fs::write(root.join(name), "DELETE FROM orders WHERE 2 = 2;\n").expect("write sql");
    }
    git(root, &["commit", "-q", "-am", "every file"]);
    let review = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(review.code, 0, "stderr: {}", review.stderr);
    assert_eq!(
        entries(&review, "files", "file"),
        entries(&scan, "files", "file")
    );
    assert_eq!(
        entries(&review, "skipped_files", "path"),
        entries(&scan, "skipped_files", "path")
    );
    assert_eq!(entries(&review, "skipped_files", "reason"), skipped_reasons);

    // A change that adds a project whose macro path is `..` (the
    // repository's root), changes a model of `shop` and adds a script in no
    // project.
    let added = root.join("tools/dbt_project.yml");
    std::fs::create_dir_all(added.parent().expect("parent")).expect("create dir");
    std::fs::write(&added, "name: 'tools'\nmacro-paths: [\"..\"]\n").expect("write project");
    std::fs::write(root.join("shop/models/m.sql"), "DELETE FROM orders;\n").expect("write sql");
    let script = root.join("scripts/load.sql");
    std::fs::create_dir_all(script.parent().expect("parent")).expect("create dir");
    std::fs::write(&script, "DELETE FROM app.orders;\n").expect("write sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "add a project"]);
    let review = run_in(
        root,
        &[
            "review",
            "HEAD~1..HEAD",
            "--format",
            "json",
            "--quiet",
            "--min-severity",
            "info",
        ],
        None,
    );
    assert_eq!(review.code, 0, "stderr: {}", review.stderr);
    let reviewed = ["scripts/load.sql", "shop/models/m.sql"];
    assert_eq!(entries(&review, "files", "file"), reviewed);
    assert_eq!(
        entries(&review, "skipped_files", "path"),
        Vec::<String>::new()
    );
    let batch: serde_json::Value = serde_json::from_str(&review.stdout).expect("json batch");
    for file in batch["files"].as_array().expect("files") {
        let raised = rule_ids(&file["result"]["report"]["findings"]);
        assert!(
            raised.iter().any(|rule| rule == "DML-WRITE-UNBOUNDED"),
            "{raised:?}\n{}",
            review.stdout
        );
    }
    let expected = reviewed.map(|file| (file.to_string(), "DML-WRITE-UNBOUNDED".to_string()));

    let sarif = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "sarif", "--quiet"],
        None,
    );
    assert_eq!(sarif.code, 0, "stderr: {}", sarif.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&sarif.stdout).expect("sarif");
    let mut results: Vec<(String, String)> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|result| {
            let location = &result["locations"][0]["physicalLocation"]["artifactLocation"];
            (
                location["uri"].as_str().expect("uri").to_string(),
                result["ruleId"].as_str().expect("rule id").to_string(),
            )
        })
        .collect();
    results.sort();
    assert_eq!(results, expected, "{sarif}");

    let gl = run_in(
        root,
        &["review", "HEAD~1..HEAD", "--format", "gl-sast", "--quiet"],
        None,
    );
    assert_eq!(gl.code, 0, "stderr: {}", gl.stderr);
    let report: serde_json::Value = serde_json::from_str(&gl.stdout).expect("gl-sast");
    let mut vulnerabilities: Vec<(String, String)> = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities")
        .iter()
        .map(|finding| {
            (
                finding["location"]["file"]
                    .as_str()
                    .expect("file")
                    .to_string(),
                finding["name"].as_str().expect("name").to_string(),
            )
        })
        .collect();
    vulnerabilities.sort();
    assert_eq!(vulnerabilities, expected, "{report}");
}

/// Makes a directory unreadable for as long as it lives.
#[cfg(unix)]
struct Locked<'a>(&'a Path);

#[cfg(unix)]
impl<'a> Locked<'a> {
    fn new(dir: &'a Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        Self(dir)
    }
}

#[cfg(unix)]
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        // The temporary directory is removed after this; it needs the mode back.
        let restored = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
        assert!(restored.is_ok() || std::thread::panicking(), "chmod back");
    }
}

// A directory a scan cannot read may hold SQL: the scan lists it as
// skipped, and under `--strict` it fails the run and is named, through a
// directory walk and a glob. A directory named outright that cannot be read
// is an error, as a named file that cannot be read is.
#[cfg(unix)]
#[test]
fn a_scan_lists_a_directory_it_cannot_read_and_strict_fails_on_it() {
    let dir = TempDir::new().expect("temp dir");
    let locked = dir.path().join("part/locked");
    std::fs::create_dir_all(&locked).expect("create dirs");
    std::fs::write(dir.path().join("part/ok.sql"), "SELECT 1;\n").expect("write");
    std::fs::write(locked.join("drop.sql"), "DROP TABLE prod.users;\n").expect("write");
    let _lock = Locked::new(&locked);
    if std::fs::read_dir(&locked).is_ok() {
        eprintln!("skipped: this user reads a directory of mode 000 (root), so none is unreadable");
        return;
    }
    for args in [
        &["analyze", "part/locked"][..],
        &["analyze", "part/locked", "--strict"],
        &["analyze", "part/locked", "-r"],
    ] {
        let named = run_in(dir.path(), args, None);
        assert_eq!(named.code, 1, "{args:?}: {}", named.stderr);
        assert!(
            named
                .stderr
                .contains("Error reading directory 'part/locked'"),
            "{args:?}: {}",
            named.stderr
        );
    }
    let scan = ["analyze", "part", "-r", "--format", "json"];
    let glob = ["analyze", "part/*/*.sql", "--format", "json"];
    for args in [&scan[..], &glob[..]] {
        let plain = run_in(dir.path(), args, None);
        let strict_args: Vec<&str> = args.iter().copied().chain(["--strict"]).collect();
        let strict = run_in(dir.path(), &strict_args, None);
        assert_eq!(plain.code, 0, "{args:?}: {}", plain.stderr);
        let batch: serde_json::Value = serde_json::from_str(&plain.stdout).expect("json batch");
        let skipped = &batch["skipped_files"][0];
        assert!(
            skipped["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("locked")),
            "{args:?}: {batch}"
        );
        assert_eq!(strict.code, 1, "{args:?}: {}", strict.stderr);
        assert!(
            strict.stderr.contains(
                "locked: [E_STRICT_NOT_ANALYZED] not analyzed: a directory the scan could not read"
            ),
            "{args:?}: {}",
            strict.stderr
        );
    }
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

#[test]
fn analyze_reads_every_file_named() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("a.sql"), "DELETE FROM orders;\n").expect("write a.sql");
    std::fs::write(dir.path().join("b.sql"), "SELECT 1;\n").expect("write b.sql");
    let out = TempDir::new().expect("temp dir");
    let run = run_in(
        dir.path(),
        &[
            "analyze",
            "a.sql",
            "b.sql",
            "--min-severity",
            "info",
            "--report-out",
            out.path().to_str().expect("utf-8 path"),
        ],
        None,
    );
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(out.path().join("batch_summary.json")).expect("summary written"),
    )
    .expect("summary json");
    let per_file = summary["per_file"].as_array().expect("per_file");
    assert_eq!(per_file.len(), 2, "{summary}");
    // The first file's finding is reported, not only the last file's.
    assert!(
        summary.to_string().contains("DML-WRITE-UNBOUNDED"),
        "{summary}"
    );
}

#[test]
fn a_batch_report_is_on_stdout_lists_findings_and_survives_quiet() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("a.sql"), "DELETE FROM orders;\n").expect("write a.sql");
    std::fs::write(dir.path().join("b.sql"), "SELECT 1;\n").expect("write b.sql");
    for quiet in [false, true] {
        for format in ["text", "markdown"] {
            let mut args = vec![
                "analyze",
                ".",
                "-r",
                "--format",
                format,
                "--min-severity",
                "info",
            ];
            if quiet {
                args.push("-q");
            }
            let run = run_in(dir.path(), &args, None);
            assert_eq!(run.code, 0, "{args:?}\nstderr: {}", run.stderr);
            // The report is on stdout, with each file's finding in it.
            assert!(
                run.stdout.contains("Per-File Finding Details")
                    && run.stdout.contains("Unbounded write operation detected"),
                "{args:?}\nstdout: {}",
                run.stdout
            );
            assert!(
                !run.stderr.contains("Files processed"),
                "{args:?}: the report is not on stderr\nstderr: {}",
                run.stderr
            );
        }
    }
}

/// `text` as UTF-16 with its byte-order mark, of `little` or big endian.
fn utf16(text: &str, little: bool) -> Vec<u8> {
    let mut bytes = if little {
        vec![0xFF, 0xFE]
    } else {
        vec![0xFE, 0xFF]
    };
    for unit in text.encode_utf16() {
        bytes.extend(if little {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        });
    }
    bytes
}

#[test]
fn a_utf16_file_is_read_and_written_back_as_utf16() {
    for little in [true, false] {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("q.sql");
        std::fs::write(&path, utf16("DELETE FROM orders;\n", little)).expect("write");
        let run = run_in(
            dir.path(),
            &[
                "analyze",
                "q.sql",
                "--format",
                "json",
                "--min-severity",
                "info",
            ],
            None,
        );
        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("json");
        assert!(
            rule_ids(&report["findings"]).contains(&"DML-WRITE-UNBOUNDED".to_string()),
            "{report}"
        );

        std::fs::write(&path, utf16("select 1 from t;\n", little)).expect("write");
        let run = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
        assert_eq!(run.code, 0, "stderr: {}", run.stderr);
        let written = std::fs::read(&path).expect("read back");
        // Written back in the encoding it was read in.
        assert_eq!(&written[..2], &utf16("", little)[..], "the mark kept");
        assert!(
            written.len() > 2 && written.len().is_multiple_of(2),
            "UTF-16 units: {written:?}"
        );
    }
}

#[test]
fn a_rules_file_overriding_a_former_rule_id_applies_to_the_rule_that_absorbed_it() {
    let dir = TempDir::new().expect("temp dir");
    let rules = dir.path().join("rules.yaml");
    std::fs::write(
        &rules,
        "rules:\n  - id: SNW-PWDPOL-EXPIRY-STALE\n    enabled: false\n",
    )
    .expect("write rules");
    let sql = "CREATE PASSWORD POLICY p PASSWORD_MAX_AGE_DAYS = 365;";
    let ids = |extra: &[&str]| -> (Vec<String>, String) {
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
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
        (rule_ids(&report["findings"]), out.stderr)
    };
    let rules_path = rules.to_str().expect("utf-8 path");
    let (before, _) = ids(&[]);
    assert!(
        before.contains(&"SNW-PWDPOL-EXPIRY-LONG".to_string()),
        "{before:?}"
    );
    let (after, stderr) = ids(&["--custom-rules", rules_path, "-q"]);
    assert!(
        !after.contains(&"SNW-PWDPOL-EXPIRY-LONG".to_string()),
        "{after:?}"
    );
    // One note on stderr, which `-q` keeps.
    assert_eq!(
        stderr.trim(),
        format!(
            "SNW-PWDPOL-EXPIRY-STALE is now SNW-PWDPOL-EXPIRY-LONG; the override in {rules_path} applies to it"
        )
    );
}

// Without the built-in rules an entry under a former id overrides nothing: a
// full rule is reported under the current id, and a partial override is an
// error, with no note that it applies.
#[test]
fn a_former_id_entry_without_built_in_rules_is_noted_as_what_it_does() {
    let dir = TempDir::new().expect("temp dir");
    let full = dir.path().join("full.yaml");
    std::fs::write(
        &full,
        "rules:\n  - id: SNW-PWDPOL-EXPIRY-STALE\n    risk_level: high\n    message: \"mine\"\n    \
         triggers:\n      kind: create_password_policy\n",
    )
    .expect("write rules");
    let partial = dir.path().join("partial.yaml");
    std::fs::write(
        &partial,
        "rules:\n  - id: SNW-PWDPOL-EXPIRY-STALE\n    enabled: false\n",
    )
    .expect("write rules");
    let sql = "CREATE PASSWORD POLICY p PASSWORD_MAX_AGE_DAYS = 365;";
    let full = full.to_str().expect("utf-8");
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--no-builtin",
            "--custom-rules",
            full,
            "-q",
        ],
        Some(sql),
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(
        out.stderr.trim(),
        format!(
            "SNW-PWDPOL-EXPIRY-STALE is now SNW-PWDPOL-EXPIRY-LONG; the rule in {full} is reported as SNW-PWDPOL-EXPIRY-LONG"
        )
    );
    let out = run(
        &[
            "analyze",
            "--stdin",
            "--no-builtin",
            "--custom-rules",
            partial.to_str().expect("utf-8"),
        ],
        Some(sql),
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(!out.stderr.contains("applies to it"), "{}", out.stderr);
}

// A strict mode that names no mode is reported, in the option and in
// `LEXEGA_STRICT`; it is never read as off. A file after a bare `--strict`
// is still read as a file.
#[test]
fn a_strict_mode_that_names_no_mode_is_an_error() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("q.sql"), "SELECT 1;\n").expect("write");
    for args in [
        &["analyze", "--strict=pedantik", "q.sql"][..],
        &["analyze", "--strict", "bogus", "q.sql"],
    ] {
        let out = run_in(dir.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}: {}", out.stderr);
        assert!(
            out.stderr
                .contains("is not a strict mode (off|strict|pedantic)"),
            "{args:?}: {}",
            out.stderr
        );
    }
    let out = run_env(
        dir.path(),
        &["analyze", "q.sql"],
        None,
        &[("LEXEGA_STRICT", "bogus")],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("LEXEGA_STRICT='bogus' is not a strict mode (off|strict|pedantic)"),
        "{}",
        out.stderr
    );
    let out = run_env(
        dir.path(),
        &["analyze", "--strict", "off", "q.sql"],
        None,
        &[("LEXEGA_STRICT", "bogus")],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run_in(dir.path(), &["analyze", "--strict", "q.sql"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
}

/// The files a JSON review batch analyzed, by name, with each one's rules.
fn reviewed(out: &Run) -> Vec<(String, Vec<String>)> {
    let batch: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("json batch ({e}): {}\nstderr: {}", out.stdout, out.stderr));
    batch["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|file| {
            (
                file["file"].as_str().expect("file").to_string(),
                rule_ids(&file["result"]["report"]["findings"]),
            )
        })
        .collect()
}

// `base..` is `base..HEAD` and `..head` is `HEAD..head`, as git reads them.
#[test]
fn a_range_with_an_empty_side_reads_head_there() {
    let repo = repo_with_a_change();
    let changed = vec![("a.sql".to_string(), vec!["DML-WRITE-UNBOUNDED".to_string()])];
    for args in [
        &["review", "HEAD~1..", "--format", "json", "--quiet"][..],
        &["ci", "--range", "HEAD~1..", "--format", "json", "--quiet"],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 0, "{args:?}\nstderr: {}", out.stderr);
        assert_eq!(reviewed(&out), changed, "{args:?}");
    }
    git(repo.path(), &["branch", "tip"]);
    git(repo.path(), &["checkout", "-q", "HEAD~1"]);
    let out = run_in(
        repo.path(),
        &["review", "..tip", "--format", "json", "--quiet"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(reviewed(&out), changed);
}

/// A repository whose `feature` branch adds an unbounded delete to `a.sql`
/// while `trunk` moves on with `c.sql`, checked out at `trunk`.
fn repo_with_a_branch() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    git(root, &["branch", "trunk"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("a.sql"), "DELETE FROM orders WHERE 1 = 1;\n").expect("write a.sql");
    git(root, &["commit", "-q", "-am", "feature"]);
    git(root, &["checkout", "-q", "trunk"]);
    std::fs::write(root.join("c.sql"), "DELETE FROM items WHERE 1 = 1;\n").expect("write c.sql");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "trunk moves on"]);
    dir
}

// `trunk...feature` is what `feature` changes since it left `trunk`: the
// range from their merge base to `feature`, as git reads it.
#[test]
fn a_three_dot_range_reads_from_the_merge_base() {
    let repo = repo_with_a_branch();
    let changed = vec![("a.sql".to_string(), vec!["DML-WRITE-UNBOUNDED".to_string()])];
    for args in [
        &["review", "trunk...feature", "--format", "json", "--quiet"][..],
        &[
            "ci",
            "--range",
            "trunk...feature",
            "--format",
            "json",
            "--quiet",
        ],
        &["review", "...feature", "--format", "json", "--quiet"],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 0, "{args:?}\nstderr: {}", out.stderr);
        assert_eq!(reviewed(&out), changed, "{args:?}");
    }
}

/// Runs `lexega` in `dir` with no CI platform in its environment but the
/// one `vars` set.
fn run_in_ci(dir: &Path, args: &[&str], vars: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lexega"));
    for name in [
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_BASE_REF",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_CI",
        "BITBUCKET_PIPELINE_UUID",
        "BITBUCKET_BUILD_NUMBER",
        "TF_BUILD",
        "LEXEGA_CI",
    ] {
        command.env_remove(name);
    }
    let out = command
        .args(args)
        .current_dir(dir)
        .envs(vars.iter().copied())
        .output()
        .expect("run lexega");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

// A range naming a commit the clone does not hold says so, and how to fetch
// it where the clone is shallow, as `actions/checkout` makes it by default.
#[test]
fn a_range_the_clone_does_not_hold_is_refused_with_how_to_fetch_it() {
    let repo = repo_with_a_change();
    let dir = TempDir::new().expect("temp dir");
    let origin = format!("file://{}", repo.path().display());
    git(
        dir.path(),
        &["clone", "-q", "--depth", "1", &origin, "clone"],
    );
    let clone = dir.path().join("clone");
    let shallow = [
        run_in(&clone, &["review", "HEAD~1..HEAD"], None),
        run_in_ci(
            &clone,
            &["ci"],
            &[
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_EVENT_NAME", "pull_request"),
                ("GITHUB_BASE_REF", "main"),
            ],
        ),
    ];
    for out in &shallow {
        assert_eq!(
            out.code, 1,
            "stdout: {}\nstderr: {}",
            out.stdout, out.stderr
        );
        // Each platform's way to fetch the whole history.
        for hint in [
            "shallow",
            "fetch-depth: 0",
            "GIT_DEPTH: 0",
            "depth: full",
            "fetchDepth: 0",
        ] {
            assert!(out.stderr.contains(hint), "{hint}\n{}", out.stderr);
        }
    }

    let single = TempDir::new().expect("temp dir");
    git(single.path(), &["init", "-q"]);
    std::fs::write(single.path().join("a.sql"), "SELECT 1;\n").expect("write a.sql");
    git(single.path(), &["add", "."]);
    git(single.path(), &["commit", "-q", "-m", "only"]);
    let out = run_in(single.path(), &["review", "HEAD~1..HEAD"], None);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("'HEAD~1' names no commit in this repository"),
        "{}",
        out.stderr
    );

    let outside = TempDir::new().expect("temp dir");
    let out = run_in(outside.path(), &["review", "HEAD~1..HEAD"], None);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr.contains("not a git repository"),
        "{}",
        out.stderr
    );
}

/// `repo_with_a_change` with a last commit that changes no SQL file.
fn repo_with_a_docs_change() -> TempDir {
    let repo = repo_with_a_change();
    std::fs::write(repo.path().join("notes.md"), "x\n").expect("write notes");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "docs"]);
    repo
}

// A range that changes no SQL file still prints the report asked for, with
// no file in it, and writes the --report-out file: a pipeline that uploads
// or reads them gets one on every pull request.
#[test]
fn a_review_of_a_range_without_sql_changes_prints_and_writes_an_empty_report() {
    let repo = repo_with_a_docs_change();
    for command in [
        &["review", "HEAD~1..HEAD"][..],
        &["ci", "--range", "HEAD~1..HEAD"],
    ] {
        for format in ["json", "yaml", "sarif", "gl-sast"] {
            let mut args = command.to_vec();
            args.extend(["--format", format, "-q"]);
            let out = run_in(repo.path(), &args, None);
            assert_eq!(out.code, 0, "{args:?}\n{}", out.stderr);
            let printed: serde_json::Value = if format == "yaml" {
                serde_yaml_ng::from_str(&out.stdout).expect("yaml report")
            } else {
                serde_json::from_str(&out.stdout)
                    .unwrap_or_else(|e| panic!("{args:?} ({e}): {}", out.stdout))
            };
            match format {
                "json" | "yaml" => {
                    assert_eq!(printed["batch_summary"]["files_total"], 0, "{args:?}");
                    assert_eq!(printed["files"], serde_json::json!([]), "{args:?}");
                }
                "sarif" => assert_eq!(
                    printed["runs"][0]["results"],
                    serde_json::json!([]),
                    "{args:?}"
                ),
                _ => assert_eq!(
                    printed["vulnerabilities"],
                    serde_json::json!([]),
                    "{args:?}"
                ),
            }
        }
    }
    for name in ["out/report.json", "out/report.sarif"] {
        let out = run_in(
            repo.path(),
            &["review", "HEAD~1..HEAD", "--report-out", name, "-q"],
            None,
        );
        assert_eq!(out.code, 0, "{name}\n{}", out.stderr);
        assert!(out.stdout.is_empty(), "{name}\n{}", out.stdout);
        let written = std::fs::read_to_string(repo.path().join(name)).expect("report written");
        let written: serde_json::Value = serde_json::from_str(&written).expect("json report");
        assert!(written.is_object(), "{name}");
    }
}

// A comment that cannot be posted never writes into a machine-readable
// report on stdout: outside CI, and in a pull request run without a token.
#[test]
fn a_pr_comment_that_cannot_be_posted_leaves_the_report_on_stdout_whole() {
    let repo = repo_with_a_change();
    let pull_request = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REPOSITORY", "acme/models"),
        ("GITHUB_REF", "refs/pull/7/merge"),
    ];
    for format in ["json", "sarif", "gl-sast"] {
        for vars in [&[][..], &pull_request[..]] {
            let out = run_in_ci(
                repo.path(),
                &[
                    "review",
                    "HEAD~1..HEAD",
                    "--pr-comment",
                    "--format",
                    format,
                    "-q",
                ],
                vars,
            );
            assert_eq!(out.code, 0, "{format} {vars:?}\n{}", out.stderr);
            let printed: Result<serde_json::Value, _> = serde_json::from_str(&out.stdout);
            assert!(
                printed.is_ok(),
                "{format} {vars:?}: stdout is not one document\n{}",
                out.stdout
            );
            assert!(
                out.stderr.contains("Cannot post PR comment")
                    && out.stderr.contains("Batch Analysis Summary"),
                "{format} {vars:?}\n{}",
                out.stderr
            );
        }
    }
}

/// A `curl` that never reaches a network: it logs each request's method
/// and URL to `requests.log` and its payload to `payload-<n>.json` in its
/// own directory, answers a GET with `page<n>.json` for the URL's
/// `page=<n>` (`page1.json` without one), and anything else with `{}`.
#[cfg(unix)]
fn fake_curl(pages: &[String]) -> TempDir {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("temp dir");
    for (n, page) in pages.iter().enumerate() {
        std::fs::write(dir.path().join(format!("page{}.json", n + 1)), page).expect("write page");
    }
    let script = format!(
        r#"#!/bin/sh
here='{}'
out=""; method=GET; url=""; payload=""; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a";; -X) method="$a";; esac
  case "$a" in @*) payload="${{a#@}}";; http*) url="$a";; esac
  prev="$a"
done
cat > /dev/null
echo "$method $url" >> "$here/requests.log"
if [ -n "$payload" ]; then
  n=$(wc -l < "$here/requests.log")
  cp "$payload" "$here/payload-$n.json"
fi
if [ "$method" = GET ]; then
  page=$(printf '%s' "$url" | sed -n 's/.*[?&]page=\([0-9]*\).*/\1/p')
  cat "$here/page${{page:-1}}.json" > "$out" 2>/dev/null || printf '[]' > "$out"
else
  printf '{{}}' > "$out"
fi
printf 200
"#,
        dir.path().display()
    );
    let curl = dir.path().join("curl");
    std::fs::write(&curl, script).expect("write curl");
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).expect("chmod curl");
    dir
}

/// A pull-request run on `platform` whose API calls go to the `curl` in
/// `curl_dir`.
#[cfg(unix)]
fn pull_request_env(platform: &str, curl_dir: &Path) -> Vec<(&'static str, String)> {
    let path = format!(
        "{}:{}",
        curl_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut vars = vec![("PATH", path)];
    let platform_vars: &[(&'static str, &str)] = match platform {
        "github" => &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_TOKEN", "test-token"),
            ("GITHUB_REPOSITORY", "acme/models"),
            ("GITHUB_REF", "refs/pull/7/merge"),
            ("GITHUB_API_URL", "https://api.github.invalid"),
        ],
        _ => &[
            ("GITLAB_CI", "true"),
            ("GITLAB_TOKEN", "test-token"),
            ("CI_PROJECT_ID", "42"),
            ("CI_MERGE_REQUEST_IID", "7"),
            ("CI_API_V4_URL", "https://gitlab.invalid/api/v4"),
        ],
    };
    vars.extend(platform_vars.iter().map(|(k, v)| (*k, v.to_string())));
    vars
}

// The review comment of an earlier run is found on any page of a busy pull
// request's comments and updated, not posted again.
#[cfg(unix)]
#[test]
fn a_review_comment_is_updated_wherever_the_earlier_one_is_listed() {
    let repo = repo_with_a_change();
    let others: Vec<serde_json::Value> = (1..=100)
        .map(|id| serde_json::json!({"id": id, "body": "looks good"}))
        .collect();
    let marked = serde_json::json!([{"id": 4242, "body": "<!-- lexega-review-comment -->\nold"}]);
    for (platform, update) in [
        (
            "github",
            "PATCH https://api.github.invalid/repos/acme/models/issues/comments/4242",
        ),
        (
            "gitlab",
            "PUT https://gitlab.invalid/api/v4/projects/42/merge_requests/7/notes/4242",
        ),
    ] {
        let curl = fake_curl(&[
            serde_json::Value::Array(others.clone()).to_string(),
            marked.to_string(),
        ]);
        let vars = pull_request_env(platform, curl.path());
        let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let out = run_in_ci(
            repo.path(),
            &["review", "HEAD~1..HEAD", "--pr-comment", "-q"],
            &vars,
        );
        assert_eq!(out.code, 0, "{platform}\n{}", out.stderr);
        let log = std::fs::read_to_string(curl.path().join("requests.log")).expect("requests");
        let writes: Vec<&str> = log.lines().filter(|l| !l.starts_with("GET ")).collect();
        assert_eq!(writes, [update], "{platform}\n{log}\n{}", out.stderr);
    }
}

// A pull-request comment's request and response are files in a private
// directory of an unpredictable name, made exclusively and removed when the
// call ends whether curl succeeded or not.
#[cfg(unix)]
#[test]
fn a_pr_comment_is_staged_privately_and_removed() {
    use std::os::unix::fs::PermissionsExt;

    let repo = repo_with_a_change();
    for code in [0, 22] {
        let bin = TempDir::new().expect("temp dir");
        let tmp = TempDir::new().expect("temp dir");
        let script = format!(
            r#"#!/bin/sh
here='{dir}'
out=""; payload=""; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a";; esac
  case "$a" in @*) payload="${{a#@}}";; esac
  prev="$a"
done
cat > /dev/null
echo "$out" >> "$here/out-paths.txt"
ls -ld "$(dirname "$out")" | cut -c1-10 >> "$here/dir-modes.txt"
if [ -n "$payload" ]; then
  echo "$payload" >> "$here/payload-paths.txt"
  ls -l "$payload" | cut -c1-10 >> "$here/payload-modes.txt"
fi
if [ {code} -ne 0 ]; then exit {code}; fi
printf '[]' > "$out"
printf 200
"#,
            dir = bin.path().display(),
        );
        let curl = bin.path().join("curl");
        std::fs::write(&curl, script).expect("write curl");
        std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut vars = pull_request_env("github", bin.path());
        vars.push((
            "TMPDIR",
            tmp.path().to_str().expect("utf-8 path").to_string(),
        ));
        let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let out = run_in_ci(
            repo.path(),
            &["review", "HEAD~1..HEAD", "--pr-comment", "-q"],
            &vars,
        );
        assert_eq!(out.code, 0, "curl exits {code}\n{}", out.stderr);
        let read = |name: &str| std::fs::read_to_string(bin.path().join(name)).unwrap_or_default();
        let paths = read("out-paths.txt");
        assert!(!paths.is_empty(), "curl ran (exits {code})");
        for path in paths.lines().chain(read("payload-paths.txt").lines()) {
            let path = std::path::Path::new(path);
            let dir = path.parent().expect("a staging directory");
            assert_eq!(dir.parent(), Some(tmp.path()), "{path:?}");
            let name = dir.file_name().and_then(|n| n.to_str()).expect("name");
            assert!(name.starts_with("lexega-upload-"), "{name}");
        }
        assert!(read("dir-modes.txt").lines().all(|m| m == "drwx------"));
        assert!(read("payload-modes.txt").lines().all(|m| m == "-rw-------"));
        assert_eq!(
            std::fs::read_dir(tmp.path()).expect("read tmp").count(),
            0,
            "the staged files are removed (curl exits {code})"
        );
    }
}

// A review whose Markdown is longer than a comment may be is posted cut at
// a line, within GitHub's 65,536-character limit, saying it is cut.
#[cfg(unix)]
#[test]
fn a_review_comment_longer_than_a_comment_may_be_is_cut() {
    let dir = TempDir::new().expect("temp dir");
    let root = dir.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join("seed.sql"), "SELECT 1;\n").expect("write seed");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    for i in 0..150 {
        std::fs::write(
            root.join(format!("m{i:03}.sql")),
            format!(
                "DROP TABLE prod.s.t{i};\nDELETE FROM prod.s.t{i};\nTRUNCATE TABLE prod.s.t{i};\n"
            ),
        )
        .expect("write model");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "many"]);

    let full = run_in(root, &["review", "HEAD~1..HEAD", "-q"], None);
    assert!(full.stdout.len() > 65_536, "{} bytes", full.stdout.len());

    let curl = fake_curl(&[]);
    let vars = pull_request_env("github", curl.path());
    let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run_in_ci(
        root,
        &[
            "review",
            "HEAD~1..HEAD",
            "--pr-comment",
            "--format",
            "json",
            "-q",
        ],
        &vars,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let log = std::fs::read_to_string(curl.path().join("requests.log")).expect("requests");
    let posted = log
        .lines()
        .position(|l| l.starts_with("POST "))
        .unwrap_or_else(|| panic!("no comment posted\n{log}"));
    let payload = std::fs::read_to_string(curl.path().join(format!("payload-{}.json", posted + 1)))
        .expect("payload");
    let payload: serde_json::Value = serde_json::from_str(&payload).expect("payload json");
    let body = payload["body"].as_str().expect("body");
    assert!(
        body.chars().count() <= 65_536,
        "{} characters",
        body.chars().count()
    );
    assert!(
        body.contains("is cut here"),
        "{}",
        &body[body.len() - 300..]
    );
    assert!(
        body.starts_with("<!-- lexega-review-comment -->\n## "),
        "{}",
        &body[..80]
    );
}

/// The commit `rev` names in the repository at `dir`.
fn commit_of(dir: &Path, rev: &str) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "--verify", rev])
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git rev-parse {rev} failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// On `pull_request_target` the workflow checks out the base branch, so the
// review reads the pull request's head commit the event names, not HEAD;
// an event that names no head is refused.
#[test]
fn ci_on_pull_request_target_reviews_the_pull_requests_head() {
    let repo = repo_with_a_branch();
    let base = commit_of(repo.path(), "trunk~1");
    let head = commit_of(repo.path(), "feature");
    let event = repo.path().join("event.json");
    std::fs::write(
        &event,
        serde_json::json!({
            "pull_request": {"number": 7, "base": {"sha": base}, "head": {"sha": head}}
        })
        .to_string(),
    )
    .expect("write event");
    let event = event.display().to_string();
    let vars = [
        ("GITHUB_ACTIONS", "true"),
        ("GITHUB_EVENT_NAME", "pull_request_target"),
        ("GITHUB_EVENT_PATH", event.as_str()),
    ];
    let out = run_in_ci(repo.path(), &["ci", "--format", "json", "-q"], &vars);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr.contains(&format!("reviewing {base}..{head}")),
        "{}",
        out.stderr
    );
    assert_eq!(
        reviewed(&out),
        [("a.sql".to_string(), vec!["DML-WRITE-UNBOUNDED".to_string()])]
    );

    let out = run_in_ci(
        repo.path(),
        &["ci", "--format", "json", "-q"],
        &[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request_target"),
            ("GITHUB_BASE_REF", "trunk"),
        ],
    );
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(out.stderr.contains("head.sha"), "{}", out.stderr);

    // The default checkout holds the base branch alone; a fork's head is
    // only under the pull request's ref, which the error names.
    let dir = TempDir::new().expect("temp dir");
    let origin = format!("file://{}", repo.path().display());
    git(
        dir.path(),
        &[
            "clone", "-q", "--depth", "1", "--branch", "trunk", &origin, "clone",
        ],
    );
    let out = run_in_ci(
        &dir.path().join("clone"),
        &["ci", "--format", "json", "-q"],
        &vars,
    );
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr.contains("git fetch origin pull/7/head"),
        "{}",
        out.stderr
    );
}

// A review runs no git listing it does not need: a listing of the whole
// tree already holds every move, and a path is checked without listing
// what it holds.
#[cfg(unix)]
#[test]
fn a_review_runs_no_git_listing_it_does_not_need() {
    use std::os::unix::fs::PermissionsExt;

    let repo = repo_with_a_change();
    std::fs::write(repo.path().join("c.sql"), "SELECT 3;\n").expect("write c.sql");
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "add"]);

    let real_git = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .expect("find git");
    let real_git = String::from_utf8_lossy(&real_git.stdout).trim().to_string();
    let wrapper = TempDir::new().expect("temp dir");
    let log = wrapper.path().join("git.log");
    let script = wrapper.path().join("git");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            real_git
        ),
    )
    .expect("write git");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = format!(
        "{}:{}",
        wrapper.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    for (paths, whole_tree) in [(&[][..], true), (&["c.sql"][..], false)] {
        std::fs::write(&log, "").expect("clear log");
        let mut args = vec!["review", "HEAD~1..HEAD"];
        args.extend_from_slice(paths);
        args.extend(["--format", "json", "-q"]);
        let out = run_env(repo.path(), &args, None, &[("PATH", path.as_str())]);
        assert_eq!(out.code, 0, "{args:?}\n{}", out.stderr);
        let ran = std::fs::read_to_string(&log).expect("git log");
        assert_eq!(
            ran.contains("--diff-filter=R"),
            !whole_tree,
            "{args:?}\n{ran}"
        );
        assert!(!ran.contains("--name-only"), "{args:?}\n{ran}");
    }
}

// A range with both sides empty names no range and is refused.
#[test]
fn a_range_with_no_side_is_refused() {
    let repo = repo_with_a_change();
    for args in [
        &["review", ".."][..],
        &["review", "..."],
        &["ci", "--range", "..."],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr
                .contains("commit range must be in format 'base..head' or 'base...head'"),
            "{args:?}\n{}",
            out.stderr
        );
    }
}

// A --report-out that names a file of a kind no report is written as is
// refused, rather than made a directory of that name; a name ending in `/`
// is a directory whatever it holds.
#[test]
fn a_report_out_of_an_unknown_kind_is_refused() {
    let repo = repo_with_a_change();
    for args in [
        &["review", "HEAD~1..HEAD", "--report-out", "r.txt", "-q"][..],
        &["analyze", "a.sql", "--report-out", "r.txt", "-q"],
        &["analyze", ".", "-r", "--report-out", "r.txt", "-q"],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr
                .contains("--report-out 'r.txt' names neither a report file"),
            "{args:?}\n{}",
            out.stderr
        );
        assert!(!repo.path().join("r.txt").exists(), "{args:?}");
    }
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--report-out", "r.d/", "-q"],
        None,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(repo.path().join("r.d/batch_summary.json").is_file());
}

// A path that matches no file at either commit of the range is an error, as
// a path `analyze` cannot find is: a misspelled path never passes a review.
#[test]
fn a_review_path_that_matches_no_file_is_an_error() {
    let repo = repo_with_a_change();
    for args in [
        &["review", "HEAD~1..HEAD", "nosuch", "--format", "json", "-q"][..],
        &["review", "HEAD~1..HEAD", "a.sql", "nosuch"],
        &["ci", "--range", "HEAD~1..HEAD", "nosuch", "-q"],
    ] {
        let out = run_in(repo.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr
                .contains("Error: 'nosuch' matches no file at HEAD~1 or HEAD"),
            "{args:?}\n{}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "{args:?}\n{}", out.stdout);
    }
    // A path the range leaves alike is reviewed and has nothing changed.
    let out = run_in(repo.path(), &["review", "HEAD~1..HEAD", "b.sql"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr.contains("No SQL files changed"),
        "{}",
        out.stderr
    );
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

// A formatted file keeps the final newline an editor gives it, in a batch
// as alone, and `--write` leaves exactly one.
#[test]
fn fmt_keeps_the_final_newline_alone_and_in_a_batch() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir(dir.path().join("m")).expect("mkdir");
    std::fs::write(dir.path().join("m/a.sql"), "select  a from t;\n").expect("write");
    std::fs::write(dir.path().join("n.sql"), "select  a from t;").expect("write");

    let out = run_in(dir.path(), &["fmt", "m", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run_in(dir.path(), &["fmt", "n.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    for path in [dir.path().join("m/a.sql"), dir.path().join("n.sql")] {
        let text = read(&path);
        assert!(
            text.ends_with(";\n") && !text.ends_with("\n\n"),
            "{path:?}: {text:?}"
        );
    }

    let out = run_in(dir.path(), &["fmt", "m", "--check"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let before = read(&dir.path().join("m/a.sql"));
    let out = run_in(dir.path(), &["fmt", "m", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(read(&dir.path().join("m/a.sql")), before);
}

// A directory named with neither `--write` nor `--check` is refused: the run
// would otherwise report success having formatted nothing.
#[test]
fn fmt_of_a_directory_needs_write_or_check() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir(dir.path().join("m")).expect("mkdir");
    std::fs::write(dir.path().join("m/a.sql"), "select  a from t;\n").expect("write");
    let out = run_in(dir.path(), &["fmt", "m"], None);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr.contains("--write") && out.stderr.contains("--check"),
        "{}",
        out.stderr
    );
    assert_eq!(read(&dir.path().join("m/a.sql")), "select  a from t;\n");
}

/// `written` with each of `tokens` removed, which must be there as written.
fn without_tokens(written: &str, tokens: &[&str]) -> String {
    let mut rest = written.to_string();
    for token in tokens {
        assert!(rest.contains(token), "{token:?} changed in {written:?}");
        rest = rest.replacen(token, "", 1);
    }
    rest
}

fn assert_only_crlf_breaks(text: &str) {
    assert!(text.contains("\r\n"), "{text:?}");
    assert_eq!(
        text.matches('\n').count(),
        text.matches("\r\n").count(),
        "a bare line feed in {text:?}"
    );
}

// Formatting a file changes the line breaks between its tokens and no byte
// inside one: a literal, a dollar-quoted body, a comment or a template
// expression keeps the breaks it was written with.
#[test]
fn fmt_keeps_every_byte_inside_a_token_in_a_crlf_file() {
    let dir = TempDir::new().expect("tempdir");
    let tokens = ["'line1\nline2'", "$$body\nline$$", "/* c1\nc2 */"];
    let source = format!(
        "select 1;\r\nselect  {}\r\n as a, {} as b, {} x\r\nfrom t;\r\n",
        tokens[0], tokens[1], tokens[2]
    );
    let model = dir.path().join("q.sql");
    std::fs::write(&model, &source).expect("write");
    let verified = run_in(dir.path(), &["fmt", "q.sql", "--verify-only"], None);
    assert_eq!(verified.code, 0, "{}", verified.stderr);
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let written = read(&model);
    assert_only_crlf_breaks(&without_tokens(&written, &tokens));
    let out = run_in(dir.path(), &["fmt", "q.sql", "--check"], None);
    assert_eq!(out.code, 0, "-w then --check: {}", out.stderr);
    let before = read(&model);
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(read(&model), before);

    let template = "select {{ var('a') }} as a\r\nfrom {{ ref(\n'x') }};\r\n";
    std::fs::write(&model, template).expect("write");
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w", "--jinja"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let written = read(&model);
    assert_only_crlf_breaks(&without_tokens(&written, &["{{ ref(\n'x') }}"]));
}

// The ending is read from a line break between tokens, not from one inside a
// literal.
#[test]
fn fmt_reads_the_line_ending_outside_the_tokens() {
    let dir = TempDir::new().expect("tempdir");
    let model = dir.path().join("q.sql");

    std::fs::write(&model, "select 'a\nb'\r\nfrom t;\r\n").expect("write");
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_only_crlf_breaks(&without_tokens(&read(&model), &["'a\nb'"]));

    std::fs::write(&model, "select 'a\r\nb'\nfrom t;\n").expect("write");
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let rest = without_tokens(&read(&model), &["'a\r\nb'"]);
    assert!(!rest.contains('\r'), "{rest:?}");
}

// An explicit `newline_style` decides the line ending; without one the file
// keeps its own. A literal keeps its bytes whatever the ending, and `--write`
// followed by `--check` is stable in every case.
#[test]
fn fmt_writes_the_line_ending_newline_style_says_and_the_files_own_without_one() {
    let lf_with_crlf_literal = "select  'a\r\nb' as x\nfrom t;\n";
    let crlf_with_lf_literal = "select  'a\nb' as x\r\nfrom t;\r\n";
    for (config, source, crlf) in [
        ("", lf_with_crlf_literal, false),
        ("", crlf_with_lf_literal, true),
        ("newline_style = \"auto\"\n", lf_with_crlf_literal, false),
        ("newline_style = \"auto\"\n", crlf_with_lf_literal, true),
        ("newline_style = \"unix\"\n", crlf_with_lf_literal, false),
        ("newline_style = \"unix\"\n", lf_with_crlf_literal, false),
        ("newline_style = \"windows\"\n", lf_with_crlf_literal, true),
        ("newline_style = \"windows\"\n", crlf_with_lf_literal, true),
    ] {
        let literal = if source.contains("'a\r\nb'") {
            "'a\r\nb'"
        } else {
            "'a\nb'"
        };
        for batch in [false, true] {
            let dir = TempDir::new().expect("tempdir");
            std::fs::write(dir.path().join(".lexega.toml"), config).expect("write");
            std::fs::write(dir.path().join("q.sql"), source).expect("write");
            let target = if batch { "." } else { "q.sql" };
            let case = format!("{config:?} {source:?} batch={batch}");
            let out = run_in(dir.path(), &["fmt", target, "-w"], None);
            assert_eq!(out.code, 0, "{case}: {}", out.stderr);
            let rest = without_tokens(&read(&dir.path().join("q.sql")), &[literal]);
            if crlf {
                assert_only_crlf_breaks(&rest);
            } else {
                assert!(!rest.contains('\r'), "{case}: {rest:?}");
            }
            let out = run_in(dir.path(), &["fmt", target, "--check"], None);
            assert_eq!(out.code, 0, "{case}: {}", out.stderr);
        }
    }
}

// A file with CRLF line endings is formatted, checked and written with CRLF.
#[test]
fn fmt_keeps_crlf_line_endings() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir(dir.path().join("m")).expect("mkdir");
    let source = "select  a,\r\n b -- note\r\nfrom t\r\nwhere x = 1 and y = 2;\r\n";
    std::fs::write(dir.path().join("q.sql"), source).expect("write");
    std::fs::write(dir.path().join("m/q.sql"), source).expect("write");

    let out = run_in(dir.path(), &["fmt", "q.sql", "--check"], None);
    assert_eq!(out.code, 1, "an unformatted file: {}", out.stderr);
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run_in(dir.path(), &["fmt", "m", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    for path in [dir.path().join("q.sql"), dir.path().join("m/q.sql")] {
        let text = read(&path);
        assert!(text.contains("\r\n"), "{path:?}: {text:?}");
        assert_eq!(
            text.matches('\n').count(),
            text.matches("\r\n").count(),
            "{path:?}: a bare line feed in {text:?}"
        );
    }
    for args in [["fmt", "q.sql", "--check"], ["fmt", "m", "--check"]] {
        let out = run_in(dir.path(), &args, None);
        assert_eq!(out.code, 0, "{args:?}: {}", out.stderr);
    }
    let out = run_in(dir.path(), &["fmt", "q.sql"], None);
    assert!(out.stdout.contains("\r\n"), "{:?}", out.stdout);
}

const FMT_PROBE: &str = "select a from t where x = 1 and y = 2;\n";

fn fmt_stdin_in(dir: &Path) -> Run {
    run_in(dir, &["fmt", "--stdin"], Some(FMT_PROBE))
}

// `.lexega.toml` is read by every way of running `fmt`, from the directory
// the run is in or above it, and a file that is not valid is an error.
#[test]
fn fmt_reads_lexega_toml_the_same_way_everywhere() {
    let plain = TempDir::new().expect("tempdir");
    let default_output = fmt_stdin_in(plain.path()).stdout;
    assert!(default_output.starts_with("SELECT"), "{default_output}");

    let lower = TempDir::new().expect("tempdir");
    std::fs::write(
        lower.path().join(".lexega.toml"),
        "keyword_case = \"lower\"\n",
    )
    .expect("write");
    let out = fmt_stdin_in(lower.path());
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.starts_with("select"), "stdin: {}", out.stdout);

    // A file found above the working directory.
    std::fs::create_dir(lower.path().join("sub")).expect("mkdir");
    std::fs::write(lower.path().join("sub/q.sql"), FMT_PROBE).expect("write");
    let out = run_in(&lower.path().join("sub"), &["fmt", "q.sql"], None);
    assert!(out.stdout.starts_with("select"), "file: {}", out.stdout);

    // A file with no formatting keys, or only keys of another command,
    // leaves the default output as it is.
    for text in ["", "[template.substitution]\nfoo = \"bar\"\n"] {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(".lexega.toml"), text).expect("write");
        let out = fmt_stdin_in(dir.path());
        assert_eq!(out.stdout, default_output, "{text:?}");
    }

    for text in ["keyword_case = \n", "dialect = \"oracle\"\n"] {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(".lexega.toml"), text).expect("write");
        let out = fmt_stdin_in(dir.path());
        assert_eq!(out.code, 1, "{text:?}: {}", out.stderr);
        assert!(out.stderr.contains(".lexega.toml"), "{}", out.stderr);
        assert!(out.stdout.is_empty(), "{}", out.stdout);
    }
}

// The configuration is looked for from where a path is written, not from
// where a link on it leads.
#[cfg(unix)]
#[test]
fn fmt_finds_the_configuration_of_the_directory_a_link_is_in() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir(dir.path().join("proj")).expect("mkdir");
    std::fs::create_dir(dir.path().join("shared")).expect("mkdir");
    std::fs::write(
        dir.path().join("proj/.lexega.toml"),
        "keyword_case = \"lower\"\n",
    )
    .expect("write");
    std::fs::write(dir.path().join("shared/x.sql"), FMT_PROBE).expect("write");
    std::os::unix::fs::symlink("../shared/x.sql", dir.path().join("proj/q.sql")).expect("link");
    let out = run_in(&dir.path().join("proj"), &["fmt", "q.sql"], None);
    assert!(out.stdout.starts_with("select"), "{}", out.stdout);
    let out = run_in(dir.path(), &["fmt", "proj/../proj/q.sql"], None);
    assert!(out.stdout.starts_with("select"), "{}", out.stdout);
}

// A `..` after a link is the directory above where the link leads, as the
// file system reads it, and the configuration is that directory's.
#[cfg(unix)]
#[test]
fn fmt_reads_dot_dot_after_a_link_as_the_file_system_does() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("real/x")).expect("mkdir");
    std::fs::create_dir(dir.path().join("a")).expect("mkdir");
    std::fs::write(dir.path().join("real/q.sql"), FMT_PROBE).expect("write");
    std::fs::write(
        dir.path().join("real/.lexega.toml"),
        "keyword_case = \"lower\"\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("a/.lexega.toml"),
        "keyword_case = \"upper\"\n",
    )
    .expect("write");
    std::os::unix::fs::symlink("../real/x", dir.path().join("a/b")).expect("link");
    let out = run_in(dir.path(), &["fmt", "a/b/../q.sql"], None);
    assert!(out.stdout.starts_with("select"), "{}", out.stdout);
    let out = run_in(&dir.path().join("a"), &["fmt", "b/../q.sql"], None);
    assert!(out.stdout.starts_with("select"), "{}", out.stdout);
}

// A dollar-quoted body is a token: a break in it says nothing about the line
// ending of the file, nor does one in a body nested in another; an opener
// nothing closes quotes nothing.
#[test]
fn fmt_reads_the_line_ending_outside_dollar_quoted_bodies() {
    const SF: &[&str] = &[];
    const PG: &[&str] = &["--dialect", "postgresql"];
    for (args, source, body, crlf) in [
        (
            SF,
            "select  $$body\nline$$ as b\r\nfrom t;\r\n",
            "$$body\nline$$",
            true,
        ),
        (
            SF,
            "select  $$body\r\nline$$ as b\nfrom t;\n",
            "$$body\r\nline$$",
            false,
        ),
        (SF, "select $$abc\r\nfrom t;\r\n", "", true),
        (
            PG,
            "select  $a$x $b$y\nz$b$ w$a$ as c\r\nfrom t;\r\n",
            "$a$x $b$y\nz$b$ w$a$",
            true,
        ),
        (
            PG,
            "create function f() returns text language plpgsql as $f$\nbegin\n  return $q$a\nb$q$;\nend\n$f$;\r\nselect  1;\r\n",
            "$f$\nbegin\n  return $q$a\nb$q$;\nend\n$f$",
            true,
        ),
        (
            PG,
            "create function f() returns text language plpgsql as $f$\r\nbegin\r\n  return $q$a\r\nb$q$;\r\nend\r\n$f$;\nselect  1;\n",
            "$f$\r\nbegin\r\n  return $q$a\r\nb$q$;\r\nend\r\n$f$",
            false,
        ),
        (
            SF,
            // A SQL body is formatted as the statements it holds: no byte of it is kept.
            "create or replace procedure p() returns string language sql as $$\nbegin\n  return 'x';\nend\n$$;\r\nselect  1;\r\n",
            "",
            true,
        ),
        (
            PG,
            "select  $tag$a\nb$tag$ as x\r\nfrom t;\r\n",
            "$tag$a\nb$tag$",
            true,
        ),
        (
            PG,
            "select  $tag$a\r\nb$tag$ as x\nfrom t;\n",
            "$tag$a\r\nb$tag$",
            false,
        ),
        (
            PG,
            "create function f() returns int as $$\nselect 1\n$$ language sql;\r\nselect  1;\r\n",
            "$$\nselect 1\n$$",
            true,
        ),
    ] {
        let dir = TempDir::new().expect("tempdir");
        let model = dir.path().join("q.sql");
        std::fs::write(&model, source).expect("write");
        let mut write = vec!["fmt", "q.sql", "-w"];
        write.extend_from_slice(args);
        let out = run_in(dir.path(), &write, None);
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
        let rest = without_tokens(&read(&model), &[body]);
        if crlf {
            assert_only_crlf_breaks(&rest);
        } else {
            assert!(!rest.contains('\r'), "{source:?}: {rest:?}");
        }
        let mut check = vec!["fmt", "q.sql", "--check"];
        check.extend_from_slice(args);
        let out = run_in(dir.path(), &check, None);
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
    }
}

// A procedure body in another language is copied as written, its last line
// break included, whatever the file's ending and `newline_style` say; the
// breaks around it are the ones `fmt` writes.
#[test]
fn fmt_keeps_the_bytes_of_a_procedure_body_in_another_language() {
    const JS: &str = "create or replace procedure p() returns string language javascript as ";
    const PY: &str = "create or replace procedure p() returns string language python runtime_version='3.11' packages=('snowflake-snowpark-python') handler='run' as ";
    for (header, body) in [
        (
            JS,
            "$$\nvar x = 1;\n\n  if (x) {\n    return 'a';\n  }\nreturn 'b';\n$$",
        ),
        (PY, "$$\ndef run(session):\n    x = 1\n    return 'a'\n$$"),
    ] {
        for file_crlf in [false, true] {
            for body_crlf in [false, true] {
                for style in [None, Some("unix"), Some("windows")] {
                    let dir = TempDir::new().expect("tempdir");
                    if let Some(style) = style {
                        std::fs::write(
                            dir.path().join(".lexega.toml"),
                            format!("newline_style = \"{style}\"\n"),
                        )
                        .expect("write");
                    }
                    let file_break = if file_crlf { "\r\n" } else { "\n" };
                    let body = if body_crlf {
                        body.replace('\n', "\r\n")
                    } else {
                        body.to_string()
                    };
                    let source = format!("{header}{body};{file_break}select  1;{file_break}");
                    let model = dir.path().join("q.sql");
                    std::fs::write(&model, &source).expect("write");
                    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
                    assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
                    let rest = without_tokens(&read(&model), &[&body]);
                    if style.map_or(file_crlf, |style| style == "windows") {
                        assert_only_crlf_breaks(&rest);
                    } else {
                        assert!(!rest.contains('\r'), "{source:?}: {rest:?}");
                    }
                    let out = run_in(dir.path(), &["fmt", "q.sql", "--check"], None);
                    assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
                }
            }
        }
    }
}

// The language a procedure's `LANGUAGE` clause names decides whether its
// body is SQL: a comment, a column name, a package or a handler holding the
// letters SQL does not, so a JavaScript or Python body is copied as written
// whatever else the header says, and a SQL body is still laid out as SQL.
#[test]
fn fmt_keeps_a_procedure_body_whose_header_holds_the_word_sql() {
    const JS_BODY: &str =
        "$$\n  var x = 1;\n    if (x) {\n        return 'a';\n    }\n  return 'b';\n$$";
    const PY_BODY: &str =
        "$$\ndef run_sql(session):\n    if True:\n        return 'a'\n    return 'b'\n$$";
    for (header, body) in [
        (
            "create or replace procedure p() returns string language javascript comment = 'SQL helper' as ",
            JS_BODY,
        ),
        (
            "create or replace procedure p() returns table (sql_text varchar) language javascript as ",
            JS_BODY,
        ),
        (
            "create or replace procedure p() returns string language python runtime_version='3.11' packages=('snowflake-snowpark-python') handler='run_sql' as ",
            PY_BODY,
        ),
        (
            "create or replace procedure p() returns string language python runtime_version='3.11' packages=('sqlalchemy') handler='run' as ",
            PY_BODY,
        ),
    ] {
        let dir = TempDir::new().expect("tempdir");
        let source = format!("{header}{body};\nselect  1;\n");
        let model = dir.path().join("q.sql");
        std::fs::write(&model, &source).expect("write");
        let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
        let written = read(&model);
        assert!(written.contains(body), "{body:?} changed in {written:?}");
        assert!(written.ends_with("SELECT 1;\n"), "{written:?}");
        let out = run_in(dir.path(), &["fmt", "q.sql", "--check"], None);
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
    }

    let dir = TempDir::new().expect("tempdir");
    let source = "create or replace procedure p() returns string language sql comment = 'x' as $$\nbegin\n  select  a from t;\n  return 'x';\nend\n$$;\n";
    let model = dir.path().join("q.sql");
    std::fs::write(&model, source).expect("write");
    let out = run_in(dir.path(), &["fmt", "q.sql", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let written = read(&model);
    assert!(
        written.contains("    SELECT a\n") && written.contains("    return 'x';"),
        "{written:?}"
    );
}

// A clause after a copied body (`$$ LANGUAGE plv8`) is copied with it, and a
// quoted language name (`'plpgsql'`) names the language its value names.
#[test]
fn fmt_keeps_a_clause_after_a_procedure_body() {
    const BLOCK: &str = "$$\nbegin\n      perform  1;\nend\n$$";
    for (dialect, source) in [
        (
            "postgresql",
            "create procedure p() as $$\n  insert into t values (1);\n$$ language sql;\n",
        ),
        (
            "postgresql",
            "create procedure p() as $$\ndef run(s):\n    return 1\n$$  language plpython3u;\n",
        ),
        (
            "postgresql",
            "create procedure p() as $$ return 1; $$ language 'plv8';\n",
        ),
        (
            "snowflake",
            "create procedure p() returns string as $$ return 1; $$ language javascript;\n",
        ),
        (
            "postgresql",
            "create procedure p() as 'insert into t values (1)'  language sql;\n",
        ),
    ] {
        let dir = TempDir::new().expect("tempdir");
        let model = dir.path().join("q.sql");
        std::fs::write(&model, source).expect("write");
        let out = run_in(
            dir.path(),
            &["fmt", "q.sql", "-w", "--dialect", dialect],
            None,
        );
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
        let written = read(&model);
        let body = &source[source.find(" as ").expect("as") + 4..];
        assert!(written.ends_with(body), "{body:?} changed in {written:?}");
        let out = run_in(
            dir.path(),
            &["fmt", "q.sql", "--check", "--dialect", dialect],
            None,
        );
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
    }

    for (dialect, language) in [
        ("postgresql", "'plpgsql'"),
        ("postgresql", "\"plpgsql\""),
        ("redshift", "'plpgsql'"),
    ] {
        let dir = TempDir::new().expect("tempdir");
        let model = dir.path().join("q.sql");
        let source = format!("create procedure p() as {BLOCK} language {language};\n");
        std::fs::write(&model, &source).expect("write");
        let out = run_in(
            dir.path(),
            &["fmt", "q.sql", "-w", "--dialect", dialect],
            None,
        );
        assert_eq!(out.code, 0, "{source:?}: {}", out.stderr);
        let written = read(&model);
        assert!(
            written.contains("\n    perform  1;\n")
                && written.ends_with(&format!("$$ language {language};\n")),
            "{written:?}"
        );
    }
}

// Several files named on the command line are formatted as a directory is.
#[test]
fn fmt_takes_several_files() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir(dir.path().join("m")).expect("mkdir");
    std::fs::write(dir.path().join("a.sql"), "select  a from t;\n").expect("write");
    std::fs::write(dir.path().join("b.sql"), "select  b from t;\n").expect("write");
    std::fs::write(dir.path().join("m/c.sql"), "select  c from t;\n").expect("write");

    let out = run_in(dir.path(), &["fmt", "a.sql", "b.sql", "--check"], None);
    assert_eq!(out.code, 1, "{}", out.stderr);
    let out = run_in(dir.path(), &["fmt", "a.sql", "b.sql", "m", "-w"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    for name in ["a.sql", "b.sql", "m/c.sql"] {
        assert!(
            read(&dir.path().join(name)).starts_with("SELECT"),
            "{name} not formatted"
        );
    }
    let out = run_in(dir.path(), &["fmt", "a.sql", "b.sql", "m", "--check"], None);
    assert_eq!(out.code, 0, "{}", out.stderr);

    let out = run_in(
        dir.path(),
        &["fmt", "a.sql", "b.sql", "-o", "out.sql"],
        None,
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(!dir.path().join("out.sql").exists());
}

/// The binary with a home, configuration and cache directory of its own.
fn run_sandboxed(sandbox: &TempDir, dir: &Path, args: &[&str]) -> Run {
    let home = sandbox.path().join("home");
    let home = home.to_str().expect("utf-8 path");
    run_env(
        dir,
        args,
        None,
        &[
            ("HOME", home),
            ("XDG_CONFIG_HOME", &format!("{home}/.config")),
            ("XDG_DATA_HOME", &format!("{home}/.local/share")),
            ("XDG_CACHE_HOME", &format!("{home}/.cache")),
        ],
    )
}

/// Every file of `dir` with its bytes.
fn files_under(dir: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(dir: &Path, out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.insert(path.clone(), Vec::new());
                visit(&path, out);
            } else {
                out.insert(path.clone(), std::fs::read(&path).expect("read"));
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(dir, &mut out);
    out
}

/// The first word of each line of a help text's `Commands:` list.
fn listed_commands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Asks `--help` and `-h` of the command `path` names and of each
/// subcommand its help lists: each prints help, exits 0 and changes nothing.
fn help_everywhere(
    sandbox: &TempDir,
    path: &[&str],
    seen: &mut std::collections::BTreeSet<String>,
) {
    let work = sandbox.path().join("work");
    let mut listed = Vec::new();
    for flag in ["--help", "-h"] {
        let mut args = path.to_vec();
        args.push(flag);
        let before = files_under(sandbox.path());
        let out = run_sandboxed(sandbox, &work, &args);
        assert_eq!(
            out.code, 0,
            "{args:?}\nstdout: {}\nstderr: {}",
            out.stdout, out.stderr
        );
        let help = format!("{}{}", out.stdout, out.stderr);
        assert!(help.contains("Usage:"), "{args:?} prints no help: {help}");
        assert_eq!(
            files_under(sandbox.path()),
            before,
            "{args:?} changed the sandbox"
        );
        if flag == "--help" {
            listed = listed_commands(&help);
        }
    }
    seen.insert(path.join(" "));
    // A subcommand's help may be its command's, listing it again.
    if path.len() < 2 {
        for sub in &listed {
            let mut next = path.to_vec();
            next.push(sub);
            help_everywhere(sandbox, &next, seen);
        }
    }
}

// Help is asked of every command and subcommand the usage text lists; it
// never runs the command.
#[test]
fn help_on_every_listed_subcommand_prints_help_and_changes_nothing() {
    let sandbox = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(sandbox.path().join("work")).expect("work dir");
    std::fs::write(sandbox.path().join("work/a.sql"), "select 1;\n").expect("write");
    let mut seen = std::collections::BTreeSet::new();
    help_everywhere(&sandbox, &[], &mut seen);
    for expected in [
        "analyze",
        "review",
        "ci",
        "catalog",
        "catalog pull",
        "catalog inspect",
        "catalog diff",
        "fmt",
    ] {
        assert!(seen.contains(expected), "{expected} not walked: {seen:?}");
    }
}

#[test]
fn the_word_help_is_help_for_catalog() {
    let sandbox = TempDir::new().expect("tempdir");
    let out = run_sandboxed(&sandbox, sandbox.path(), &["catalog", "help"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("Usage:"), "{}", out.stderr);
}

// The dialect named before the command is the dialect of the command, as
// the usage says of a global option.
#[test]
fn a_global_dialect_option_goes_before_the_command() {
    let sandbox = TempDir::new().expect("tempdir");
    let dir = sandbox.path();
    for args in [
        &["--dialect", "bogus", "fmt", "--stdin"][..],
        &["--dialect=bogus", "analyze", "--stdin"],
    ] {
        let out = run_sandboxed(&sandbox, dir, args);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains("Unknown dialect 'bogus'"),
            "{args:?}\nstderr: {}",
            out.stderr
        );
    }

    let sql = "select a::int from t where a > 1";
    let out = run(&["--dialect", "postgresql", "fmt", "--stdin"], Some(sql));
    let same = run(&["fmt", "--stdin", "--dialect", "postgresql"], Some(sql));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!((out.stdout, out.stderr), (same.stdout, same.stderr));

    // Commands that read a positional first read it as written.
    let repo = repo_with_a_change();
    for (global, trailing) in [
        (
            &["--dialect", "postgresql", "review", "HEAD~1..HEAD"][..],
            &["review", "HEAD~1..HEAD", "--dialect", "postgresql"][..],
        ),
        (
            &["--dialect", "postgresql", "ci", "a.sql"],
            &["ci", "a.sql", "--dialect", "postgresql"],
        ),
        (
            &[
                "--dialect",
                "postgresql",
                "analyze",
                "a.sql",
                "--format",
                "json",
            ],
            &[
                "analyze",
                "a.sql",
                "--format",
                "json",
                "--dialect",
                "postgresql",
            ],
        ),
    ] {
        let out = run_in(repo.path(), global, None);
        let same = run_in(repo.path(), trailing, None);
        assert_eq!(out.code, same.code, "{global:?}\nstderr: {}", out.stderr);
        assert!(
            !out.stderr.contains("commit range") && !out.stderr.contains("after the options"),
            "{global:?}\nstderr: {}",
            out.stderr
        );
        let untimed = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|line| !line.contains("\"timestamp\""))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(untimed(&out.stdout), untimed(&same.stdout), "{global:?}");
    }
    let out = run_in(
        repo.path(),
        &["--dialect", "postgresql", "diff", "HEAD~1..HEAD"],
        None,
    );
    assert!(
        out.stderr.contains("`diff` is not a command of this build"),
        "{}",
        out.stderr
    );

    // A mistyped command is not taken for one that reads no dialect alone.
    let out = run(&["--dialect", "postgresql", "analyse", "a.sql"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("'analyse', or it is not a command"),
        "{}",
        out.stderr
    );
    assert!(
        format!("{}{}", out.stdout, out.stderr).contains("Usage:"),
        "{}",
        out.stderr
    );

    let out = run(&["--dialect"], None);
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("--dialect requires a value"),
        "{}",
        out.stderr
    );
    let out = run(
        &["--dialect", "postgresql", "catalog", "inspect", "x"],
        None,
    );
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("--dialect") && out.stderr.contains("catalog"),
        "{}",
        out.stderr
    );
}

/// A snapshot listing one table twice.
const DUPLICATE_TABLE_CATALOG: &str = r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": "T", "kind": "Table", "columns": []}, {"name": "T", "kind": "Table", "columns": []}]}]}]}"#;

// A snapshot a run refuses is refused by `catalog inspect` and `catalog
// diff`, in the run's words.
#[test]
fn catalog_inspect_refuses_a_snapshot_analyze_refuses() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("dup.json"), DUPLICATE_TABLE_CATALOG).expect("write");
    let analyzed = run_in(
        dir.path(),
        &["analyze", "--stdin", "--catalog", "dup.json"],
        Some("SELECT 1;"),
    );
    assert_eq!(analyzed.code, 1, "{}", analyzed.stderr);
    let refusal = analyzed
        .stderr
        .lines()
        .find(|line| line.contains("Duplicate catalog entry"))
        .expect("analyze names the duplicate")
        .to_string();
    for args in [
        &["catalog", "inspect", "dup.json"][..],
        &["catalog", "diff", "dup.json", "dup.json"],
    ] {
        let out = run_in(dir.path(), args, None);
        assert_eq!(out.code, 1, "{args:?}\nstdout: {}", out.stdout);
        assert!(
            out.stderr.contains(&refusal),
            "{args:?}\nstderr: {}\nexpected: {refusal}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "{args:?}\nstdout: {}", out.stdout);
    }
}

#[cfg(unix)]
fn extractor_writing(dir: &Path, name: &str, snapshot: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    // The extractor is called `<extractor> pull --out <file> ...`.
    std::fs::write(
        &path,
        format!("#!/bin/sh\nprintf '%s' '{snapshot}' > \"$3\"\n"),
    )
    .expect("write extractor");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

// A pull whose extractor wrote a snapshot no run can load fails, as a run
// loading it would.
#[cfg(unix)]
#[test]
fn catalog_pull_fails_when_the_extractor_wrote_an_unusable_snapshot() {
    let dir = TempDir::new().expect("tempdir");
    let good = r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": []}"#;
    let old = r#"{"schema_version": 1, "databases": []}"#;
    for (name, snapshot, code, needle) in [
        ("good.sh", good, 0, ""),
        ("old.sh", old, 1, "schema version"),
        ("garbage.sh", "not json", 1, "parse error"),
        (
            "dup.sh",
            DUPLICATE_TABLE_CATALOG,
            1,
            "Duplicate catalog entry",
        ),
    ] {
        let extractor = extractor_writing(dir.path(), name, snapshot);
        let out_file = format!("{name}.json");
        let out = run_in(
            dir.path(),
            &[
                "catalog",
                "pull",
                "--out",
                &out_file,
                "--sidecar",
                extractor.to_str().expect("utf-8 path"),
            ],
            None,
        );
        assert_eq!(out.code, code, "{name}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.to_lowercase().contains(&needle.to_lowercase()),
            "{name}\nstderr: {}",
            out.stderr
        );
        if code == 0 {
            assert!(!out.stderr.contains("Warning"), "{}", out.stderr);
        }
    }
}

/// A custom rule that reports every DELETE.
const DELETE_RULE_YAML: &str = "schema_version: 1\nrules:\n  - id: MY-DELETE\n    risk_level: high\n    message: a delete\n    triggers:\n      kind: delete\n";

/// The rule ids of the findings a JSON report holds.
fn found_rules(out: &Run) -> Vec<String> {
    let report: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("json report: {e}\nstdout: {}", out.stdout));
    rule_ids(&report["findings"])
}

/// `run_env` with the sandbox's home, configuration and cache directories.
fn run_sandboxed_in(sandbox: &TempDir, dir: &Path, args: &[&str], stdin: Option<&str>) -> Run {
    let home = sandbox.path().join("home");
    let home = home.to_str().expect("utf-8 path");
    run_env(
        dir,
        args,
        stdin,
        &[
            ("HOME", home),
            ("XDG_CONFIG_HOME", &format!("{home}/.config")),
            ("XDG_DATA_HOME", &format!("{home}/.local/share")),
            ("XDG_CACHE_HOME", &format!("{home}/.cache")),
        ],
    )
}

// A rules file is YAML, JSON or TOML by its extension, one schema in each;
// any other extension is refused naming the ones read.
#[test]
fn a_custom_rules_file_is_yaml_json_or_toml() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    let json = r#"{"schema_version": 1, "rules": [{"id": "MY-DELETE", "risk_level": "high", "message": "a delete", "triggers": {"kind": "delete"}}]}"#;
    let toml = "schema_version = 1\n\n[[rules]]\nid = \"MY-DELETE\"\nrisk_level = \"high\"\nmessage = \"a delete\"\n\n[rules.triggers]\nkind = \"delete\"\n";
    for (name, text) in [
        ("rules.yaml", DELETE_RULE_YAML),
        ("rules.yml", DELETE_RULE_YAML),
        ("rules.json", json),
        ("rules.toml", toml),
    ] {
        std::fs::write(dir.path().join(name), text).expect("write rules");
        let out = run_sandboxed_in(
            &sandbox,
            dir.path(),
            &[
                "analyze",
                "--stdin",
                "--format",
                "json",
                "--custom-rules",
                name,
            ],
            Some("DELETE FROM orders;"),
        );
        assert_eq!(out.code, 0, "{name}\nstderr: {}", out.stderr);
        assert!(
            found_rules(&out).contains(&"MY-DELETE".to_string()),
            "{name}\n{}",
            out.stdout
        );
    }

    std::fs::write(dir.path().join("rules.txt"), DELETE_RULE_YAML).expect("write rules");
    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", "--stdin", "--custom-rules", "rules.txt"],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    for extension in [".yaml", ".yml", ".json", ".toml"] {
        assert!(out.stderr.contains(extension), "{}", out.stderr);
    }

    std::fs::write(dir.path().join("bad.toml"), "rules = [").expect("write rules");
    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", "--stdin", "--custom-rules", "bad.toml"],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(out.stderr.contains("bad.toml"), "{}", out.stderr);
}

// `--report-out` is written in the format `--report-artifact-format` names,
// else the one its extension names, else JSON, for one file and a batch
// alike; a format that contradicts the extension is refused, and `--format`
// decides what goes to standard output alone.
#[test]
fn the_report_out_format_is_one_rule_for_a_file_and_a_batch() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("q.sql"), "DELETE FROM orders;\n").expect("write");
    std::fs::write(dir.path().join("a.sql"), "DELETE FROM orders;\n").expect("write");
    std::fs::write(dir.path().join("b.sql"), "SELECT 1;\n").expect("write");
    let analyze = |paths: &[&str], extra: &[&str]| {
        let mut args = vec!["analyze"];
        args.extend_from_slice(paths);
        args.push("-q");
        args.extend_from_slice(extra);
        run_sandboxed_in(&sandbox, dir.path(), &args, None)
    };
    let read_json = |name: &str| -> serde_json::Value {
        let text = std::fs::read_to_string(dir.path().join(name))
            .unwrap_or_else(|e| panic!("{name} was not written: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} is no JSON: {e}\n{text}"))
    };
    let read_yaml = |name: &str| -> serde_yaml_ng::Value {
        let text = std::fs::read_to_string(dir.path().join(name))
            .unwrap_or_else(|e| panic!("{name} was not written: {e}"));
        serde_yaml_ng::from_str(&text).unwrap_or_else(|e| panic!("{name} is no YAML: {e}\n{text}"))
    };

    // A file and a batch.
    for paths in [&["q.sql"][..], &["a.sql", "b.sql"][..]] {
        let target = paths.join("+");
        let tag = paths[0].replace('.', "_");
        let run = |report: &str, more: &[&str]| {
            let mut extra = vec!["--report-out", report];
            extra.extend_from_slice(more);
            analyze(paths, &extra)
        };
        let sarif = format!("{tag}.sarif");
        let out = run(&sarif, &[]);
        assert_eq!(out.code, 0, "{target} {sarif}\nstderr: {}", out.stderr);
        assert!(read_json(&sarif)["runs"].is_array(), "{target} {sarif}");
        for yaml in [format!("{tag}.yaml"), format!("{tag}.yml")] {
            let out = run(&yaml, &[]);
            assert_eq!(out.code, 0, "{target} {yaml}\nstderr: {}", out.stderr);
            assert!(read_yaml(&yaml).is_mapping(), "{target} {yaml}");
        }
        let json = format!("{tag}.json");
        let out = run(&json, &[]);
        assert_eq!(out.code, 0, "{target} {json}\nstderr: {}", out.stderr);
        assert!(read_json(&json).get("runs").is_none(), "{target} {json}");

        // The format named wins over nothing, and agrees with the extension.
        let named = format!("{tag}-named.yaml");
        let out = run(&named, &["--report-artifact-format", "yaml"]);
        assert_eq!(out.code, 0, "{target}\nstderr: {}", out.stderr);
        assert!(read_yaml(&named).is_mapping());
        for (format, file) in [("yaml", &json), ("json", &sarif), ("sarif", &named)] {
            let refused = format!(
                "{tag}-refused-{format}{}",
                &file[file.rfind('.').unwrap_or(0)..]
            );
            let out = run(&refused, &["--report-artifact-format", format]);
            assert_eq!(
                out.code, 1,
                "{target} {format} {refused}\nstdout: {}",
                out.stdout
            );
            assert!(
                out.stderr.contains(format) && out.stderr.contains(&refused),
                "{target} {format}\nstderr: {}",
                out.stderr
            );
            assert!(!dir.path().join(&refused).exists(), "{refused}");
        }

        // `--format` decides standard output, not the file.
        let out = run(&format!("{tag}-fmt.json"), &["--format", "sarif"]);
        assert_eq!(out.code, 0, "{target}\nstderr: {}", out.stderr);
        let stdout: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{target}: stdout is no SARIF: {e}\n{}", out.stdout));
        assert!(stdout["runs"].is_array(), "{target}\n{}", out.stdout);
        assert!(read_json(&format!("{tag}-fmt.json")).get("runs").is_none());
        let out = run(&format!("{tag}-fmt.sarif"), &["--format", "json"]);
        assert_eq!(out.code, 0, "{target}\nstderr: {}", out.stderr);
        let stdout: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{target}: stdout is no JSON: {e}\n{}", out.stdout));
        assert!(stdout.get("runs").is_none(), "{target}\n{}", out.stdout);
        assert!(read_json(&format!("{tag}-fmt.sarif"))["runs"].is_array());

        // A directory names no format: `--format sarif` makes it SARIF, and
        // standard output then holds none.
        let directory = format!("{tag}-dir/");
        let out = run(&directory, &["--format", "sarif"]);
        assert_eq!(out.code, 0, "{target}\nstderr: {}", out.stderr);
        assert!(out.stdout.trim().is_empty(), "{target}\n{}", out.stdout);
        let written: Vec<String> = std::fs::read_dir(dir.path().join(&directory))
            .expect("report directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(written.len(), 1, "{target}: {written:?}");
        assert!(written[0].ends_with(".sarif"), "{target}: {written:?}");
        assert!(read_json(&format!("{directory}{}", written[0]))["runs"].is_array());
    }
}

/// A directory holding an `az` that records the file it is asked to upload
/// (`--file`): its path in `path.txt`, the modes of the file and its
/// directory in `file-mode.txt` and `dir-mode.txt`, its text in
/// `upload.txt`; it exits with `code`.
#[cfg(unix)]
fn recording_az(code: i32) -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let bin = TempDir::new().expect("temp dir");
    let az = bin.path().join("az");
    std::fs::write(
        &az,
        format!(
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"--file\" ]; then f=\"$2\"; fi; shift; done\n\
             echo \"$f\" > '{dir}/path.txt'\n\
             ls -ld \"$(dirname \"$f\")\" | cut -c1-10 > '{dir}/dir-mode.txt'\n\
             ls -l \"$f\" | cut -c1-10 > '{dir}/file-mode.txt'\n\
             cat \"$f\" > '{dir}/upload.txt'\nexit {code}\n",
            dir = bin.path().display()
        ),
    )
    .expect("write az");
    std::fs::set_permissions(&az, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

// An `az://` upload stages the report in a file made exclusively, in a
// private directory of an unpredictable name, and removes both whether the
// upload succeeds or not, so no name can be guessed and a link planted in
// the temporary directory is never written through.
#[cfg(unix)]
#[test]
fn an_az_upload_is_staged_privately_and_removed() {
    let mut staging_dirs = Vec::new();
    for code in [0, 1] {
        let bin = recording_az(code);
        let tmp = TempDir::new().expect("temp dir");
        let work = TempDir::new().expect("temp dir");
        let path = format!(
            "{}:{}",
            bin.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = run_env(
            work.path(),
            &[
                "analyze",
                "--stdin",
                "--format",
                "json",
                "--report-out",
                "az://c/b/r.json",
            ],
            Some("DELETE FROM orders;"),
            &[
                ("PATH", path.as_str()),
                ("TMPDIR", tmp.path().to_str().expect("utf-8 path")),
            ],
        );
        assert_eq!(out.code, code, "az exits {code}\nstderr: {}", out.stderr);
        let read = |name: &str| {
            std::fs::read_to_string(bin.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        let staged = std::path::PathBuf::from(read("path.txt").trim());
        let dir = staged.parent().expect("a staging directory");
        assert_eq!(dir.parent(), Some(tmp.path()), "{staged:?}");
        let name = dir.file_name().and_then(|n| n.to_str()).expect("name");
        assert!(
            name.starts_with("lexega-upload-") && !name.ends_with(".tmp"),
            "{name}"
        );
        assert_eq!(read("dir-mode.txt").trim(), "drwx------");
        assert_eq!(read("file-mode.txt").trim(), "-rw-------");
        assert!(
            read("upload.txt").contains("\"findings\""),
            "{}",
            read("upload.txt")
        );
        assert_eq!(
            std::fs::read_dir(tmp.path()).expect("read tmp").count(),
            0,
            "the staged report is removed (az exits {code})"
        );
        staging_dirs.push(name.to_string());
    }
    assert_ne!(
        staging_dirs[0], staging_dirs[1],
        "the name is not predictable"
    );
}

// A diagnostic flag does what its help says or is refused: the explanation
// and trace of one statement's evaluation are for one file, and
// `--explain-facts` and `--explain-findings` print text or JSON; neither
// keeps `--report-out` from being written.
#[test]
fn a_diagnostic_flag_applies_to_one_file_or_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("a.sql"), "DELETE FROM orders;\n").expect("write");
    std::fs::write(dir.path().join("b.sql"), "SELECT 1;\n").expect("write");
    std::fs::write(
        dir.path().join("job.py"),
        "spark.sql(\"DROP TABLE prod.users\")\n",
    )
    .expect("write");
    let analyze = |args: &[&str]| {
        let mut all = vec!["analyze"];
        all.extend_from_slice(args);
        run_sandboxed_in(&sandbox, dir.path(), &all, None)
    };

    for flag in ["--explain-findings", "--explain-facts", "--verbose"] {
        for target in [
            &["a.sql", "b.sql"][..],
            &["."],
            &["job.py", "--scan-embedded"],
        ] {
            let mut args = target.to_vec();
            args.push(flag);
            let out = analyze(&args);
            assert_eq!(out.code, 1, "{args:?}\nstderr: {}", out.stderr);
            assert!(
                out.stderr.contains(flag) && out.stderr.contains("one file"),
                "{args:?}\nstderr: {}",
                out.stderr
            );
            assert!(out.stdout.is_empty(), "{args:?}\nstdout: {}", out.stdout);
        }
    }
    // One file: they apply.
    for flag in ["--explain-findings", "--explain-facts", "--verbose"] {
        let out = analyze(&["a.sql", flag]);
        assert_eq!(out.code, 0, "{flag}\nstderr: {}", out.stderr);
        assert!(!out.stdout.is_empty(), "{flag}");
    }

    // The formats each explanation prints; any other is refused naming them.
    for (flag, printed, refused) in [
        (
            "--explain-findings",
            &["text", "json", "yaml"][..],
            &["sarif", "gl-sast", "markdown", "both"][..],
        ),
        (
            "--explain-facts",
            &["text", "json"][..],
            &["yaml", "sarif", "gl-sast", "markdown", "both"][..],
        ),
    ] {
        for format in refused {
            let out = analyze(&["a.sql", flag, "--format", format]);
            assert_eq!(out.code, 1, "{flag} {format}\nstderr: {}", out.stderr);
            assert!(
                out.stderr.contains(flag)
                    && printed.iter().all(|name| out.stderr.contains(name))
                    && out.stderr.contains(format),
                "{flag} {format}\nstderr: {}",
                out.stderr
            );
            assert!(
                out.stdout.is_empty(),
                "{flag} {format}\nstdout: {}",
                out.stdout
            );
        }
        for format in printed {
            let out = analyze(&["a.sql", flag, "--format", format]);
            assert_eq!(out.code, 0, "{flag} {format}\nstderr: {}", out.stderr);
            assert!(!out.stdout.is_empty(), "{flag} {format}");
        }
        // The explanation does not keep the report from being written.
        let report = format!("report{flag}.json");
        let out = analyze(&["a.sql", flag, "--report-out", &report]);
        assert_eq!(out.code, 0, "{flag}\nstderr: {}", out.stderr);
        let written: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(&report)).expect("report written"),
        )
        .expect("report json");
        assert!(written["findings"].is_array(), "{flag}");
    }

    // `--trace` adds to the JSON and YAML report, and help says so.
    let out = analyze(&["a.sql", "--trace", "--format", "json"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let traced: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
    assert!(traced["statement_traces"].is_array(), "{}", out.stdout);
    let out = analyze(&["--help"]);
    let line = out
        .stdout
        .lines()
        .find(|line| line.trim_start().starts_with("--trace"))
        .expect("help lists --trace");
    assert!(line.contains("JSON") && line.contains("YAML"), "{line}");
}

// A variable file is a JSON or YAML object and a SnowSQL config an INI file
// with `[variables]`: anything else is an error naming the file, and a
// config with no `[variables]` is said to supply none.
#[test]
fn a_variable_input_that_loads_nothing_says_so_and_names_the_file() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    let write =
        |name: &str, text: &str| std::fs::write(dir.path().join(name), text).expect("write");
    write("array.json", "[\"ENV\", \"prod\"]");
    write("list.yaml", "- ENV\n- prod\n");
    write("pairs.txt", "ENV=prod\n");
    write("broken.json", "{\"ENV\": ");
    write("good.json", "{\"ENV\": \"prod\"}");
    write("bad.cfg", "[variables]\nschema prod\n");
    write("unclosed.cfg", "[variables\nschema=prod\n");
    write("numkey.yaml", "1: prod\n");
    write("no_variables.cfg", "[connections]\naccountname = x\n");
    write("colon.cfg", "[variables]\nschema: prod\n");
    let analyze = |extra: &[&str]| {
        let mut args = vec!["analyze", "--stdin", "--format", "json"];
        args.extend_from_slice(extra);
        run_sandboxed_in(
            &sandbox,
            dir.path(),
            &args,
            Some("DELETE FROM ${ENV}_db.t;"),
        )
    };

    for (file, shape) in [
        ("array.json", "object"),
        ("list.yaml", "object"),
        ("pairs.txt", ".json"),
        ("broken.json", "broken.json"),
        ("numkey.yaml", "not a string"),
        ("missing.json", "missing.json"),
    ] {
        let out = analyze(&["--var-file", file]);
        assert_eq!(out.code, 1, "{file}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.contains(file) && out.stderr.contains(shape),
            "{file}\nstderr: {}",
            out.stderr
        );
    }
    let out = analyze(&["--var-file", "numkey.yaml"]);
    assert!(!out.stderr.contains("Number("), "stderr: {}", out.stderr);
    let out = analyze(&["--var-file", "good.json"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    for file in ["bad.cfg", "unclosed.cfg"] {
        let out = analyze(&["--snowsql-config", file]);
        assert_eq!(out.code, 1, "{file}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.contains(file) && out.stderr.contains("line"),
            "{file}\nstderr: {}",
            out.stderr
        );
    }
    let out = analyze(&["--snowsql-config", "no_variables.cfg"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("no_variables.cfg") && out.stderr.contains("[variables]"),
        "stderr: {}",
        out.stderr
    );
    let out = analyze(&["--snowsql-config", "colon.cfg"]);
    assert_eq!(out.code, 0, "colon.cfg\nstderr: {}", out.stderr);
    assert!(
        !out.stderr.contains("Warning"),
        "colon.cfg\nstderr: {}",
        out.stderr
    );
}

// A single-valued option given twice with different values is refused
// naming the option and both values; the same value twice is accepted, and
// `--stdin` with a path is refused.
#[test]
fn an_option_given_twice_with_different_values_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("q.sql"), "DELETE FROM orders;\n").expect("write");
    std::fs::write(dir.path().join("a.yaml"), DELETE_RULE_YAML).expect("write");
    std::fs::write(
        dir.path().join("b.yaml"),
        DELETE_RULE_YAML.replace("MY-DELETE", "MY-OTHER"),
    )
    .expect("write");
    let analyze = |extra: &[&str]| {
        let mut args = vec!["analyze", "q.sql", "-q"];
        args.extend_from_slice(extra);
        run_sandboxed_in(&sandbox, dir.path(), &args, None)
    };
    for extra in [
        &["--custom-rules", "a.yaml", "--custom-rules", "b.yaml"][..],
        &["--dialect", "snowflake", "--dialect", "mssql"],
        &["--format", "json", "--format", "text"],
        &["--min-severity", "high", "--min-severity", "info"],
        &["--report-out", "x/", "--report-out", "y/"],
    ] {
        let out = analyze(extra);
        assert_eq!(out.code, 1, "{extra:?}\nstderr: {}", out.stderr);
        for needle in [extra[0], extra[1], extra[3]] {
            assert!(
                out.stderr.contains(needle),
                "{extra:?}: {needle}\nstderr: {}",
                out.stderr
            );
        }
        assert!(out.stdout.is_empty(), "{extra:?}\nstdout: {}", out.stdout);
    }
    assert!(!dir.path().join("x").exists() && !dir.path().join("y").exists());
    // `--strict` takes an optional mode; a bare one is `strict`.
    for (extra, first, second) in [
        (
            &["--strict", "strict", "--strict", "off"][..],
            "strict",
            "off",
        ),
        (&["--strict", "--strict", "off"], "strict", "off"),
        (&["--strict", "pedantic", "--strict"], "pedantic", "strict"),
    ] {
        let out = analyze(extra);
        assert_eq!(out.code, 1, "{extra:?}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.contains("--strict is given twice")
                && out.stderr.contains(&format!("'{first}'"))
                && out.stderr.contains(&format!("'{second}'")),
            "{extra:?}\nstderr: {}",
            out.stderr
        );
    }
    for extra in [
        &["--strict", "--strict", "strict"][..],
        &["--strict", "off", "--strict", "off"],
        &["--custom-rules", "a.yaml", "--custom-rules", "a.yaml"][..],
        &["--format=json", "--format", "json"],
        &["--var", "A=1", "--var", "B=2"],
    ] {
        let out = analyze(extra);
        assert_eq!(out.code, 0, "{extra:?}\nstderr: {}", out.stderr);
    }

    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", "--stdin", "q.sql"],
        Some("SELECT 1;"),
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("--stdin") && out.stderr.contains("q.sql"),
        "{}",
        out.stderr
    );

    // `ci` forwards its options, and has `--range` of its own.
    for command in [
        &[
            "ci",
            "--snapshot",
            "--custom-rules",
            "a.yaml",
            "--custom-rules",
            "b.yaml",
        ][..],
        &["ci", "--range", "a..b", "--range", "c..d"],
    ] {
        let out = run_sandboxed_in(&sandbox, dir.path(), command, None);
        assert_eq!(out.code, 1, "{command:?}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.contains("given twice"),
            "{command:?}\nstderr: {}",
            out.stderr
        );
    }
}

// A file named on the command line that cannot be read or decoded is an
// error alone and beside other files: the rest are analyzed and reported,
// and the run exits 1. A file a scan finds that cannot be read is listed as
// skipped, as before.
#[test]
fn a_named_file_that_cannot_be_read_fails_the_run_beside_others() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("a.sql"), "DELETE FROM orders;\n").expect("write");
    // Bytes that are no text: neither UTF-8 nor marked UTF-16.
    std::fs::write(dir.path().join("latin1.sql"), [0x41, 0xFF, 0x42]).expect("write");
    std::fs::write(dir.path().join("bad.ipynb"), "{not json").expect("write");
    std::fs::write(dir.path().join("job.py"), [0x41, 0xFF, 0x42]).expect("write");
    for (named, scan_embedded) in [
        (&["a.sql", "latin1.sql"][..], false),
        (&["latin1.sql", "a.sql"][..], false),
        (&["a.sql", "missing.sql"][..], false),
        (&["missing.sql", "a.sql"][..], false),
        (&["a.sql", "bad.ipynb"][..], true),
        (&["a.sql", "job.py"][..], true),
    ] {
        let mut args = vec!["analyze"];
        args.extend_from_slice(named);
        args.extend_from_slice(&["--format", "json", "-q", "--report-out", "out/"]);
        if scan_embedded {
            args.push("--scan-embedded");
        }
        let out = run_sandboxed_in(&sandbox, dir.path(), &args, None);
        assert_eq!(out.code, 1, "{named:?}\nstderr: {}", out.stderr);
        let unread = named
            .iter()
            .find(|name| **name != "a.sql")
            .expect("a bad file");
        assert!(
            out.stderr.contains(unread) && out.stderr.contains("named"),
            "{named:?}\nstderr: {}",
            out.stderr
        );
        // The file that reads is analyzed and reported, the other listed.
        let batch: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{named:?}: {e}\n{}", out.stdout));
        assert!(
            batch["files"].to_string().contains("DML-WRITE-UNBOUNDED"),
            "{named:?}"
        );
        assert!(
            batch["skipped_files"].to_string().contains(unread),
            "{named:?}"
        );
        assert!(
            dir.path().join("out/batch_summary.json").exists(),
            "{named:?}"
        );
    }

    // Every file named missing still exits 1, naming each.
    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", "missing.sql", "nope.sql", "-q"],
        None,
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("missing.sql") && out.stderr.contains("nope.sql"),
        "stderr: {}",
        out.stderr
    );

    // Found by a scan, the same files are listed and the run passes.
    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", ".", "--format", "json", "-q"],
        None,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("latin1.sql"), "{}", out.stdout);
}

// A directory named on the command line that holds no SQL file is an error
// wherever it stands among the paths.
#[test]
fn a_named_directory_without_sql_is_an_error_in_any_position() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("risky.sql"), "DELETE FROM orders;\n").expect("write");
    std::fs::write(dir.path().join("note.txt"), "x").expect("write");
    for order in [&["empty", "risky.sql"][..], &["risky.sql", "empty"]] {
        std::fs::create_dir_all(dir.path().join("empty")).expect("empty dir");
        std::fs::copy(
            dir.path().join("note.txt"),
            dir.path().join("empty/note.txt"),
        )
        .expect("copy");
        let mut args = vec!["analyze"];
        args.extend_from_slice(order);
        let out = run_sandboxed_in(&sandbox, dir.path(), &args, None);
        assert_eq!(out.code, 1, "{order:?}\nstderr: {}", out.stderr);
        assert!(
            out.stderr.contains("No SQL files found in 'empty'"),
            "{order:?}\nstderr: {}",
            out.stderr
        );
    }
}

/// The binary run with `stdin` as its standard input, byte for byte.
fn run_with_bytes(dir: &Path, args: &[&str], stdin: &[u8]) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lexega"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lexega");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        code: out.status.code().unwrap_or(-1),
    }
}

// Standard input and a single named Python file are decoded as a scanned
// file is: UTF-8 with or without its mark, or UTF-16 of either byte order
// behind its mark.
#[test]
fn stdin_and_a_named_embedded_file_are_decoded_as_a_scanned_file_is() {
    let dir = TempDir::new().expect("temp dir");
    for little in [true, false] {
        let out = run_with_bytes(
            dir.path(),
            &["analyze", "--stdin", "--format", "json"],
            &utf16("DELETE FROM orders;\n", little),
        );
        assert_eq!(out.code, 0, "little {little}\nstderr: {}", out.stderr);
        assert!(
            found_rules(&out).contains(&"DML-WRITE-UNBOUNDED".to_string()),
            "little {little}\n{}",
            out.stdout
        );

        let name = format!("job-{little}.py");
        std::fs::write(
            dir.path().join(&name),
            utf16("spark.sql(\"DROP TABLE prod.users\")\n", little),
        )
        .expect("write");
        let out = run_in(
            dir.path(),
            &[
                "analyze",
                &name,
                "--scan-embedded",
                "--format",
                "json",
                "-q",
            ],
            None,
        );
        assert_eq!(out.code, 0, "{name}\nstderr: {}", out.stderr);
        assert!(out.stdout.contains("TBL-DROP"), "{name}\n{}", out.stdout);
    }
    let out = run_with_bytes(
        dir.path(),
        &["analyze", "--stdin", "--format", "json"],
        b"\xEF\xBB\xBFDELETE FROM orders;\n",
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(found_rules(&out).contains(&"DML-WRITE-UNBOUNDED".to_string()));
    let out = run_with_bytes(dir.path(), &["analyze", "--stdin"], b"SELECT \xFF;");
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(out.stderr.contains("not UTF-8 text"), "{}", out.stderr);
}

/// A notebook of code cells with the sources given.
fn notebook(cells: &[&str]) -> String {
    let cells: Vec<serde_json::Value> = cells
        .iter()
        .map(|source| {
            let lines: Vec<String> = source.split_inclusive('\n').map(str::to_string).collect();
            serde_json::json!({"cell_type": "code", "source": lines, "metadata": {}, "outputs": []})
        })
        .collect();
    serde_json::json!({"nbformat": 4, "nbformat_minor": 5, "cells": cells, "metadata": {}})
        .to_string()
}

// A notebook's code cells are read as Python files are: `spark.sql("…")` and
// the other calls a `.py` file gets, and a Databricks cell `%sql` followed by
// a line break and the SQL.
#[test]
fn a_notebook_yields_the_sql_a_python_file_does_and_a_magic_cell_with_a_line_break() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(
        dir.path().join("spark.ipynb"),
        notebook(&[
            "import pyspark\n",
            "%pip install requests\nspark.sql(\"DROP TABLE prod.users\")\n",
        ]),
    )
    .expect("write");
    std::fs::write(
        dir.path().join("pct.ipynb"),
        notebook(&["%sql\nDELETE FROM orders\n"]),
    )
    .expect("write");
    // The cells share one namespace: a query assigned in one is run in a later.
    std::fs::write(
        dir.path().join("xcell.ipynb"),
        notebook(&[
            "q = \"DROP TABLE prod.users\"\n",
            "import os\n",
            "spark.sql(q)\n",
        ]),
    )
    .expect("write");
    for (name, rule) in [
        ("spark.ipynb", "TBL-DROP"),
        ("pct.ipynb", "DML-WRITE-UNBOUNDED"),
        ("xcell.ipynb", "TBL-DROP"),
    ] {
        for target in [name, "."] {
            let out = run_sandboxed_in(
                &sandbox,
                dir.path(),
                &[
                    "analyze",
                    target,
                    "--scan-embedded",
                    "--format",
                    "json",
                    "-q",
                ],
                None,
            );
            assert_eq!(out.code, 0, "{name} {target}\nstderr: {}", out.stderr);
            assert!(
                out.stdout.contains(rule) && out.stdout.contains(name),
                "{name} {target}: {rule}\nstdout: {}",
                out.stdout
            );
        }
    }
}

// A notebook that is no JSON is an error naming the file where it is named,
// and, found in a scan, is listed as not analysed beside the SQL files, so
// `--strict` fails; it never disappears from the batch.
#[test]
fn a_notebook_that_is_no_json_is_reported_by_name() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    std::fs::write(dir.path().join("bad.ipynb"), "{not json").expect("write");
    std::fs::write(dir.path().join("q.sql"), "SELECT 1;\n").expect("write");

    let out = run_sandboxed_in(
        &sandbox,
        dir.path(),
        &["analyze", "bad.ipynb", "--scan-embedded"],
        None,
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(out.stderr.contains("bad.ipynb"), "{}", out.stderr);
    assert!(
        !out.stderr.contains("No embedded SQL found"),
        "{}",
        out.stderr
    );

    let args = ["analyze", ".", "--scan-embedded", "--format", "json", "-q"];
    let out = run_sandboxed_in(&sandbox, dir.path(), &args, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    let skipped = batch["skipped_files"].to_string();
    assert!(skipped.contains("bad.ipynb"), "{skipped}");
    assert!(
        skipped.contains("not a valid Jupyter notebook"),
        "{skipped}"
    );

    let mut strict = args.to_vec();
    strict.push("--strict");
    let out = run_sandboxed_in(&sandbox, dir.path(), &strict, None);
    assert_eq!(out.code, 1, "stdout: {}", out.stdout);
    assert!(
        out.stderr.contains("bad.ipynb: [E_STRICT_NOT_ANALYZED]"),
        "{}",
        out.stderr
    );
}

// A rule that names a statement kind no statement has would never fire: it
// is refused when the file loads, naming the value, the rule and the
// nearest kind.
#[test]
fn a_custom_rule_naming_no_statement_kind_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    let rule = |kind: &str| {
        format!(
            "schema_version: 1\nrules:\n  - id: X1\n    risk_level: high\n    message: m\n    triggers:\n      all_of:\n        - kind:\n            in: [{kind}]\n"
        )
    };
    std::fs::write(dir.path().join("bad.yaml"), rule("delet")).expect("write rules");
    std::fs::write(dir.path().join("good.yaml"), rule("delete")).expect("write rules");
    let analyze = |rules: &str| {
        run_sandboxed_in(
            &sandbox,
            dir.path(),
            &["analyze", "--stdin", "--custom-rules", rules],
            Some("DELETE FROM orders;"),
        )
    };
    let out = analyze("bad.yaml");
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    for needle in ["'delet'", "X1", "did you mean 'delete'"] {
        assert!(
            out.stderr.contains(needle),
            "{needle}\nstderr: {}",
            out.stderr
        );
    }
    let out = analyze("good.yaml");
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

// A report and a decision are written to a local path or uploaded to
// s3://, gs:// or az://: an http(s) address, in any case, is refused before
// the analysis, naming the option and the destinations that work, and
// nothing is written.
#[test]
fn an_output_at_a_web_address_is_refused_and_writes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("q.sql"), "DELETE FROM orders;\n").expect("write");
    for (option, target) in [
        ("--report-out", "https://example.invalid/r.json"),
        ("--report-out", "http://example.invalid/out/"),
        ("--report-out", "HTTPS://example.invalid/r.json"),
        ("--decision-out", "https://example.invalid/d/"),
        ("--decision-out", "Http://example.invalid/d/"),
    ] {
        let out = run_in(dir.path(), &["analyze", "q.sql", option, target], None);
        assert_eq!(out.code, 1, "{option} {target}\nstderr: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{target}\nstdout: {}", out.stdout);
        for needle in [option, "a local path", "s3://", "gs://", "az://"] {
            assert!(
                out.stderr.contains(needle),
                "{option} {target}: {needle}\nstderr: {}",
                out.stderr
            );
        }
        assert!(!out.stderr.contains("written to:"), "{}", out.stderr);
        let made: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(
            made,
            [std::ffi::OsString::from("q.sql")],
            "{option} {target}"
        );
    }
}

// Every config input drops a leading UTF-8 byte-order mark, as a SQL file
// does: the editors that write one (Windows PowerShell's `Set-Content
// -Encoding UTF8`) produce files that load.
#[test]
fn a_byte_order_mark_does_not_stop_a_config_input_loading() {
    let dir = TempDir::new().expect("temp dir");
    let sandbox = TempDir::new().expect("sandbox");
    let write = |name: &str, text: &str| {
        std::fs::write(dir.path().join(name), format!("\u{FEFF}{text}")).expect("write");
    };
    write("rules.yaml", DELETE_RULE_YAML);
    write(
        "catalog.json",
        r#"{"schema_version": 2, "generated_at": "2026-01-01T00:00:00Z", "source": "test", "databases": []}"#,
    );
    write(
        "catalog.yaml",
        "schema_version: 2\ngenerated_at: \"2026-01-01T00:00:00Z\"\nsource: test\ndatabases: []\n",
    );
    write("vars.json", r#"{"ENV": "prod"}"#);
    write("vars.yaml", "ENV: prod\n");
    write("snowsql.cfg", "[variables]\nschema=prod\n");
    let analyze = |extra: &[&str], sql: &str| {
        let mut args = vec!["analyze", "--stdin", "--format", "json"];
        args.extend_from_slice(extra);
        run_sandboxed_in(&sandbox, dir.path(), &args, Some(sql))
    };

    let out = analyze(&["--custom-rules", "rules.yaml"], "DELETE FROM orders;");
    assert_eq!(out.code, 0, "rules\nstderr: {}", out.stderr);
    assert!(found_rules(&out).contains(&"MY-DELETE".to_string()));

    for catalog in ["catalog.json", "catalog.yaml"] {
        let out = analyze(&["--catalog", catalog], "SELECT 1;");
        assert_eq!(out.code, 0, "{catalog}\nstderr: {}", out.stderr);
        let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json report");
        assert_eq!(report["catalog_info"]["catalog_loaded"], true, "{catalog}");
        let inspected =
            run_sandboxed_in(&sandbox, dir.path(), &["catalog", "inspect", catalog], None);
        assert_eq!(inspected.code, 0, "{catalog}\nstderr: {}", inspected.stderr);
    }

    for vars in ["vars.json", "vars.yaml"] {
        let out = analyze(
            &["--var-file", vars],
            "DELETE FROM ${ENV}_db.public.orders;",
        );
        assert_eq!(out.code, 0, "{vars}\nstderr: {}", out.stderr);
        assert!(
            out.stdout.to_lowercase().contains("prod_db"),
            "{vars}\n{}",
            out.stdout
        );
    }

    let out = analyze(
        &["--snowsql-config", "snowsql.cfg"],
        "!define other=x\nDELETE FROM &schema.orders;",
    );
    assert_eq!(out.code, 0, "snowsql\nstderr: {}", out.stderr);
    assert!(
        out.stdout.to_lowercase().contains("prod.orders"),
        "{}",
        out.stdout
    );
}

/// A directory holding `top.sql` and `migrations/v1/a.sql`, each a write
/// with no `WHERE`, and its canonical path.
fn tree_of_writes() -> (TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("migrations/v1")).expect("create migrations");
    std::fs::write(dir.path().join("top.sql"), "DELETE FROM t2;\n").expect("write top.sql");
    std::fs::write(
        dir.path().join("migrations/v1/a.sql"),
        "DELETE FROM orders;\n",
    )
    .expect("write a.sql");
    let root = std::fs::canonicalize(dir.path())
        .expect("canonical root")
        .display()
        .to_string();
    (dir, root)
}

/// Each file a JSON, SARIF or GitLab SAST report names: a batch's `file`
/// and `path` entries, each finding's `source_file`, its `location` without
/// line and column, and each SARIF artifact `uri`, leaving out the base a
/// SARIF report resolves relative URIs against.
fn files_named(value: &serde_json::Value, names: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                match (key.as_str(), field) {
                    ("originalUriBaseIds", _) => {}
                    ("file" | "path" | "source_file" | "uri", serde_json::Value::String(name)) => {
                        names.insert(name.clone());
                    }
                    ("location", serde_json::Value::String(location)) => {
                        let mut name = location.as_str();
                        for _ in 0..2 {
                            name = name.rsplit_once(':').map_or(name, |(head, _)| head);
                        }
                        names.insert(name.to_string());
                    }
                    _ => files_named(field, names),
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| files_named(item, names)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

/// The files `analyze` with `args` names in `dir` in each of the JSON,
/// SARIF and GitLab SAST formats, with its text report.
fn files_reported(dir: &Path, args: &[&str]) -> (Vec<(String, Vec<String>)>, String) {
    let mut by_format = Vec::new();
    for format in ["json", "sarif", "gl-sast"] {
        let mut all = vec!["analyze"];
        all.extend_from_slice(args);
        all.extend(["--format", format, "--quiet"]);
        let out = run_in(dir, &all, None);
        assert_eq!(out.code, 0, "{all:?}: {}", out.stderr);
        let report: serde_json::Value = serde_json::from_str(&out.stdout)
            .unwrap_or_else(|e| panic!("{all:?}: {e}: {}", out.stdout));
        let mut names = std::collections::BTreeSet::new();
        files_named(&report, &mut names);
        by_format.push((format.to_string(), names.into_iter().collect()));
    }
    let mut all = vec!["analyze"];
    all.extend_from_slice(args);
    let text = run_in(dir, &all, None);
    assert_eq!(text.code, 0, "{all:?}: {}", text.stderr);
    (by_format, format!("{}{}", text.stdout, text.stderr))
}

#[test]
fn a_folder_run_names_each_file_by_its_path_from_the_working_directory() {
    let (dir, root) = tree_of_writes();
    for (args, expected) in [
        (&[".", "-r"][..], &["migrations/v1/a.sql", "top.sql"][..]),
        (&["migrations", "-r"][..], &["migrations/v1/a.sql"][..]),
        (&["./migrations/", "-r"][..], &["migrations/v1/a.sql"][..]),
        (&["."][..], &["top.sql"][..]),
        (
            &["migrations/v1/a.sql", "top.sql"][..],
            &["migrations/v1/a.sql", "top.sql"][..],
        ),
    ] {
        let (by_format, text) = files_reported(dir.path(), args);
        for (format, names) in by_format {
            assert_eq!(names, expected, "{args:?} as {format}");
        }
        for name in expected {
            assert!(
                text.contains(&format!("{name}:1:1")),
                "{args:?} text names no {name}:1:1:\n{text}"
            );
        }
        assert!(!text.contains(&root), "{args:?} text names {root}:\n{text}");
    }
}

#[test]
fn a_file_is_named_by_its_path_from_the_working_directory_however_it_is_typed() {
    let (dir, root) = tree_of_writes();
    for typed in [
        "migrations/v1/a.sql",
        "./migrations/v1/a.sql",
        "migrations/../migrations/v1/./a.sql",
    ] {
        let (by_format, text) = files_reported(dir.path(), &[typed]);
        for (format, names) in by_format {
            assert_eq!(names, ["migrations/v1/a.sql"], "{typed} as {format}");
        }
        assert!(
            text.contains("migrations/v1/a.sql:1:1"),
            "{typed} text:\n{text}"
        );
        assert!(!text.contains(&root), "{typed} text names {root}:\n{text}");
    }
}

#[test]
fn a_file_outside_the_working_directory_is_named_by_its_absolute_path() {
    let (dir, root) = tree_of_writes();
    let top = format!("{root}/top.sql");
    let cwd = dir.path().join("migrations");
    for (args, expected) in [
        (&["../top.sql"][..], vec![top.clone()]),
        (&["..", "-r"][..], vec![top.clone(), "v1/a.sql".to_string()]),
    ] {
        let (by_format, text) = files_reported(&cwd, args);
        for (format, names) in by_format {
            let mut expected: Vec<String> = expected
                .iter()
                .map(|name| match (format.as_str(), name.starts_with('/')) {
                    ("sarif", true) => format!("file://{name}"),
                    _ => name.clone(),
                })
                .collect();
            expected.sort();
            assert_eq!(names, expected, "{args:?} as {format}");
        }
        for name in &expected {
            assert!(
                text.contains(&format!("{name}:1:1")),
                "{args:?} text names no {name}:1:1:\n{text}"
            );
        }
    }
}

/// A git repository holding `top.sql` and `sub/a.sql`, each a write with no
/// `WHERE`, `sub/a.sql` added by the last of two commits, with the
/// repository's canonical root.
fn repository_with_a_subdirectory() -> (TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join("sub")).expect("create sub");
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("top.sql"), "DELETE FROM t2;\n").expect("write top.sql");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    std::fs::write(repo.join("sub/a.sql"), "DELETE FROM orders;\n").expect("write a.sql");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "change"]);
    let root = std::fs::canonicalize(&repo)
        .expect("canonical root")
        .display()
        .to_string();
    (dir, root)
}

// Inside a git repository a file is named by its path from the repository
// root, wherever in it the run starts: SARIF resolves it against that root,
// and `review` names it so. From outside every repository a file is named
// from the working directory, the root SARIF then declares.
#[test]
fn inside_a_repository_a_file_is_named_by_its_path_from_the_repository_root() {
    let (dir, root) = repository_with_a_subdirectory();
    let repo = dir.path().join("repo");
    let sub = repo.join("sub");
    for (cwd, args, expected) in [
        (&sub, &[".", "-r"][..], &["sub/a.sql"][..]),
        (&sub, &["a.sql"][..], &["sub/a.sql"][..]),
        (&sub, &["./a.sql"][..], &["sub/a.sql"][..]),
        (&sub, &["../top.sql"][..], &["top.sql"][..]),
        (&sub, &["..", "-r"][..], &["sub/a.sql", "top.sql"][..]),
        (&repo, &[".", "-r"][..], &["sub/a.sql", "top.sql"][..]),
        (&repo, &["sub/a.sql"][..], &["sub/a.sql"][..]),
        (
            &dir.path().to_path_buf(),
            &["repo", "-r"][..],
            &["repo/sub/a.sql", "repo/top.sql"][..],
        ),
    ] {
        let (by_format, text) = files_reported(cwd, args);
        for (format, names) in by_format {
            assert_eq!(names, expected, "{cwd:?} {args:?} as {format}");
        }
        for name in expected {
            assert!(
                text.contains(&format!("{name}:1:1")),
                "{cwd:?} {args:?} text names no {name}:1:1:\n{text}"
            );
        }
        assert!(
            !text.contains(&root),
            "{cwd:?} {args:?} text names {root}:\n{text}"
        );
    }
    let sarif = run_in(
        &sub,
        &["analyze", ".", "-r", "--format", "sarif", "--quiet"],
        None,
    );
    let sarif: serde_json::Value = serde_json::from_str(&sarif.stdout).expect("sarif");
    assert_eq!(
        sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"],
        format!("file://{root}")
    );
}

// A file of a dbt project nested in a package that is a git repository of
// its own, installed in a project of the run's repository, is named from the
// run's repository root in SARIF, JSON, GitLab SAST and text, so every SARIF
// location resolves against `%SRCROOT%`.
#[test]
fn a_file_of_a_project_inside_a_package_repository_is_named_from_the_runs_root() {
    let dir = TempDir::new().expect("temp dir");
    let repo = dir.path().join("repo");
    let project = repo.join("transform/proj");
    let package = project.join("dbt_packages/pkg");
    for (name, text) in [
        ("dbt_project.yml", "name: 'proj'\n"),
        ("models/m.sql", "DELETE FROM orders;\n"),
        ("dbt_packages/pkg/dbt_project.yml", "name: 'pkg'\n"),
        (
            "dbt_packages/pkg/models/pm.sql",
            "DELETE FROM pkg_orders;\n",
        ),
        (
            "dbt_packages/pkg/integration_tests/dbt_project.yml",
            "name: 'pkg_integration_tests'\n",
        ),
        (
            "dbt_packages/pkg/integration_tests/packages.yml",
            "packages:\n  - local: ../\n",
        ),
        (
            "dbt_packages/pkg/integration_tests/models/it.sql",
            "DELETE FROM it_orders;\n",
        ),
    ] {
        let path = project.join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, text).expect("write file");
    }
    git(&repo, &["init", "-q"]);
    git(&package, &["init", "-q"]);
    let root = std::fs::canonicalize(&repo)
        .expect("canonical root")
        .display()
        .to_string();

    let expected = [
        "transform/proj/dbt_packages/pkg/integration_tests/models/it.sql",
        "transform/proj/dbt_packages/pkg/models/pm.sql",
        "transform/proj/models/m.sql",
    ];
    let (by_format, text) = files_reported(&project, &[".", "-r"]);
    for (format, names) in by_format {
        assert_eq!(names, expected, "as {format}");
    }
    for name in expected {
        assert!(
            text.contains(&format!("{name}:1:1")),
            "text names no {name}:1:1:\n{text}"
        );
        assert!(
            Path::new(&root).join(name).is_file(),
            "{name} is no file under {root}"
        );
    }
    let sarif = run_in(
        &project,
        &["analyze", ".", "-r", "--format", "sarif", "--quiet"],
        None,
    );
    let sarif: serde_json::Value = serde_json::from_str(&sarif.stdout).expect("sarif");
    assert_eq!(
        sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"],
        format!("file://{root}")
    );
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), expected.len(), "{sarif}");
    for result in results {
        let location = &result["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(location["uriBaseId"], "%SRCROOT%", "{result}");
    }
}

// A comment between a statement's first and last token, in the statement or
// in a routine body, is printed in no format and not in the trace, on stdout
// or in a report file; the preview still shows the statement.
#[test]
fn a_comment_inside_a_statement_is_printed_in_no_report() {
    let dir = TempDir::new().expect("temp dir");
    let mut leaks = Vec::new();
    for (dialect, sql, shown) in [
        (
            "snowflake",
            "DELETE /* password=Zq9CmtPw */ FROM analytics.public.orders;",
            "DELETE FROM analytics.public.orders",
        ),
        (
            "snowflake",
            "DELETE FROM -- secret=Zq9CmtPw\n  analytics.public.orders;",
            "DELETE FROM analytics.public.orders",
        ),
        (
            "snowflake",
            "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS\n$$\nBEGIN\n  \
             -- previous value was password=Zq9CmtPw\n  DELETE FROM t3;\n  RETURN 'ok';\nEND;\n$$;",
            "DELETE FROM t3",
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.p AS\nBEGIN\n  -- old: Password=Zq9CmtPw\n  \
             DELETE FROM dbo.t;\nEND;",
            "DELETE FROM dbo.t",
        ),
    ] {
        let base = [
            "analyze",
            "--stdin",
            "--dialect",
            dialect,
            "--min-severity",
            "info",
        ];
        let text = run(&[&base[..], &["--detail"]].concat(), Some(sql));
        assert!(text.stdout.contains(shown), "{sql}\n{}", text.stdout);
        let mut outputs = vec![("text --detail".to_string(), text.stdout)];
        for format in ["json", "yaml", "sarif", "markdown", "gl-sast"] {
            let out = run(&[&base[..], &["--format", format]].concat(), Some(sql));
            outputs.push((format.to_string(), out.stdout));
        }
        let traced = run(
            &[&base[..], &["--format", "json", "--trace"]].concat(),
            Some(sql),
        );
        outputs.push(("json --trace".to_string(), traced.stdout));
        let file = dir.path().join("trace.json");
        let file_arg = file.to_str().expect("utf-8 path");
        let written = run(
            &[
                &base[..],
                &["--format", "json", "--trace", "--report-out", file_arg],
            ]
            .concat(),
            Some(sql),
        );
        outputs.push(("--trace --report-out stdout".to_string(), written.stdout));
        outputs.push((
            "--trace --report-out file".to_string(),
            std::fs::read_to_string(&file).expect("report file"),
        ));
        for (surface, printed) in outputs {
            if printed.contains("Zq9Cmt") {
                leaks.push(format!("[{dialect} {surface}] {sql}"));
            }
        }
    }
    assert!(leaks.is_empty(), "comments printed:\n{}", leaks.join("\n"));
}

// `ci` names a file alike on a push and on a pull request, run from the
// repository root or from a subdirectory of it.
#[test]
fn ci_names_a_file_alike_on_a_push_and_on_a_pull_request() {
    let (dir, _) = repository_with_a_subdirectory();
    let repo = dir.path().join("repo");
    for (cwd, pushed) in [
        (repo.join("sub"), &["sub/a.sql"][..]),
        (repo.clone(), &["sub/a.sql", "top.sql"][..]),
    ] {
        for (mode, expected) in [
            (&["--snapshot"][..], pushed),
            (&["--range", "HEAD~1..HEAD"][..], &["sub/a.sql"][..]),
        ] {
            let mut args = vec!["ci"];
            args.extend_from_slice(mode);
            args.extend(["--format", "json", "--quiet"]);
            let out = run_in(&cwd, &args, None);
            assert_eq!(out.code, 0, "{cwd:?} {args:?}: {}", out.stderr);
            let report: serde_json::Value = serde_json::from_str(&out.stdout)
                .unwrap_or_else(|e| panic!("{args:?}: {e}: {}", out.stdout));
            let mut names = std::collections::BTreeSet::new();
            files_named(&report, &mut names);
            let names: Vec<String> = names.into_iter().collect();
            assert_eq!(names, expected, "{cwd:?} {args:?}");
        }
    }
}

/// A folder of two dbt models this build analyzes as written, beside a
/// plain SQL file.
fn unrendered_models() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    std::fs::create_dir(dir.path().join("models")).expect("models");
    for name in ["a", "b"] {
        std::fs::write(
            dir.path().join(format!("models/{name}.sql")),
            "select id from {{ ref('orders') }} where id > 0\n",
        )
        .expect("write model");
    }
    std::fs::write(dir.path().join("plain.sql"), "SELECT 1;\n").expect("write plain.sql");
    dir
}

const UNRENDERED_NOTE: &str =
    "2 template files were analyzed as written, not rendered: findings that depend on the rendered SQL may be missing.";
const RENDERING_OFFER: &str = "The full build renders Jinja and dbt templates: https://lexega.com";

// Every report of a batch with templates analyzed as written says how many
// and what renders them, and none reads as all clear.
#[test]
fn a_batch_of_unrendered_templates_says_so_in_every_format() {
    let dir = unrendered_models();
    let args = |format: &'static str| ["analyze", ".", "-r", "--quiet", "--format", format];

    for format in ["text", "markdown"] {
        let out = run_in(dir.path(), &args(format), None);
        assert_eq!(out.code, 0, "{format}: {}", out.stderr);
        assert!(
            out.stdout.contains(UNRENDERED_NOTE),
            "{format}: {}",
            out.stdout
        );
        assert!(
            out.stdout.contains(RENDERING_OFFER),
            "{format}: {}",
            out.stdout
        );
        assert!(!out.stdout.contains("🟢"), "{format}: {}", out.stdout);
        assert!(
            !out.stdout.contains("Highest risk level: LOW"),
            "{format}: {}",
            out.stdout
        );
    }

    for format in ["json", "yaml"] {
        let out = run_in(dir.path(), &args(format), None);
        assert_eq!(out.code, 0, "{format}: {}", out.stderr);
        let batch: serde_json::Value = if format == "json" {
            serde_json::from_str(&out.stdout).expect("json batch")
        } else {
            serde_yaml_ng::from_str(&out.stdout).expect("yaml batch")
        };
        let summary = &batch["batch_summary"];
        assert_eq!(summary["rendering"]["files_not_rendered"], 2, "{format}");
        assert_eq!(
            summary["notes"],
            serde_json::json!([format!("{UNRENDERED_NOTE} {RENDERING_OFFER}")]),
            "{format}: {}",
            out.stdout
        );
    }

    let out = run_in(dir.path(), &args("sarif"), None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    let notes: Vec<&str> = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("notifications")
        .iter()
        .filter(|n| n["descriptor"]["id"] == "run-limited")
        .filter_map(|n| n["message"]["text"].as_str())
        .collect();
    assert_eq!(notes, [format!("{UNRENDERED_NOTE} {RENDERING_OFFER}")]);

    let out = run_in(dir.path(), &args("gl-sast"), None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("gl-sast");
    assert!(
        report["scan"]["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["value"] == format!("{UNRENDERED_NOTE} {RENDERING_OFFER}")),
        "{}",
        out.stdout
    );
}

const NOT_COMPARED_NOTE: &str = "The change was not compared with its base: no DIFF-* rule ran.";
const COMPARISON_OFFER: &str = "Comparing a change is part of the full build: https://lexega.com";

// A review this build cannot compare says so in every format, the
// pull-request comment included.
#[test]
fn a_review_says_the_change_was_not_compared() {
    let repo = repo_with_a_change();
    for format in ["text", "markdown"] {
        let out = run_in(
            repo.path(),
            &["review", "HEAD~1..HEAD", "--quiet", "--format", format],
            None,
        );
        assert_eq!(out.code, 0, "{format}: {}", out.stderr);
        assert!(
            out.stdout.contains(NOT_COMPARED_NOTE),
            "{format}: {}",
            out.stdout
        );
        assert!(
            out.stdout.contains(COMPARISON_OFFER),
            "{format}: {}",
            out.stdout
        );
    }
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--quiet", "--pr-comment"],
        None,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains(NOT_COMPARED_NOTE), "{}", out.stdout);
    let out = run_in(
        repo.path(),
        &["review", "HEAD~1..HEAD", "--quiet", "--format", "json"],
        None,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let batch: serde_json::Value = serde_json::from_str(&out.stdout).expect("json batch");
    assert_eq!(
        batch["batch_summary"]["notes"],
        serde_json::json!([format!("{NOT_COMPARED_NOTE} {COMPARISON_OFFER}")])
    );
    // A plain analysis compares nothing and says nothing of it.
    let out = run_in(repo.path(), &["analyze", ".", "-r", "--quiet"], None);
    assert!(!out.stdout.contains(NOT_COMPARED_NOTE), "{}", out.stdout);
}

// This build's reports are titled for the analysis it runs.
#[test]
fn reports_are_not_titled_semantic_analysis() {
    let dir = unrendered_models();
    let out = run_in(dir.path(), &["analyze", ".", "-r", "--quiet"], None);
    assert!(
        out.stdout.contains("Batch Analysis Summary"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("Semantic"), "{}", out.stdout);
    let out = run_in(dir.path(), &["analyze", "plain.sql"], None);
    assert!(out.stdout.contains("Analysis Report"), "{}", out.stdout);
    assert!(!out.stdout.contains("Semantic"), "{}", out.stdout);
}

// A finding in SQL a Python file embeds is placed at its line and column in
// that file, where its SQL begins, in the text report and in SARIF; the
// fragment is named by the same place.
#[test]
fn an_embedded_finding_is_placed_in_its_file() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("pipeline.py"),
        "from pyspark.sql import SparkSession\nspark = SparkSession.builder.getOrCreate()\nspark.sql(\"DELETE FROM main.sales.orders\")\n",
    )
    .expect("write pipeline.py");
    std::fs::write(
        dir.path().join("multi.py"),
        "t = 'orders'\nspark.sql(f\"DELETE FROM {t}\")\nquery = \"\"\"DELETE\nFROM main.sales.items\"\"\"\nspark.sql(query)\n",
    )
    .expect("write multi.py");
    let out = run_in(
        dir.path(),
        &[
            "analyze",
            "--scan-embedded",
            "--dialect",
            "databricks",
            "multi.py",
        ],
        None,
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    // The f-string's SQL begins after `f"`, the variable's after `"""`.
    assert!(out.stdout.contains("── multi.py:2:13"), "{}", out.stdout);
    assert!(out.stdout.contains("• multi.py:2:13"), "{}", out.stdout);
    assert!(out.stdout.contains("── multi.py:3:12"), "{}", out.stdout);
    assert!(out.stdout.contains("• multi.py:3:12"), "{}", out.stdout);
    let args = [
        "analyze",
        "--scan-embedded",
        "--dialect",
        "databricks",
        "pipeline.py",
    ];
    let out = run_in(dir.path(), &args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("── pipeline.py:3:12"), "{}", out.stdout);
    assert!(out.stdout.contains("• pipeline.py:3:12"), "{}", out.stdout);
    assert!(!out.stdout.contains("pipeline.py:3:1:1"), "{}", out.stdout);

    let sarif_args: Vec<&str> = args.iter().copied().chain(["--format", "sarif"]).collect();
    let out = run_in(dir.path(), &sarif_args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    let location = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(location["region"]["startLine"], 3, "{}", out.stdout);
    assert_eq!(location["region"]["startColumn"], 12, "{}", out.stdout);
    assert!(
        location["artifactLocation"]["uri"]
            .as_str()
            .is_some_and(|uri| uri.ends_with("/pipeline.py") || uri == "pipeline.py"),
        "{}",
        out.stdout
    );
}

/// `file:line:column` of the first place `needle` is written in `text`, the
/// column counted in characters.
fn written_at(file: &str, text: &str, needle: &str) -> String {
    let at = text.find(needle).expect("written");
    let line_start = text[..at].rfind('\n').map_or(0, |newline| newline + 1);
    format!(
        "{file}:{}:{}",
        text[..at].matches('\n').count() + 1,
        text[line_start..at].chars().count() + 1
    )
}

// A finding in a notebook cell's SQL is placed at its line and column in the
// file: behind a Databricks cell's `# MAGIC ` prefix on every line of the
// cell, after a Jupyter cell's `%sql`, on the line of the notebook's JSON
// its text is written on; a column counts the characters before it, not
// their bytes.
#[test]
fn a_notebook_finding_is_placed_where_its_sql_is() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("nb.py"),
        "# Databricks notebook source\n# MAGIC %sql\n# MAGIC DELETE FROM main.sales.nb\n\n# COMMAND ----------\n\n# MAGIC %sql DELETE FROM main.sales.inl\n\n# COMMAND ----------\n\n# MAGIC %sql\n# MAGIC\n# MAGIC SELECT 1;\n# MAGIC   DELETE FROM main.sales.third\n\n# COMMAND ----------\n\nñ = 1; spark.sql(\"DELETE FROM main.sales.py\")\n",
    )
    .expect("write nb.py");
    let ipynb = r#"{"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": [
{"cell_type": "code", "metadata": {}, "outputs": [], "source": ["%sql DELETE FROM main.sales.ia"]},
{"cell_type": "code", "metadata": {}, "outputs": [], "source": ["\n", "%sql DELETE FROM main.sales.ib"]},
{"cell_type": "code", "metadata": {}, "outputs": [], "source": ["%%sql\n", "SELECT 1;\n", "  DELETE FROM main.sales.ic"]},
{"cell_type": "code", "metadata": {}, "outputs": [], "source": ["x = 1\n", "ñ = 1; spark.sql(\"DELETE FROM main.sales.id\")"]}
]}"#;
    std::fs::write(dir.path().join("nb.ipynb"), ipynb).expect("write nb.ipynb");
    let in_nb = |needle: &str| written_at("nb.ipynb", ipynb, needle);
    std::fs::write(
        dir.path().join("cases.py"),
        "ñame = 1; spark.sql(\"DELETE FROM main.sales.b\")\nñ = 1; spark.sql(f\"DELETE FROM main.sales.{t}\")\n",
    )
    .expect("write cases.py");

    let args = [
        "analyze",
        ".",
        "-r",
        "--scan-embedded",
        "--dialect",
        "databricks",
    ];
    let out = run_in(dir.path(), &args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let ia = in_nb("DELETE FROM main.sales.ia");
    let ib = in_nb("DELETE FROM main.sales.ib");
    let ic = in_nb("DELETE FROM main.sales.ic");
    let id = in_nb(r#"DELETE FROM main.sales.id\""#);
    assert_eq!(
        [ia.as_str(), ib.as_str(), ic.as_str(), id.as_str()],
        [
            "nb.ipynb:2:71",
            "nb.ipynb:3:77",
            "nb.ipynb:4:94",
            "nb.ipynb:5:96"
        ]
    );
    for place in [
        "── nb.py:3:9".to_string(),
        "• nb.py:3:9".to_string(),
        "── nb.py:7:14".to_string(),
        "• nb.py:7:14".to_string(),
        "── nb.py:13:9".to_string(),
        "• nb.py:14:11".to_string(),
        "• nb.py:18:19".to_string(),
        format!("── {ia}"),
        format!("• {ia}"),
        format!("── {ib}"),
        format!("• {ib}"),
        format!("── {}", in_nb("SELECT 1;")),
        format!("• {ic}"),
        format!("• {id}"),
        "• cases.py:1:22".to_string(),
        "• cases.py:2:20".to_string(),
    ] {
        assert!(out.stdout.contains(&place), "{place}\n{}", out.stdout);
    }

    let sarif_args: Vec<&str> = args.iter().copied().chain(["--format", "sarif"]).collect();
    let out = run_in(dir.path(), &sarif_args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    let mut places: Vec<String> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .flat_map(|result| result["locations"].as_array().cloned().unwrap_or_default())
        .map(|location| {
            let at = &location["physicalLocation"];
            let uri = at["artifactLocation"]["uri"].as_str().unwrap_or_default();
            let file = uri.rsplit('/').next().unwrap_or_default();
            format!(
                "{file}:{}:{}",
                at["region"]["startLine"], at["region"]["startColumn"]
            )
        })
        .collect();
    places.sort();
    places.dedup();
    // The notebook's text before each finding is ASCII or `ñ`, one UTF-16
    // unit as it is one character.
    let mut expected: Vec<String> = [
        "cases.py:1:22",
        "cases.py:2:20",
        "nb.py:14:11",
        "nb.py:18:19",
        "nb.py:3:9",
        "nb.py:7:14",
    ]
    .iter()
    .map(|place| place.to_string())
    .chain([ia, ib, ic, id])
    .collect();
    expected.sort();
    assert_eq!(places, expected, "{}", out.stdout);
}

/// The text of `line` (1-based) of `text` from `column` (1-based) on,
/// `column` counted in `unit`s: characters or UTF-16 code units.
fn from_column(text: &str, line: usize, column: usize, utf16: bool) -> String {
    let line = text.lines().nth(line - 1).expect("the line");
    if utf16 {
        let units: Vec<u16> = line.encode_utf16().skip(column - 1).collect();
        String::from_utf16(&units).expect("a character boundary")
    } else {
        line.chars().skip(column - 1).collect()
    }
}

// On a line with multi-byte text (`ñ`, `€`, an emoji, CJK) before a finding,
// every report places it at the finding: text and JSON count characters,
// SARIF declares and counts UTF-16 code units. So for plain SQL, for SQL a
// Python string embeds (text before it on the line and inside it), a
// Databricks cell and a Jupyter cell, whose JSON escapes come before it.
#[test]
fn a_column_counts_characters_and_sarif_counts_utf16_units() {
    let dir = TempDir::new().expect("temp dir");
    let files = [
        (
            "p.sql",
            "select 1;\nselect 'ñ€😀中' as x; delete from main.sales.p;\n".to_string(),
        ),
        (
            "e.py",
            "x = '€😀'; spark.sql(\"select 'ñ中😀' as a; delete from main.sales.e\")\n".to_string(),
        ),
        (
            "d.py",
            "# Databricks notebook source\n# MAGIC %sql\n# MAGIC select 1;\n# MAGIC select '😀ñ' as a; delete from main.sales.d\n".to_string(),
        ),
        (
            "n.ipynb",
            notebook(&["%%sql\nselect 1;\nselect \"€😀\" as a; delete from main.sales.n"]),
        ),
    ];
    for (name, text) in &files {
        std::fs::write(dir.path().join(name), text).expect("write");
    }
    let text_of = |file: &str| {
        files
            .iter()
            .find(|(name, _)| *name == file)
            .map(|(_, text)| text.as_str())
            .expect("a probe file")
    };
    let args = [
        "analyze",
        ".",
        "-r",
        "--scan-embedded",
        "--dialect",
        "databricks",
    ];

    let out = run_in(dir.path(), &args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let mut placed = Vec::new();
    for (name, _) in &files {
        let marker = format!("• {name}:");
        for rest in out.stdout.split(&marker).skip(1) {
            let place: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            let (line, column) = place.split_once(':').expect("line:column");
            let at = from_column(
                text_of(name),
                line.parse().expect("line"),
                column.parse().expect("column"),
                false,
            );
            assert!(at.starts_with("delete"), "{name}:{place} is at {at:?}");
            placed.push(name);
        }
    }
    assert_eq!(placed.len(), files.len(), "{}", out.stdout);

    let json_args: Vec<&str> = args.iter().copied().chain(["--format", "json"]).collect();
    let out = run_in(dir.path(), &json_args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let report: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    let mut locations = Vec::new();
    fn collect(value: &serde_json::Value, into: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("rule_id").and_then(|r| r.as_str()) == Some("DML-WRITE-UNBOUNDED") {
                    if let Some(location) = map.get("location").and_then(|l| l.as_str()) {
                        into.push(location.to_string());
                    }
                }
                map.values().for_each(|v| collect(v, into));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| collect(v, into)),
            _ => {}
        }
    }
    collect(&report, &mut locations);
    locations.sort();
    locations.dedup();
    assert_eq!(locations.len(), files.len(), "{locations:?}");
    for location in &locations {
        let mut parts = location.rsplitn(3, ':');
        let (column, line, path) = (
            parts.next().expect("column"),
            parts.next().expect("line"),
            parts.next().expect("path"),
        );
        let name = path.rsplit('/').next().expect("file");
        let at = from_column(
            text_of(name),
            line.parse().expect("line"),
            column.parse().expect("column"),
            false,
        );
        assert!(at.starts_with("delete"), "{location} is at {at:?}");
    }

    let sarif_args: Vec<&str> = args.iter().copied().chain(["--format", "sarif"]).collect();
    let out = run_in(dir.path(), &sarif_args, None);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let sarif: serde_json::Value = serde_json::from_str(&out.stdout).expect("sarif");
    assert_eq!(sarif["runs"][0]["columnKind"], "utf16CodeUnits");
    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), files.len(), "{}", out.stdout);
    for result in results {
        let at = &result["locations"][0]["physicalLocation"];
        let uri = at["artifactLocation"]["uri"].as_str().expect("uri");
        let name = uri.rsplit('/').next().expect("file");
        let line = at["region"]["startLine"].as_u64().expect("line") as usize;
        let column = at["region"]["startColumn"].as_u64().expect("column") as usize;
        let text = from_column(text_of(name), line, column, true);
        assert!(
            text.starts_with("delete"),
            "{name}:{line}:{column} is at {text:?}"
        );
    }
}

/// A T-SQL catalog of the database `SalesDb`: `dbo.Customers` and `hr.Emp`.
const SCHEMAS_CATALOG: &str = r#"{"schema_version": 2, "provider": "mssql", "generated_at": "2026-01-01T00:00:00Z", "databases": [{"name": "SalesDb", "schemas": [{"name": "dbo", "tables": [{"name": "Customers", "kind": "Table", "columns": [{"name": "Id", "data_type": "int", "nullable": false}]}]}, {"name": "hr", "tables": [{"name": "Emp", "kind": "Table", "columns": [{"name": "SSN", "data_type": "nvarchar", "nullable": true}]}]}]}]}"#;

/// What a T-SQL run in `dir` with `extra` options reports reading
/// `SELECT SSN FROM Emp; SELECT Id FROM Customers;` against
/// [`SCHEMAS_CATALOG`]: its exit code, the tables the catalog lacked, each
/// by its last part, and what it printed on stderr.
fn bare_names_under(dir: &Path, extra: &[&str]) -> (i32, Vec<String>, String) {
    let catalog = dir.join("catalog.json");
    std::fs::write(&catalog, SCHEMAS_CATALOG).expect("write catalog");
    let mut args = vec![
        "analyze",
        "--stdin",
        "--dialect",
        "mssql",
        "--format",
        "json",
        "--catalog",
        catalog.to_str().expect("utf-8 path"),
    ];
    args.extend_from_slice(extra);
    let out = run_in(
        dir,
        &args,
        Some("SELECT SSN FROM Emp; SELECT Id FROM Customers;"),
    );
    let missing = serde_json::from_str::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|report| {
            report["catalog_info"]["missing_tables"]
                .as_array()
                .map(|tables| {
                    tables
                        .iter()
                        .filter_map(|table| table.as_str()?.rsplit('.').next())
                        .map(str::to_lowercase)
                        .collect()
                })
        })
        .unwrap_or_default();
    (out.code, missing, out.stderr)
}

// A table named without a schema is looked for where `--default-schema`
// says, else where `.lexega.toml`'s `[session] default_schema` says, else
// in the dialect's default schema (T-SQL `dbo`).
#[test]
fn the_default_schema_a_run_gives_is_where_a_bare_name_is_looked_for() {
    let dir = TempDir::new().expect("temp dir");
    let (code, missing, stderr) = bare_names_under(dir.path(), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(missing, ["emp"]);
    for schema in ["hr", "SalesDb.hr", "[hr]"] {
        let (code, missing, stderr) = bare_names_under(dir.path(), &["--default-schema", schema]);
        assert_eq!(code, 0, "{schema}: {stderr}");
        assert_eq!(missing, ["customers"], "{schema}");
    }
    std::fs::write(
        dir.path().join(".lexega.toml"),
        "[session]\ndefault_schema = \"hr\"\n",
    )
    .expect("write config");
    let (code, missing, stderr) = bare_names_under(dir.path(), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(missing, ["customers"]);
    // The command line is read before the file.
    let (code, missing, stderr) = bare_names_under(dir.path(), &["--default-schema", "dbo"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(missing, ["emp"]);
    // A name of more than two parts is refused, naming where it was given.
    let (code, _, stderr) = bare_names_under(dir.path(), &["--default-schema", "a.b.c"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("--default-schema"), "{stderr}");
    // So is a name of an empty part, naming the form it takes.
    for written in ["x.", ".x", "x..y"] {
        let (code, _, stderr) = bare_names_under(dir.path(), &["--default-schema", written]);
        assert_ne!(code, 0, "{written}");
        assert!(
            stderr.contains("--default-schema") && stderr.contains("SCHEMA"),
            "{written}: {stderr}"
        );
    }
    std::fs::write(
        dir.path().join(".lexega.toml"),
        "[session]\ndefault_schema = \"a.b.c\"\n",
    )
    .expect("write config");
    let (code, _, stderr) = bare_names_under(dir.path(), &[]);
    assert_ne!(code, 0);
    assert!(stderr.contains("default_schema"), "{stderr}");
}

/// What `analyze . -r --trace` prints, report file included, of the files
/// `files` (name, text) under `dialect`.
fn analyzed_folder(files: &[(&str, &str)], dialect: &str) -> String {
    let dir = TempDir::new().expect("temp dir");
    for (name, text) in files {
        std::fs::write(dir.path().join(name), text).expect("write file");
    }
    let report = dir.path().join("report.json");
    let report_arg = report.display().to_string();
    let out = run_in(
        dir.path(),
        &[
            "analyze",
            ".",
            "-r",
            "--dialect",
            dialect,
            "--min-severity",
            "info",
            "--format",
            "json",
            "--trace",
            "--report-out",
            &report_arg,
        ],
        None,
    );
    out.stdout + &std::fs::read_to_string(&report).unwrap_or_default()
}

#[test]
fn a_value_one_file_stores_and_a_later_file_runs_is_masked() {
    let seed = "INSERT INTO jobs (q) VALUES ('ALTER ROLE a PASSWORD ''XpXf01canary''');\nINSERT INTO audit (at) VALUES (DATE '2024-06-01');\n";
    let run = "DO $$ DECLARE s text; BEGIN SELECT q INTO s FROM jobs; EXECUTE s; END $$;\n";
    for files in [
        &[("V1__seed.sql", seed), ("V2__run.sql", run)][..],
        &[("V1__seed.sql", seed)][..],
    ] {
        let printed = analyzed_folder(files, "postgresql");
        assert!(!printed.contains("XpXf01canary"), "{printed}");
        // A value that is no text is shown, whatever another file runs.
        assert!(printed.contains("DATE '2024-06-01'"), "{printed}");
    }
}

#[test]
fn a_value_stored_where_a_runner_an_earlier_file_defines_runs_it_is_masked() {
    let cases: [(&str, &[(&str, &str)]); 3] = [
        (
            "postgresql",
            &[
                ("V1__proc.sql", "CREATE PROCEDURE run_jobs() LANGUAGE plpgsql AS $$ DECLARE r record; BEGIN FOR r IN SELECT q FROM jobs LOOP EXECUTE r.q; END LOOP; END $$;\n"),
                ("V2__seed.sql", "INSERT INTO jobs (q) VALUES ('ALTER ROLE a PASSWORD ''XpXg01canary''');\n"),
                ("V3__call.sql", "CALL run_jobs();\n"),
            ],
        ),
        (
            "postgresql",
            &[
                ("V1__trigger.sql", "CREATE FUNCTION run_q() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN EXECUTE NEW.q; RETURN NEW; END $$;\nCREATE TRIGGER t_run AFTER INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION run_q();\n"),
                ("V2__seed.sql", "INSERT INTO jobs (q) VALUES ('ALTER ROLE a PASSWORD ''XpXg02canary''');\n"),
            ],
        ),
        (
            "snowflake",
            &[
                ("V1__task.sql", "CREATE TASK run_jobs WAREHOUSE = wh SCHEDULE = '5 MINUTE' AS EXECUTE IMMEDIATE (SELECT q FROM jobs LIMIT 1);\n"),
                ("V2__seed.sql", "INSERT INTO jobs (q) VALUES ('ALTER USER u SET PASSWORD = ''XpXg03canary''');\n"),
            ],
        ),
    ];
    for (dialect, files) in cases {
        let printed = analyzed_folder(files, dialect);
        assert!(!printed.contains("XpXg0"), "{dialect}\n{printed}");
    }
}

#[test]
fn a_value_written_into_a_view_another_file_makes_is_masked() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("V1__view.sql"),
        "CREATE VIEW v_users AS SELECT id, password AS p FROM users;\n",
    )
    .expect("write view");
    std::fs::write(
        dir.path().join("V2__upd.sql"),
        "UPDATE v_users SET p = 'XpXf02canary' WHERE id = 1;\n",
    )
    .expect("write update");
    let report = dir.path().join("report.json");
    let report_arg = report.display().to_string();
    let out = run_in(
        dir.path(),
        &[
            "analyze",
            ".",
            "-r",
            "--min-severity",
            "info",
            "--format",
            "json",
            "--trace",
            "--report-out",
            &report_arg,
        ],
        None,
    );
    let printed = out.stdout + &std::fs::read_to_string(&report).unwrap_or_default();
    assert!(!printed.contains("XpXf02canary"), "{printed}");
}

// A sqlcmd command that runs what the analysis did not read is said in
// every format: an included file, a batch sent to another server, an
// operating-system command. `--strict` fails on it, and no format quotes
// the rest of a `:connect` line or the operating-system command.
#[test]
fn every_format_names_a_sqlcmd_command_that_runs_what_was_not_read() {
    let sql = ":r .\\deploy\\tables.sql\n:connect srv2 -U sa -P Zq9ConnectPw\n!! del Zq9ShellArg\nGO\nSELECT a FROM dbo.t\nGO\n";
    for format in ["text", "markdown", "sarif", "gl-sast", "json", "yaml"] {
        let out = run(
            &[
                "analyze",
                "--stdin",
                "--dialect",
                "mssql",
                "--format",
                format,
            ],
            Some(sql),
        );
        assert_eq!(out.code, 0, "{format}: {}", out.stderr);
        for said in ["deploy", "srv2", "!!"] {
            assert!(
                out.stdout.contains(said),
                "{format}: {said}\n{}",
                out.stdout
            );
        }
        let says = match format {
            "json" | "yaml" => ["IncludedFile", "OtherServer", "OsCommand"],
            _ => [
                "includes a file the analysis did not read",
                "sends the batch to another server",
                "runs an operating-system command",
            ],
        };
        for said in says {
            assert!(
                out.stdout.contains(said),
                "{format}: {said}\n{}",
                out.stdout
            );
        }
        assert!(!out.stdout.contains("Zq9"), "{format}\n{}", out.stdout);
    }
    let out = run(
        &["analyze", "--stdin", "--dialect", "mssql", "--strict"],
        Some(sql),
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert_eq!(
        out.stderr.matches("E_STRICT_NOT_READ").count(),
        3,
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Zq9"), "{}", out.stderr);
    let client = ":setvar Db Prod\n:on error exit\nGO\nSELECT a FROM dbo.t\nGO\n";
    let out = run(
        &["analyze", "--stdin", "--dialect", "mssql", "--strict"],
        Some(client),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
}
