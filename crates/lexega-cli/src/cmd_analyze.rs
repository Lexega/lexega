// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `analyze` command: one source, or a batch of files, analyzed
//! through the build's [`Session`] and written in
//! the requested format.
//! `review` runs the same batch over the files a commit range touches.

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process;

use lexega_core::analyzer::{self, ToolRun};
use lexega_core::template::RenderArtifacts;

use super::artifacts::{
    is_artifact_file_path, resolve_report_format, write_optional_report_artifact,
    write_report_artifact, ArtifactKeys, DecisionArtifactFormat, ReportArtifactFormat,
};
use super::extension::{
    governance_capabilities, BatchCase, BatchFile, BatchPlan, Capability, ChangeRange, Extension,
    FileFailure, OrderingHazard, PolicyGate, PolicyOutcome, PolicySetup, Session, SessionOptions,
    SourceCase,
};
use super::git::FileAtCommitError;
use super::io::load_custom_rules;
use super::io::{
    collect_embedded_files, collect_sql_files, resolve_dialect, strip_bom, FoundFiles, SkipReason,
    SkippedFile,
};
use super::output::{
    print_analyze_markdown, print_fact_explanation, print_finding_explanation, risk_icon,
    write_text_entries,
};
use super::types::{BatchProcessingConfig, GivenOptions, RenderDiagnosticsLevel};
use super::usage::{print_review_usage, print_risk_usage, print_rule_syntax};

/// `println!` into a `String`.
macro_rules! outln {
    ($dst:expr) => {
        $dst.push('\n')
    };
    ($dst:expr, $($arg:tt)*) => {{
        $dst.push_str(&format!($($arg)*));
        $dst.push('\n');
    }};
}

/// A file's entries in the batch report's per-file sections.
struct FileSection {
    path: String,
    findings: Vec<analyzer::RuleMatch>,
    context: Vec<analyzer::RuleMatch>,
}

/// The occurrences a finding stands for: a rule raised on several
/// statements of a file is one finding, "(N occurrences)", counting each.
fn occurrences(finding: &analyzer::AnalysisFinding) -> usize {
    finding.findings_merged.unwrap_or(1)
}

/// A Markdown table of entries: level, message and up to `evidence_listed`
/// evidence summaries. `column` names the entries' kind.
fn write_markdown_entries(
    md: &mut String,
    column: &str,
    entries: &[analyzer::RuleMatch],
    evidence_listed: usize,
) {
    if entries.is_empty() {
        return;
    }
    outln!(md, "| Level | {} | Evidence |", column);
    outln!(md, "|-------|--------|----------|");
    for entry in entries {
        let level = entry.risk_level();
        let evidence = entry.evidence();
        let mut parts: Vec<String> = evidence
            .iter()
            .take(evidence_listed)
            .filter_map(|ev| {
                let analyzer::RiskEvidence::RuleMatch { rule_id, .. } = ev else {
                    return None;
                };
                let mut p = Vec::new();
                if let Some(line) = super::output::source_line(ev) {
                    p.push(format!("Line {}", line));
                }
                if !rule_id.is_empty() {
                    p.push(format!("`{}`", rule_id));
                }
                (!p.is_empty()).then(|| p.join(": "))
            })
            .collect();
        if evidence.len() > evidence_listed {
            parts.push(format!("+{} more", evidence.len() - evidence_listed));
        }
        // Escape pipes in message for markdown table
        let msg = entry.message().replace('|', "\\|");
        outln!(
            md,
            "| {} {} | {} | {} |",
            risk_icon(level),
            level.as_str(),
            msg,
            parts.join("; ")
        );
    }
    outln!(md);
}

/// The title of the per-file sections: context entries are not findings.
fn sections_title(sections: &[FileSection]) -> &'static str {
    if sections.iter().any(|section| !section.context.is_empty()) {
        "Per-File Details"
    } else {
        "Per-File Finding Details"
    }
}

/// What a run of the analyze driver measures.
pub(crate) enum Scope {
    /// The sources named on the command line, as checked out.
    Snapshot,
    /// The SQL files a commit range touches, read at its head.
    Change(super::git::CommitRange),
}

fn print_usage(program: &str, ext: &dyn Extension, change: bool) {
    if change {
        print_review_usage(program, ext);
    } else {
        print_risk_usage(program, ext);
    }
}

/// This build's run, as a SARIF or GitLab report describes it.
fn tool_run<'a>(
    ext: &dyn Extension,
    base_path: Option<&'a str>,
    depth_note: Option<&'a str>,
) -> ToolRun<'a> {
    ToolRun {
        name: ext.tool_name(),
        version: env!("CARGO_PKG_VERSION"),
        base_path,
        depth_note,
        unrendered_files: &[],
        skipped_files: &[],
        macro_files: &[],
        run_notes: &[],
    }
}

/// The highest risk level a batch's text summary states: none where it
/// found nothing, and then not as all clear where `run_notes` say what it
/// left undone.
fn highest_risk(
    findings: usize,
    max_level: lexega_core::analyzer::RiskLevel,
    run_notes: &[String],
) -> String {
    match (findings, run_notes.is_empty()) {
        (0, true) => "NONE".to_string(),
        (0, false) => "none found in what was checked (see the notes above)".to_string(),
        _ => max_level.as_str().to_uppercase(),
    }
}

/// What a run left undone that its findings do not show, a sentence each:
/// `unrendered` template files analyzed as written, `render_failed` files
/// that did not render and were not analyzed, and, for a `review`, a change
/// `session` does not compare. Each says what the build adds where the
/// session cannot do it.
pub fn run_notes(
    ext: &dyn Extension,
    session: &dyn Session,
    unrendered: usize,
    render_failed: usize,
    review: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    if render_failed > 0 {
        notes.push(if render_failed == 1 {
            "1 template file did not render and was not analyzed: the skipped files say why."
                .to_string()
        } else {
            format!(
                "{} template files did not render and were not analyzed: the skipped files say why for each.",
                render_failed
            )
        });
    }
    if unrendered > 0 {
        let mut note = if unrendered == 1 {
            "1 template file was analyzed as written, not rendered".to_string()
        } else {
            format!(
                "{} template files were analyzed as written, not rendered",
                unrendered
            )
        };
        note.push_str(": findings that depend on the rendered SQL may be missing.");
        if !session.renders_templates() {
            note.push(' ');
            note.push_str(&ext.rendering_offer());
        }
        notes.push(note);
    }
    if review && !session.compares_changes() {
        notes.push(format!(
            "The change was not compared with its base: no DIFF-* rule ran. {}",
            ext.comparison_offer()
        ));
    }
    notes
}

/// Each sqlcmd command line of `report` that runs what the analysis did not
/// read, as a run's note lists it: its line (after `file`, in a batch),
/// what it does, and the command as the report quotes it.
pub fn unread_sqlcmd_lines(
    file: Option<&str>,
    report: &lexega_core::analyzer::AnalysisReport,
) -> Vec<String> {
    report
        .unread_sqlcmd()
        .map(|(skipped, runs)| {
            let place = match file {
                Some(file) => format!("{} line {}", file, skipped.line_number),
                None => format!("line {}", skipped.line_number),
            };
            format!(
                "{} {} (`{}`)",
                place,
                runs.describe(),
                skipped.statement_prefix
            )
        })
        .collect()
}

/// The run's note on its sqlcmd command lines that run what the analysis
/// did not read ([`unread_sqlcmd_lines`]), naming the first ten; `None`
/// where there is none.
pub fn unread_sqlcmd_note(lines: &[String]) -> Option<String> {
    const LISTED: usize = 10;
    let (first, rest) = lines.split_at(lines.len().min(LISTED));
    let mut note = match lines.len() {
        0 => return None,
        1 => "1 sqlcmd command runs what the analysis did not read, and --strict fails on it: "
            .to_string(),
        n => format!(
            "{} sqlcmd commands run what the analysis did not read, and --strict fails on each: ",
            n
        ),
    };
    note.push_str(&first.join("; "));
    if !rest.is_empty() {
        note.push_str(&format!(
            "; and {} more (the JSON report's skipped_details lists each)",
            rest.len()
        ));
    }
    note.push('.');
    Some(note)
}

/// The options that take one value, so a second, different one is a
/// mistake. `--var`, `--var-file`, `--snowsql-config`, `--var-env` and
/// `--var-syntax` may repeat.
const SINGLE_VALUED_OPTIONS: &[&str] = &[
    "--format",
    "--color",
    "--report-artifact-format",
    "--decision-artifact-format",
    "--min-severity",
    "--policy",
    "--env",
    "--exceptions",
    "--decision-out",
    "--report-out",
    "--team",
    "--job-type",
    "--change-id",
    "--repo",
    "--commit",
    "--run-id",
    "--dbt-profile",
    "--dbt-project",
    "--custom-rules",
    "--catalog",
    "--provider",
    "--default-schema",
    "--render-diagnostics",
    "--builtin-rules",
    "--mode",
    "--dialect",
];

/// Whether a path names a scan (a glob or a directory) rather than a file.
fn scans(path: &str) -> bool {
    path.contains('*') || path.contains('?') || Path::new(path).is_dir()
}

/// Handle the `analyze` subcommand.
pub fn handle_risk_command(args: &[String], ext: &dyn Extension) {
    run(args, ext, Scope::Snapshot);
}

/// Parse the options that follow the command — or, for a change scope, the
/// commit range — and run the analysis.
pub(crate) fn run(args: &[String], ext: &dyn Extension, scope: Scope) {
    let program = args[0].as_str();
    let change = matches!(scope, Scope::Change(_));
    // Parse risk-specific arguments
    // The paths named: a change-scoped run's scope, or the files, directories
    // and globs a snapshot reads.
    let mut paths: Vec<String> = Vec::new();
    let mut pr_comment = false;
    let mut use_stdin = false;
    // A change-scoped run reports for a pull request by default.
    let mut output_format = if change { "markdown" } else { "text" };
    let mut report_artifact_format: Option<ReportArtifactFormat> = None;
    let mut decision_artifact_format = DecisionArtifactFormat::Json;
    // Quiet by default: only High and above, unless --min-severity lowers it.
    let mut min_severity: Option<lexega_core::analyzer::RiskLevel> =
        Some(lexega_core::analyzer::RiskLevel::High);
    let mut recursive = false;
    let mut cross_script = false;

    // Policy gate
    let mut policy_path: Option<String> = None;
    let mut policy_env: Option<String> = None;
    let mut exceptions_path: Option<String> = None;
    let mut decision_out: Option<String> = None;
    let mut report_out: Option<String> = None;
    let mut policy_team: Option<String> = None;
    let mut policy_job_type: Option<String> = None;
    let mut policy_change_id: Option<String> = None;
    let mut policy_repo: Option<String> = None;
    let mut policy_commit: Option<String> = None;
    let mut run_id: Option<String> = None;
    let mut dbt_profile: Option<String> = None;
    let mut dbt_project_path: Option<String> = None;
    let mut load_macros = false;
    let mut fail_on_missing_packages = false;
    let mut custom_rules_path: Option<String> = None;
    let mut catalog_path: Option<String> = None;
    let mut default_schema_flag: Option<String> = None;
    let mut catalog_provider: Option<String> = None;
    let mut trace_mode = false;
    let mut verbose_mode = false;
    let mut detail_mode = change;
    let mut explain_findings = false;
    let mut explain_facts = false;
    let mut builtin_rules = true; // Default: run built-in rules
    let mut render_diagnostics = RenderDiagnosticsLevel::None; // none|summary|impacted|all
    let mut quiet_mode = false; // Suppress progress output
    let mut runtime_mode = false; // Runtime/agent mode: decision-only JSON to stdout
    let mut color_choice = super::color::ColorChoice::Auto; // text-output color

    // Jinja rendering options
    let mut jinja_vars: Vec<(String, String)> = Vec::new();
    let mut jinja_var_files: Vec<String> = Vec::new();
    let mut snowsql_configs: Vec<String> = Vec::new();

    // Deployment-variable substitution options
    let mut var_env_names: Vec<String> = Vec::new();
    let mut var_syntax_names: Vec<String> = Vec::new();

    // SQL dialect (defaults to Snowflake)
    let mut dialect_name: Option<String> = None;

    // Embedded SQL extraction from Python/notebook files
    let mut scan_embedded = false;

    // Strict-analysis mode: `--strict[=<mode>]`, else LEXEGA_STRICT.
    let mut strict_flag: Option<lexega_core::StrictMode> = None;

    let mut given = GivenOptions::default();

    let mut i = if change { 3 } else { 2 }; // after the command, or after the commit range
    while i < args.len() {
        let option = args[i].as_str();
        if SINGLE_VALUED_OPTIONS.contains(&option) {
            if let Some(value) = args.get(i + 1) {
                if let Err(e) = given.record(option, value) {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        match option {
            "--stdin" if change => {
                eprintln!(
                    "Error: --stdin does not apply to review: it reads the files the range changes"
                );
                print_usage(program, ext, change);
                process::exit(1);
            }
            "--stdin" => {
                use_stdin = true;
                i += 1;
            }
            "--recursive" | "-r" => {
                recursive = true;
                i += 1;
            }
            "--cross-script" => {
                cross_script = true;
                i += 1;
            }
            "--format" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --format requires a value (text|json|yaml|sarif|gl-sast|markdown|both)"
                    );
                    process::exit(1);
                }
                output_format = match args[i + 1].as_str() {
                    "text" | "json" | "yaml" | "sarif" | "gl-sast" | "markdown" | "both" => {
                        args[i + 1].as_str()
                    }
                    _ => {
                        eprintln!(
                            "Error: --format must be text, json, yaml, sarif, gl-sast, markdown, or both"
                        );
                        process::exit(1);
                    }
                };
                i += 2;
            }
            "--color" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --color requires a value (auto|always|never)");
                    process::exit(1);
                }
                color_choice = super::color::ColorChoice::from_cli_arg(&args[i + 1])
                    .unwrap_or_else(|| {
                        eprintln!("Error: --color must be auto, always, or never");
                        process::exit(1);
                    });
                i += 2;
            }
            "--no-color" => {
                color_choice = super::color::ColorChoice::Never;
                i += 1;
            }
            "--report-artifact-format" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --report-artifact-format requires a value (json|yaml|sarif)");
                    process::exit(1);
                }
                report_artifact_format = Some(
                    ReportArtifactFormat::from_cli_arg(&args[i + 1]).unwrap_or_else(|msg| {
                        eprintln!("Error: {}", msg);
                        process::exit(1);
                    }),
                );
                i += 2;
            }
            "--decision-artifact-format" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --decision-artifact-format requires a value (json|yaml)");
                    process::exit(1);
                }
                decision_artifact_format = DecisionArtifactFormat::from_cli_arg(&args[i + 1])
                    .unwrap_or_else(|msg| {
                        eprintln!("Error: {}", msg);
                        process::exit(1);
                    });
                i += 2;
            }
            "--min-severity" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --min-severity requires a risk level (info|low|medium|high|critical)");
                    process::exit(1);
                }
                min_severity = lexega_core::analyzer::RiskLevel::from_str(&args[i + 1]);
                if min_severity.is_none() {
                    eprintln!("Error: --min-severity must be info, low, medium, high, or critical");
                    process::exit(1);
                }
                i += 2;
            }
            "--policy" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --policy requires a file path");
                    process::exit(1);
                }
                policy_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--env" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --env requires a value (e.g. prod|staging|dev)");
                    process::exit(1);
                }
                policy_env = Some(args[i + 1].clone());
                i += 2;
            }
            "--exceptions" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --exceptions requires a file path");
                    process::exit(1);
                }
                exceptions_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--decision-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --decision-out requires a file path or directory");
                    process::exit(1);
                }
                if let Err(e) =
                    super::artifacts::check_output_target("--decision-out", &args[i + 1])
                {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
                decision_out = Some(args[i + 1].clone());
                i += 2;
            }
            "--report-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --report-out requires a file path or directory");
                    process::exit(1);
                }
                if let Err(e) = super::artifacts::check_report_target(&args[i + 1]) {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
                report_out = Some(args[i + 1].clone());
                i += 2;
            }
            "--team" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --team requires a value");
                    process::exit(1);
                }
                policy_team = Some(args[i + 1].clone());
                i += 2;
            }
            "--job-type" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --job-type requires a value (e.g. ad_hoc|scheduled)");
                    process::exit(1);
                }
                policy_job_type = Some(args[i + 1].clone());
                i += 2;
            }
            "--change-id" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --change-id requires a value");
                    process::exit(1);
                }
                policy_change_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--repo" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --repo requires a value");
                    process::exit(1);
                }
                policy_repo = Some(args[i + 1].clone());
                i += 2;
            }
            "--commit" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --commit requires a value");
                    process::exit(1);
                }
                policy_commit = Some(args[i + 1].clone());
                i += 2;
            }
            "--run-id" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --run-id requires a value");
                    process::exit(1);
                }
                run_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--dbt-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --dbt-profile requires a profile name");
                    process::exit(1);
                }
                dbt_profile = Some(args[i + 1].clone());
                i += 2;
            }
            "--dbt-project" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --dbt-project requires a directory path");
                    process::exit(1);
                }
                dbt_project_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--load-macros" => {
                load_macros = true;
                i += 1;
            }
            "--fail-on-missing-packages" => {
                fail_on_missing_packages = true;
                i += 1;
            }
            "--var" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --var requires KEY=VALUE");
                    process::exit(1);
                }
                let var_arg = &args[i + 1];
                if let Some(eq_pos) = var_arg.find('=') {
                    let key = var_arg[..eq_pos].to_string();
                    let value = var_arg[eq_pos + 1..].to_string();
                    jinja_vars.push((key, value));
                } else {
                    eprintln!("Error: --var requires KEY=VALUE format");
                    process::exit(1);
                }
                i += 2;
            }
            "--var-file" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --var-file requires a file path");
                    process::exit(1);
                }
                jinja_var_files.push(args[i + 1].clone());
                i += 2;
            }
            "--snowsql-config" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --snowsql-config requires a file path");
                    process::exit(1);
                }
                snowsql_configs.push(args[i + 1].clone());
                i += 2;
            }
            "--var-env" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --var-env requires an environment variable name");
                    process::exit(1);
                }
                var_env_names.push(args[i + 1].clone());
                i += 2;
            }
            "--var-syntax" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --var-syntax requires a preset (dollar-brace, dollar-paren) or a marker shape such as '%%NAME%%'"
                    );
                    process::exit(1);
                }
                var_syntax_names.push(args[i + 1].clone());
                i += 2;
            }
            "--custom-rules" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --custom-rules requires a file path");
                    process::exit(1);
                }
                custom_rules_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--catalog" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --catalog requires a file path");
                    process::exit(1);
                }
                catalog_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--default-schema" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --default-schema requires SCHEMA or DATABASE.SCHEMA");
                    process::exit(1);
                }
                default_schema_flag = Some(args[i + 1].clone());
                i += 2;
            }
            "--provider" => {
                if i + 1 >= args.len() {
                    let valid = lexega_core::builtin_catalog_provider_names().join(", ");
                    eprintln!("Error: --provider requires a value ({})", valid);
                    process::exit(1);
                }
                catalog_provider = Some(args[i + 1].clone());
                i += 2;
            }
            "--trace" => {
                // Full output mode - no truncation of evaluated rules
                trace_mode = true;
                i += 1;
            }
            "--verbose" => {
                // Verbose mode — populate v1 rule-evaluation introspection
                // (`statement_explanations`) and render it after the
                // normal report. Auto-enables trace_mode so the
                // per-family evaluators collect per-statement rule
                // outcomes.
                verbose_mode = true;
                trace_mode = true;
                i += 1;
            }
            "--detail" => {
                // Detail mode - show per-file finding details in batch text/markdown output
                detail_mode = true;
                i += 1;
            }
            // `--list-signals` is accepted as well; help does not list it.
            "--rule-syntax" | "--list-signals" => {
                // Print the custom-rule syntax primer and exit
                print_rule_syntax(program, ext);
                process::exit(0);
            }
            // `--explain-signals` is accepted as well; help does not list it.
            "--explain-findings" | "--explain-signals" => {
                // Findings preview mode — show per-statement matched rules
                // (populated when trace_mode is on via
                // `statement_explanations`).
                explain_findings = true;
                trace_mode = true;
                i += 1;
            }
            "--explain-facts" => {
                // Facts preview mode - show structured facts extracted from policies
                // Auto-enable trace to populate statement-level metadata
                explain_facts = true;
                trace_mode = true;
                i += 1;
            }
            "--no-builtin" => {
                // Convenience flag: disable all built-in analyzers (equivalent to --builtin-rules false)
                builtin_rules = false;
                i += 1;
            }
            "--render-diagnostics" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --render-diagnostics requires a value (none|summary|impacted|all)"
                    );
                    process::exit(1);
                }
                render_diagnostics = RenderDiagnosticsLevel::from_cli_arg(&args[i + 1])
                    .unwrap_or_else(|msg| {
                        eprintln!("Error: {}", msg);
                        process::exit(1);
                    });
                i += 2;
            }
            "--builtin-rules" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --builtin-rules requires a value (true|false)");
                    process::exit(1);
                }
                match args[i + 1].to_lowercase().as_str() {
                    "true" | "1" | "yes" => builtin_rules = true,
                    "false" | "0" | "no" => builtin_rules = false,
                    _ => {
                        eprintln!("Error: --builtin-rules must be 'true' or 'false'");
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "--quiet" | "-q" => {
                quiet_mode = true;
                i += 1;
            }
            "--mode" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --mode requires a value (ci|runtime)");
                    process::exit(1);
                }
                match args[i + 1].as_str() {
                    "ci" => runtime_mode = false,
                    "runtime" => runtime_mode = true,
                    _ => {
                        eprintln!("Error: --mode must be 'ci' or 'runtime'");
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "--dialect" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --dialect requires a value ({})",
                        super::io::DIALECT_OPTIONS
                    );
                    process::exit(1);
                }
                dialect_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--scan-embedded" => {
                scan_embedded = true;
                i += 1;
            }
            // `--strict` → Strict; `--strict <mode>` allows explicit choice.
            "--strict" => {
                // Consume the next token as the mode only when it actually parses
                // as one (off|strict|pedantic); otherwise treat `--strict` as bare
                // (Strict) and leave the token for positional handling — so
                // `--strict query.sql` runs strict on the file instead of
                // misreading the path as the mode. `--strict=<mode>` also works via
                // the global `--key=value` normalization.
                let (mode, consumed) = match args
                    .get(i + 1)
                    .and_then(|s| lexega_core::parse_strict_mode(s).ok())
                {
                    Some(mode) => (mode, 2),
                    None => {
                        // A token after it that is neither a mode nor a path
                        // a run reads is a mode misspelled.
                        if let Some(next) = args.get(i + 1).filter(|next| {
                            !change
                                && !next.starts_with('-')
                                && !next.contains(['*', '?'])
                                && !Path::new(next.as_str()).exists()
                        }) {
                            eprintln!(
                                "Error: '{}' after --strict is not a strict mode (off|strict|pedantic) and no such file exists",
                                next
                            );
                            process::exit(1);
                        }
                        (lexega_core::StrictMode::Strict, 1)
                    }
                };
                if let Err(e) = given.record("--strict", mode.as_str()) {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
                strict_flag = Some(mode);
                i += consumed;
            }
            "--pr-comment" if change => {
                pr_comment = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage(program, ext, change);
                process::exit(0);
            }
            "--" => {
                paths.extend(args[i + 1..].iter().cloned());
                break;
            }
            arg if !arg.starts_with('-') => {
                paths.push(arg.to_string());
                i += 1;
            }
            arg => {
                eprintln!(
                    "Error: Unknown {} argument '{}'",
                    if change { "review" } else { "analyze" },
                    arg
                );
                print_usage(program, ext, change);
                process::exit(1);
            }
        }
    }

    if use_stdin && !paths.is_empty() {
        eprintln!(
            "Error: --stdin reads standard input and takes no path (given: {})",
            paths.join(", ")
        );
        process::exit(1);
    }

    let one_file_flags = [
        ("--explain-findings", explain_findings),
        ("--explain-facts", explain_facts),
        ("--verbose", verbose_mode),
    ];

    let strict_mode = super::io::strict_mode_or_exit(strict_flag);

    // The `--report-out` artifact's format: one rule for a file and a batch.
    // A target that names no format is SARIF under `--format sarif`, JSON
    // otherwise.
    let default_report_format = if output_format == "sarif" {
        ReportArtifactFormat::Sarif
    } else {
        ReportArtifactFormat::Json
    };
    let report_artifact_format = match report_out.as_deref() {
        Some(target) => {
            resolve_report_format(target, report_artifact_format, default_report_format)
                .unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                })
        }
        None => report_artifact_format.unwrap_or(ReportArtifactFormat::Json),
    };

    // Everything parsed so far is plain analysis unless an option reaches a
    // capability the build has to grant.
    let mut needs = governance_capabilities(
        policy_path.as_deref(),
        exceptions_path.as_deref(),
        decision_out.as_deref(),
    );
    if cross_script {
        needs.push(Capability::CrossScript);
    }
    if runtime_mode {
        needs.push(Capability::RuntimeMode);
    }
    if dbt_profile.is_some()
        || dbt_project_path.is_some()
        || load_macros
        || fail_on_missing_packages
    {
        needs.push(Capability::TemplateRendering);
    }
    ext.authorize(program, &needs);

    // A decision record is a policy's decision.
    if decision_out.is_some() && policy_path.is_none() {
        eprintln!("Error: --decision-out requires --policy");
        print_usage(program, ext, change);
        process::exit(1);
    }
    // Runtime mode prints one decision and nothing else: on standard
    // output unless --decision-out names a file.
    if runtime_mode && policy_path.is_none() {
        eprintln!("Error: --mode runtime requires --policy");
        process::exit(1);
    }
    if runtime_mode && decision_out.is_none() {
        decision_out = Some("-".to_string());
    }

    // CI strict mode: a missing policy is a hard error so the gate can't be
    // silently bypassed.
    super::ci_env::enforce_policy_required_in_ci(
        policy_path.is_some(),
        ext.offers(Capability::PolicyGate),
        &format!(
            "{} analyze <FILE|DIR> --policy policy.json --env <env> --decision-out <path>",
            program
        ),
    );

    // Load custom rules if provided (MUST be before batch check)
    let user_rules =
        custom_rules_path
            .as_ref()
            .map(|rules_path| match load_custom_rules(rules_path) {
                Ok(rules) => rules,
                Err(e) => {
                    eprintln!("Error loading custom rules from '{}': {}", rules_path, e);
                    process::exit(1);
                }
            });

    // Build the v1 corpus: built-ins (unless --no-builtin) layered
    // with customer rules; customer full-rule entries override built-in
    // entries with the same `id` (last-write-wins), and customer
    // partial-override entries inherit `triggers`/`emission`/`per_statement`
    // from the matching built-in and replace only the fields they set.
    // With neither, the corpus is empty and no rule runs.
    if !builtin_rules && user_rules.is_none() && !quiet_mode {
        eprintln!("Note: built-in rules are off and no --custom-rules is given: no rule runs.");
    }
    // The masking policy the custom rule file states, if any.
    let masking = std::sync::Arc::new(
        user_rules
            .as_ref()
            .map(|loaded| loaded.masking().clone())
            .unwrap_or_default(),
    );
    let custom_rules: Option<Vec<lexega_core::rules::Rule>> =
        match super::io::rule_corpus(custom_rules_path.as_deref().zip(user_rules), builtin_rules) {
            Ok(merged) => Some(merged),
            Err(e) => {
                eprintln!("Error merging custom rules with built-in corpus: {}", e);
                process::exit(1);
            }
        };

    // Resolve deployment-variable substitution once: .lexega.toml
    // [template.substitution] presets plus --var-syntax; --var-env names.
    let (substitution, env_allowlist) =
        match super::io::resolve_substitution(&var_syntax_names, &var_env_names) {
            Ok(resolved) => resolved,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        };

    // Where a table named without a database or schema is looked for:
    // --default-schema, else .lexega.toml [session] default_schema.
    let default_schema = match super::io::resolve_default_schema(default_schema_flag.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Resolve artifact identity once. Stamped on reports/decisions so
    // dashboards can group by repository, run, and change.
    let meta =
        super::ci_env::resolve_run_metadata(run_id, policy_repo, policy_change_id, policy_commit);
    let run_id = meta.run_id;
    let policy_repo = meta.repo;
    let policy_change_id = meta.change_id;
    let policy_commit = meta.commit;
    // Batch analyze (and runtime per-statement evaluation below) always
    // measures checked-out state, never a commit range.
    let snapshot_identity = super::ci_env::RunIdentity {
        scope: lexega_core::analyzer::RunScope::Snapshot {
            commit: policy_commit.clone(),
        },
        repo: policy_repo.clone(),
        run_id: run_id.clone(),
    };

    // Names each file of the run by the path it is reported by.
    let names = super::io::ReportedPaths::new();
    // The files named outright, which a batch must read, by the path the
    // batch reports each file under.
    let named_files: Vec<String> = if change {
        Vec::new()
    } else {
        paths
            .iter()
            .filter(|path| !scans(path))
            .map(|path| names.name(&super::io::absolute(Path::new(path))))
            .collect()
    };

    // The run's one reading of the dbt projects it finds on disk.
    let projects = lexega_core::template::ProjectsOnDisk::default();

    // Batch options, shared by the directory, embedded-file and
    // change-scoped paths below.
    let config = BatchProcessingConfig {
        output_format,
        report_artifact_format,
        decision_artifact_format,
        quiet_mode,
        runtime_mode,
        policy_path: policy_path.as_deref(),
        policy_env: policy_env.as_deref(),
        exceptions_path: exceptions_path.as_deref(),
        decision_out: decision_out.as_deref(),
        report_out: report_out.as_deref(),
        policy_team: policy_team.as_deref(),
        policy_job_type: policy_job_type.as_deref(),
        policy_change_id: policy_change_id.as_deref(),
        policy_repo: policy_repo.as_deref(),
        policy_commit: policy_commit.as_deref(),
        run_identity: snapshot_identity.clone(),
        catalog_path: catalog_path.as_deref(),
        catalog_provider: catalog_provider.as_deref(),
        default_schema: default_schema.as_ref(),
        custom_rules,
        masking,
        load_macros,
        dbt_project_path: dbt_project_path.as_deref(),
        dbt_profile: dbt_profile.as_deref(),
        fail_on_missing_packages,
        jinja_vars: &jinja_vars,
        jinja_var_files: &jinja_var_files,
        snowsql_configs: &snowsql_configs,
        env_allowlist: &env_allowlist,
        substitution: &substitution,
        min_severity,
        detail_mode,
        dialect: dialect_name.as_deref(),
        trace_mode,
        verbose_mode,
        render_diagnostics,
        strict: strict_mode,
        cross_script,
        capture_markdown: false,
        named_files: &named_files,
        projects: &projects,
    };

    // Change scope: the SQL files the commit range touches, read at its head.
    if let Scope::Change(commits) = &scope {
        let (base, head) = (&commits.base, &commits.head);
        if runtime_mode {
            refuse_runtime_batch();
        }
        refuse_diagnostics_in_batch(&one_file_flags);
        require_batch_policy_outputs(
            policy_path.as_deref(),
            decision_out.as_deref(),
            policy_env.as_deref(),
        );
        // A path that matches nothing at either commit is a mistake, as a
        // file `analyze` cannot find is.
        if let Err(e) = commits.check_paths(&paths) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
        if paths.is_empty() {
            paths.push(".".to_string());
        }
        let changed = match super::git::get_changed_files(base, head, &paths) {
            Ok(changed) => changed,
            Err(e) => {
                eprintln!("Error getting changed files: {}", e);
                process::exit(1);
            }
        };
        // `--scan-embedded` reads the Python and notebook files the range
        // changes, at its head.
        let embedded_paths: Vec<BatchFile> = if scan_embedded {
            changed.embedded.iter().map(BatchFile::in_change).collect()
        } else {
            Vec::new()
        };
        // A range that changes no SQL file under the paths is still handed
        // to the session, whose analysis across the batch may add one; the
        // batch says "No SQL files changed" where nothing is left.
        let (embedded_fragments, unread_embedded) =
            extract_sql_from_paths(&embedded_paths, Some(head.as_str()), quiet_mode);
        let changed = changed.sql;
        let config = BatchProcessingConfig {
            run_identity: super::ci_env::RunIdentity {
                scope: lexega_core::analyzer::RunScope::Change {
                    base: Some(base.clone()),
                    head: Some(head.clone()),
                    change_id: policy_change_id.clone(),
                },
                repo: policy_repo.clone(),
                run_id: run_id.clone(),
            },
            capture_markdown: pr_comment,
            ..config
        };
        let files = changed
            .files
            .into_iter()
            .map(BatchFile::in_change)
            .collect();
        let range = ChangeRange {
            base,
            head,
            renamed_from: &changed.renamed_from,
            paths: &paths,
        };
        let outcome = handle_risk_batch(
            files,
            embedded_fragments,
            changed.skipped,
            unread_embedded,
            &config,
            Some(ReviewScope {
                range,
                paths: &paths,
            }),
            ext,
        );
        if pr_comment {
            if let Some(markdown) = &outcome.markdown {
                post_review_comment(markdown, output_format == "markdown");
            }
        }
        finish(outcome);
        return;
    }

    // Batch mode: several paths, or a directory or glob. Every path named is
    // read, and the run is one batch over all of them.
    if paths.len() > 1 || paths.first().is_some_and(|path| scans(path)) {
        if runtime_mode {
            refuse_runtime_batch();
        }
        refuse_diagnostics_in_batch(&one_file_flags);
        require_batch_policy_outputs(
            policy_path.as_deref(),
            decision_out.as_deref(),
            policy_env.as_deref(),
        );
        let mut found = FoundFiles::default();
        let mut embedded = FoundFiles::default();
        // A file named that does not exist is unread like any other.
        let mut missing: Vec<(String, String)> = Vec::new();
        // Each path read, and whether SQL files are looked for under it.
        let mut read: Vec<(&str, bool)> = Vec::new();
        for path in &paths {
            if !scans(path) && !Path::new(path).is_file() {
                missing.push((names.name(Path::new(path)), "no such file".to_string()));
                continue;
            }
            // A directory named outright that cannot be read is an error,
            // as a named file is; one found under it is listed as skipped.
            if Path::new(path).is_dir() {
                if let Err(e) = fs::read_dir(path) {
                    eprintln!("Error reading directory '{}': {}", path, e);
                    process::exit(1);
                }
            }
            // A file named outright is read as what its extension says.
            let named_embedded = !scans(path) && super::io::has_embedded_extension(Path::new(path));
            read.push((path, !(scan_embedded && named_embedded)));
        }
        // Every path is walked before a file of any is sorted as a macro.
        let sql_paths: Vec<&str> = read
            .iter()
            .filter(|(_, sql)| *sql)
            .map(|(path, _)| *path)
            .collect();
        let mut sql_found = collect_sql_files(&sql_paths, recursive, &projects).into_iter();
        for (path, reads_sql) in read {
            let sql = if reads_sql {
                sql_found.next().unwrap_or_default()
            } else {
                FoundFiles::default()
            };
            let more = if scan_embedded {
                collect_embedded_files(path, recursive)
            } else {
                FoundFiles::default()
            };
            // Each path must match something of its own.
            if scans(path) && sql.is_empty() && more.is_empty() {
                if scan_embedded {
                    eprintln!("No SQL or Python/notebook files found in '{}'", path);
                } else {
                    eprintln!("No SQL files found in '{}'", path);
                }
                process::exit(1);
            }
            found.files.extend(sql.files);
            found.skipped.extend(sql.skipped);
            embedded.files.extend(more.files);
            embedded.skipped.extend(more.skipped);
        }
        // A file reached twice (named and under a directory) is read once.
        // The batch then names each file by the path it reports it under.
        found.files.sort();
        found.files.dedup();
        embedded.files.sort();
        embedded.files.dedup();
        let files = working_tree_files(&found.files, &names);
        let embedded_files = working_tree_files(&embedded.files, &names);
        {
            let (embedded_fragments, mut unread_embedded) =
                extract_sql_from_paths(&embedded_files, None, quiet_mode);
            unread_embedded.extend(missing);
            let mut skipped = found.skipped;
            skipped.extend(embedded.skipped);
            for unread in &mut skipped {
                unread.path = PathBuf::from(names.name(&unread.path));
            }
            finish(handle_risk_batch(
                files,
                embedded_fragments,
                skipped,
                unread_embedded,
                &config,
                None,
                ext,
            ));
            return;
        }
    }

    // The one file, where it is read from, and the path its report names
    // it by.
    let input_path: Option<PathBuf> = if change {
        None
    } else {
        paths.first().map(PathBuf::from)
    };
    let input_file: Option<String> = input_path.as_deref().map(|path| names.name(path));
    // A Python or notebook file named outright, read for the SQL it embeds.
    let embedded_input =
        input_file
            .as_deref()
            .zip(input_path.as_deref())
            .filter(|(_, read_from)| {
                scan_embedded && lexega_core::extract::extractor_for_file(read_from).is_some()
            });
    if let Some((path, file_path)) = embedded_input {
        // Each fragment is decided apart, as a batch's files are.
        if runtime_mode {
            refuse_runtime_batch();
        }
        refuse_diagnostics_in_batch(&one_file_flags);
        if policy_path.is_some() && decision_out.as_deref().is_some_and(is_artifact_file_path) {
            eprintln!(
                "Error: --decision-out must be a directory for a Python or notebook file: each SQL fragment it holds gets a decision record of its own"
            );
            process::exit(1);
        }
        require_batch_policy_outputs(
            policy_path.as_deref(),
            decision_out.as_deref(),
            policy_env.as_deref(),
        );
        let source = super::io::read_sql_file(file_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading file '{}': {}", path, e);
                process::exit(1);
            })
            .text;

        let patterns = lexega_core::extract::SqlCallPattern::spark_defaults();
        let fragments = match lexega_core::extract::extract_sql_from_file(
            Path::new(path),
            &source,
            &patterns,
        ) {
            Some(Ok(f)) if !f.is_empty() => f,
            Some(Err(e)) => {
                eprintln!("Error reading file '{}': {}", path, e);
                process::exit(1);
            }
            Some(Ok(_)) | None => {
                eprintln!("No embedded SQL found in '{}'", path);
                process::exit(0);
            }
        };

        eprintln!(
            "Extracted {} SQL fragment(s) from {}",
            fragments.len(),
            path
        );

        // Process as batch with extracted fragments
        finish(handle_risk_batch(
            Vec::new(),
            fragments,
            Vec::new(),
            Vec::new(),
            &config,
            None,
            ext,
        ));
        return;
    }

    // The explanations print the formats they have.
    for (flag, given, formats) in [
        (
            "--explain-findings",
            explain_findings,
            &["text", "json", "yaml"][..],
        ),
        ("--explain-facts", explain_facts, &["text", "json"][..]),
    ] {
        if given && !formats.contains(&output_format) {
            eprintln!(
                "Error: {} prints {}: --format {} is none of them",
                flag,
                formats.join(", "),
                output_format
            );
            process::exit(1);
        }
    }

    // Single file mode
    // Auto-detect stdin: if no file provided and stdin is piped (not a TTY), read from stdin
    let use_stdin = use_stdin || (input_file.is_none() && !io::stdin().is_terminal());

    let source = if use_stdin {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes).unwrap_or_else(|e| {
            eprintln!("Error reading from stdin: {}", e);
            process::exit(1);
        });
        lexega_core::extract::decode_source(&bytes).unwrap_or_else(|e| {
            eprintln!("Error reading from stdin: {}", e);
            process::exit(1);
        })
    } else if let (Some(file_path), Some(read_from)) = (&input_file, input_path.as_deref()) {
        super::io::read_sql_file(read_from).unwrap_or_else(|e| {
            eprintln!("Error reading file '{}': {}", file_path, e);
            process::exit(1);
        })
    } else {
        eprintln!("Error: No input provided. Provide a filename or pipe input.");
        print_usage(program, ext, change);
        process::exit(1);
    };
    // Text that is not the source's bytes as written (a mark removed, UTF-16
    // decoded).
    let rewritten = source.encoding != lexega_core::extract::SourceEncoding::Utf8;
    let input = source.text;

    // Policy gate requires env + decision-out when enabled
    let policy_enabled = policy_path.is_some();
    if policy_enabled {
        if policy_env.is_none() {
            eprintln!("Error: --env is required when using --policy");
            process::exit(1);
        }
        if decision_out.is_none() {
            eprintln!("Error: --decision-out is required when using --policy");
            process::exit(1);
        }
    }

    // Strip BOM
    let input = strip_bom(&input);

    // Open the session that renders and analyzes this run's sources.
    let mut session = ext
        .open_session(SessionOptions {
            jinja_vars: &jinja_vars,
            jinja_var_files: &jinja_var_files,
            snowsql_configs: &snowsql_configs,
            env_allowlist: &env_allowlist,
            substitution: &substitution,
            dbt_profile: dbt_profile.as_deref(),
            dbt_project_path: dbt_project_path.as_deref(),
            load_macros,
            fail_on_missing_packages,
            custom_rules: config.custom_rules.clone(),
            masking: config.masking.clone(),
            trace_mode,
            verbose_mode,
            catalog_path: catalog_path.as_deref(),
            catalog_provider: catalog_provider.as_deref(),
            default_schema: default_schema.as_ref(),
            dialect_name: dialect_name.as_deref(),
            output_format,
            quiet: quiet_mode,
            projects: &projects,
            change: false,
        })
        .unwrap_or_else(|e| {
            eprintln!("{}", e);
            process::exit(1);
        });

    // Set dialect if specified
    if let Some(ref name) = dialect_name {
        match resolve_dialect(name) {
            Some(d) => session.set_dialect(Some(d)),
            None => {
                eprintln!(
                    "Error: Unknown dialect '{}'. Valid options: {}",
                    name,
                    super::io::DIALECT_OPTIONS
                );
                process::exit(1);
            }
        }
    }

    // Render the source if it is a template
    let source_path = if use_stdin {
        None
    } else {
        input_path.as_deref()
    };
    // A file is planned as a batch of one, so the session analyzes it with
    // what it knows across files (the model graph of the dbt project it is
    // in); text read from no file is rendered and analyzed on its own.
    let planned = match (source_path, input_file.as_deref()) {
        (Some(path), Some(name)) => {
            let file = BatchFile {
                path: path.to_path_buf(),
                name: name.to_string(),
            };
            let plan = BatchPlan {
                cross_script: false,
                quiet: quiet_mode,
                change: None,
            };
            let planned = session.plan_batch(std::slice::from_ref(&file), &plan);
            Some(planned.map(|_| session.analyze_planned(0, &file, input, rewritten)))
        }
        (Some(_), None) | (None, Some(_)) | (None, None) => None,
    };
    let analyzed = match planned {
        Some(Ok(Ok((render, report)))) => Ok((render, Ok(report))),
        Some(Ok(Err(FileFailure::Render(e)))) => Err(e),
        Some(Ok(Err(FileFailure::Analysis(e)))) => {
            eprintln!("Error analyzing SQL: {}", e);
            process::exit(1);
        }
        Some(Err(e)) => {
            eprintln!("{}", e);
            process::exit(1);
        }
        None => session.render_file(source_path, input).map(|render| {
            let report = session.analyze(&render, input_file.as_deref());
            (render, report)
        }),
    };
    let (render, report) = match analyzed {
        Ok(done) => done,
        Err(e) => {
            if fail_on_missing_packages {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
            // Graceful degradation: fall back to template analysis
            eprintln!("⚠️  {}", e);
            eprintln!("⚠️  Falling back to template analysis (results may be limited)");
            eprintln!(
                "Hint: Template uses runtime-only functions (run_query, adapter.*, exceptions.*)"
            );
            eprintln!("      Risk analysis will work on template structure, not rendered SQL");
            let render = RenderArtifacts::not_rendered(input.to_string(), e);
            let report = session.analyze(&render, input_file.as_deref());
            (render, report)
        }
    };

    // Run risk analysis
    let mut report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error analyzing SQL: {}", e);
            process::exit(1);
        }
    };

    // Stamp what this run measured before any artifact or decision is
    // derived from the report (decisions inherit the report's identity).
    let identity = if runtime_mode {
        super::ci_env::RunIdentity {
            scope: lexega_core::analyzer::RunScope::Runtime,
            ..snapshot_identity
        }
    } else {
        snapshot_identity
    };
    identity.apply(&mut report);

    // Strict-mode enforcement. Permissive is the default and this is a
    // no-op in that case. A violation, or a source whose template did not
    // render (a file not analyzed, as a batch fails one), fails the run: its
    // report stands and is decided, and the run exits 1 once it is out.
    let strict_fails = {
        let label = input_file.as_deref().unwrap_or("<stdin>");
        let unrendered_fails = render
            .render_error
            .as_deref()
            .is_some_and(|reason| strict_not_analyzed(strict_mode, label, reason));
        report_strict_violations(strict_mode, &report, label) || unrendered_fails
    };
    let strict_exit = if strict_fails { 1 } else { 0 };

    // Set source file path for the report (use absolute path for easy navigation)
    if let (Some(file_path), Some(read_from)) = (&input_file, input_path.as_deref()) {
        report.source_file_path = dunce::canonicalize(read_from)
            .map(|p| p.display().to_string())
            .ok()
            .or_else(|| Some(file_path.clone()));
    }

    // The policy decides on every finding and context entry; --min-severity
    // filters what the run shows and counts.
    let evaluated = (policy_path.is_some() && min_severity.is_some()).then(|| report.clone());
    if let Some(threshold) = min_severity {
        report.retain_at_least(threshold);
    }

    // A SARIF --report-out holds what the run shows, as without a policy,
    // and this driver writes it; the gate writes the risk report a decision
    // names, a JSON or YAML --report-out or a file beside the decision.
    let sarif_report_out =
        report_out.is_some() && report_artifact_format == ReportArtifactFormat::Sarif;

    // The policy decides before the run prints, so an explained run is
    // decided too.
    let mut policy_blocked = false;
    if let Some(policy_file) = policy_path.as_deref() {
        let gate = ext
            .policy_gate(&PolicySetup {
                policy_path: policy_file,
                exceptions_path: exceptions_path.as_deref(),
                rules: config.custom_rules.as_deref().unwrap_or_default(),
                env: policy_env.as_deref(),
                team: policy_team.as_deref(),
                job_type: policy_job_type.as_deref(),
                change_id: policy_change_id.as_deref(),
                repo: policy_repo.as_deref(),
                commit: policy_commit.as_deref(),
                decision_out: decision_out.as_deref(),
                decision_artifact_format,
                report_out: report_out.as_deref(),
                report_artifact_format,
                output_format,
                quiet: quiet_mode,
                runtime_mode,
                batch: false,
            })
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                process::exit(1);
            });
        let scope_path = if use_stdin {
            None
        } else {
            input_file.as_deref()
        };
        policy_blocked = !gate
            .decide(&SourceCase {
                sql: &render.sql,
                report: evaluated.as_ref().unwrap_or(&report),
                scope_path,
            })
            .allowed;
    }

    // How this run's depth is reported, when it ran at reduced depth.
    let depth_note = report
        .summary
        .analysis_depth
        .as_ref()
        .map(|depth| ext.depth_note(depth));
    // What the run left undone that its findings do not show.
    let mut run_notes = run_notes(
        ext,
        session.as_ref(),
        usize::from(
            report.summary.render_completeness == analyzer::RenderCompleteness::NotRendered,
        ),
        0,
        false,
    );
    let unread_sqlcmd = unread_sqlcmd_lines(None, &report);
    run_notes.extend(unread_sqlcmd_note(&unread_sqlcmd));

    // A blocked run exits 2, a strict failure 1.
    let exit_code = if policy_blocked { 2 } else { strict_exit };

    // Write --report-out here unless the policy gate wrote it as the report
    // its decision names; an explained run writes it too.
    if (!policy_enabled || sarif_report_out) && report_out.is_some() {
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let name =
            if output_format == "sarif" && report_artifact_format == ReportArtifactFormat::Sarif {
                "analysis_report"
            } else {
                "risk_report"
            };
        if let Some(path) = write_optional_report_artifact(
            report_artifact_format,
            &report,
            &report,
            report_out.as_deref(),
            name,
            &ToolRun {
                run_notes: &run_notes,
                ..tool_run(ext, git_root.as_deref(), depth_note.as_deref())
            },
        ) {
            eprintln!("Risk report written to: {}", path);
        }
    }

    // Handle --explain-facts mode: show structured facts extracted from policies
    if explain_facts {
        print_fact_explanation(&report, &render.sql, output_format);
        process::exit(exit_code);
    }

    // Handle --explain-findings mode: show only extracted findings by statement
    if explain_findings {
        print_finding_explanation(&report, &render.sql, output_format);
        process::exit(exit_code);
    }

    // Output report (stdout) - suppress in runtime mode
    if !runtime_mode && (output_format == "json" || output_format == "both") {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing report to JSON: {}", e);
                process::exit(1);
            }
        }
    }

    if !runtime_mode && output_format == "yaml" {
        match serde_yaml_ng::to_string(&report) {
            Ok(yaml) => print!("{}", yaml),
            Err(e) => {
                eprintln!("Error serializing report to YAML: {}", e);
                process::exit(1);
            }
        }
    }

    // A SARIF report is on standard output unless `--report-out` delivers it.
    if !runtime_mode && output_format == "sarif" && !sarif_report_out {
        // Use git repo root for SARIF base path since file paths may be relative to repo root
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let run = ToolRun {
            run_notes: &run_notes,
            ..tool_run(ext, git_root.as_deref(), depth_note.as_deref())
        };
        match serde_json::to_string_pretty(&analyzer::to_sarif(&report, &run)) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing SARIF report: {}", e);
                process::exit(1);
            }
        }
    }

    // GitLab SAST report always goes to stdout — redirect to
    // gl-sast-report.json in CI and declare it as an artifacts.reports.sast
    // path. (--report-out continues to write its own artifact formats.)
    if !runtime_mode && output_format == "gl-sast" {
        let gl_report = analyzer::to_gl_sast(
            &report,
            &ToolRun {
                run_notes: &run_notes,
                ..tool_run(ext, None, depth_note.as_deref())
            },
        );
        match serde_json::to_string_pretty(&gl_report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing GitLab SAST report: {}", e);
                process::exit(1);
            }
        }
    }

    if !runtime_mode && output_format == "markdown" {
        let display_path = if use_stdin {
            "stdin".to_string()
        } else {
            input_file.clone().unwrap_or_else(|| "input".to_string())
        };
        print_analyze_markdown(
            &report,
            &display_path,
            &render.placeholders,
            depth_note.as_deref(),
            &run_notes,
        );
    }

    if !runtime_mode && (output_format == "text" || output_format == "both") {
        if output_format == "both" {
            println!("\n---\n");
        }

        let palette = super::color::Palette::resolve(color_choice);

        // Print text summary
        // A run at reduced depth is not titled for the analysis it lacks.
        println!(
            "{}",
            palette.bold(if depth_note.is_some() {
                "Analysis Report"
            } else {
                "Semantic Analysis Report"
            })
        );
        println!("========================");

        // Confidence first - this is the most important indicator for trust
        let confidence_display = match (
            &report.summary.render_completeness,
            &report.summary.analysis_confidence,
        ) {
            (analyzer::RenderCompleteness::NotRendered, _) => {
                "LOW (template could not be rendered; analysis ran on template text)".to_string()
            }
            (analyzer::RenderCompleteness::Full, analyzer::ConfidenceLevel::High) => {
                "HIGH (full render, no placeholders)".to_string()
            }
            (analyzer::RenderCompleteness::Partial, analyzer::ConfidenceLevel::High) => {
                // Partial but high confidence means low-impact only
                if let Some(ref ph) = report.summary.placeholders {
                    if ph.high_impact == 0 {
                        format!(
                            "HIGH (partial render, {} low-impact placeholders only)",
                            ph.low_impact
                        )
                    } else {
                        format!("MEDIUM ({} high-impact placeholders)", ph.high_impact)
                    }
                } else {
                    "HIGH (partial render, low-impact only)".to_string()
                }
            }
            (analyzer::RenderCompleteness::Partial, analyzer::ConfidenceLevel::Medium) => {
                if let Some(ref ph) = report.summary.placeholders {
                    format!(
                        "MEDIUM ({} high-impact, {} low-impact placeholders)",
                        ph.high_impact, ph.low_impact
                    )
                } else {
                    "MEDIUM (some placeholders in analysis zones)".to_string()
                }
            }
            (analyzer::RenderCompleteness::Partial, analyzer::ConfidenceLevel::Low) => {
                if let Some(ref ph) = report.summary.placeholders {
                    format!(
                        "LOW ({} high-impact placeholders in critical zones)",
                        ph.high_impact
                    )
                } else {
                    "LOW (placeholders in critical zones)".to_string()
                }
            }
            (_, conf) => format!("{:?}", conf).to_uppercase(),
        };
        println!("Confidence: {}", confidence_display);
        if let Some(note) = &depth_note {
            println!("Note: {}", note);
        }
        for note in &run_notes {
            println!("Note: {}", note);
        }
        println!();

        // Severity-color non-zero counts; dim the zeros so the real
        // findings stand out at a glance.
        let count_line = |level: analyzer::RiskLevel, label: &str, n: usize| -> String {
            let text = format!("  {}: {}", label, n);
            if n > 0 {
                palette.severity(level, &text)
            } else {
                palette.dim(&text)
            }
        };
        println!("{}", palette.bold("Summary:"));
        println!(
            "  Total findings: {}",
            report.summary.total_reported_findings
        );
        println!(
            "{}",
            count_line(
                analyzer::RiskLevel::Critical,
                "Critical",
                report.summary.critical_count
            )
        );
        println!(
            "{}",
            count_line(analyzer::RiskLevel::High, "High", report.summary.high_count)
        );
        println!(
            "{}",
            count_line(
                analyzer::RiskLevel::Medium,
                "Medium",
                report.summary.medium_count
            )
        );
        println!(
            "{}",
            count_line(analyzer::RiskLevel::Low, "Low", report.summary.low_count)
        );
        println!(
            "{}",
            count_line(
                analyzer::RiskLevel::Info,
                "Context",
                report.summary.info_count
            )
        );
        println!();
        println!("{}", palette.bold("Coverage:"));
        println!(
            "  Analyzed: {} SQL statements",
            report.summary.statements_analyzed
        );
        if report.summary.statements_partial > 0 {
            println!(
                "  Partial: {} (kind recognized, payload incompletely parsed)",
                report.summary.statements_partial
            );
        }
        if report.summary.jinja_blocks > 0 {
            println!(
                "  Template blocks, not SQL statements: {}",
                report.summary.jinja_blocks
            );
        }
        if render_diagnostics != RenderDiagnosticsLevel::None && render.placeholders.total > 0 {
            println!(
                "  Placeholders: {} (high-impact {}, low-impact {})",
                render.placeholders.total,
                render.placeholders.high_impact,
                render.placeholders.low_impact
            );

            if render_diagnostics >= RenderDiagnosticsLevel::All {
                let sources = render.placeholders.top_sources();
                if !sources.is_empty() {
                    println!("  Top placeholder sources:");
                    for (source, count) in sources {
                        println!("    - {} ({})", source, count);
                    }
                }

                let mut kinds: Vec<_> = render.placeholders.by_kind.iter().collect();
                kinds.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !kinds.is_empty() {
                    println!("  Top placeholder kinds:");
                    for (kind, count) in kinds.into_iter().take(5) {
                        println!("    - {} ({})", kind, count);
                    }
                }
            }
        }
        // Only show unrecognized if there are any — statements the parser
        // could not recognize (opaque / error / stray clause), so they were
        // not analyzed. This is coverage loss, not a clean parse. The sqlcmd
        // commands that run what was not read are skipped too, and say so.
        let unrecognized = report
            .summary
            .statements_skipped
            .saturating_sub(unread_sqlcmd.len());
        if unrecognized > 0 {
            println!(
                "  Unrecognized: {} (could not parse, no analysis)",
                unrecognized
            );
        }
        if !unread_sqlcmd.is_empty() {
            println!(
                "  Not read: {} (sqlcmd commands that run SQL or commands the analysis did not read)",
                unread_sqlcmd.len()
            );
        }
        println!();
        println!("{}", palette.bold("Data Operations:"));
        println!("  Tables Read: {}", report.summary.tables_read);
        if report.summary.tables_written > 0 {
            println!("  Tables Written (DML): {}", report.summary.tables_written);
        }
        if report.summary.ddl_operations > 0 {
            println!("  DDL Operations: {}", report.summary.ddl_operations);
        }
        if report.summary.cross_database {
            let dbs: Vec<String> = report.summary.databases_accessed.iter().cloned().collect();
            println!("  Cross-Database: Yes ({})", dbs.join(", "));
        } else {
            println!("  Cross-Database: No");
        }
        if report.summary.cross_schema {
            println!("  Cross-Schema (within DB): Yes");
        }
        println!();

        // Findings, then (with --min-severity info) context entries.
        let print_entries = |heading: &str, entries: &[analyzer::RuleMatch]| {
            if entries.is_empty() {
                return;
            }
            println!("{}", palette.bold(heading));
            let mut lines = String::new();
            write_text_entries(&mut lines, entries, 3, &palette);
            print!("{}", lines);
            println!();
        };
        print_entries("findings:", &report.findings);
        print_entries("Context:", &report.context);

        // --verbose: append the v1 rule-evaluation explanation surface
        // (`statement_explanations`). Only emitted in text/both
        // output — JSON/YAML callers get the same data automatically
        // via the report's `Serialize` derive.
        if verbose_mode {
            println!();
            super::output::print_rule_explanation(&report);
        }
    }

    if exit_code != 0 {
        process::exit(exit_code);
    }
}

/// Extract SQL fragments from a list of Python/notebook files, each read
/// from the working tree or as of `commit`. The files that could not be
/// read come back beside them, each with its reason; a file `commit` does
/// not hold has no fragments.
fn extract_sql_from_paths(
    paths: &[BatchFile],
    commit: Option<&str>,
    quiet_mode: bool,
) -> (
    Vec<lexega_core::extract::ExtractedSql>,
    Vec<(String, String)>,
) {
    let patterns = lexega_core::extract::SqlCallPattern::spark_defaults();
    let mut fragments = Vec::new();
    let mut unread = Vec::new();

    for file in paths {
        let source = match read_source(&file.path, commit) {
            Ok(content) => content.text,
            Err(ReadFailure::Removed(_)) => continue,
            Err(ReadFailure::Unreadable(reason)) => {
                unread.push((file.name.clone(), reason));
                continue;
            }
        };

        // Each fragment is named after the file's reported path.
        match lexega_core::extract::extract_sql_from_file(Path::new(&file.name), &source, &patterns)
        {
            Some(Ok(extracted)) => {
                if !extracted.is_empty() && !quiet_mode {
                    eprintln!(
                        "  📋 {} - extracted {} SQL fragment(s)",
                        file.name,
                        extracted.len()
                    );
                }
                fragments.extend(extracted);
            }
            Some(Err(e)) => unread.push((file.name.clone(), e.to_string())),
            None => {}
        }
    }

    (fragments, unread)
}

/// Emit strict-mode violations for a single analysis report on stderr.
///
/// Returns `true` if any violations were recorded. Callers decide what to
/// do with that result — the single-file path exits immediately, the
/// batch path accumulates and exits once at the end.
fn report_strict_violations(
    strict: lexega_core::StrictMode,
    report: &lexega_core::analyzer::AnalysisReport,
    label: &str,
) -> bool {
    if matches!(strict, lexega_core::StrictMode::Permissive) {
        return false;
    }
    let opts = lexega_core::AnalysisOptions {
        strict,
        default_span: None,
    };
    let violations = lexega_core::enforce_strict_mode(report, &opts);
    for v in &violations {
        match v.line {
            Some(line) => {
                eprintln!("{}: [{}] line {}: {}", label, v.code, line, v.message);
            }
            None => eprintln!("{}: [{}] {}", label, v.code, v.message),
        }
    }
    !violations.is_empty()
}

/// Runtime mode gives one decision for one source; a run of several gives
/// one per file. Exit, saying so, when runtime mode is asked of one.
fn refuse_runtime_batch() -> ! {
    eprintln!(
        "Error: --mode runtime decides one source: name one SQL file or pipe the SQL on stdin"
    );
    process::exit(1);
}

/// The flags that explain the analysis of one source, each with whether it
/// was given. Exit, saying so, when one is asked of a batch.
fn refuse_diagnostics_in_batch(flags: &[(&str, bool)]) {
    if let Some((flag, _)) = flags.iter().find(|(_, given)| *given) {
        eprintln!(
            "Error: {} applies to one file: name a single SQL file or pipe the SQL on stdin",
            flag
        );
        process::exit(1);
    }
}

/// A batch decides each file on its own, so a policy needs a directory for
/// the decision records and an environment to decide in. Exit otherwise.
fn require_batch_policy_outputs(
    policy_path: Option<&str>,
    decision_out: Option<&str>,
    policy_env: Option<&str>,
) {
    if policy_path.is_none() {
        return;
    }
    let out = decision_out.unwrap_or("");
    if out.is_empty() {
        eprintln!("Error: --decision-out is required when using --policy");
        process::exit(1);
    }
    if is_artifact_file_path(out) {
        eprintln!("Error: In batch mode, --decision-out must be a directory (not a file path)");
        process::exit(1);
    }
    if policy_env.is_none() {
        eprintln!("Error: --env is required when using --policy");
        process::exit(1);
    }
}

/// What a batch run produced beyond its output.
pub(crate) struct BatchOutcome {
    /// The Markdown summary, when a surface asked for it.
    pub markdown: Option<String>,
    pub exit_code: i32,
}

/// Exit with the batch's status when it failed.
fn finish(outcome: BatchOutcome) {
    if outcome.exit_code != 0 {
        process::exit(outcome.exit_code);
    }
}

/// Why one file of a batch could not be read.
enum ReadFailure {
    /// The commit read does not hold the file: the change removes it.
    Removed(String),
    /// The file is there and could not be read.
    Unreadable(String),
}

/// One file's text, read as its byte-order mark says: from the working
/// tree, or as of `commit`.
fn read_source(
    path: &Path,
    commit: Option<&str>,
) -> Result<lexega_core::extract::SourceText, ReadFailure> {
    match commit {
        Some(commit) => super::git::read_source_at_commit(commit, &path.display().to_string())
            .map_err(|e| match e {
                FileAtCommitError::Absent(reason) => ReadFailure::Removed(reason),
                FileAtCommitError::Unreadable(reason) => ReadFailure::Unreadable(reason),
            }),
        None => super::io::read_sql_file(&super::io::absolute(path))
            .map_err(|e| ReadFailure::Unreadable(format!("Error reading: {}", e))),
    }
}

/// The less complete of two renders, in the order `RenderCompleteness`
/// declares them: full, partial with low-impact placeholders only, partial,
/// not rendered.
fn less_complete(
    a: analyzer::RenderCompleteness,
    b: &analyzer::RenderCompleteness,
) -> analyzer::RenderCompleteness {
    fn rank(completeness: &analyzer::RenderCompleteness) -> u8 {
        match completeness {
            analyzer::RenderCompleteness::Full => 0,
            analyzer::RenderCompleteness::PartialLowImpactOnly => 1,
            analyzer::RenderCompleteness::Partial => 2,
            analyzer::RenderCompleteness::NotRendered => 3,
        }
    }
    if rank(b) > rank(&a) {
        b.clone()
    } else {
        a
    }
}

/// List `label` as a file of the batch that was not analyzed, for `reason`.
fn skip(skipped: &mut Vec<(String, String)>, label: String, reason: String, quiet: bool) {
    if !quiet {
        eprintln!("  ✗ {} - {}", label, reason);
    }
    skipped.push((label, reason));
}

/// The files of `skipped` (path, reason) by reason, each reason once in the
/// order first met: a dbt project's macro paths leave every file in them
/// unread for one reason, which a report says once.
fn skips_by_reason(skipped: &[(String, String)]) -> Vec<(&str, Vec<&str>)> {
    let mut grouped: Vec<(&str, Vec<&str>)> = Vec::new();
    for (path, reason) in skipped {
        match grouped
            .iter_mut()
            .find(|(seen, _)| *seen == reason.as_str())
        {
            Some((_, paths)) => paths.push(path),
            None => grouped.push((reason, vec![path])),
        }
    }
    grouped
}

/// Under a strict mode, say on stderr that `label` was not analyzed, for
/// `reason`. True when that fails the run.
fn strict_not_analyzed(strict: lexega_core::StrictMode, label: &str, reason: &str) -> bool {
    let fails = !matches!(strict, lexega_core::StrictMode::Permissive);
    if fails {
        eprintln!(
            "{}: [E_STRICT_NOT_ANALYZED] not analyzed: {}",
            label, reason
        );
    }
    fails
}

/// List `label` as a file of the batch that could not be analyzed, for
/// `reason`, among the `skipped` files and the `not_analyzed` ones. Under a
/// strict mode that fails the run: it is said on stderr, and the return is
/// true.
fn fail_unanalyzed(
    skipped: &mut Vec<(String, String)>,
    not_analyzed: &mut Vec<(String, String)>,
    strict: lexega_core::StrictMode,
    label: String,
    reason: String,
    quiet: bool,
) -> bool {
    let fails = strict_not_analyzed(strict, &label, &reason);
    not_analyzed.push((label.clone(), reason.clone()));
    skip(skipped, label, reason, quiet);
    fails
}

/// The name a batch gives an embedded fragment: its file, and the line and
/// column (1-based) where its SQL begins, so two fragments on one line are
/// two entries and two decision records.
fn fragment_name(fragment: &lexega_core::extract::ExtractedSql) -> String {
    format!(
        "{}:{}:{}",
        fragment.origin_file.display(),
        fragment.origin.line,
        fragment.origin.column
    )
}

/// Place each evidence of `report`, analyzed from `fragment`'s SQL, at its
/// place in the file the fragment came from
/// ([`lexega_core::extract::ExtractedSql::place`]).
fn place_in_origin(
    report: &mut lexega_core::analyzer::AnalysisReport,
    fragment: &lexega_core::extract::ExtractedSql,
) {
    let lines = analyzer::LineIndex::new(&fragment.sql);
    for entry in report.findings.iter_mut().chain(report.context.iter_mut()) {
        let lexega_core::analyzer::RuleMatch::Analysis(finding) = entry;
        for evidence in &mut finding.evidence {
            let lexega_core::analyzer::RiskEvidence::RuleMatch {
                location,
                position: Some(position),
                ..
            } = evidence
            else {
                continue;
            };
            let Some(offset) = lines.offset_at(&fragment.sql, position.line, position.column)
            else {
                continue;
            };
            *position = fragment.place(offset);
            *location = Some(format!(
                "{}:{}:{}",
                fragment.origin_file.display(),
                position.line,
                position.column
            ));
        }
    }
}

/// Whether the file reported as `name` was named on the command line.
fn is_named(config: &BatchProcessingConfig, name: &str) -> bool {
    config.named_files.iter().any(|file| file == name)
}

/// Say on stderr that the file reported as `name`, named on the command
/// line, could not be read for `reason`: that fails the run.
fn report_named_unread(name: &str, reason: &str) {
    eprintln!(
        "Error: '{}' was named on the command line and could not be read: {}",
        name, reason
    );
}

/// The files of a batch found in the working tree, each named by the path
/// it is reported by.
fn working_tree_files(files: &[PathBuf], names: &super::io::ReportedPaths) -> Vec<BatchFile> {
    files
        .iter()
        .map(|path| BatchFile {
            name: names.name(path),
            path: path.clone(),
        })
        .collect()
}

/// Whether a file a scan found and left unread for `reason` is SQL the run
/// leaves unanalyzed, which fails the strict gate. Macro definitions are not
/// statements; a symbolic link the scan does not follow names a file it
/// would otherwise analyze, and a directory it could not read may hold one.
fn unread_is_unanalyzed_sql(reason: &SkipReason) -> bool {
    match reason {
        SkipReason::MacroDirectory(_) => false,
        SkipReason::SymbolicLink | SkipReason::UnreadableDirectory => true,
    }
}

/// Whether a file discovery left unread for `reason` holds dbt macros.
pub fn unread_is_macro_file(reason: &SkipReason) -> bool {
    match reason {
        SkipReason::MacroDirectory(_) => true,
        SkipReason::SymbolicLink | SkipReason::UnreadableDirectory => false,
    }
}

/// What a report says of a macro file skipped for `reason`: in a change,
/// with the `models` the change renders differently, which were reviewed
/// in its place.
pub fn macro_file_note(reason: &str, models: &[String]) -> String {
    match models {
        [] => reason.to_string(),
        [model] => format!(
            "{}; the change is reviewed through the model it renders differently: {}",
            reason, model
        ),
        models => format!(
            "{}; the change is reviewed through the {} models it renders differently: {}",
            reason,
            models.len(),
            models.join(", ")
        ),
    }
}

/// The note of a run that analyzed no SQL file because each of its
/// `macro_files` SQL files holds macros; `change` for a review.
pub fn analyzed_nothing_note(macro_files: usize, change: bool) -> String {
    let files = match macro_files {
        1 => "1 file".to_string(),
        n => format!("{} files", n),
    };
    let hold = if macro_files == 1 { "holds" } else { "hold" };
    if change {
        format!(
            "No SQL file was analyzed: {} of the change {} dbt macro definitions, not statements, and no model the change renders differently was reviewed. --strict fails on a run that analyzes nothing.",
            files, hold
        )
    } else {
        format!(
            "No SQL file was analyzed: {} found {} dbt macro definitions, not statements. --strict fails on a run that analyzes nothing.",
            files, hold
        )
    }
}

/// How many template files a batch did not render: `unrendered` analyzed as
/// written and `render_failed` not analyzed. None where it rendered every
/// one.
fn not_rendered_line(unrendered: usize, render_failed: usize) -> Option<String> {
    match (unrendered, render_failed) {
        (0, 0) => None,
        (count, 0) => Some(count.to_string()),
        (unrendered, failed) => Some(format!("{} ({} not analyzed)", unrendered + failed, failed)),
    }
}

/// A file of the batch the session could not render: with
/// `--fail-on-missing-packages` the run stops with exit code 1, and the file
/// is listed as not analyzed otherwise, which leaves the batch's
/// `completeness` not rendered. True when that fails the strict gate.
fn render_failed(
    config: &BatchProcessingConfig,
    skipped: &mut Vec<(String, String)>,
    not_analyzed: &mut Vec<(String, String)>,
    completeness: &mut analyzer::RenderCompleteness,
    name: &str,
    reason: String,
) -> bool {
    if config.fail_on_missing_packages {
        eprintln!("Error: {} (file: {})", reason, name);
        process::exit(1);
    }
    *completeness = analyzer::RenderCompleteness::NotRendered;
    fail_unanalyzed(
        skipped,
        not_analyzed,
        config.strict,
        name.to_string(),
        reason,
        config.quiet_mode,
    )
}

/// Post the review as a pull-request comment. Without a detectable pull
/// request the Markdown goes to standard error instead, unless it was
/// already printed: standard output holds the report in the format asked
/// for, and nothing else.
fn post_review_comment(markdown: &str, already_printed: bool) {
    use super::pr_comment::{post_pr_comment, PRContext};
    match PRContext::from_env() {
        Ok(pr) => {
            eprintln!(
                "Detected CI: {:?} (repo: {}, PR: {})",
                pr.platform, pr.repo, pr.pr_number
            );
            if let Err(e) = post_pr_comment(&pr, markdown) {
                eprintln!("⚠️  Failed to post PR comment: {}", e);
            }
        }
        Err(e) => {
            eprintln!("⚠️  Cannot post PR comment: {}", e);
            if !already_printed {
                eprintln!("   The comment follows.");
                eprint!("{}", markdown);
            }
        }
    }
}

/// One file of a batch as the driver hands it to the session.
enum BatchSource {
    /// The file's text, to render and analyze.
    Text(lexega_core::extract::SourceText),
    /// A file the change removes: the session's report on it, and the text
    /// at the range's base that report was made from (empty when the base
    /// holds the file and it cannot be read).
    Removed(Box<(RenderArtifacts, analyzer::AnalysisReport)>),
}

/// The session's report on `path`, which `range` removes, with the text it
/// is read from at the range's base. `None` when the base does not hold the
/// file either.
fn removed(
    session: &mut dyn Session,
    path: &Path,
    range: ChangeRange<'_>,
) -> Result<Option<(RenderArtifacts, analyzer::AnalysisReport)>, String> {
    let base = match super::git::read_file_at_commit(range.base, &path.display().to_string()) {
        Ok(base) => Some(base),
        Err(FileAtCommitError::Unreadable(_)) => None,
        Err(FileAtCommitError::Absent(_)) => return Ok(None),
    };
    let base = base.as_deref().map(strip_bom);
    Ok(session.analyze_removed(path, base)?.map(|report| {
        (
            RenderArtifacts::raw(base.unwrap_or_default().to_string()),
            report,
        )
    }))
}

/// Which files of the planned batch `planned` are analyzed, by planned
/// index: each of `files`, and, in a review, a file the session added
/// where the review's head holds it under its paths. Outside a review,
/// every planned file.
fn planned_under_paths(
    planned: &[BatchFile],
    files: &[BatchFile],
    review: Option<ReviewScope<'_>>,
) -> Vec<bool> {
    let given: std::collections::BTreeSet<&BatchFile> = files.iter().collect();
    let Some(scope) = review else {
        return vec![true; planned.len()];
    };
    if planned.iter().all(|file| given.contains(file)) {
        return vec![true; planned.len()];
    }
    let under = super::git::sql_files_at_commit_under(scope.range.head, scope.paths)
        .unwrap_or_else(|e| {
            eprintln!("Error listing files at {}: {}", scope.range.head, e);
            process::exit(1);
        });
    planned
        .iter()
        .map(|file| given.contains(file) || under.contains(&file.name))
        .collect()
}

/// The range a `review` batch covers, and the path arguments it reviews.
#[derive(Clone, Copy)]
pub(crate) struct ReviewScope<'a> {
    pub(crate) range: ChangeRange<'a>,
    pub(crate) paths: &'a [String],
}

/// Analyze `files` and `embedded_fragments` as one batch. `found_unread` are
/// the files discovery matched and left unread, each by the path it is
/// reported by; they are reported with the
/// files the batch itself fails to read or analyze. `unreadable` are the
/// files whose fragments could not be read, each with its reason; they fail
/// the strict gate as a file the batch fails to read does. `review` is the
/// range a `review` batch covers; each file is then read at its head, and
/// a file the session adds is analyzed where the head holds it under the
/// review's paths. A review left with nothing to analyze says so and
/// reports nothing.
pub(crate) fn handle_risk_batch(
    files: Vec<BatchFile>,
    embedded_fragments: Vec<lexega_core::extract::ExtractedSql>,
    found_unread: Vec<SkippedFile>,
    unreadable: Vec<(String, String)>,
    config: &BatchProcessingConfig,
    review: Option<ReviewScope<'_>>,
    ext: &dyn Extension,
) -> BatchOutcome {
    let change = review.map(|scope| scope.range);

    // Open the session (same as single-file mode)
    let mut session = ext
        .open_session(SessionOptions {
            jinja_vars: config.jinja_vars,
            jinja_var_files: config.jinja_var_files,
            snowsql_configs: config.snowsql_configs,
            env_allowlist: config.env_allowlist,
            substitution: config.substitution,
            dbt_profile: config.dbt_profile,
            dbt_project_path: config.dbt_project_path,
            load_macros: config.load_macros,
            fail_on_missing_packages: config.fail_on_missing_packages,
            custom_rules: config.custom_rules.clone(),
            masking: config.masking.clone(),
            trace_mode: config.trace_mode,
            verbose_mode: config.verbose_mode,
            catalog_path: config.catalog_path,
            catalog_provider: config.catalog_provider,
            default_schema: config.default_schema,
            dialect_name: config.dialect,
            output_format: config.output_format,
            quiet: config.quiet_mode,
            projects: config.projects,
            change: change.is_some(),
        })
        .unwrap_or_else(|e| {
            eprintln!("{}", e);
            process::exit(1);
        });

    // Set dialect if specified (mirrors single-file path)
    if let Some(name) = config.dialect {
        match resolve_dialect(name) {
            Some(d) => session.set_dialect(Some(d)),
            None => {
                eprintln!(
                    "Error: Unknown dialect '{}'. Valid options: {}",
                    name,
                    super::io::DIALECT_OPTIONS
                );
                process::exit(1);
            }
        }
    }

    // A review with nothing to read under its paths, whose head holds no
    // SQL file under them either, keeps no file the session could add: the
    // batch is not planned. A head that cannot be listed may hold one, so
    // its batch is planned; the files the session adds are listed again
    // below, and only there does a listing error stop the run.
    let nothing_to_plan = match review {
        Some(scope)
            if files.is_empty()
                && embedded_fragments.is_empty()
                && found_unread.is_empty()
                && unreadable.is_empty() =>
        {
            super::git::sql_files_at_commit_under(scope.range.head, scope.paths)
                .is_ok_and(|held| held.is_empty())
        }
        Some(_) | None => false,
    };

    // The session orders the batch, adds what its analysis across the
    // files adds, and prepares that analysis.
    let ordered_files = if nothing_to_plan {
        Vec::new()
    } else {
        session
            .plan_batch(
                &files,
                &BatchPlan {
                    cross_script: config.cross_script,
                    quiet: config.quiet_mode,
                    change,
                },
            )
            .unwrap_or_else(|e| {
                eprintln!("{}", e);
                process::exit(1);
            })
    };
    // Which planned files to analyze: each of `files`, and a file the
    // session adds where the review's head holds it under its paths. A
    // file left out keeps its index in the planned batch.
    let analyzed_files = planned_under_paths(&ordered_files, &files, review);
    let planned_count = analyzed_files.iter().filter(|kept| **kept).count();

    // Each file and fragment the batch analyzes writes its decision under a
    // key no other one of them has.
    let fragment_names: Vec<String> = embedded_fragments.iter().map(fragment_name).collect();
    let artifact_keys = ArtifactKeys::new(
        ordered_files
            .iter()
            .zip(&analyzed_files)
            .filter(|(_, analyzed)| **analyzed)
            .map(|(file, _)| file.name.as_str())
            .chain(fragment_names.iter().map(String::as_str)),
    );

    // A review left with nothing to analyze says so. The reports and
    // decisions a program reads are still written, holding no file; the
    // text and Markdown reports, and so the pull-request comment, are not.
    let nothing_changed = change.is_some()
        && planned_count == 0
        && embedded_fragments.is_empty()
        && found_unread.is_empty()
        && unreadable.is_empty();
    if nothing_changed {
        if let Some(range) = change {
            if !config.quiet_mode {
                eprintln!("No SQL files changed in {}..{}", range.base, range.head);
            }
        }
        if !config.writes_records() {
            return BatchOutcome {
                markdown: None,
                exit_code: 0,
            };
        }
    }

    let to_analyze = planned_count + embedded_fragments.len();
    let total = to_analyze + found_unread.len() + unreadable.len();
    if !config.quiet_mode && !nothing_changed {
        eprintln!("Analyzing {} file(s)...", to_analyze);
    }

    let policy_enabled = config.policy_enabled();

    // Load the policy gate once for the batch.
    let gate: Option<Box<dyn PolicyGate>> = config.policy_path.map(|policy_path| {
        ext.policy_gate(&PolicySetup {
            policy_path,
            exceptions_path: config.exceptions_path,
            rules: config.custom_rules.as_deref().unwrap_or_default(),
            env: config.policy_env,
            team: config.policy_team,
            job_type: config.policy_job_type,
            change_id: config.policy_change_id,
            repo: config.policy_repo,
            commit: config.policy_commit,
            decision_out: config.decision_out,
            decision_artifact_format: config.decision_artifact_format,
            report_out: config.report_out,
            report_artifact_format: config.report_artifact_format,
            output_format: config.output_format,
            quiet: config.quiet_mode,
            runtime_mode: config.runtime_mode,
            batch: true,
        })
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(1);
        })
    });

    if policy_enabled && config.decision_out.is_none() {
        eprintln!("Error: --decision-out is required when using --policy");
        process::exit(1);
    }

    // A review that analyzes no file of the range, whatever it skipped, is
    // decided once, for the range, on a report with nothing in it, as
    // `diff` decides one; the batch report holds that decision.
    let mut range_decision: Option<PolicyOutcome> = None;
    if planned_count == 0 && embedded_fragments.is_empty() {
        if let (Some(gate), Some(range)) = (&gate, change) {
            let mut empty = analyzer::AnalysisReport::new();
            config.run_identity.apply(&mut empty);
            range_decision = Some(gate.decide(&SourceCase {
                sql: &format!("review:{}..{}", range.base, range.head),
                report: &empty,
                scope_path: None,
            }));
        }
    }
    let range_blocked = range_decision
        .as_ref()
        .is_some_and(|outcome| !outcome.allowed);

    let mut total_findings = 0;
    let mut max_level = lexega_core::analyzer::RiskLevel::Low;
    let mut files_with_findings = 0;
    let mut files_blocked = 0;
    // What the --report-out artifact, if any, is written as: it drives both
    // what the batch retains per file and the artifact written at the end, so
    // retention can never disagree with the output.
    let artifact_format = config.report_out.map(|_| config.report_artifact_format);
    // Per-file retention is matched to what the selected outputs actually
    // read. Retaining whole AnalysisReports made batch memory grow with
    // analysis internals (statement groupings, explanations, ledger) far
    // beyond the promised output — multi-GB on large estates.
    let retain_files_json = config.output_format == "json"
        || config.output_format == "both"
        || config.output_format == "yaml";
    let retain_per_file_json = matches!(
        artifact_format,
        Some(ReportArtifactFormat::Json | ReportArtifactFormat::Yaml)
    );
    let retain_all_findings = config.output_format == "sarif"
        || config.output_format == "gl-sast"
        || artifact_format == Some(ReportArtifactFormat::Sarif);
    // The per-file sections only the text and Markdown reports read.
    let retain_sections = config.output_format == "text"
        || config.output_format == "both"
        || config.output_format == "markdown"
        || config.capture_markdown;
    // Pre-built per-file entries for the json/yaml stdout payloads.
    let mut files_json: Vec<serde_json::Value> = Vec::new();
    // Pre-built entries for the batch artifact's `per_file` payload
    // (json/yaml --report-out only; the SARIF artifact never reads it).
    let mut per_file_json: Vec<serde_json::Value> = Vec::new();
    // Per-file sections; only files with a finding or a context entry.
    let mut file_sections: Vec<FileSection> = Vec::new();
    let mut all_findings: Vec<lexega_core::analyzer::RuleMatch> = Vec::new(); // Combined report (SARIF / gl-sast surfaces)
                                                                              // (path, reason)
    let mut skipped_files: Vec<(String, String)> = found_unread
        .iter()
        .map(|skipped| {
            (
                skipped.path.display().to_string(),
                skipped.reason.to_string(),
            )
        })
        .collect();
    if !config.quiet_mode {
        for (reason, paths) in skips_by_reason(&skipped_files) {
            match paths.as_slice() {
                [path] => eprintln!("  - {} - skipped ({})", path, reason),
                several => eprintln!("  - {} files skipped ({})", several.len(), reason),
            }
        }
    }
    // The dbt macro files discovery left unread, each with why.
    let macro_files: Vec<(String, String)> = found_unread
        .iter()
        .filter(|found| unread_is_macro_file(&found.reason))
        .map(|found| (found.path.display().to_string(), found.reason.to_string()))
        .collect();
    // The files and fragments analyzed, and of the files those the session
    // added to the ones given.
    let given: std::collections::BTreeSet<&str> =
        files.iter().map(|file| file.name.as_str()).collect();
    let mut files_analyzed: usize = 0;
    let mut added_analyzed: Vec<String> = Vec::new();

    // Aggregate data for summary
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;
    let mut risky_files: Vec<(String, usize, lexega_core::analyzer::RiskLevel)> = Vec::new(); // (path, count, max_level)
                                                                                              // Track rule occurrences with names: rule_id -> (name, count)
    let mut rule_counts: std::collections::HashMap<String, (String, usize)> =
        std::collections::HashMap::new();

    // Statement-level aggregates
    // These three must always sum to ledger_entries_total
    let mut total_statements_analyzed: usize = 0;
    let mut total_statements_skipped: usize = 0;
    // Of the skipped, the sqlcmd commands that run what was not read.
    let mut unread_sqlcmd: Vec<String> = Vec::new();
    let mut total_jinja_blocks: usize = 0;
    let mut total_placeholders: usize = 0;
    let mut files_with_placeholders: usize = 0;

    // Placeholder aggregation by source and kind
    let mut placeholder_source_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut placeholder_kind_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut total_high_impact: usize = 0;
    let mut total_low_impact: usize = 0;
    let mut impacted_files: Vec<(String, usize, usize, usize)> = Vec::new(); // (path, total, high, low)

    // The least complete render of the files analyzed, the lowest confidence
    // among them, and the files analyzed on their template text.
    let mut render_completeness = analyzer::RenderCompleteness::Full;
    let mut analysis_confidence = analyzer::ConfidenceLevel::High;
    let mut unrendered_files: Vec<String> = Vec::new();
    // The files of the batch that did not render and were not analyzed.
    let mut render_failed_files: Vec<String> = Vec::new();
    // The SQL files the batch left unanalyzed, with why.
    let mut not_analyzed_files: Vec<(String, String)> = Vec::new();

    // Tracks whether any file in the batch emitted strict violations so
    // we can fail the process once at the end rather than per-file.
    let mut strict_violations_found = false;
    // Whether a file named on the command line could not be read.
    let mut named_files_unread = false;

    // The depth note of the first report that carries one; a run evaluates
    // one corpus at one depth.
    let mut analysis_depth: Option<analyzer::AnalysisDepth> = None;

    for found in found_unread
        .iter()
        .filter(|found| unread_is_unanalyzed_sql(&found.reason))
    {
        // A link the scan does not follow is named by its own path, not its
        // target's.
        let label = found.path.display().to_string();
        let reason = found.reason.to_string();
        if strict_not_analyzed(config.strict, &label, &reason) {
            strict_violations_found = true;
        }
        not_analyzed_files.push((label, reason));
    }
    for (label, reason) in unreadable {
        if is_named(config, &label) {
            report_named_unread(&label, &reason);
            named_files_unread = true;
        }
        if fail_unanalyzed(
            &mut skipped_files,
            &mut not_analyzed_files,
            config.strict,
            label,
            reason,
            config.quiet_mode,
        ) {
            strict_violations_found = true;
        }
    }

    let planned = ordered_files
        .iter()
        .enumerate()
        .zip(&analyzed_files)
        .filter(|(_, analyzed)| **analyzed)
        .map(|(planned, _)| planned);
    for (position, (idx, file)) in planned.enumerate() {
        // Print progress in batch mode so long-running files are discoverable.
        // Use stderr so JSON/YAML stdout remains valid when requested.
        if !config.quiet_mode {
            eprintln!(
                "  [{}/{}] analyzing {}",
                position + 1,
                to_analyze,
                file.name
            );
        }

        let source = match read_source(&file.path, change.map(|range| range.head)) {
            Ok(content) => BatchSource::Text(content),
            // A file the change removes is reported from its text at the
            // base, when the session reports on removals.
            Err(ReadFailure::Removed(reason)) => {
                match change.map(|range| removed(session.as_mut(), &file.path, range)) {
                    Some(Ok(Some(removed))) => BatchSource::Removed(Box::new(removed)),
                    // The head holds no text of it to analyze: listed, and
                    // no strict failure.
                    Some(Ok(None)) | None => {
                        let label = file.name.clone();
                        skip(&mut skipped_files, label, reason, config.quiet_mode);
                        continue;
                    }
                    Some(Err(reason)) => {
                        render_failed_files.push(file.name.clone());
                        if render_failed(
                            config,
                            &mut skipped_files,
                            &mut not_analyzed_files,
                            &mut render_completeness,
                            &file.name,
                            reason,
                        ) {
                            strict_violations_found = true;
                        }
                        continue;
                    }
                }
            }
            Err(ReadFailure::Unreadable(reason)) => {
                if is_named(config, &file.name) {
                    report_named_unread(&file.name, &reason);
                    named_files_unread = true;
                }
                if fail_unanalyzed(
                    &mut skipped_files,
                    &mut not_analyzed_files,
                    config.strict,
                    file.name.clone(),
                    reason,
                    config.quiet_mode,
                ) {
                    strict_violations_found = true;
                }
                continue;
            }
        };

        // Render and analyze through the session, which applies the
        // analysis across files it planned for this batch.
        let analyzed = match source {
            BatchSource::Text(input) => {
                // Text that is not the file's bytes as written (a mark
                // removed, UTF-16 decoded).
                let had_bom = input.encoding != lexega_core::extract::SourceEncoding::Utf8;
                session
                    .analyze_planned(idx, file, &input.text, had_bom)
                    .map(|done| (done, session.not_compared(idx)))
            }
            BatchSource::Removed(removed) => Ok((*removed, None)),
        };
        let ((render, mut report), not_compared) = match analyzed {
            Ok(done) => done,
            Err(FileFailure::Render(reason)) => {
                render_failed_files.push(file.name.clone());
                if render_failed(
                    config,
                    &mut skipped_files,
                    &mut not_analyzed_files,
                    &mut render_completeness,
                    &file.name,
                    reason,
                ) {
                    strict_violations_found = true;
                }
                continue;
            }
            Err(FileFailure::Analysis(reason)) => {
                if fail_unanalyzed(
                    &mut skipped_files,
                    &mut not_analyzed_files,
                    config.strict,
                    file.name.clone(),
                    reason,
                    config.quiet_mode,
                ) {
                    strict_violations_found = true;
                }
                continue;
            }
        };

        config.run_identity.apply(&mut report);
        files_analyzed += 1;
        if !given.contains(file.name.as_str()) {
            added_analyzed.push(file.name.clone());
        }
        if analysis_depth.is_none() {
            analysis_depth = report.summary.analysis_depth.clone();
        }

        // Strict-mode enforcement. Accumulates across the batch so the
        // loop completes and the user sees every offending file before we
        // exit non-zero.
        if report_strict_violations(config.strict, &report, &file.name.clone()) {
            strict_violations_found = true;
        }
        // A file analyzed without the comparison of its change, or as its
        // template text where the template did not render, fails the strict
        // gate as a file not analyzed; its report stands.
        if let Some(reason) = not_compared.or_else(|| render.render_error.clone()) {
            if strict_not_analyzed(config.strict, &file.name.clone(), &reason) {
                strict_violations_found = true;
            }
        }

        // Stamp render completeness from this file's render artifacts. For the
        // analyze paths this restates what the core already derived (same
        // stats); for the cross-script arm the report came from the repo pass,
        // which never saw this render, so the stamp is load-bearing.
        if render.placeholders.total > 0 {
            if render.placeholders.high_impact == 0 {
                report.summary.render_completeness =
                    analyzer::RenderCompleteness::PartialLowImpactOnly;
            } else {
                report.summary.render_completeness = analyzer::RenderCompleteness::Partial;
            }
            report.summary.placeholders = Some(analyzer::PlaceholderSummary {
                total: render.placeholders.total,
                statements_impacted: 0,
                high_impact: render.placeholders.high_impact,
                low_impact: render.placeholders.low_impact,
                top_sources: render.placeholders.top_sources(),
                top_kinds: render.placeholders.top_kinds(),
            });
        }
        render_completeness =
            less_complete(render_completeness, &report.summary.render_completeness);

        // Set source file path for the report (use absolute path for easy navigation)
        report.source_file_path = dunce::canonicalize(&file.path)
            .map(|p| p.display().to_string())
            .ok()
            .or_else(|| Some(file.name.clone()));
        analysis_confidence = analysis_confidence.min(report.summary.analysis_confidence.clone());
        if report.summary.render_completeness == analyzer::RenderCompleteness::NotRendered {
            unrendered_files.push(file.name.clone());
        }

        let key = artifact_keys.key(&file.name);

        // The policy decides on every finding and context entry of the file;
        // --min-severity then filters what the batch shows and counts. A
        // decision is shown beside the report it decided on.
        let mut decided: Option<(serde_json::Value, serde_json::Value)> = None;
        if let Some(gate) = &gate {
            let outcome = gate.decide_in_batch(&BatchCase {
                sql: &render.sql,
                report: &report,
                file_path: Path::new(&file.name),
                artifact_key: &key,
                want_record: retain_files_json,
            });
            if !outcome.allowed {
                files_blocked += 1;
            }
            decided = outcome
                .record
                .map(|decision| (serde_json::json!(&report), decision));
        }
        if let Some(threshold) = config.min_severity {
            report.retain_at_least(threshold);
        }

        let finding_count = report.findings.len();
        total_findings += finding_count;
        info_count += report.context.len();
        if finding_count > 0 {
            files_with_findings += 1;
        }

        // Aggregate statement counts (must sum to ledger_entries)
        total_statements_analyzed += report.summary.statements_analyzed;
        total_statements_skipped += report.summary.statements_skipped;
        unread_sqlcmd.extend(unread_sqlcmd_lines(Some(&file.name), &report));
        total_jinja_blocks += report.summary.jinja_blocks;

        // Aggregate placeholder counts from render stats (has source/kind breakdown)
        // This supplements report.summary.placeholders which only has counts
        if render.placeholders.total > 0 {
            total_placeholders += render.placeholders.total;
            files_with_placeholders += 1;
            total_high_impact += render.placeholders.high_impact;
            total_low_impact += render.placeholders.low_impact;

            impacted_files.push((
                file.name.clone(),
                render.placeholders.total,
                render.placeholders.high_impact,
                render.placeholders.low_impact,
            ));

            // Aggregate by source from render stats
            for (source, count) in &render.placeholders.by_source {
                *placeholder_source_counts.entry(source.clone()).or_insert(0) += count;
            }

            // Aggregate by kind from render stats
            for (kind, count) in &render.placeholders.by_kind {
                *placeholder_kind_counts.entry(kind.clone()).or_insert(0) += count;
            }
        }

        let file_max = report.max_risk_level();
        if file_max > max_level {
            max_level = file_max;
        }

        // Aggregate findings by level and collect for combined report
        for finding in &report.findings {
            match finding.risk_level() {
                lexega_core::analyzer::RiskLevel::Critical => critical_count += 1,
                lexega_core::analyzer::RiskLevel::High => high_count += 1,
                lexega_core::analyzer::RiskLevel::Medium => medium_count += 1,
                lexega_core::analyzer::RiskLevel::Low => low_count += 1,
                // Context entries are not findings; `report.context` counts them.
                lexega_core::analyzer::RiskLevel::Info => {}
            }

            // Track violated rules (only for Policy findings)
            let lexega_core::analyzer::RuleMatch::Analysis(policy_finding) = finding;
            let entry = rule_counts
                .entry(policy_finding.matched_rule.clone())
                .or_insert_with(|| (policy_finding.finding_type.clone(), 0));
            entry.1 += occurrences(policy_finding);

            // Collect finding for the combined report, but only when a
            // combined surface (SARIF / gl-sast) will read it.
            if retain_all_findings {
                all_findings.push(finding.clone());
            }
        }

        // Track risky files
        if finding_count > 0 {
            risky_files.push((file.name.clone(), finding_count, file_max));
        }

        // Retain only what the selected outputs read from this file's
        // report — pre-built JSON fragments and per-file sections — never
        // the report itself.
        if retain_sections && (!report.findings.is_empty() || !report.context.is_empty()) {
            file_sections.push(FileSection {
                path: file.name.clone(),
                findings: report.findings.clone(),
                context: report.context.clone(),
            });
        }
        if retain_files_json {
            let result = match decided {
                Some((decided_report, decision)) => {
                    serde_json::json!({"report": decided_report, "decision": decision})
                }
                None => serde_json::json!({"report": report}),
            };
            files_json.push(serde_json::json!({
                "file": file.name.clone(),
                "result": result,
            }));
        }
        if retain_per_file_json {
            // Each `per_file` entry of the batch artifact has the shape of
            // a single-file `--report-out <file>` report.
            per_file_json.push(serde_json::json!({
                "source_file": file.name.clone(),
                "report": report,
            }));
        }

        // Print summary per file in text mode (when not printing policy allow/block already)
        if !config.quiet_mode
            && !policy_enabled
            && (config.output_format == "text" || config.output_format == "both")
            && finding_count > 0
        {
            eprintln!(
                "  {} - {} finding(s), max: {}",
                file.name,
                finding_count,
                file_max.as_str().to_uppercase()
            );
        }
    }

    // Process embedded SQL fragments (from --scan-embedded), each in the
    // run's dialect, whatever call or cell it came from.
    for (frag_idx, fragment) in embedded_fragments.iter().enumerate() {
        // The report's evidence places the fragment by file and line; the
        // batch names it by file, line and column, so two fragments on one
        // line are two entries and two decision records.
        let source_name = format!(
            "{}:{}",
            fragment.origin_file.display(),
            fragment.origin.line
        );
        let display_name = fragment_name(fragment);
        let batch_idx = planned_count + frag_idx;

        if !config.quiet_mode {
            eprintln!(
                "  [{}/{}] analyzing {} (embedded {:?})",
                batch_idx + 1,
                to_analyze,
                display_name,
                fragment.embedding
            );
        }

        // Analyze the extracted SQL fragment as-is: fragments are never
        // rendered, and must not inherit the previous file's render state.
        let fragment_render = RenderArtifacts::raw(fragment.sql.clone());
        let mut report = match session.analyze(&fragment_render, Some(&source_name)) {
            Ok(r) => r,
            Err(e) => {
                if fail_unanalyzed(
                    &mut skipped_files,
                    &mut not_analyzed_files,
                    config.strict,
                    display_name,
                    e,
                    config.quiet_mode,
                ) {
                    strict_violations_found = true;
                }
                continue;
            }
        };
        config.run_identity.apply(&mut report);
        files_analyzed += 1;
        place_in_origin(&mut report, fragment);
        if analysis_depth.is_none() {
            analysis_depth = report.summary.analysis_depth.clone();
        }

        // Strict-mode enforcement for embedded fragments.
        if report_strict_violations(config.strict, &report, &display_name) {
            strict_violations_found = true;
        }

        // Each fragment is decided on its own, as a file is.
        let mut decided: Option<(serde_json::Value, serde_json::Value)> = None;
        if let Some(gate) = &gate {
            let outcome = gate.decide_in_batch(&BatchCase {
                sql: &fragment.sql,
                report: &report,
                file_path: &fragment.origin_file,
                artifact_key: &artifact_keys.key(&display_name),
                want_record: retain_files_json,
            });
            if !outcome.allowed {
                files_blocked += 1;
            }
            decided = outcome
                .record
                .map(|decision| (serde_json::json!(&report), decision));
        }
        if let Some(threshold) = config.min_severity {
            report.retain_at_least(threshold);
        }

        let finding_count = report.findings.len();
        total_findings += finding_count;
        info_count += report.context.len();
        total_statements_analyzed += report.summary.statements_analyzed;
        total_statements_skipped += report.summary.statements_skipped;
        unread_sqlcmd.extend(unread_sqlcmd_lines(Some(&display_name), &report));
        total_jinja_blocks += report.summary.jinja_blocks;

        if finding_count > 0 {
            files_with_findings += 1;
        }

        let file_max = report.max_risk_level();
        if file_max > max_level {
            max_level = file_max;
        }

        // Aggregate findings by level
        for finding in &report.findings {
            match finding.risk_level() {
                lexega_core::analyzer::RiskLevel::Critical => critical_count += 1,
                lexega_core::analyzer::RiskLevel::High => high_count += 1,
                lexega_core::analyzer::RiskLevel::Medium => medium_count += 1,
                lexega_core::analyzer::RiskLevel::Low => low_count += 1,
                // Context entries are not findings; `report.context` counts them.
                lexega_core::analyzer::RiskLevel::Info => {}
            }

            let lexega_core::analyzer::RuleMatch::Analysis(policy_finding) = finding;
            let entry = rule_counts
                .entry(policy_finding.matched_rule.clone())
                .or_insert_with(|| (policy_finding.finding_type.clone(), 0));
            entry.1 += occurrences(policy_finding);

            if retain_all_findings {
                all_findings.push(finding.clone());
            }
        }

        if finding_count > 0 {
            risky_files.push((display_name.clone(), finding_count, file_max));
        }

        // Same retention as the file loop above; fragments are marked
        // `embedded` in the json/yaml payload.
        if retain_sections && (!report.findings.is_empty() || !report.context.is_empty()) {
            file_sections.push(FileSection {
                path: display_name.clone(),
                findings: report.findings.clone(),
                context: report.context.clone(),
            });
        }
        if retain_files_json {
            let (fragment_report, decision) = match decided {
                Some((decided_report, decision)) => (decided_report, Some(decision)),
                None => (serde_json::json!(report), None),
            };
            let mut result = serde_json::json!({"report": fragment_report, "embedded": true});
            if let Some(decision) = decision {
                result["decision"] = decision;
            }
            files_json.push(serde_json::json!({
                "file": display_name.clone(),
                "result": result,
            }));
        }
        if retain_per_file_json {
            per_file_json.push(serde_json::json!({
                "source_file": report.source_file_path.clone().unwrap_or_else(|| display_name.clone()),
                "report": report,
            }));
        }

        if !config.quiet_mode
            && !policy_enabled
            && (config.output_format == "text" || config.output_format == "both")
            && finding_count > 0
        {
            eprintln!(
                "  {} - {} finding(s), max: {}",
                display_name,
                finding_count,
                file_max.as_str().to_uppercase()
            );
        }
    }

    // How this run's depth is reported, when it ran at reduced depth.
    let depth_note = analysis_depth.as_ref().map(|depth| ext.depth_note(depth));
    // What the run left undone that its findings do not show, so no report
    // reads it as all clear.
    let mut run_notes = run_notes(
        ext,
        session.as_ref(),
        unrendered_files.len(),
        render_failed_files.len(),
        change.is_some() && !nothing_changed,
    );
    run_notes.extend(unread_sqlcmd_note(&unread_sqlcmd));

    // A run whose SQL files are all macro files analyzed nothing: no report
    // reads it at high confidence, and a strict mode fails it.
    if files_analyzed == 0 && !macro_files.is_empty() {
        analysis_confidence = analyzer::ConfidenceLevel::Low;
        run_notes.push(analyzed_nothing_note(macro_files.len(), change.is_some()));
        for (path, reason) in &macro_files {
            let reason = format!("{}; the run analyzed no file", reason);
            if strict_not_analyzed(config.strict, path, &reason) {
                strict_violations_found = true;
            }
        }
    }
    // Each macro file is named in every report with why it was skipped and,
    // in a change, the models the session reviewed in its place.
    let reviewed_through: &[String] = if change.is_some() {
        &added_analyzed
    } else {
        &[]
    };
    let macro_notes: Vec<(String, String)> = macro_files
        .iter()
        .map(|(path, reason)| (path.clone(), macro_file_note(reason, reviewed_through)))
        .collect();
    let note_of: std::collections::BTreeMap<&str, &str> = macro_notes
        .iter()
        .map(|(path, note)| (path.as_str(), note.as_str()))
        .collect();
    for (path, reason) in skipped_files.iter_mut() {
        if let Some(note) = note_of.get(path.as_str()) {
            *reason = (*note).to_string();
        }
    }

    // Sort risky files by severity (descending), then by count (descending)
    // This must happen before format-specific output so all formats see the same order
    risky_files.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));

    // Map connected-set results (batch indices) to file paths and build the
    // shared JSON view once — reused by every structured output and the text
    // summary. Null when the batch was not analyzed as a connected set.
    let connected = session.connected_set();
    let cs_paths = |idxs: &[usize]| -> Vec<String> {
        idxs.iter()
            .filter_map(|&i| ordered_files.get(i).map(|file| file.name.clone()))
            .collect()
    };
    let cross_script_json: serde_json::Value = match connected {
        Some(set) => {
            let hazards: Vec<serde_json::Value> = set
                .hazards
                .iter()
                .map(|h| match h {
                    OrderingHazard::CircularDependency { files } => serde_json::json!({
                        "kind": "circular_dependency",
                        "files": cs_paths(files),
                    }),
                    OrderingHazard::MultipleWriters { object, files } => serde_json::json!({
                        "kind": "written_by_multiple_files",
                        "object": object,
                        "files": cs_paths(files),
                    }),
                })
                .collect();
            serde_json::json!({
                "dependency_order": cs_paths(&set.order),
                "hazards": hazards,
            })
        }
        None => serde_json::Value::Null,
    };

    // The text report: written to stdout after any JSON report, whatever
    // -q says (it quiets progress only).
    let mut text = String::new();
    // Where each finding's evidence is listed, how many places: --detail
    // lists more.
    let evidence_shown = if config.detail_mode { 3 } else { 1 };
    if !nothing_changed && (config.output_format == "text" || config.output_format == "both") {
        outln!(text);
        // A run at reduced depth is not titled for the analysis it lacks.
        outln!(
            text,
            "{}",
            if depth_note.is_some() {
                "Batch Analysis Summary"
            } else {
                "Batch Semantic Analysis Summary"
            }
        );
        outln!(text, "==================");
        outln!(
            text,
            "Files processed: {}/{}",
            total - skipped_files.len(),
            total
        );
        outln!(text, "Files skipped: {}", skipped_files.len());
        if !skipped_files.is_empty() {
            outln!(text, "\nSkipped files:");
            // A reason several files share is said once; --detail lists each.
            for (reason, paths) in skips_by_reason(&skipped_files) {
                match paths.as_slice() {
                    [path] => outln!(text, "  - {}: {}", path, reason),
                    several if config.detail_mode => {
                        for path in several {
                            outln!(text, "  - {}: {}", path, reason);
                        }
                    }
                    several => outln!(text, "  - {} files: {}", several.len(), reason),
                }
            }
        }
        outln!(text);
        if let Some(set) = connected {
            outln!(
                text,
                "Cross-script: {} scripts analyzed as a connected set (producer-first)",
                set.order.len()
            );
            if set.hazards.is_empty() {
                outln!(text, "  no ordering hazards");
            } else {
                for h in &set.hazards {
                    match h {
                        OrderingHazard::CircularDependency { files } => {
                            outln!(
                                text,
                                "  ⚠ circular dependency: {}",
                                cs_paths(files).join(", ")
                            )
                        }
                        OrderingHazard::MultipleWriters { object, files } => {
                            outln!(
                                text,
                                "  ⚠ '{}' written by multiple files: {}",
                                object,
                                cs_paths(files).join(", ")
                            )
                        }
                    }
                }
            }
            outln!(text);
        }
        // Simple, trust-building output
        outln!(
            text,
            "Analyzed: {} SQL statements",
            total_statements_analyzed
        );
        if total_jinja_blocks > 0 {
            outln!(
                text,
                "Template blocks, not SQL statements: {}",
                total_jinja_blocks
            );
        }
        if let Some(line) = not_rendered_line(unrendered_files.len(), render_failed_files.len()) {
            outln!(text, "Templates not rendered: {}", line);
        }
        // Placeholder/taint tracking - show when templates had runtime-dependent values
        if config.render_diagnostics != RenderDiagnosticsLevel::None && total_placeholders > 0 {
            outln!(
                text,
                "Placeholders: {} ({} files) - runtime-dependent values",
                total_placeholders,
                files_with_placeholders
            );
            outln!(
                text,
                "  High-impact: {}, Low-impact: {}",
                total_high_impact,
                total_low_impact
            );

            if config.render_diagnostics >= RenderDiagnosticsLevel::Impacted {
                let mut files_sorted = impacted_files.clone();
                files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                outln!(text, "  Top impacted files:");
                for (path, total, high, low) in files_sorted.into_iter().take(10) {
                    outln!(
                        text,
                        "    - {}: {} (high {}, low {})",
                        path,
                        total,
                        high,
                        low
                    );
                }
            }

            if config.render_diagnostics >= RenderDiagnosticsLevel::All {
                let mut sources: Vec<_> = placeholder_source_counts.iter().collect();
                sources.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !sources.is_empty() {
                    outln!(text, "  Top placeholder sources:");
                    for (source, count) in sources.into_iter().take(5) {
                        outln!(text, "    - {} ({})", source, count);
                    }
                }

                let mut kinds: Vec<_> = placeholder_kind_counts.iter().collect();
                kinds.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !kinds.is_empty() {
                    outln!(text, "  Top placeholder kinds:");
                    for (kind, count) in kinds.into_iter().take(5) {
                        outln!(text, "    - {} ({})", kind, count);
                    }
                }
            }

            if config.render_diagnostics >= RenderDiagnosticsLevel::Summary {
                outln!(text, "  Note: To reduce placeholders, provide --catalog, --dbt-project, or --var settings.");
            }
        }
        // Only show unrecognized if there are any — statements the parser
        // could not recognize (opaque / error / stray clause), not analyzed;
        // the sqlcmd commands that run what was not read apart.
        let unrecognized = total_statements_skipped.saturating_sub(unread_sqlcmd.len());
        if unrecognized > 0 {
            outln!(
                text,
                "Unrecognized: {} (could not parse, no analysis)",
                unrecognized
            );
        }
        if !unread_sqlcmd.is_empty() {
            outln!(
                text,
                "Not read: {} (sqlcmd commands that run SQL or commands the analysis did not read)",
                unread_sqlcmd.len()
            );
        }
        if let Some(note) = &depth_note {
            outln!(text, "Note: {}", note);
        }
        for note in &run_notes {
            outln!(text, "Note: {}", note);
        }
        outln!(text, "Files with findings: {}", files_with_findings);
        outln!(text, "Total findings: {}", total_findings);
        if info_count > 0 {
            outln!(text, "Context: {}", info_count);
        }
        if total_findings > 0 {
            outln!(
                text,
                "  By level: {} CRITICAL, {} HIGH, {} MEDIUM, {} LOW",
                critical_count,
                high_count,
                medium_count,
                low_count
            );
        }
        if files_with_findings > 0 {
            outln!(
                text,
                "Average findings per file: {:.1}",
                total_findings as f64 / files_with_findings as f64
            );
        }
        outln!(
            text,
            "Highest risk level: {}",
            highest_risk(total_findings, max_level, &run_notes)
        );
        if policy_enabled {
            outln!(text, "Files blocked by policy: {}", files_blocked);
        }

        // Top 5 risky files (already sorted above)
        if !risky_files.is_empty() {
            outln!(text);
            outln!(text, "Top risky files:");
            for (path, count, level) in risky_files.iter().take(5) {
                outln!(
                    text,
                    "  {} - {} finding(s), max {}",
                    path,
                    count,
                    level.as_str().to_uppercase()
                );
            }
        }

        // Top 5 matched rules
        if !rule_counts.is_empty() {
            let mut rules: Vec<_> = rule_counts.iter().collect();
            rules.sort_by(|a, b| (b.1).1.cmp(&(a.1).1).then_with(|| a.0.cmp(b.0)));
            outln!(text);
            outln!(text, "Top Matched Rules:");
            for (rule, (_, count)) in rules.iter().take(5) {
                outln!(text, "  {} - {} occurrence(s)", rule, count);
            }
        }

        // Each file's findings and context entries.
        if !file_sections.is_empty() {
            let plain = super::color::Palette::resolve(super::color::ColorChoice::Never);
            outln!(text);
            outln!(text, "{}", sections_title(&file_sections));
            outln!(
                text,
                "══════════════════════════════════════════════════════════════"
            );
            for section in &file_sections {
                outln!(text);
                let findings = section.findings.len();
                let context = if section.context.is_empty() {
                    String::new()
                } else {
                    format!(", {} context", section.context.len())
                };
                outln!(
                    text,
                    "── {} ({} finding{}{})",
                    section.path,
                    findings,
                    if findings == 1 { "" } else { "s" },
                    context
                );
                write_text_entries(&mut text, &section.findings, evidence_shown, &plain);
                if !section.context.is_empty() {
                    outln!(text, "  Context:");
                    write_text_entries(&mut text, &section.context, evidence_shown, &plain);
                }
            }
        }
    } // end text summary block

    // Accounting invariant: ledger_entries == sql_analyzed + sql_unrecognized + jinja_blocks
    // This must always reconcile perfectly - any mismatch indicates a bug
    let ledger_entries_total =
        total_statements_analyzed + total_statements_skipped + total_jinja_blocks;

    // Build top placeholder sources (sorted by count)
    let top_sources: Vec<_> = {
        let mut sources: Vec<_> = placeholder_source_counts.iter().collect();
        sources.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        sources
            .iter()
            .take(5)
            .map(|(source, count)| serde_json::json!({ "source": source, "count": count }))
            .collect()
    };

    // Build top placeholder kinds (sorted by count)
    let top_kinds: Vec<_> = {
        let mut kinds: Vec<_> = placeholder_kind_counts.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        kinds
            .iter()
            .take(5)
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect()
    };

    // Guidance message (only when placeholders present and verbosity wants it)
    let placeholder_guidance = if config.render_diagnostics >= RenderDiagnosticsLevel::Summary
        && total_placeholders > 0
    {
        Some("To reduce placeholders, provide --catalog for schema metadata, --dbt-project with --load-macros, or --var settings. Placeholders come from macros requiring database introspection; Lexega runs offline by default.")
    } else {
        None
    };

    // Top impacted files - ALWAYS show when there are placeholders (useful for triage)
    let top_impacted_files: Vec<_> = if total_placeholders > 0 {
        let mut files_sorted = impacted_files.clone();
        files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        files_sorted
            .into_iter()
            .take(10)
            .map(|(path, total, high, low)| {
                serde_json::json!({
                    "path": path,
                    "total": total,
                    "high_impact": high,
                    "low_impact": low
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    // Built once, shared verbatim by the three batch payload surfaces
    // (report artifact, json stdout, yaml stdout) so their shapes cannot
    // drift apart.
    let top_matched_rules: Vec<serde_json::Value> = {
        let mut rules: Vec<_> = rule_counts.iter().collect();
        rules.sort_by(|a, b| (b.1).1.cmp(&(a.1).1).then_with(|| a.0.cmp(b.0)));
        rules
            .iter()
            .take(5)
            .map(|(rule, (name, count))| {
                serde_json::json!({
                    "rule": rule,
                    "name": name,
                    "count": count
                })
            })
            .collect()
    };
    let skipped_files_json: Vec<serde_json::Value> = skipped_files
        .iter()
        .map(|(path, reason)| serde_json::json!({ "path": path, "reason": reason }))
        .collect();
    let top_risky_files_json: Vec<serde_json::Value> = risky_files
        .iter()
        .take(5)
        .map(|(path, count, level)| {
            serde_json::json!({
                "path": path,
                "finding_count": count,
                "max_risk_level": level.as_str()
            })
        })
        .collect();
    let mut batch_summary = serde_json::json!({
        // === FILE COUNTS ===
        "files_total": total,
        "files_processed": total - skipped_files.len(),
        "files_skipped": skipped_files.len(),
        "files_with_findings": files_with_findings,

        // === STATEMENT LEDGER (accounting invariant: ledger = sql + jinja) ===
        "statements": {
            "ledger_total": ledger_entries_total,
            "sql_total": total_statements_analyzed + total_statements_skipped,
            "sql_analyzed": total_statements_analyzed,
            "sql_unrecognized": total_statements_skipped,
            "jinja_blocks": total_jinja_blocks,
        },

        // === findings ===
        "findings": {
            "total_reported": total_findings,
            "by_level": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            // None where nothing was found.
            "max_level": (total_findings > 0).then(|| max_level.as_str()),
        },

        // === RENDERING (placeholder taint tracking) ===
        "rendering": {
            "completeness": render_completeness,
            "files_not_rendered": unrendered_files.len() + render_failed_files.len(),
            "files_render_failed": render_failed_files.len(),
            "placeholders_total": total_placeholders,
            "placeholders_high_impact": total_high_impact,
            "placeholders_low_impact": total_low_impact,
            "files_with_placeholders": files_with_placeholders,
            "top_impacted_files": top_impacted_files.clone(),
            "top_sources": if config.render_diagnostics >= RenderDiagnosticsLevel::All { top_sources.clone() } else { Vec::new() },
            "top_kinds": if config.render_diagnostics >= RenderDiagnosticsLevel::All { top_kinds.clone() } else { Vec::new() },
            "guidance": placeholder_guidance,
        },

        // === POLICY ===
        "policy_enabled": policy_enabled,
        "files_blocked": files_blocked,

        // === CROSS-SCRIPT (null unless a non-dbt directory was analyzed as a set) ===
        "cross_script": cross_script_json.clone(),

        // === WHAT THE RUN LEFT UNDONE (unrendered templates, a change not compared) ===
        "notes": run_notes.clone(),
    });
    if let Some(depth) = &analysis_depth {
        batch_summary["analysis_depth"] = serde_json::json!(depth);
    }
    // The decision a review that analyzed no file made for its range.
    if let Some(record) = range_decision.and_then(|outcome| outcome.record) {
        batch_summary["range_decision"] = record;
    }
    // Write combined batch report if report_out is provided (like init/review commands)
    if config.report_out.is_some() {
        let summary_data = serde_json::json!({
            "engine_version": env!("CARGO_PKG_VERSION"),
            "run_scope": config.run_identity.scope.clone(),
            "repo": config.run_identity.repo.clone(),
            "run_id": config.run_identity.run_id.clone(),
            "batch_summary": batch_summary.clone(),
            "skipped_files": skipped_files_json.clone(),
            "top_risky_files": top_risky_files_json.clone(),
            "top_matched_rules": top_matched_rules.clone(),
            // Per-file payload: identical shape to what a single-file
            // `--report-out <file>` would produce, packaged into a single
            // batch artifact, so a reader gets a row per file from one
            // batch_summary.json instead of N individual reports. Built in
            // the batch loop; empty for a SARIF artifact, which never reads
            // it.
            "per_file": per_file_json,
        });

        let risk_out = match config.report_out {
            Some(path) => path,
            None => {
                eprintln!("Error: report output path is required for batch summary output");
                process::exit(1);
            }
        };

        // Build combined AnalysisReport for format conversion (like init command)
        let mut combined_report = lexega_core::analyzer::AnalysisReport::new();
        combined_report.summary.total_reported_findings = total_findings;
        combined_report.summary.critical_count = critical_count;
        combined_report.summary.high_count = high_count;
        combined_report.summary.medium_count = medium_count;
        combined_report.summary.low_count = low_count;
        combined_report.summary.info_count = info_count;
        combined_report.summary.statements_analyzed = total_statements_analyzed;
        combined_report.summary.statements_skipped = total_statements_skipped;
        combined_report.summary.jinja_blocks = total_jinja_blocks;
        combined_report.summary.analysis_depth = analysis_depth.clone();
        combined_report.summary.render_completeness = render_completeness.clone();
        combined_report.summary.analysis_confidence = analysis_confidence.clone();
        // Only the SARIF and gl-sast stdout blocks can still read
        // all_findings after this point, so move unless one is active.
        combined_report.findings = if matches!(config.output_format, "sarif" | "gl-sast") {
            all_findings.clone()
        } else {
            std::mem::take(&mut all_findings)
        };

        let effective_format = config.report_artifact_format;
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let written = write_report_artifact(
            effective_format,
            &combined_report,
            &summary_data,
            risk_out,
            "batch_summary",
            &ToolRun {
                unrendered_files: &unrendered_files,
                skipped_files: &not_analyzed_files,
                macro_files: &macro_notes,
                run_notes: &run_notes,
                ..tool_run(ext, git_root.as_deref(), depth_note.as_deref())
            },
        );
        eprintln!("\n✓ Batch summary written to {}", written);
    }

    // Batch SARIF / GitLab SAST to stdout, as a single file's: SARIF is on
    // standard output unless `--report-out` delivers it.
    if config.output_format == "sarif" && artifact_format != Some(ReportArtifactFormat::Sarif) {
        let mut combined_report = lexega_core::analyzer::AnalysisReport::new();
        // Last reader of all_findings on this path — move, don't clone.
        combined_report.findings = std::mem::take(&mut all_findings);
        combined_report.summary.render_completeness = render_completeness.clone();
        combined_report.summary.analysis_confidence = analysis_confidence.clone();
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let sarif_report = lexega_core::analyzer::to_sarif(
            &combined_report,
            &ToolRun {
                unrendered_files: &unrendered_files,
                skipped_files: &not_analyzed_files,
                macro_files: &macro_notes,
                run_notes: &run_notes,
                ..tool_run(ext, git_root.as_deref(), depth_note.as_deref())
            },
        );
        match serde_json::to_string_pretty(&sarif_report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing SARIF report: {}", e);
                process::exit(1);
            }
        }
    }

    if config.output_format == "gl-sast" {
        let mut combined_report = lexega_core::analyzer::AnalysisReport::new();
        // Last reader of all_findings on this path — move, don't clone.
        combined_report.findings = std::mem::take(&mut all_findings);
        combined_report.summary.render_completeness = render_completeness.clone();
        combined_report.summary.analysis_confidence = analysis_confidence.clone();
        let gl_report = lexega_core::analyzer::to_gl_sast(
            &combined_report,
            &ToolRun {
                unrendered_files: &unrendered_files,
                skipped_files: &not_analyzed_files,
                macro_files: &macro_notes,
                run_notes: &run_notes,
                ..tool_run(ext, None, depth_note.as_deref())
            },
        );
        match serde_json::to_string_pretty(&gl_report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing GitLab SAST report: {}", e);
                process::exit(1);
            }
        }
    }

    // Markdown batch summary, built for whichever surface reads it: the
    // `markdown` output format and the pull-request comment.
    let markdown: Option<String> = if !nothing_changed
        && (config.output_format == "markdown" || config.capture_markdown)
    {
        let mut md = String::new();
        // Markdown batch summary for PR comments. A run the policy blocked is
        // headed as blocked, whatever the levels shown.
        let policy_blocked = policy_enabled && (files_blocked > 0 || range_blocked);
        let risk_emoji = if policy_blocked {
            "⛔"
        } else if critical_count > 0 {
            "🔴"
        } else if high_count > 0 {
            "🟠"
        } else if medium_count > 0 {
            "🟡"
        } else if !run_notes.is_empty() {
            // Not all clear: the notes say what was not checked.
            "⚠️"
        } else {
            "🟢"
        };

        outln!(md, "## {} Batch Analysis Summary", risk_emoji);
        outln!(md);
        outln!(
            md,
            "**{} files analyzed** | **{} with findings** | **{} total findings**",
            total - skipped_files.len(),
            files_with_findings,
            total_findings
        );
        outln!(md);
        if policy_enabled {
            outln!(md, "**Files blocked by policy: {}**", files_blocked);
            outln!(md);
        }
        if !skipped_files.is_empty() {
            outln!(
                md,
                "**{} file(s) not analyzed** — listed under Analysis Transparency.",
                skipped_files.len()
            );
            outln!(md);
        }
        if let Some(note) = &depth_note {
            outln!(md, "**Note**: {}", note);
            outln!(md);
        }
        for note in &run_notes {
            outln!(md, "**Note**: {}", note);
            outln!(md);
        }

        // Finding summary
        if total_findings > 0 || info_count > 0 {
            outln!(md, "| Level | Count |");
            outln!(md, "|-------|-------|");
            if critical_count > 0 {
                outln!(md, "| 🔴 Critical | {} |", critical_count);
            }
            if high_count > 0 {
                outln!(md, "| 🟠 High | {} |", high_count);
            }
            if medium_count > 0 {
                outln!(md, "| 🟡 Medium | {} |", medium_count);
            }
            if low_count > 0 {
                outln!(md, "| 🟢 Low | {} |", low_count);
            }
            if info_count > 0 {
                outln!(md, "| ℹ️ Context | {} |", info_count);
            }
            outln!(md);
        }

        // Top risky files
        if !risky_files.is_empty() {
            outln!(md, "### Top Risky Files");
            outln!(md);
            outln!(md, "| File | Findings | Max Level |");
            outln!(md, "|------|---------|-----------|");
            for (path, count, level) in risky_files.iter().take(10) {
                let level_icon = risk_icon(*level);
                outln!(
                    md,
                    "| `{}` | {} | {} {} |",
                    path,
                    count,
                    level_icon,
                    level.as_str()
                );
            }
            outln!(md);
        }

        // Top matched rules
        if !rule_counts.is_empty() {
            outln!(md, "### Top Matched Rules");
            outln!(md);
            outln!(md, "| Rule | Occurrences |");
            outln!(md, "|------|-------------|");
            let mut rules: Vec<_> = rule_counts.iter().collect();
            rules.sort_by(|a, b| (b.1).1.cmp(&(a.1).1).then_with(|| a.0.cmp(b.0)));
            for (rule, (_, count)) in rules.iter().take(5) {
                outln!(md, "| `{}` | {} |", rule, count);
            }
            outln!(md);
        }

        // Transparency section
        outln!(md, "<details>");
        outln!(md, "<summary>🔍 Analysis Transparency</summary>");
        outln!(md);
        outln!(md, "| Metric | Value |");
        outln!(md, "|--------|-------|");
        outln!(
            md,
            "| Files Processed | {}/{} |",
            total - skipped_files.len(),
            total
        );
        outln!(md, "| SQL Statements | {} |", total_statements_analyzed);
        if total_jinja_blocks > 0 {
            outln!(
                md,
                "| Template blocks, not SQL statements | {} |",
                total_jinja_blocks
            );
        }
        if let Some(line) = not_rendered_line(unrendered_files.len(), render_failed_files.len()) {
            outln!(md, "| Templates not rendered | {} |", line);
        }
        let unrecognized = total_statements_skipped.saturating_sub(unread_sqlcmd.len());
        if unrecognized > 0 {
            outln!(md, "| Unrecognized (opaque) | {} |", unrecognized);
        }
        if !unread_sqlcmd.is_empty() {
            outln!(
                md,
                "| Not read (sqlcmd commands) | {} |",
                unread_sqlcmd.len()
            );
        }
        if total_placeholders > 0 {
            outln!(
                md,
                "| Placeholders | {} ({} high-impact) |",
                total_placeholders,
                total_high_impact
            );
        }
        outln!(md);

        // --render-diagnostics, at the levels the text summary prints.
        if config.render_diagnostics >= RenderDiagnosticsLevel::Impacted && total_placeholders > 0 {
            let mut files_sorted = impacted_files.clone();
            files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            outln!(md, "**Top impacted files:**");
            for (path, total, high, low) in files_sorted.into_iter().take(10) {
                outln!(md, "- `{}`: {} (high {}, low {})", path, total, high, low);
            }
            outln!(md);
        }
        if config.render_diagnostics >= RenderDiagnosticsLevel::All && total_placeholders > 0 {
            for (title, counts) in [
                ("Top placeholder sources", &placeholder_source_counts),
                ("Top placeholder kinds", &placeholder_kind_counts),
            ] {
                let mut sorted: Vec<_> = counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !sorted.is_empty() {
                    outln!(md, "**{}:**", title);
                    for (name, count) in sorted.into_iter().take(5) {
                        outln!(md, "- {} ({})", name, count);
                    }
                    outln!(md);
                }
            }
        }
        if let Some(guidance) = placeholder_guidance {
            outln!(md, "_{}_", guidance);
            outln!(md);
        }

        if !skipped_files.is_empty() {
            outln!(md, "**Skipped Files ({}):**", skipped_files.len());
            for (path, reason) in skipped_files.iter().take(5) {
                outln!(md, "- `{}`: {}", path, reason);
            }
            if skipped_files.len() > 5 {
                outln!(md, "- *...and {} more*", skipped_files.len() - 5);
            }
            outln!(md);
        }

        outln!(md, "</details>");

        // Each file's findings and context entries; --detail lists more of
        // each one's evidence.
        if !file_sections.is_empty() {
            outln!(md);
            outln!(md, "### {}", sections_title(&file_sections));
            outln!(md);
            let evidence_listed = if config.detail_mode { 2 } else { 1 };
            for section in &file_sections {
                outln!(md, "#### `{}`", section.path);
                outln!(md);
                write_markdown_entries(&mut md, "Finding", &section.findings, evidence_listed);
                if !section.context.is_empty() {
                    outln!(md, "**ℹ️ Context ({})**", section.context.len());
                    outln!(md);
                    write_markdown_entries(&mut md, "Context", &section.context, evidence_listed);
                }
            }
        }
        Some(md)
    } else {
        None
    };

    if config.output_format == "json" || config.output_format == "both" {
        let json_output = serde_json::json!({
            "engine_version": env!("CARGO_PKG_VERSION"),
            "batch_summary": batch_summary.clone(),
            "skipped_files": skipped_files_json.clone(),
            "top_risky_files": top_risky_files_json.clone(),
            "top_matched_rules": top_matched_rules.clone(),
            "files": files_json
        });

        let json_output_pretty = serde_json::to_string_pretty(&json_output).unwrap_or_else(|e| {
            eprintln!("Error serializing batch JSON output: {}", e);
            process::exit(1);
        });
        println!("{}", json_output_pretty);
    } else if config.output_format == "yaml" {
        let payload = serde_json::json!({
            "batch_summary": batch_summary.clone(),
            "skipped_files": skipped_files_json.clone(),
            "top_risky_files": top_risky_files_json.clone(),
            "top_matched_rules": top_matched_rules.clone(),
            "files": files_json
        });

        match serde_yaml_ng::to_string(&payload) {
            Ok(yaml) => print!("{}", yaml),
            Err(e) => {
                eprintln!("Error serializing batch report to YAML: {}", e);
                process::exit(1);
            }
        }
    } else if config.output_format == "markdown" {
        if let Some(md) = &markdown {
            print!("{}", md);
        }
    }
    if !text.is_empty() {
        if config.output_format == "both" {
            println!("\n---\n");
        }
        print!("{}", text);
    }

    let exit_code = if policy_enabled && (files_blocked > 0 || range_blocked) {
        2
    } else if strict_violations_found || named_files_unread {
        // Strict mode is independent of policy: any file that violated
        // strict analysis fails the batch, and so does a file named on the
        // command line that could not be read.
        1
    } else {
        0
    };
    BatchOutcome {
        markdown,
        exit_code,
    }
}
