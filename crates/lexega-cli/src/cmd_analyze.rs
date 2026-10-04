// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `analyze` command: one source, or a batch of files, analyzed
//! through the build's [`Session`](super::extension::Session) and written in
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
    is_artifact_file_path, sanitize_artifact_key, write_optional_report_artifact,
    write_report_artifact, DecisionArtifactFormat, ReportArtifactFormat,
};
use super::extension::{
    governance_capabilities, BatchCase, BatchPlan, Capability, Extension, FileFailure,
    OrderingHazard, PolicyGate, PolicySetup, SessionOptions,
};
use super::io::load_custom_rules;
use super::io::{
    collect_embedded_files, collect_sql_files, resolve_dialect, strip_bom, FoundFiles, SkippedFile,
};
use super::output::{print_analyze_markdown, print_fact_explanation, print_signal_explanation};
use super::types::{BatchProcessingConfig, RenderDiagnosticsLevel};
use super::usage::{print_review_usage, print_risk_usage, print_signal_catalog};

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

/// What a run of the analyze driver measures.
pub(crate) enum Scope {
    /// The sources named on the command line, as checked out.
    Snapshot,
    /// The SQL files a commit range touches, read at its head.
    Change { base: String, head: String },
}

fn print_usage(program: &str, ext: &dyn Extension, change: bool) {
    if change {
        print_review_usage(program);
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
    }
}

/// Handle the `analyze` subcommand.
pub fn handle_risk_command(args: &[String], ext: &dyn Extension) {
    run(args, ext, Scope::Snapshot);
}

/// Parse the options that follow the command — or, for a change scope, the
/// commit range — and run the analysis.
pub(crate) fn run(args: &[String], ext: &dyn Extension, scope: Scope) {
    let program = args[0].as_str();
    let change = matches!(scope, Scope::Change { .. });
    // Parse risk-specific arguments
    let mut input_file: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();
    let mut pr_comment = false;
    let mut use_stdin = false;
    // A change-scoped run reports for a pull request by default.
    let mut output_format = if change { "markdown" } else { "text" };
    let mut report_artifact_format = ReportArtifactFormat::Json;
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
    let mut catalog_provider: Option<String> = None;
    let mut trace_mode = false;
    let mut verbose_mode = false;
    let mut detail_mode = change;
    let mut explain_signals = false;
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

    // Strict-analysis mode. Default comes from
    // LEXEGA_STRICT; `--strict[=<mode>]` overrides.
    let mut strict_mode = lexega_core::strict_mode_from_env();

    let mut i = if change { 3 } else { 2 }; // after the command, or after the commit range
    while i < args.len() {
        match args[i].as_str() {
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
                report_artifact_format = ReportArtifactFormat::from_cli_arg(&args[i + 1])
                    .unwrap_or_else(|msg| {
                        eprintln!("Error: {}", msg);
                        process::exit(1);
                    });
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
                decision_out = Some(args[i + 1].clone());
                i += 2;
            }
            "--report-out" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --report-out requires a file path or directory");
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
                // Detail mode - show per-file signal details in batch text/markdown output
                detail_mode = true;
                i += 1;
            }
            "--list-signals" => {
                // Show available signal types and exit
                print_signal_catalog(program, ext);
                process::exit(0);
            }
            "--explain-signals" => {
                // Signal preview mode — show per-statement matched rules
                // (populated when trace_mode is on via
                // `statement_explanations`).
                explain_signals = true;
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
                    eprintln!("Error: --dialect requires a value (snowflake|postgresql|bigquery|databricks|redshift)");
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
                match args
                    .get(i + 1)
                    .and_then(|s| lexega_core::parse_strict_mode(s).ok())
                {
                    Some(m) => {
                        strict_mode = m;
                        i += 2;
                    }
                    None => {
                        strict_mode = lexega_core::StrictMode::Strict;
                        i += 1;
                    }
                }
            }
            "--pr-comment" if change => {
                pr_comment = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage(program, ext, change);
                process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                if change {
                    paths.push(arg.to_string());
                } else {
                    input_file = Some(arg.to_string());
                }
                i += 1;
            }
            arg => {
                eprintln!(
                    "Error: Unknown {} argument '{}'",
                    if change { "review" } else { "risk" },
                    arg
                );
                print_usage(program, ext, change);
                process::exit(1);
            }
        }
    }

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
    let custom_rules: Option<Vec<lexega_core::rules::Rule>> =
        if builtin_rules || user_rules.is_some() {
            match lexega_core::rules::build_v1_rule_corpus(
                user_rules.unwrap_or_default(),
                builtin_rules,
            ) {
                Ok(merged) => Some(merged),
                Err(e) => {
                    eprintln!("Error merging custom rules with built-in corpus: {}", e);
                    process::exit(1);
                }
            }
        } else {
            None
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
        custom_rules,
        load_macros,
        dbt_project_path: dbt_project_path.as_deref(),
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
        source_commit: None,
    };

    // Change scope: the SQL files the commit range touches, read at its head.
    if let Scope::Change { base, head } = &scope {
        if paths.is_empty() {
            paths.push(".".to_string());
        }
        let changed = match super::git::get_changed_sql_files(base, head, &paths, recursive) {
            Ok(changed) => changed,
            Err(e) => {
                eprintln!("Error getting changed files: {}", e);
                process::exit(1);
            }
        };
        if changed.is_empty() {
            if !quiet_mode {
                eprintln!("No SQL files changed in {}..{}", base, head);
            }
            return;
        }
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
            source_commit: Some(head.as_str()),
            ..config
        };
        let files = changed.files.into_iter().map(PathBuf::from).collect();
        let outcome = handle_risk_batch(files, Vec::new(), changed.skipped, &config, ext);
        if pr_comment {
            if let Some(markdown) = &outcome.markdown {
                post_review_comment(markdown, output_format == "markdown");
            }
        }
        finish(outcome);
        return;
    }

    // Handle batch mode (directory or multiple files)
    if let Some(ref path) = input_file {
        let path_obj = Path::new(path);
        if path_obj.is_dir() || path.contains('*') || path.contains('?') {
            // Policy gating in batch mode writes per-file artifacts.
            // For batch with policy, require decision-out to be a directory.
            // Note: --report-out can be a file (writes merged batch JSON) or directory.

            if policy_path.is_some() {
                let out = decision_out.as_deref().unwrap_or("");
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

            let found = collect_sql_files(path, recursive);

            // Also collect embedded files if --scan-embedded is set
            let embedded = if scan_embedded {
                collect_embedded_files(path, recursive)
            } else {
                FoundFiles::default()
            };

            if found.is_empty() && embedded.is_empty() {
                if scan_embedded {
                    eprintln!("No SQL or Python/notebook files found in '{}'", path);
                } else {
                    eprintln!("No SQL files found in '{}'", path);
                }
                process::exit(1);
            }

            let embedded_fragments = extract_sql_from_paths(&embedded.files, quiet_mode);
            let mut skipped = found.skipped;
            skipped.extend(embedded.skipped);
            finish(handle_risk_batch(
                found.files,
                embedded_fragments,
                skipped,
                &config,
                ext,
            ));
            return;
        }

        // Single embedded file: extract and analyze fragments
        if scan_embedded {
            let file_path = Path::new(path);
            if lexega_core::extract::extractor_for_file(file_path).is_some() {
                let source = fs::read_to_string(file_path).unwrap_or_else(|e| {
                    eprintln!("Error reading file '{}': {}", path, e);
                    process::exit(1);
                });

                let patterns = lexega_core::extract::SqlCallPattern::spark_defaults();
                let fragments = match lexega_core::extract::extract_sql_from_file(
                    file_path, &source, &patterns,
                ) {
                    Some(f) if !f.is_empty() => f,
                    _ => {
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
                    &config,
                    ext,
                ));
                return;
            }
        }
    }

    // Single file mode
    // Auto-detect stdin: if no file provided and stdin is piped (not a TTY), read from stdin
    let use_stdin = use_stdin || (input_file.is_none() && !io::stdin().is_terminal());

    let input = if use_stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).unwrap_or_else(|e| {
            eprintln!("Error reading from stdin: {}", e);
            process::exit(1);
        });
        buffer
    } else if let Some(ref file_path) = input_file {
        fs::read_to_string(file_path).unwrap_or_else(|e| {
            eprintln!("Error reading file '{}': {}", file_path, e);
            process::exit(1);
        })
    } else {
        eprintln!("Error: No input provided. Provide a filename or pipe input.");
        print_usage(program, ext, change);
        process::exit(1);
    };

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
            custom_rules: config.custom_rules,
            trace_mode,
            verbose_mode,
            catalog_path: catalog_path.as_deref(),
            catalog_provider: catalog_provider.as_deref(),
            dialect_name: dialect_name.as_deref(),
            output_format,
            quiet: quiet_mode,
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
    let render = match session.render(input) {
        Ok(artifacts) => artifacts,
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
            RenderArtifacts::not_rendered(input.to_string(), e)
        }
    };

    // Run risk analysis
    let mut report = match session.analyze(&render, input_file.as_deref()) {
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

    // Strict-mode enforcement. Runs before the rest of the pipeline so
    // CI failures stop early. Permissive is the default and this is a
    // no-op in that case.
    {
        let label = input_file.as_deref().unwrap_or("<stdin>");
        if report_strict_violations(strict_mode, &report, label) {
            process::exit(1);
        }
    }

    // Set source file path for the report (use absolute path for easy navigation)
    if let Some(ref file_path) = input_file {
        report.source_file_path = dunce::canonicalize(file_path)
            .map(|p| p.display().to_string())
            .ok()
            .or_else(|| Some(file_path.clone()));
    }

    // Filter signals by --min-severity if specified
    if let Some(threshold) = min_severity {
        report.signals.retain(|s| s.risk_level() >= threshold);
        report.summary.recalculate_from_signals(&report.signals);
    }

    // How this run's depth is reported, when it ran at reduced depth.
    let depth_note = report
        .summary
        .analysis_depth
        .as_ref()
        .map(|depth| ext.depth_note(depth));

    // Handle --explain-facts mode: show structured facts extracted from policies
    if explain_facts {
        print_fact_explanation(&report, &render.sql, output_format);
        process::exit(0);
    }

    // Handle --explain-signals mode: show only extracted signals by statement
    if explain_signals {
        print_signal_explanation(&report, &render.sql, output_format);
        process::exit(0);
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

    if !runtime_mode && output_format == "sarif" {
        // Use git repo root for SARIF base path since file paths may be relative to repo root
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let sarif_report = analyzer::to_sarif(
            &report,
            &tool_run(ext, git_root.as_deref(), depth_note.as_deref()),
        );
        match serde_json::to_string_pretty(&sarif_report) {
            Ok(json) => {
                // If --report-out is provided, write to file instead of stdout
                if let Some(ref risk_path) = report_out {
                    let sarif_path = if is_artifact_file_path(risk_path) {
                        risk_path.clone()
                    } else {
                        format!("{}/analysis_report.sarif", risk_path.trim_end_matches('/'))
                    };

                    // Ensure parent directory exists
                    if let Some(parent) = std::path::Path::new(&sarif_path).parent() {
                        let _ = fs::create_dir_all(parent);
                    }

                    if let Err(e) = fs::write(&sarif_path, &json) {
                        eprintln!("Error writing SARIF file: {}", e);
                        process::exit(1);
                    }
                    eprintln!("Analysis SARIF report written to: {}", sarif_path);
                } else {
                    // No --report-out, print to stdout
                    println!("{}", json);
                }
            }
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
        let gl_report = analyzer::to_gl_sast(&report, &tool_run(ext, None, depth_note.as_deref()));
        match serde_json::to_string_pretty(&gl_report) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing GitLab SAST report: {}", e);
                process::exit(1);
            }
        }
    }

    if output_format == "markdown" {
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
        );
    }

    // Write risk report to --report-out when policy is NOT enabled
    // (When policy IS enabled, write_optional_report_artifact is called inside that block)
    // Note: SARIF stdout-format already handles --report-out above, so skip it here
    if !policy_enabled && report_out.is_some() && output_format != "sarif" {
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        if let Some(path) = write_optional_report_artifact(
            report_artifact_format,
            &report,
            &report,
            report_out.as_deref(),
            "risk_report",
            &tool_run(ext, git_root.as_deref(), depth_note.as_deref()),
        ) {
            eprintln!("Risk report written to: {}", path);
        }
    }

    // Optional policy evaluation + artifacts
    let mut policy_blocked = false;
    if let Some(policy_file) = policy_path.as_deref() {
        let gate = ext
            .policy_gate(&PolicySetup {
                policy_path: policy_file,
                exceptions_path: exceptions_path.as_deref(),
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
        policy_blocked = !gate.decide(&render.sql, &report, scope_path).allowed;
    }

    if !runtime_mode && (output_format == "text" || output_format == "both") {
        if output_format == "both" {
            println!("\n---\n");
        }

        let palette = super::color::Palette::resolve(color_choice);

        // Print text summary
        println!("{}", palette.bold("Semantic Analysis Report"));
        println!("========================");

        // Confidence first - this is the most important signal for trust
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
        println!("  Total signals: {}", report.summary.total_reported_signals);
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
            count_line(analyzer::RiskLevel::Info, "Info", report.summary.info_count)
        );
        if !report.positive_signals.is_empty() {
            println!("  Positive signals: {}", report.positive_signals.len());
        }
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
            println!("  Jinja Blocks: {}", report.summary.jinja_blocks);
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
        // not analyzed. This is coverage loss, not a clean parse.
        if report.summary.statements_skipped > 0 {
            println!(
                "  Unrecognized: {} (could not parse, no analysis)",
                report.summary.statements_skipped
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

        if !report.signals.is_empty() {
            println!("{}", palette.bold("signals:"));
            for signal in &report.signals {
                let level = signal.risk_level();
                let tag = palette.severity(level, &format!("[{}]", level.as_str().to_uppercase()));
                println!("  {} {}", tag, signal.message());

                // Show evidence (line numbers & previews) directly from signal
                let evidence = signal.evidence();

                if !evidence.is_empty() {
                    for ev in evidence.iter().take(3) {
                        if let analyzer::RiskEvidence::RuleMatch {
                            line_number,
                            statement_preview,
                            signal_value,
                            location,
                            ..
                        } = ev
                        {
                            let mut parts = Vec::new();
                            if let Some(line) = line_number {
                                parts.push(palette.dim(&format!("Line {}", line)));
                            }
                            if !signal_value.is_empty() {
                                parts.push(palette.rule_id(&format!("`{}`", signal_value)));
                            }
                            if let Some(preview) = statement_preview {
                                if !preview.is_empty() {
                                    // Collapse embedded newlines/indentation so each
                                    // occurrence stays on one physical line and doesn't
                                    // bury the signal headlines below it.
                                    let one_line =
                                        preview.split_whitespace().collect::<Vec<_>>().join(" ");
                                    parts.push(palette.dim(&format!("\"{}\"", one_line)));
                                }
                            }
                            // Add clickable location link
                            if let Some(loc) = location {
                                parts.push(palette.dim(loc));
                            }
                            if !parts.is_empty() {
                                println!("    {} {}", palette.dim("↳"), parts.join(" • "));
                            }
                        }
                    }
                    if evidence.len() > 3 {
                        println!(
                            "    {}",
                            palette.dim(&format!("↳ (+{} more occurrences)", evidence.len() - 3))
                        );
                    }
                }
            }
            println!();
        }

        if !report.positive_signals.is_empty() {
            println!("{}", palette.bold("Positive signals:"));
            for signal in &report.positive_signals {
                println!("  {} {}", palette.success("✓"), signal.message);
                if let Some(details) = &signal.details {
                    println!("    {}", palette.dim(details));
                }
            }
            println!();
        }

        // --verbose: append the v1 rule-evaluation explanation surface
        // (`statement_explanations`). Only emitted in text/both
        // output — JSON/YAML callers get the same data automatically
        // via the report's `Serialize` derive.
        if verbose_mode {
            println!();
            super::output::print_rule_explanation(&report);
        }
    }

    if policy_blocked {
        process::exit(2);
    }
}

/// Extract SQL fragments from a list of Python/notebook files.
fn extract_sql_from_paths(
    paths: &[PathBuf],
    quiet_mode: bool,
) -> Vec<lexega_core::extract::ExtractedSql> {
    let patterns = lexega_core::extract::SqlCallPattern::spark_defaults();
    let mut fragments = Vec::new();

    for file_path in paths {
        let source = match fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(e) => {
                if !quiet_mode {
                    eprintln!("  ⚠ {} - skipped ({})", file_path.display(), e);
                }
                continue;
            }
        };

        if let Some(extracted) =
            lexega_core::extract::extract_sql_from_file(file_path, &source, &patterns)
        {
            if !extracted.is_empty() && !quiet_mode {
                eprintln!(
                    "  📋 {} - extracted {} SQL fragment(s)",
                    file_path.display(),
                    extracted.len()
                );
            }
            fragments.extend(extracted);
        }
    }

    fragments
}

/// Emit strict-mode violations for a single analysis report on stderr.
///
/// Returns `true` if any violations were recorded. Callers decide what to
/// do with that signal — the single-file path exits immediately, the
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

/// One file's text: from the working tree, or as of `commit`.
fn read_source(path: &Path, commit: Option<&str>) -> Result<String, String> {
    match commit {
        Some(commit) => super::git::get_file_at_commit(commit, &path.display().to_string()),
        None => fs::read_to_string(path).map_err(|e| format!("Error reading: {}", e)),
    }
}

/// Post the review as a pull-request comment. Without a detectable pull
/// request the Markdown goes to standard output instead, unless it was
/// already printed there.
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
                eprintln!("   Falling back to stdout output.");
                print!("{}", markdown);
            }
        }
    }
}

/// Analyze `files` and `embedded_fragments` as one batch. `found_unread` are
/// the files discovery matched and left unread; they are reported with the
/// files the batch itself fails to read or analyze.
pub(crate) fn handle_risk_batch(
    files: Vec<PathBuf>,
    embedded_fragments: Vec<lexega_core::extract::ExtractedSql>,
    found_unread: Vec<SkippedFile>,
    config: &BatchProcessingConfig,
    ext: &dyn Extension,
) -> BatchOutcome {
    let to_analyze = files.len() + embedded_fragments.len();
    let total = to_analyze + found_unread.len();
    if !config.quiet_mode {
        eprintln!("Analyzing {} file(s)...", to_analyze);
    }

    let policy_enabled = config.policy_enabled();

    // Load the policy gate once for the batch.
    let gate: Option<Box<dyn PolicyGate>> = config.policy_path.map(|policy_path| {
        ext.policy_gate(&PolicySetup {
            policy_path,
            exceptions_path: config.exceptions_path,
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

    let mut total_signals = 0;
    let mut max_level = lexega_core::analyzer::RiskLevel::Low;
    let mut files_with_signals = 0;
    let mut files_blocked = 0;
    // Effective --report-out artifact format, resolved once from config
    // (file extension wins, then `--format sarif`, then
    // --report-artifact-format). Drives both what the batch retains per
    // file and the artifact written at the end — derived in one place so
    // retention can never disagree with the output.
    let report_out_format: Option<ReportArtifactFormat> =
        config.report_out.map(
            |path| match super::artifacts::OutputFileFormat::from_path(path) {
                Some(super::artifacts::OutputFileFormat::Sarif) => ReportArtifactFormat::Sarif,
                Some(super::artifacts::OutputFileFormat::Yaml) => ReportArtifactFormat::Yaml,
                Some(super::artifacts::OutputFileFormat::Json) => ReportArtifactFormat::Json,
                None if config.output_format == "sarif" => ReportArtifactFormat::Sarif,
                None => config.report_artifact_format,
            },
        );
    // Per-file retention is matched to what the selected outputs actually
    // read. Retaining whole AnalysisReports made batch memory grow with
    // analysis internals (statement groupings, explanations, ledger) far
    // beyond the promised output — multi-GB on large estates.
    let retain_files_json = config.output_format == "json"
        || config.output_format == "both"
        || config.output_format == "yaml";
    let retain_per_file_json = matches!(
        report_out_format,
        Some(ReportArtifactFormat::Json | ReportArtifactFormat::Yaml)
    );
    let retain_all_signals = config.output_format == "sarif"
        || config.output_format == "gl-sast"
        || matches!(report_out_format, Some(ReportArtifactFormat::Sarif));
    // Pre-built per-file entries for the json/yaml stdout payloads.
    let mut files_json: Vec<serde_json::Value> = Vec::new();
    // Pre-built entries for the batch artifact's `per_file` payload
    // (json/yaml --report-out only; the SARIF artifact never reads it).
    let mut per_file_json: Vec<serde_json::Value> = Vec::new();
    // (path, signals) for the --detail sections; only files with signals.
    let mut detail_signals: Vec<(String, Vec<lexega_core::analyzer::RuleMatch>)> = Vec::new();
    let mut all_signals: Vec<lexega_core::analyzer::RuleMatch> = Vec::new(); // Combined report (SARIF / gl-sast surfaces)
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
        for (path, reason) in &skipped_files {
            eprintln!("  - {} - skipped ({})", path, reason);
        }
    }

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

    // Open the session (same as single-file mode)
    let mut session = ext
        .open_session(SessionOptions {
            jinja_vars: config.jinja_vars,
            jinja_var_files: config.jinja_var_files,
            snowsql_configs: config.snowsql_configs,
            env_allowlist: config.env_allowlist,
            substitution: config.substitution,
            dbt_profile: None, // No dbt profile in batch mode
            dbt_project_path: config.dbt_project_path,
            load_macros: config.load_macros,
            fail_on_missing_packages: config.fail_on_missing_packages,
            custom_rules: config.custom_rules.clone(),
            trace_mode: config.trace_mode,
            verbose_mode: config.verbose_mode,
            catalog_path: config.catalog_path,
            catalog_provider: config.catalog_provider,
            dialect_name: config.dialect,
            output_format: config.output_format,
            quiet: config.quiet_mode,
        })
        .unwrap_or_else(|e| {
            eprintln!("{}", e);
            process::exit(1);
        });

    // Tracks whether any file in the batch emitted strict violations so
    // we can fail the process once at the end rather than per-file.
    let mut strict_violations_found = false;

    // The depth note of the first report that carries one; a run evaluates
    // one corpus at one depth.
    let mut analysis_depth: Option<analyzer::AnalysisDepth> = None;

    // Set dialect if specified (mirrors single-file path)
    if let Some(name) = config.dialect {
        if let Some(d) = resolve_dialect(name) {
            session.set_dialect(Some(d));
        }
    }

    // The session orders the batch and prepares whatever analysis across
    // files it performs.
    let ordered_files = session.plan_batch(
        &files,
        &BatchPlan {
            dbt_project_path: config.dbt_project_path,
            cross_script: config.cross_script,
            quiet: config.quiet_mode,
        },
    );

    for (idx, file_path) in ordered_files.iter().enumerate() {
        // Print progress in batch mode so long-running files are discoverable.
        // Use stderr so JSON/YAML stdout remains valid when requested.
        if !config.quiet_mode {
            eprintln!(
                "  [{}/{}] analyzing {}",
                idx + 1,
                to_analyze,
                file_path.display()
            );
        }

        let input = match read_source(file_path, config.source_commit) {
            Ok(content) => content,
            Err(reason) => {
                if !config.quiet_mode {
                    eprintln!("  ✗ {} - {}", file_path.display(), reason);
                }
                skipped_files.push((file_path.display().to_string(), reason));
                continue;
            }
        };
        let had_bom = input.starts_with('\u{feff}');
        let input = strip_bom(&input);

        // Render and analyze through the session, which applies the
        // analysis across files it planned for this batch.
        let (render, mut report) = match session.analyze_planned(idx, file_path, input, had_bom) {
            Ok(done) => done,
            Err(FileFailure::Render(reason)) => {
                if config.fail_on_missing_packages {
                    eprintln!("Error: {} (file: {})", reason, file_path.display());
                    process::exit(1);
                }
                if !config.quiet_mode {
                    eprintln!("  ✗ {} - {}", file_path.display(), reason);
                }
                skipped_files.push((file_path.display().to_string(), reason));
                continue;
            }
            Err(FileFailure::Analysis(reason)) => {
                if !config.quiet_mode {
                    eprintln!("  ✗ {} - {}", file_path.display(), reason);
                }
                skipped_files.push((file_path.display().to_string(), reason));
                continue;
            }
        };

        config.run_identity.apply(&mut report);
        if analysis_depth.is_none() {
            analysis_depth = report.summary.analysis_depth.clone();
        }

        // Strict-mode enforcement. Accumulates across the batch so the
        // loop completes and the user sees every offending file before we
        // exit non-zero.
        if report_strict_violations(config.strict, &report, &file_path.display().to_string()) {
            strict_violations_found = true;
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

        // Set source file path for the report (use absolute path for easy navigation)
        report.source_file_path = dunce::canonicalize(file_path)
            .map(|p| p.display().to_string())
            .ok()
            .or_else(|| Some(file_path.display().to_string()));

        // Apply --min-severity filter (same as single-file mode)
        if let Some(threshold) = config.min_severity {
            report.signals.retain(|s| s.risk_level() >= threshold);
            report.summary.recalculate_from_signals(&report.signals);
        }

        // Collect signals for combined batch report (no per-file reports in batch mode)
        let key = sanitize_artifact_key(&file_path.display().to_string());

        // Optional per-file policy decision + artifacts
        let mut decision_opt: Option<serde_json::Value> = None;
        if let Some(gate) = &gate {
            let outcome = gate.decide_in_batch(&BatchCase {
                sql: &render.sql,
                report: &report,
                file_path,
                artifact_key: &key,
                want_record: retain_files_json,
            });
            if !outcome.allowed {
                files_blocked += 1;
            }
            decision_opt = outcome.record;
        }

        let signal_count = report.signals.len();
        total_signals += signal_count;
        if signal_count > 0 {
            files_with_signals += 1;
        }

        // Aggregate statement counts (must sum to ledger_entries)
        total_statements_analyzed += report.summary.statements_analyzed;
        total_statements_skipped += report.summary.statements_skipped;
        total_jinja_blocks += report.summary.jinja_blocks;

        // Aggregate placeholder counts from render stats (has source/kind breakdown)
        // This supplements report.summary.placeholders which only has counts
        if render.placeholders.total > 0 {
            total_placeholders += render.placeholders.total;
            files_with_placeholders += 1;
            total_high_impact += render.placeholders.high_impact;
            total_low_impact += render.placeholders.low_impact;

            impacted_files.push((
                file_path.display().to_string(),
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

        // Aggregate signals by level and collect for combined report
        for signal in &report.signals {
            match signal.risk_level() {
                lexega_core::analyzer::RiskLevel::Critical => critical_count += 1,
                lexega_core::analyzer::RiskLevel::High => high_count += 1,
                lexega_core::analyzer::RiskLevel::Medium => medium_count += 1,
                lexega_core::analyzer::RiskLevel::Low => low_count += 1,
                lexega_core::analyzer::RiskLevel::Info => info_count += 1,
            }

            // Track violated rules (only for Policy signals)
            let lexega_core::analyzer::RuleMatch::Analysis(policy_signal) = signal;
            let entry = rule_counts
                .entry(policy_signal.matched_rule.clone())
                .or_insert_with(|| (policy_signal.signal_type.clone(), 0));
            entry.1 += 1;

            // Collect signal for the combined report, but only when a
            // combined surface (SARIF / gl-sast) will read it.
            if retain_all_signals {
                all_signals.push(signal.clone());
            }
        }

        // Track risky files
        if signal_count > 0 {
            risky_files.push((file_path.display().to_string(), signal_count, file_max));
        }

        // Retain only what the selected outputs read from this file's
        // report — pre-built JSON fragments and detail signals — never the
        // report itself.
        if config.detail_mode && !report.signals.is_empty() {
            detail_signals.push((file_path.display().to_string(), report.signals.clone()));
        }
        if retain_files_json {
            let mut result = serde_json::json!({"report": report});
            if let Some(dec) = &decision_opt {
                result["decision"] = serde_json::json!(dec);
            }
            files_json.push(serde_json::json!({
                "file": file_path.display().to_string(),
                "result": result,
            }));
        }
        if retain_per_file_json {
            // Each `per_file` entry of the batch artifact has the shape of
            // a single-file `--report-out <file>` report.
            per_file_json.push(serde_json::json!({
                "source_file": report.source_file_path.clone().unwrap_or_else(|| file_path.display().to_string()),
                "report": report,
            }));
        }

        // Print summary per file in text mode (when not printing policy allow/block already)
        if !config.quiet_mode
            && !policy_enabled
            && (config.output_format == "text" || config.output_format == "both")
            && signal_count > 0
        {
            eprintln!(
                "  {} - {} signal(s), max: {}",
                file_path.display(),
                signal_count,
                file_max.as_str().to_uppercase()
            );
        }
    }

    // Process embedded SQL fragments (from --scan-embedded).
    //
    // Each fragment may carry a `dialect_hint` (e.g. spark.sql in a
    // Databricks notebook). When present, the hint overrides the user's
    // `--dialect` for this fragment only. We snapshot the user-chosen
    // dialect here and restore it per-iteration so a fragment-level hint
    // can't leak into the *next* fragment's analysis.
    let user_dialect = session.dialect();
    for (frag_idx, fragment) in embedded_fragments.iter().enumerate() {
        let display_name = format!(
            "{}:{}",
            fragment.origin_file.display(),
            fragment.origin_line
        );
        let batch_idx = files.len() + frag_idx;

        if !config.quiet_mode {
            eprintln!(
                "  [{}/{}] analyzing {} (embedded {:?})",
                batch_idx + 1,
                to_analyze,
                display_name,
                fragment.embedding
            );
        }

        // Resolve per-fragment dialect deterministically: hint wins if
        // present and resolvable, otherwise fall back to the user-chosen
        // dialect captured before the loop.
        session.set_dialect(
            fragment
                .dialect_hint
                .as_deref()
                .and_then(resolve_dialect)
                .or_else(|| user_dialect.clone()),
        );

        // Analyze the extracted SQL fragment as-is: fragments are never
        // rendered, and must not inherit the previous file's render state.
        let fragment_render = RenderArtifacts::raw(fragment.sql.clone());
        let mut report = match session.analyze(&fragment_render, Some(&display_name)) {
            Ok(r) => r,
            Err(e) => {
                if !config.quiet_mode {
                    eprintln!("  ✗ {} - {}", display_name, e);
                }
                skipped_files.push((display_name, e.to_string()));
                continue;
            }
        };
        config.run_identity.apply(&mut report);
        if analysis_depth.is_none() {
            analysis_depth = report.summary.analysis_depth.clone();
        }

        // Strict-mode enforcement for embedded fragments.
        if report_strict_violations(config.strict, &report, &display_name) {
            strict_violations_found = true;
        }

        // Apply --min-severity filter (same as single-file mode)
        if let Some(threshold) = config.min_severity {
            report.signals.retain(|s| s.risk_level() >= threshold);
            report.summary.recalculate_from_signals(&report.signals);
        }

        let signal_count = report.signals.len();
        total_signals += signal_count;
        total_statements_analyzed += report.summary.statements_analyzed;
        total_statements_skipped += report.summary.statements_skipped;
        total_jinja_blocks += report.summary.jinja_blocks;

        if signal_count > 0 {
            files_with_signals += 1;
        }

        let file_max = report.max_risk_level();
        if file_max > max_level {
            max_level = file_max;
        }

        // Aggregate signals by level
        for signal in &report.signals {
            match signal.risk_level() {
                lexega_core::analyzer::RiskLevel::Critical => critical_count += 1,
                lexega_core::analyzer::RiskLevel::High => high_count += 1,
                lexega_core::analyzer::RiskLevel::Medium => medium_count += 1,
                lexega_core::analyzer::RiskLevel::Low => low_count += 1,
                lexega_core::analyzer::RiskLevel::Info => info_count += 1,
            }

            let lexega_core::analyzer::RuleMatch::Analysis(policy_signal) = signal;
            let entry = rule_counts
                .entry(policy_signal.matched_rule.clone())
                .or_insert_with(|| (policy_signal.signal_type.clone(), 0));
            entry.1 += 1;

            if retain_all_signals {
                all_signals.push(signal.clone());
            }
        }

        if signal_count > 0 {
            risky_files.push((display_name.clone(), signal_count, file_max));
        }

        // Same retention as the file loop above; fragments are marked
        // `embedded` in the json/yaml payload.
        if config.detail_mode && !report.signals.is_empty() {
            detail_signals.push((display_name.clone(), report.signals.clone()));
        }
        if retain_files_json {
            let mut result = serde_json::json!({"report": report});
            result["embedded"] = serde_json::json!(true);
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
            && signal_count > 0
        {
            eprintln!(
                "  {} - {} signal(s), max: {}",
                display_name,
                signal_count,
                file_max.as_str().to_uppercase()
            );
        }
    }

    // How this run's depth is reported, when it ran at reduced depth.
    let depth_note = analysis_depth.as_ref().map(|depth| ext.depth_note(depth));

    // Sort risky files by severity (descending), then by count (descending)
    // This must happen before format-specific output so all formats see the same order
    risky_files.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.cmp(&a.1)));

    // Map connected-set results (batch indices) to file paths and build the
    // shared JSON view once — reused by every structured output and the text
    // summary. Null when the batch was not analyzed as a connected set.
    let connected = session.connected_set();
    let cs_paths = |idxs: &[usize]| -> Vec<String> {
        idxs.iter()
            .filter_map(|&i| ordered_files.get(i).map(|p| p.display().to_string()))
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

    // Print text summary to stderr (skip for json/yaml/markdown - they have structured output)
    if !config.quiet_mode && (config.output_format == "text" || config.output_format == "both") {
        eprintln!();
        eprintln!("Batch Semantic Analysis Summary");
        eprintln!("==================");
        eprintln!("Files processed: {}/{}", total - skipped_files.len(), total);
        eprintln!("Files skipped: {}", skipped_files.len());
        if !skipped_files.is_empty() {
            eprintln!("\nSkipped files:");
            for (path, reason) in &skipped_files {
                eprintln!("  - {}: {}", path, reason);
            }
        }
        eprintln!();
        if let Some(set) = connected {
            eprintln!(
                "Cross-script: {} scripts analyzed as a connected set (producer-first)",
                set.order.len()
            );
            if set.hazards.is_empty() {
                eprintln!("  no ordering hazards");
            } else {
                for h in &set.hazards {
                    match h {
                        OrderingHazard::CircularDependency { files } => {
                            eprintln!("  ⚠ circular dependency: {}", cs_paths(files).join(", "))
                        }
                        OrderingHazard::MultipleWriters { object, files } => {
                            eprintln!(
                                "  ⚠ '{}' written by multiple files: {}",
                                object,
                                cs_paths(files).join(", ")
                            )
                        }
                    }
                }
            }
            eprintln!();
        }
        // Simple, trust-building output
        eprintln!("Analyzed: {} SQL statements", total_statements_analyzed);
        if total_jinja_blocks > 0 {
            eprintln!("Jinja Blocks: {}", total_jinja_blocks);
        }
        // Placeholder/taint tracking - show when templates had runtime-dependent values
        if config.render_diagnostics != RenderDiagnosticsLevel::None && total_placeholders > 0 {
            eprintln!(
                "Placeholders: {} ({} files) - runtime-dependent values",
                total_placeholders, files_with_placeholders
            );
            eprintln!(
                "  High-impact: {}, Low-impact: {}",
                total_high_impact, total_low_impact
            );

            if config.render_diagnostics >= RenderDiagnosticsLevel::Impacted {
                let mut files_sorted = impacted_files.clone();
                files_sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                eprintln!("  Top impacted files:");
                for (path, total, high, low) in files_sorted.into_iter().take(10) {
                    eprintln!("    - {}: {} (high {}, low {})", path, total, high, low);
                }
            }

            if config.render_diagnostics >= RenderDiagnosticsLevel::All {
                let mut sources: Vec<_> = placeholder_source_counts.iter().collect();
                sources.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !sources.is_empty() {
                    eprintln!("  Top placeholder sources:");
                    for (source, count) in sources.into_iter().take(5) {
                        eprintln!("    - {} ({})", source, count);
                    }
                }

                let mut kinds: Vec<_> = placeholder_kind_counts.iter().collect();
                kinds.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                if !kinds.is_empty() {
                    eprintln!("  Top placeholder kinds:");
                    for (kind, count) in kinds.into_iter().take(5) {
                        eprintln!("    - {} ({})", kind, count);
                    }
                }
            }

            if config.render_diagnostics >= RenderDiagnosticsLevel::Summary {
                eprintln!("  Note: To reduce placeholders, provide --catalog, --dbt-project, or --var settings.");
            }
        }
        // Only show unrecognized if there are any — statements the parser
        // could not recognize (opaque / error / stray clause), not analyzed.
        if total_statements_skipped > 0 {
            eprintln!(
                "Unrecognized: {} (could not parse, no analysis)",
                total_statements_skipped
            );
        }
        if let Some(note) = &depth_note {
            eprintln!("Note: {}", note);
        }
        eprintln!("Files with signals: {}", files_with_signals);
        eprintln!("Total signals: {}", total_signals);
        if total_signals > 0 {
            eprintln!(
                "  By level: {} CRITICAL, {} HIGH, {} MEDIUM, {} LOW",
                critical_count, high_count, medium_count, low_count
            );
        }
        if files_with_signals > 0 {
            eprintln!(
                "Average signals per file: {:.1}",
                total_signals as f64 / files_with_signals as f64
            );
        }
        eprintln!("Highest risk level: {}", max_level.as_str().to_uppercase());
        if policy_enabled {
            eprintln!("Files blocked by policy: {}", files_blocked);
        }

        // Top 5 risky files (already sorted above)
        if !risky_files.is_empty() {
            eprintln!();
            eprintln!("Top risky files:");
            for (path, count, level) in risky_files.iter().take(5) {
                eprintln!(
                    "  {} - {} signal(s), max {}",
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
            eprintln!();
            eprintln!("Top Matched Rules:");
            for (rule, (_, count)) in rules.iter().take(5) {
                eprintln!("  {} - {} occurrence(s)", rule, count);
            }
        }

        // Per-file signal details (--detail flag). `detail_signals` holds
        // only files with signals, so it is non-empty exactly when some
        // file has one.
        if config.detail_mode && !detail_signals.is_empty() {
            eprintln!();
            eprintln!("Per-File Signal Details");
            eprintln!("══════════════════════════════════════════════════════════════");
            for (path, signals) in &detail_signals {
                eprintln!();
                eprintln!(
                    "── {} ({} signal{})",
                    path,
                    signals.len(),
                    if signals.len() == 1 { "" } else { "s" }
                );
                for signal in signals {
                    let level = signal.risk_level();
                    eprintln!("  [{}] {}", level.as_str().to_uppercase(), signal.message());
                    let evidence = signal.evidence();
                    if !evidence.is_empty() {
                        for ev in evidence.iter().take(3) {
                            if let lexega_core::analyzer::RiskEvidence::RuleMatch {
                                line_number,
                                statement_preview,
                                signal_value,
                                location,
                                ..
                            } = ev
                            {
                                let mut parts = Vec::new();
                                if let Some(line) = line_number {
                                    parts.push(format!("Line {}", line));
                                }
                                if !signal_value.is_empty() {
                                    parts.push(format!("`{}`", signal_value));
                                }
                                if let Some(preview) = statement_preview {
                                    if !preview.is_empty() {
                                        parts.push(format!("\"{}\"", preview));
                                    }
                                }
                                if let Some(loc) = location {
                                    parts.push(loc.clone());
                                }
                                if !parts.is_empty() {
                                    eprintln!("    ↳ {}", parts.join(" • "));
                                }
                            }
                        }
                        if evidence.len() > 3 {
                            eprintln!("    ↳ (+{} more occurrences)", evidence.len() - 3);
                        }
                    }
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

    // Determine render completeness
    let render_completeness = if total_placeholders == 0 {
        "full"
    } else if total_high_impact == 0 {
        "partial_low_impact_only"
    } else {
        "partial"
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
                "signal_count": count,
                "max_risk_level": level.as_str()
            })
        })
        .collect();
    let mut batch_summary = serde_json::json!({
        // === FILE COUNTS ===
        "files_total": total,
        "files_processed": total - skipped_files.len(),
        "files_skipped": skipped_files.len(),
        "files_with_signals": files_with_signals,

        // === STATEMENT LEDGER (accounting invariant: ledger = sql + jinja) ===
        "statements": {
            "ledger_total": ledger_entries_total,
            "sql_total": total_statements_analyzed + total_statements_skipped,
            "sql_analyzed": total_statements_analyzed,
            "sql_unrecognized": total_statements_skipped,
            "jinja_blocks": total_jinja_blocks,
        },

        // === signals ===
        "signals": {
            "total_reported": total_signals,
            "by_level": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "max_level": max_level.as_str(),
        },

        // === RENDERING (placeholder taint tracking) ===
        "rendering": {
            "completeness": render_completeness,
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
    });
    if let Some(depth) = &analysis_depth {
        batch_summary["analysis_depth"] = serde_json::json!(depth);
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

        // Determine if output is a file or directory, and derive format from extension
        use super::artifacts::OutputFileFormat;
        let file_format = OutputFileFormat::from_path(risk_out);
        let is_file_output = file_format.is_some();

        // For directory output, ensure it exists
        if !is_file_output {
            if let Err(e) = fs::create_dir_all(risk_out) {
                eprintln!("Error creating risk output directory '{}': {}", risk_out, e);
                process::exit(1);
            }
        } else {
            // For file output, ensure parent directory exists
            if let Some(parent) = Path::new(risk_out).parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        eprintln!("Error creating parent directory for '{}': {}", risk_out, e);
                        process::exit(1);
                    }
                }
            }
        }

        // Build combined AnalysisReport for format conversion (like init command)
        let mut combined_report = lexega_core::analyzer::AnalysisReport::new();
        combined_report.summary.total_reported_signals = total_signals;
        combined_report.summary.critical_count = critical_count;
        combined_report.summary.high_count = high_count;
        combined_report.summary.medium_count = medium_count;
        combined_report.summary.low_count = low_count;
        combined_report.summary.info_count = info_count;
        combined_report.summary.statements_analyzed = total_statements_analyzed;
        combined_report.summary.statements_skipped = total_statements_skipped;
        combined_report.summary.jinja_blocks = total_jinja_blocks;
        combined_report.summary.analysis_depth = analysis_depth.clone();
        // Only the gl-sast stdout block can still read all_signals after
        // this point (sarif-stdout is gated on report_out being unset), so
        // move unless that surface is active.
        combined_report.signals = if config.output_format == "gl-sast" {
            all_signals.clone()
        } else {
            std::mem::take(&mut all_signals)
        };

        // Effective report format resolved before the batch loop
        // (`report_out_format`); Some by construction here since
        // `config.report_out` is Some.
        let effective_format = report_out_format.unwrap_or(config.report_artifact_format);
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
            &tool_run(ext, git_root.as_deref(), depth_note.as_deref()),
        );
        eprintln!("\n✓ Batch summary written to {}", written);
    }

    // Batch SARIF / GitLab SAST to stdout. Mirrors single-file behavior —
    // without this, `-r --format sarif` with no --report-out printed nothing
    // and exited 0, leaving a silently empty redirect target.
    if config.output_format == "sarif" && config.report_out.is_none() {
        let mut combined_report = lexega_core::analyzer::AnalysisReport::new();
        // Last reader of all_signals on this path — move, don't clone.
        combined_report.signals = std::mem::take(&mut all_signals);
        let git_root = super::git::get_git_repo_root()
            .and_then(|p| p.to_str().map(String::from))
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
            });
        let sarif_report = lexega_core::analyzer::to_sarif(
            &combined_report,
            &tool_run(ext, git_root.as_deref(), depth_note.as_deref()),
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
        // Last reader of all_signals on this path — move, don't clone.
        combined_report.signals = std::mem::take(&mut all_signals);
        let gl_report = lexega_core::analyzer::to_gl_sast(
            &combined_report,
            &tool_run(ext, None, depth_note.as_deref()),
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
    let markdown: Option<String> = if config.output_format == "markdown" || config.capture_markdown
    {
        let mut md = String::new();
        // Markdown batch summary for PR comments
        let risk_emoji = if critical_count > 0 {
            "🔴"
        } else if high_count > 0 {
            "🟠"
        } else if medium_count > 0 {
            "🟡"
        } else {
            "🟢"
        };

        outln!(md, "## {} Batch Analysis Summary", risk_emoji);
        outln!(md);
        outln!(
            md,
            "**{} files analyzed** | **{} with signals** | **{} total signals**",
            total - skipped_files.len(),
            files_with_signals,
            total_signals
        );
        outln!(md);
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

        // Signal summary
        if total_signals > 0 {
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
                outln!(md, "| ℹ️ Info | {} |", info_count);
            }
            outln!(md);
        }

        // Top risky files
        if !risky_files.is_empty() {
            outln!(md, "### Top Risky Files");
            outln!(md);
            outln!(md, "| File | Signals | Max Level |");
            outln!(md, "|------|---------|-----------|");
            for (path, count, level) in risky_files.iter().take(10) {
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path);
                let level_icon = match level {
                    lexega_core::analyzer::RiskLevel::Critical => "🔴",
                    lexega_core::analyzer::RiskLevel::High => "🟠",
                    lexega_core::analyzer::RiskLevel::Medium => "🟡",
                    lexega_core::analyzer::RiskLevel::Low => "🟢",
                    lexega_core::analyzer::RiskLevel::Info => "ℹ️",
                };
                outln!(
                    md,
                    "| `{}` | {} | {} {} |",
                    file_name,
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
            outln!(md, "| Jinja Blocks | {} |", total_jinja_blocks);
        }
        if total_statements_skipped > 0 {
            outln!(
                md,
                "| Unrecognized (opaque) | {} |",
                total_statements_skipped
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

        if !skipped_files.is_empty() {
            outln!(md, "**Skipped Files ({}):**", skipped_files.len());
            for (path, reason) in skipped_files.iter().take(5) {
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path);
                outln!(md, "- `{}`: {}", file_name, reason);
            }
            if skipped_files.len() > 5 {
                outln!(md, "- *...and {} more*", skipped_files.len() - 5);
            }
            outln!(md);
        }

        outln!(md, "</details>");

        // Per-file signal details (--detail flag)
        if config.detail_mode && !detail_signals.is_empty() {
            outln!(md);
            outln!(md, "### Per-File Signal Details");
            outln!(md);
            for (path, signals) in &detail_signals {
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path);
                outln!(md, "#### `{}`", file_name);
                outln!(md);
                outln!(md, "| Level | Signal | Evidence |");
                outln!(md, "|-------|--------|----------|");
                for signal in signals {
                    let level = signal.risk_level();
                    let level_icon = match level {
                        lexega_core::analyzer::RiskLevel::Critical => "🔴",
                        lexega_core::analyzer::RiskLevel::High => "🟠",
                        lexega_core::analyzer::RiskLevel::Medium => "🟡",
                        lexega_core::analyzer::RiskLevel::Low => "🟢",
                        lexega_core::analyzer::RiskLevel::Info => "ℹ️",
                    };
                    // Build evidence summary
                    let evidence = signal.evidence();
                    let ev_summary = if !evidence.is_empty() {
                        let mut parts = Vec::new();
                        for ev in evidence.iter().take(2) {
                            if let lexega_core::analyzer::RiskEvidence::RuleMatch {
                                line_number,
                                signal_value,
                                ..
                            } = ev
                            {
                                let mut p = Vec::new();
                                if let Some(line) = line_number {
                                    p.push(format!("Line {}", line));
                                }
                                if !signal_value.is_empty() {
                                    p.push(format!("`{}`", signal_value));
                                }
                                if !p.is_empty() {
                                    parts.push(p.join(": "));
                                }
                            }
                        }
                        if evidence.len() > 2 {
                            parts.push(format!("+{} more", evidence.len() - 2));
                        }
                        parts.join("; ")
                    } else {
                        String::new()
                    };
                    // Escape pipes in message for markdown table
                    let msg = signal.message().replace('|', "\\|");
                    outln!(
                        md,
                        "| {} {} | {} | {} |",
                        level_icon,
                        level.as_str(),
                        msg,
                        ev_summary
                    );
                }
                outln!(md);
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

    let exit_code = if policy_enabled && files_blocked > 0 {
        2
    } else if strict_violations_found {
        // Strict mode is independent of policy: any file that violated
        // strict analysis fails the batch.
        1
    } else {
        0
    };
    BatchOutcome {
        markdown,
        exit_code,
    }
}
