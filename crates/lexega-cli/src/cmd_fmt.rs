// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Format command handler.
//!
//! Handles the `fmt` subcommand for SQL formatting with Jinja/dbt support.
//!
//! Functions:
//! - handle_fmt_command
//! - format_batch

use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process;

use lexega_core::context::RenderContext;
use lexega_core::formatter::config::FormatterConfig;
use lexega_core::formatter::Formatter;
#[cfg(debug_assertions)]
use lexega_core::lexer;
use lexega_core::parse_sql_with_dialect;

use super::extension::{Capability, Extension, FormatRenderOptions, FormatRenderer};

use super::io::{collect_sql_files, has_jinja_syntax, resolve_dialect, strip_bom};
use super::usage::print_fmt_usage;

#[allow(clippy::too_many_arguments)] // one argument per `fmt` option the batch applies
pub fn format_batch(
    files: Vec<PathBuf>,
    config: &FormatterConfig,
    write_back: bool,
    check_mode: bool,
    verify_only_mode: bool,
    verify_mode: bool,
    enable_jinja: bool,
    force_render_jinja: bool,
    jinja_preserve: bool,
    jinja_vars: &[(String, String)],
    jinja_var_files: &[String],
    dbt_profile: Option<String>,
    dbt_project_path: Option<String>,
    fail_on_missing_packages: bool,
    quiet_mode: bool,
    ext: &dyn Extension,
) -> Result<(), Box<dyn std::error::Error>> {
    let total = files.len();
    if !quiet_mode {
        eprintln!("Formatting {} file(s)...", total);
    }

    // One renderer for the whole batch, opened only when templates may be
    // rendered.
    let mut shared_renderer: Option<Box<dyn FormatRenderer>> = if enable_jinja
        || force_render_jinja
        || !jinja_vars.is_empty()
        || !jinja_var_files.is_empty()
    {
        Some(ext.format_renderer(&FormatRenderOptions {
            jinja_vars,
            jinja_var_files,
            dbt_project_path: dbt_project_path.as_deref(),
            dbt_profile: dbt_profile.as_deref(),
            fail_on_missing_packages,
            quiet: quiet_mode,
            batch: true,
        })?)
    } else {
        None
    };

    // Process files sequentially to avoid memory explosion
    let mut formatted_count = 0;
    let mut error_count = 0;

    for (idx, path) in files.iter().enumerate() {
        let path_str = path.to_string_lossy().to_string();

        // Progress indicator (like analyze batch)
        if !quiet_mode {
            eprint!("\r  [{}/{}] {}", idx + 1, total, path_str);
        }

        // Read file
        let input = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                if !quiet_mode {
                    eprintln!();
                    eprintln!("ERROR {}: Read error: {}", path_str, e);
                }
                error_count += 1;
                continue;
            }
        };

        // Strip UTF-8 BOM if present
        let input = strip_bom(&input);

        // Template/rendering path
        let has_jinja = enable_jinja || has_jinja_syntax(input);
        let should_render_jinja = !jinja_preserve
            && has_jinja
            && (force_render_jinja || !jinja_vars.is_empty() || !jinja_var_files.is_empty());

        let input_for_formatting = if should_render_jinja {
            if let Some(ref mut renderer) = shared_renderer {
                match renderer.render(input) {
                    Ok(sql) => sql,
                    Err(e) => {
                        eprintln!();
                        eprintln!("ERROR {}: Jinja render error: {}", path_str, e);
                        error_count += 1;
                        continue;
                    }
                }
            } else {
                // No shared renderer - shouldn't happen if should_render_jinja is true
                eprintln!();
                eprintln!("ERROR {}: Internal error: missing renderer", path_str);
                error_count += 1;
                continue;
            }
        } else {
            input.to_string()
        };

        let input_for_parse = input_for_formatting.as_str();

        // Parse (use dialect from config)
        let script = match parse_sql_with_dialect(input_for_parse, config.dialect.as_ref()) {
            Ok(script) => script,
            Err(e) => {
                let (start, _end) = lexega_core::span_to_line_col(input, e.span);
                let error_msg = if start.line == 1 && start.col <= 3 {
                    let first_chars: String = input.chars().take(3).collect();
                    if first_chars
                        .chars()
                        .any(|c| !c.is_ascii() && c != '\u{FEFF}')
                    {
                        format!(
                            "{}:{}:{}: {} (possible encoding/BOM issue)",
                            path_str,
                            start.line,
                            start.col,
                            e.kind.message()
                        )
                    } else {
                        format!(
                            "{}:{}:{}: {}",
                            path_str,
                            start.line,
                            start.col,
                            e.kind.message()
                        )
                    }
                } else {
                    format!(
                        "{}:{}:{}: {}",
                        path_str,
                        start.line,
                        start.col,
                        e.kind.message()
                    )
                };
                eprintln!();
                eprintln!("ERROR {}", error_msg);
                error_count += 1;
                continue;
            }
        };

        // Format
        let mut fmt_ctx = RenderContext::from_source(input_for_parse);
        if has_jinja {
            fmt_ctx = fmt_ctx.mark_as_template();
        }
        let formatter = Formatter::with_config(config.clone());
        let formatted = match formatter.format_script(fmt_ctx, &script) {
            Ok(formatted_ctx) => match formatted_ctx.formatted() {
                Some(fc) => fc.formatted_sql().to_string(),
                None => {
                    eprintln!();
                    eprintln!(
                        "ERROR {}: Formatting failed - no output generated",
                        path_str
                    );
                    error_count += 1;
                    continue;
                }
            },
            Err(e) => {
                eprintln!();
                eprintln!("ERROR {}: Format error: {}", path_str, e);
                error_count += 1;
                continue;
            }
        };

        // Verify if requested
        if verify_mode && parse_sql_with_dialect(&formatted, config.dialect.as_ref()).is_err() {
            eprintln!();
            eprintln!(
                "ERROR {}: Verification failed - formatted output doesn't parse!",
                path_str
            );
            error_count += 1;
            continue;
        }

        // Check mode - just report if different
        if check_mode {
            if formatted != input_for_parse {
                eprintln!();
                eprintln!("ERROR {}: Would reformat", path_str);
                error_count += 1;
                continue;
            }
            formatted_count += 1;
            continue;
        }

        // Verify-only mode
        if verify_only_mode {
            formatted_count += 1;
            continue;
        }

        // Write back if requested
        if write_back {
            if let Err(e) = fs::write(path, &formatted) {
                eprintln!();
                eprintln!("ERROR {}: Write error: {}", path_str, e);
                error_count += 1;
                continue;
            }
        }

        formatted_count += 1;
    }

    // Clear progress line
    if !quiet_mode {
        eprintln!();
    }

    // Print comprehensive summary
    if !quiet_mode {
        eprintln!();
        eprintln!("Summary:");
        eprintln!("  {} file(s) checked", total);

        if check_mode {
            if error_count > 0 {
                eprintln!("  {} file(s) would be reformatted", error_count);
            } else {
                eprintln!("  All files are already formatted");
            }
        } else {
            eprintln!("  {} file(s) formatted successfully", formatted_count);

            if error_count > 0 {
                eprintln!("  {} parse error(s)", error_count);
            }
        }
    }

    if check_mode && error_count > 0 {
        process::exit(1);
    }
    if error_count > 0 {
        process::exit(1);
    }

    Ok(())
}

/// Handle the `fmt` subcommand for SQL formatting
pub fn handle_fmt_command(args: &[String], ext: &dyn Extension) {
    // Parse arguments (skip program name and "fmt" subcommand)
    let mut input_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut style: Option<String> = None;
    #[cfg(debug_assertions)]
    let mut keyword_case: Option<String> = None;
    #[cfg(not(debug_assertions))]
    let keyword_case: Option<String> = None;
    #[cfg(debug_assertions)]
    let mut identifier_case: Option<String> = None;
    #[cfg(not(debug_assertions))]
    let identifier_case: Option<String> = None;
    #[cfg(debug_assertions)]
    let mut alias_align_max_width: Option<usize> = None;
    #[cfg(not(debug_assertions))]
    let alias_align_max_width: Option<usize> = None;
    let mut check_mode = false;
    let mut verify_only_mode = false;
    #[cfg(debug_assertions)]
    let mut verify_mode = false;
    #[cfg(not(debug_assertions))]
    let verify_mode = false; // Always false in release (verification always on)
    #[cfg(debug_assertions)]
    let mut no_verify = false;
    #[cfg(not(debug_assertions))]
    let no_verify = false;
    #[cfg(debug_assertions)]
    let mut debug_tokens = false;
    #[cfg(not(debug_assertions))]
    let debug_tokens = false;
    #[cfg(debug_assertions)]
    let mut debug_stmts = false;
    #[cfg(debug_assertions)]
    let mut normalize_quoted_identifiers = false;
    #[cfg(not(debug_assertions))]
    let normalize_quoted_identifiers = false;
    let mut use_stdin = false;
    let mut recursive = false;
    let mut write_back = false;
    let mut jobs: Option<usize> = None;
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    let mut config_file: Option<String> = None;
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    let mut no_config = false;
    let mut quiet_mode = false;

    // Jinja/template rendering options
    let mut enable_jinja = false;
    let mut force_render_jinja = false;
    #[cfg(debug_assertions)]
    let mut jinja_preserve = false;
    #[cfg(not(debug_assertions))]
    let jinja_preserve = false;
    #[cfg(debug_assertions)]
    let mut jinja_format_sql: Option<bool> = None;
    #[cfg(not(debug_assertions))]
    let jinja_format_sql: Option<bool> = None;
    #[cfg(debug_assertions)]
    let mut jinja_indent_delimiters: Option<bool> = None;
    #[cfg(not(debug_assertions))]
    let jinja_indent_delimiters: Option<bool> = None;
    #[cfg(debug_assertions)]
    let mut jinja_content_indent: Option<usize> = None;
    #[cfg(not(debug_assertions))]
    let jinja_content_indent: Option<usize> = None;
    let mut jinja_vars: Vec<(String, String)> = Vec::new();
    let mut jinja_var_files: Vec<String> = Vec::new();
    let mut dbt_profile: Option<String> = None;
    let mut dbt_project_path: Option<String> = None;
    // `--load-macros` is accepted and has no effect: macros load whenever
    // a project is found.
    let mut _load_macros = false;
    let mut fail_on_missing_packages = false;

    // SQL dialect (defaults to Snowflake)
    let mut dialect_name: Option<String> = None;

    // Config overrides from CLI flags
    #[cfg(debug_assertions)]
    let mut config_overrides: Vec<(&str, String)> = Vec::new();
    #[cfg(not(debug_assertions))]
    let config_overrides: Vec<(&str, String)> = Vec::new();

    // Start at index 2 to skip program name and "fmt" subcommand
    let mut i = 2;

    while i < args.len() {
        match args[i].as_str() {
            "--stdin" => {
                use_stdin = true;
                i += 1;
            }
            "--output" | "-o" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --output requires a filename");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                output_file = Some(args[i + 1].clone());
                i += 2;
            }
            "--preset" | "--style" | "-s" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --style/--preset requires a style name (compact, readable, ultra)"
                    );
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                style = Some(args[i + 1].clone());
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--keyword-case" => {
                if i + 1 >= args.len() {
                    eprintln!(
                        "Error: --keyword-case requires a value (upper, lower, title, preserve)"
                    );
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                keyword_case = Some(args[i + 1].clone());
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--identifier-case" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --identifier-case requires a value (upper, lower, preserve)");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                identifier_case = Some(args[i + 1].clone());
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--alias-align-max-width" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --alias-align-max-width requires a numeric value");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                match args[i + 1].parse::<usize>() {
                    Ok(n) => alias_align_max_width = Some(n),
                    Err(_) => {
                        eprintln!("Error: --alias-align-max-width must be a number");
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "--check" => {
                check_mode = true;
                i += 1;
            }
            "--verify-only" => {
                verify_only_mode = true;
                i += 1;
            }
            #[cfg(debug_assertions)]
            "--verify" => {
                verify_mode = true;
                i += 1;
            }
            "--use-cst" | "--v2" | "--use-cst-formatter" => {
                // v2 formatter is now the default (and only) formatter
                i += 1;
            }
            "--recursive" | "-r" => {
                recursive = true;
                i += 1;
            }
            "--write" | "-w" => {
                write_back = true;
                i += 1;
            }
            "--jobs" | "-j" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --jobs requires a number");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                match args[i + 1].parse::<usize>() {
                    Ok(n) if n > 0 => jobs = Some(n),
                    _ => {
                        eprintln!("Error: --jobs must be a positive number");
                        process::exit(1);
                    }
                }
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--config" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --config requires a path to .lexega.toml");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                config_file = Some(args[i + 1].clone());
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--no-config" => {
                no_config = true;
                i += 1;
            }
            #[cfg(debug_assertions)]
            "--normalize-quoted-identifiers" | "-Q" => {
                normalize_quoted_identifiers = true;
                i += 1;
            }
            #[cfg(debug_assertions)]
            "--no-verify" => {
                no_verify = true;
                i += 1;
            }
            "--jinja" => {
                enable_jinja = true;
                i += 1;
            }
            "--render-jinja" | "--render" => {
                // Force template rendering even with no explicit variables.
                // This is useful for `--lint` on rendered SQL.
                // Keep --render as alias for backward compatibility
                enable_jinja = true;
                force_render_jinja = true;
                i += 1;
            }
            #[cfg(debug_assertions)]
            "--jinja-preserve" => {
                jinja_preserve = true;
                i += 1;
            }
            #[cfg(debug_assertions)]
            "--jinja-format-sql" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --jinja-format-sql requires true/false");
                    process::exit(1);
                }
                jinja_format_sql = Some(matches!(
                    args[i + 1].to_lowercase().as_str(),
                    "true" | "1" | "yes"
                ));
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--jinja-indent-delim" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --jinja-indent-delim requires true/false");
                    process::exit(1);
                }
                jinja_indent_delimiters = Some(matches!(
                    args[i + 1].to_lowercase().as_str(),
                    "true" | "1" | "yes"
                ));
                i += 2;
            }
            #[cfg(debug_assertions)]
            "--jinja-content-indent" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --jinja-content-indent requires a number");
                    process::exit(1);
                }
                if let Ok(n) = args[i + 1].parse::<usize>() {
                    jinja_content_indent = Some(n);
                } else {
                    eprintln!("Error: --jinja-content-indent requires a number");
                    process::exit(1);
                }
                i += 2;
            }
            "--var" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --var requires KEY=VALUE");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                let pair = &args[i + 1];
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() != 2 {
                    eprintln!("Error: --var requires KEY=VALUE format (got '{}')", pair);
                    process::exit(1);
                }
                jinja_vars.push((parts[0].to_string(), parts[1].to_string()));
                i += 2;
            }
            "--var-file" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --var-file requires a filename");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                jinja_var_files.push(args[i + 1].clone());
                i += 2;
            }
            "--dbt-profile" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --dbt-profile requires a profile name");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                dbt_profile = Some(args[i + 1].clone());
                i += 2;
            }
            "--dbt-project" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --dbt-project requires a directory path");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                dbt_project_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--load-macros" => {
                _load_macros = true;
                i += 1;
            }
            "--fail-on-missing-packages" => {
                fail_on_missing_packages = true;
                i += 1;
            }
            "--dialect" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --dialect requires a value (snowflake|postgresql|bigquery|databricks|redshift)");
                    process::exit(1);
                }
                dialect_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--debug-tokens" => {
                #[cfg(debug_assertions)]
                {
                    debug_tokens = true;
                    i += 1;
                }

                #[cfg(not(debug_assertions))]
                {
                    eprintln!("Error: --debug-tokens is only available in debug builds.");
                    process::exit(2);
                }
            }
            "--debug-stmts" => {
                #[cfg(debug_assertions)]
                {
                    debug_stmts = true;
                    i += 1;
                }

                #[cfg(not(debug_assertions))]
                {
                    eprintln!("Error: --debug-stmts is only available in debug builds.");
                    process::exit(2);
                }
            }
            "--help" | "-h" => {
                print_fmt_usage(&args[0], ext);
                process::exit(0);
            }
            "--quiet" | "-q" => {
                quiet_mode = true;
                i += 1;
            }
            // Config options that take values (only available in debug builds)
            #[cfg(debug_assertions)]
            opt @ ("--indent-width"
            | "--max-line-length"
            | "--comma-style"
            | "--trailing-comma"
            | "--clauses-on-newlines"
            | "--select-items-on-newlines"
            | "--where-conditions-on-newlines"
            | "--joins-on-newlines"
            | "--group-by-items-on-newlines"
            | "--order-by-items-on-newlines"
            | "--from-tables-on-newlines"
            | "--spaces-around-operators"
            | "--space-after-comma"
            | "--align-select-items"
            | "--align-select-aliases"
            | "--align-joins"
            | "--align-join-conditions"
            | "--join-on-clause-on-newline"
            | "--indent-join-on-clause"
            | "--boolean-operator-position"
            | "--align-column-definitions"
            | "--align-update-set"
            | "--indent-clauses"
            | "--indent-subqueries"
            | "--uppercase-boolean-operators"
            | "--semicolon-on-newline"
            | "--indent-case-then"
            | "--parenthesized-expr-style"
            | "--normalize-join-keywords"
            | "--scripting-statement-spacing"
            | "--compact-simple-select"
            | "--case-when-aligned"
            | "--case-style-compact"
            | "--case-expression-on-newline"
            | "--in-list-threshold"
            | "--in-list-items-per-line"
            | "--in-list-style"
            | "--window-function-on-newline"
            | "--partition-by-on-newline"
            | "--order-by-in-window-on-newline"
            | "--window-frame-style"
            | "--cte-name-on-newline"
            | "--cte-indent-style"
            | "--subquery-paren-style"
            | "--flatten-style"
            | "--copy-into-options-style"
            | "--match-recognize-format"
            | "--match-recognize-measures-style"
            | "--match-recognize-define-style"
            | "--array-literal-style"
            | "--match-recognize-on-newline"
            | "--array-literal-threshold"
            | "--object-literal-style") => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires a value", opt);
                    process::exit(1);
                }
                config_overrides.push((opt, args[i + 1].clone()));
                i += 2;
            }
            arg if arg.starts_with('-') => {
                eprintln!("Error: Unknown option: {}", arg);
                eprintln!("Run '{} fmt --help' for usage information.", args[0]);
                process::exit(1);
            }
            _ => {
                if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else {
                    eprintln!("Error: Multiple input files specified");
                    print_fmt_usage(&args[0], ext);
                    process::exit(1);
                }
                i += 1;
            }
        }
    }

    // Rendering templates is up to the build.
    if force_render_jinja
        || !jinja_vars.is_empty()
        || !jinja_var_files.is_empty()
        || dbt_project_path.is_some()
        || dbt_profile.is_some()
    {
        ext.authorize(&args[0], &[Capability::TemplateRendering]);
    }

    // Load base configuration from file or use default
    let mut config = if let Some(ref config_path) = config_file {
        // Explicit --config flag provided
        match FormatterConfig::from_toml_file(std::path::Path::new(config_path)) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error loading config file '{}': {}", config_path, e);
                process::exit(1);
            }
        }
    } else if !no_config {
        // Auto-discover .lexega.toml from input file directory
        if let Some(ref input) = input_file {
            let input_path = std::path::Path::new(input);
            if let Some(discovered_path) = FormatterConfig::discover(input_path) {
                match FormatterConfig::from_toml_file(&discovered_path) {
                    Ok(cfg) => {
                        eprintln!("Using config file: {}", discovered_path.display());
                        cfg
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to load discovered config file '{}': {}",
                            discovered_path.display(),
                            e
                        );
                        eprintln!("Falling back to default configuration");
                        FormatterConfig::default()
                    }
                }
            } else {
                FormatterConfig::default()
            }
        } else {
            FormatterConfig::default()
        }
    } else {
        // --no-config flag provided, skip config file loading
        FormatterConfig::default()
    };

    // Apply style preset (overrides config file settings)
    config = match style.as_deref() {
        Some("compact") | Some("c") => FormatterConfig::compact(),
        Some("readable") | Some("r") => FormatterConfig::readable(),
        Some("ultra") | Some("u") | Some("ultra-readable") | Some("ultra_readable") => {
            FormatterConfig::ultra_readable()
        }
        Some("default") => FormatterConfig::default(),
        Some("custom") => config, // Keep loaded config
        Some(s) => {
            eprintln!("Error: Unknown style '{}'. Valid styles: compact, readable, ultra, default, custom", s);
            process::exit(1);
        }
        None => config, // Keep loaded config
    };

    // Apply keyword casing override (takes precedence over config file)
    if let Some(case) = keyword_case {
        config.keyword_case = match case.to_lowercase().as_str() {
            "upper" => lexega_core::KeywordCase::Upper,
            "lower" => lexega_core::KeywordCase::Lower,
            "title" => lexega_core::KeywordCase::Title,
            "preserve" => lexega_core::KeywordCase::Preserve,
            _ => {
                eprintln!("Error: Invalid keyword case '{}'. Valid options: upper, lower, title, preserve", case);
                process::exit(1);
            }
        };
    }

    // Apply identifier casing override (takes precedence over config file)
    if let Some(case) = identifier_case {
        config.identifier_case = match case.to_lowercase().as_str() {
            "upper" => lexega_core::IdentifierCase::Upper,
            "lower" => lexega_core::IdentifierCase::Lower,
            "preserve" => lexega_core::IdentifierCase::Preserve,
            _ => {
                eprintln!(
                    "Error: Invalid identifier case '{}'. Valid options: upper, lower, preserve",
                    case
                );
                process::exit(1);
            }
        };
    }

    // Apply alias alignment width override
    if let Some(width) = alias_align_max_width {
        config.alias_align_max_width = width;
    }

    // Apply CLI flag overrides
    // `--normalize-quoted-identifiers` is accepted and not applied.
    if normalize_quoted_identifiers {
        eprintln!("Warning: --normalize-quoted-identifiers not yet supported");
    }

    // Apply Jinja/dbt formatting flags
    if jinja_preserve {
        config.jinja_preserve_original = true;
    }
    if let Some(v) = jinja_format_sql {
        config.jinja_format_sql_content = v;
    }
    if let Some(v) = jinja_indent_delimiters {
        config.jinja_indent_delimiters = v;
    }
    if let Some(n) = jinja_content_indent {
        config.jinja_content_indent_level = n;
    }

    // Apply dialect override (takes precedence over config file)
    if let Some(ref name) = dialect_name {
        match resolve_dialect(name) {
            Some(d) => config.dialect = d,
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

    // Apply debug/verification flags
    if no_verify {
        config.skip_verification = true;
    }

    // Apply all config overrides from CLI flags
    for (flag, value) in config_overrides {
        let bool_value = matches!(value.to_lowercase().as_str(), "true" | "1" | "yes");

        match flag {
            "--indent-width" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.indent_style = lexega_core::IndentStyle::Spaces(n);
                }
            }
            "--max-line-length" => {
                if let Ok(v) = value.parse::<usize>() {
                    config.max_line_length = v;
                }
            }
            "--trailing-comma" => {
                config.trailing_commas = bool_value;
            }
            "--clauses-on-newlines" => {
                config.clauses_on_newlines = bool_value;
            }
            "--select-items-on-newlines" => {
                config.select_items_on_newlines = bool_value;
            }
            "--where-conditions-on-newlines" => {
                config.where_conditions_on_newlines = bool_value;
            }
            "--joins-on-newlines" => {
                config.joins_on_newlines = bool_value;
            }
            "--group-by-items-on-newlines" => {
                config.group_by_items_on_newlines = bool_value;
            }
            "--order-by-items-on-newlines" => {
                config.order_by_items_on_newlines = bool_value;
            }
            "--from-tables-on-newlines" => {
                config.from_tables_on_newlines = bool_value;
            }
            "--spaces-around-operators" => {
                config.spaces_around_operators = bool_value;
            }
            "--space-after-comma" => {
                config.space_after_comma = bool_value;
            }
            "--align-select-items" | "--align-select-aliases" => {
                config.align_select_aliases = bool_value;
            }
            "--align-joins" => {
                config.align_joins = bool_value;
            }
            "--align-join-conditions" => {
                config.align_join_conditions = bool_value;
            }
            "--join-on-clause-on-newline" => {
                config.join_on_clause_on_newline = bool_value;
            }
            "--indent-join-on-clause" => {
                config.indent_join_on_clause = bool_value;
            }
            "--boolean-operator-position" => {
                use lexega_core::BooleanOperatorPosition;
                config.boolean_operator_position = match value.to_lowercase().as_str() {
                    "end" | "e" => BooleanOperatorPosition::End,
                    "start" | "s" => BooleanOperatorPosition::Start,
                    _ => BooleanOperatorPosition::End,
                };
            }
            "--align-column-definitions" => {
                config.align_column_definitions = bool_value;
            }
            "--align-update-set" => {
                config.align_update_set = bool_value;
            }
            "--indent-clauses" => {
                // Map to multiple indent flags
                config.indent_select_items = bool_value;
                config.indent_from_tables = bool_value;
                config.indent_group_by_items = bool_value;
                config.indent_order_by_items = bool_value;
            }
            "--indent-subqueries" => {
                config.indent_subqueries = bool_value;
            }
            "--uppercase-boolean-operators" => {
                config.uppercase_boolean_operators = bool_value;
            }
            "--semicolon-on-newline" => {
                config.semicolon_on_newline = bool_value;
            }
            "--indent-case-then" => {
                config.indent_case_then = bool_value;
            }
            "--parenthesized-expr-style" => {
                use lexega_core::ParenthesizedExprStyle;
                config.parenthesized_expr_style = match value.to_lowercase().as_str() {
                    "compact" | "c" => ParenthesizedExprStyle::Compact,
                    "expanded" | "e" => ParenthesizedExprStyle::Expanded,
                    _ => ParenthesizedExprStyle::Compact,
                };
            }
            "--normalize-join-keywords" => {
                config.normalize_join_keywords = bool_value;
            }
            "--scripting-statement-spacing" => {
                config.scripting_statement_spacing = bool_value;
            }
            "--compact-simple-select" => {
                config.compact_simple_select = bool_value;
            }
            "--case-when-aligned" => {
                config.case_when_aligned = bool_value;
            }
            "--case-style-compact" => {
                config.case_style_compact = bool_value;
            }
            "--case-expression-on-newline" => {
                config.case_expression_on_newline = bool_value;
            }
            "--in-list-threshold" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.in_list_threshold = n;
                }
            }
            "--in-list-items-per-line" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.in_list_items_per_line = n;
                }
            }
            "--in-list-style" => {
                // Map to in_list_items_per_line: 0 = inline (compact), N = items per line
                match value.to_lowercase().as_str() {
                    "compact" | "c" => config.in_list_items_per_line = 5,
                    "oneperline" | "one-per-line" | "o" => config.in_list_items_per_line = 1,
                    _ => {}
                }
            }
            "--window-function-on-newline" => {
                config.window_function_on_newline = bool_value;
            }
            "--indent-window-function-clauses" => {
                config.indent_window_function_clauses = bool_value;
            }
            "--partition-by-on-newline" => {
                config.partition_by_on_newline = bool_value;
            }
            "--order-by-in-window-on-newline" => {
                config.order_by_in_window_on_newline = bool_value;
            }
            "--window-frame-style" => {
                use lexega_core::WindowFrameStyle;
                config.window_frame_style = match value.to_lowercase().as_str() {
                    "compact" | "c" => WindowFrameStyle::Compact,
                    "expanded" | "e" => WindowFrameStyle::Expanded,
                    _ => WindowFrameStyle::Compact,
                };
            }
            "--cte-name-on-newline" => {
                config.cte_name_on_newline = bool_value;
            }
            "--cte-indent-style" => {
                use lexega_core::CteIndentStyle;
                config.cte_indent_style = match value.to_lowercase().as_str() {
                    "standard" | "s" => CteIndentStyle::Standard,
                    "flushleft" | "flush-left" | "f" => CteIndentStyle::FlushLeft,
                    "doubleindent" | "double-indent" | "d" => CteIndentStyle::DoubleIndent,
                    _ => CteIndentStyle::Standard,
                };
            }
            "--subquery-paren-style" => {
                use lexega_core::SubqueryParenStyle;
                config.subquery_paren_style = match value.to_lowercase().as_str() {
                    "sameline" | "same-line" | "s" => SubqueryParenStyle::SameLine,
                    "newline" | "new-line" | "n" => SubqueryParenStyle::NewLine,
                    "newlineclosing" | "new-line-closing" | "c" => {
                        SubqueryParenStyle::NewLineClosing
                    }
                    _ => SubqueryParenStyle::SameLine,
                };
            }
            "--flatten-style" => {
                use lexega_core::FlattenStyle;
                config.flatten_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => FlattenStyle::Inline,
                    "stacked" | "s" => FlattenStyle::Stacked,
                    _ => FlattenStyle::Inline,
                };
            }
            "--copy-into-options-style" => {
                use lexega_core::CopyIntoOptionsStyle;
                config.copy_into_options_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => CopyIntoOptionsStyle::Inline,
                    "stacked" | "s" => CopyIntoOptionsStyle::Stacked,
                    "grouped" | "g" => CopyIntoOptionsStyle::Grouped,
                    _ => CopyIntoOptionsStyle::Stacked,
                };
            }
            "--match-recognize-format" => {
                use lexega_core::MatchRecognizeFormat;
                config.match_recognize_format = match value.to_lowercase().as_str() {
                    "compact" | "c" => MatchRecognizeFormat::Compact,
                    "expanded" | "e" => MatchRecognizeFormat::Expanded,
                    _ => MatchRecognizeFormat::Compact,
                };
            }
            "--match-recognize-on-newline" => {
                config.match_recognize_on_newline = bool_value;
            }
            "--match-recognize-measures-style" => {
                use lexega_core::MatchRecognizeMeasuresStyle;
                config.match_recognize_measures_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => MatchRecognizeMeasuresStyle::Inline,
                    "oneperline" | "one-per-line" | "o" => MatchRecognizeMeasuresStyle::OnePerLine,
                    "threshold" | "t" => MatchRecognizeMeasuresStyle::Threshold(3),
                    _ => MatchRecognizeMeasuresStyle::Threshold(3),
                };
            }
            "--match-recognize-define-style" => {
                use lexega_core::MatchRecognizeDefineStyle;
                config.match_recognize_define_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => MatchRecognizeDefineStyle::Inline,
                    "oneperline" | "one-per-line" | "o" => MatchRecognizeDefineStyle::OnePerLine,
                    "threshold" | "t" => MatchRecognizeDefineStyle::Threshold(2),
                    _ => MatchRecognizeDefineStyle::Threshold(2),
                };
            }
            "--array-literal-style" => {
                use lexega_core::ArrayLiteralStyle;
                config.array_literal_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => ArrayLiteralStyle::Inline,
                    "multiline" | "m" => ArrayLiteralStyle::Multiline,
                    _ => ArrayLiteralStyle::Inline,
                };
            }
            "--array-literal-threshold" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.array_literal_threshold = n;
                }
            }
            "--object-literal-style" => {
                use lexega_core::ObjectLiteralStyle;
                config.object_literal_style = match value.to_lowercase().as_str() {
                    "inline" | "i" => ObjectLiteralStyle::Inline,
                    "multiline" | "m" => ObjectLiteralStyle::Multiline,
                    _ => ObjectLiteralStyle::Inline,
                };
            }
            "--comma-style" => {
                use lexega_core::CommaStyle;
                config.comma_style = match value.to_lowercase().as_str() {
                    "trailing" | "t" => CommaStyle::Trailing,
                    "leading" | "l" => CommaStyle::Leading,
                    _ => CommaStyle::Trailing,
                };
            }
            _ => {} // Ignore unknown config options
        }
    }

    // Handle batch mode (directory or glob patterns)
    if let Some(ref path) = input_file {
        let path_obj = Path::new(path);
        let is_directory = path_obj.is_dir();
        let is_glob = path.contains('*') || path.contains('?');

        if is_directory || is_glob {
            // Batch mode
            if write_back && check_mode {
                eprintln!("Error: --write and --check are mutually exclusive");
                process::exit(1);
            }
            if write_back && verify_only_mode {
                eprintln!("Error: --write and --verify-only are mutually exclusive");
                process::exit(1);
            }

            if output_file.is_some() {
                eprintln!("Error: --output cannot be used with directory/glob batch formatting");
                process::exit(1);
            }

            // The pool runs the parser: give workers the parser's documented
            // minimum stack (rayon's 2 MiB default is below the parse stack
            // budget, so the graceful depth trip could not fire before the
            // guard page).
            let mut pool_builder =
                rayon::ThreadPoolBuilder::new().stack_size(lexega_core::MIN_PARSE_STACK_BYTES);
            if let Some(n) = jobs {
                pool_builder = pool_builder.num_threads(n);
            }
            pool_builder.build_global().unwrap_or_else(|e| {
                eprintln!("Warning: Could not set thread pool size: {}", e);
            });

            let found = collect_sql_files(path, recursive);
            if !quiet_mode {
                for skipped in &found.skipped {
                    eprintln!(
                        "  - {} - skipped ({})",
                        skipped.path.display(),
                        skipped.reason
                    );
                }
            }
            let files = found.files;

            if files.is_empty() {
                eprintln!("No SQL files found matching: {}", path);
                process::exit(1);
            }

            match format_batch(
                files,
                &config,
                write_back,
                check_mode,
                verify_only_mode,
                verify_mode,
                enable_jinja,
                force_render_jinja,
                jinja_preserve,
                &jinja_vars,
                &jinja_var_files,
                dbt_profile.clone(),
                dbt_project_path.clone(),
                fail_on_missing_packages,
                quiet_mode,
                ext,
            ) {
                Ok(_) => return,
                Err(e) => {
                    eprintln!("Batch formatting failed: {}", e);
                    process::exit(1);
                }
            }
        }
    }

    // Single-file mode (stdin or single file path)
    // Auto-detect stdin: if no file provided and stdin is piped (not a TTY), read from stdin
    let use_stdin = use_stdin || (input_file.is_none() && !io::stdin().is_terminal());

    // Read input: either from stdin or from the specified file
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
        print_fmt_usage(&args[0], ext);
        process::exit(1);
    };

    // Strip UTF-8 BOM if present
    let input = strip_bom(&input);

    let has_jinja_in_input = enable_jinja || has_jinja_syntax(input);

    // Determine if we should render Jinja or format as-is
    // By default, only render if user explicitly provided variables (--var or --var-file).
    // If --render is provided, force rendering even with no explicit variables.
    // If --jinja-preserve is provided, always preserve (never render).
    let should_render_jinja = !jinja_preserve
        && has_jinja_in_input
        && (force_render_jinja || !jinja_vars.is_empty() || !jinja_var_files.is_empty());

    // After rendering, formatted_input is pure SQL (no Jinja), so track that
    let (formatted_input, has_jinja) = if should_render_jinja {
        if !debug_tokens {
            if force_render_jinja && jinja_vars.is_empty() && jinja_var_files.is_empty() {
                eprintln!("🔧 Jinja template detected, rendering (--render-jinja)");
            } else {
                eprintln!("🔧 Jinja template detected with variables provided, rendering automatically...");
            }
        }

        let mut renderer = match ext.format_renderer(&FormatRenderOptions {
            jinja_vars: &jinja_vars,
            jinja_var_files: &jinja_var_files,
            dbt_project_path: dbt_project_path.as_deref(),
            dbt_profile: dbt_profile.as_deref(),
            fail_on_missing_packages,
            quiet: debug_tokens,
            batch: false,
        }) {
            Ok(renderer) => renderer,
            Err(e) => {
                eprintln!("Error setting up dbt environment: {}", e);
                process::exit(1);
            }
        };

        match renderer.render(input) {
            Ok(sql) => {
                if !debug_tokens {
                    eprintln!("✓ Template rendered successfully");
                    eprintln!("ℹ️  Formatting rendered SQL (Jinja structure not preserved)");
                }
                // After rendering, the output is pure SQL (no Jinja)
                (sql, false)
            }
            Err(e) => {
                eprintln!("Error rendering Jinja template: {}", e);
                eprintln!();
                eprintln!("Template rendering failed. Common issues:");
                eprintln!("  - Undefined variables (use --var KEY=VALUE)");
                eprintln!("  - Syntax errors in Jinja expressions");
                eprintln!("  - Missing dbt project (for ref/source functions)");
                process::exit(1);
            }
        }
    } else if has_jinja_in_input {
        if !debug_tokens {
            eprintln!("🔧 Jinja template detected, formatting with Jinja preserved");
            eprintln!("ℹ️  To render and format, use --render (or provide variables with --var/--var-file)");
        }
        // Jinja preserved in output
        (input.to_string(), true)
    } else {
        // No Jinja, process as-is
        (input.to_string(), false)
    };

    // Use the prepared input for formatting
    let input = formatted_input.as_str();

    // Determine output path
    let output_path = output_file.clone();

    // If requested, dump tokens/trivia for debugging and exit (debug builds only)
    #[cfg(debug_assertions)]
    if debug_tokens {
        let tokens = lexer::tokenize_with_dialect(input, config.dialect.as_ref()).tokens;
        for (idx, tok) in tokens.iter().enumerate() {
            eprintln!(
                "{}: {:?} '{}' [{}..{}]",
                idx,
                tok.kind,
                tok.lexeme(input),
                tok.span.start,
                tok.span.end
            );
            use lexega_core::lexer::TriviaKind;
            for trivia in &tok.leading_trivia {
                match trivia.kind {
                    TriviaKind::LineComment
                    | TriviaKind::BlockComment
                    | TriviaKind::JinjaComment
                    | TriviaKind::MysqlVersionComment => {
                        eprintln!(
                            "    leading {:?} [{}..{}]",
                            trivia.kind, trivia.span.start, trivia.span.end
                        );
                    }
                    _ => {}
                }
            }
            for trivia in &tok.trailing_trivia {
                match trivia.kind {
                    TriviaKind::LineComment
                    | TriviaKind::BlockComment
                    | TriviaKind::JinjaComment
                    | TriviaKind::MysqlVersionComment => {
                        eprintln!(
                            "    trailing {:?} [{}..{}]",
                            trivia.kind, trivia.span.start, trivia.span.end
                        );
                    }
                    _ => {}
                }
            }
        }
        return;
    }

    // If requested, dump parsed statements for debugging and exit (debug builds only)
    #[cfg(debug_assertions)]
    if debug_stmts {
        match parse_sql_with_dialect(input, config.dialect.as_ref()) {
            Ok(script) => {
                eprintln!("=== Parsed {} statement(s) ===", script.stmts.len());
                eprintln!();
                for (idx, stmt) in script.stmts.iter().enumerate() {
                    let span = stmt.span();
                    let stmt_text = &input[span.start as usize..span.end as usize];
                    let preview: String = stmt_text.chars().take(80).collect();
                    let preview = if stmt_text.len() > 80 {
                        format!("{}...", preview)
                    } else {
                        preview
                    };
                    // Clean up preview for display
                    let preview = preview.replace('\n', "↵").replace('\r', "");

                    // Get statement type name from AST variant using Debug output
                    let debug_str = format!("{:?}", stmt);
                    // Extract just the variant name (first word before '(' or '{' or whitespace)
                    let stmt_type = debug_str
                        .split(|c: char| c == '(' || c == '{' || c.is_whitespace())
                        .next()
                        .unwrap_or("Unknown");

                    eprintln!(
                        "Statement {}: {} [{}..{}] ({} bytes)",
                        idx,
                        stmt_type,
                        span.start,
                        span.end,
                        span.end - span.start
                    );
                    eprintln!("  Preview: {}", preview);

                    // Show line numbers
                    let (start_loc, end_loc) = lexega_core::span_to_line_col(input, span);
                    eprintln!(
                        "  Lines: {}:{} - {}:{}",
                        start_loc.line, start_loc.col, end_loc.line, end_loc.col
                    );
                    eprintln!();
                }

                // Also show overlapping spans if any
                let spans: Vec<_> = script.stmts.iter().map(|s| s.span()).collect();
                let mut overlaps = Vec::new();
                for i in 0..spans.len() {
                    for j in (i + 1)..spans.len() {
                        // Check if spans overlap (not just adjacent)
                        if spans[i].start < spans[j].end && spans[j].start < spans[i].end {
                            overlaps.push((i, j));
                        }
                    }
                }
                if !overlaps.is_empty() {
                    eprintln!(
                        "⚠️  WARNING: {} overlapping span pairs detected:",
                        overlaps.len()
                    );
                    for (i, j) in overlaps {
                        eprintln!(
                            "  Statement {} [{}..{}] overlaps Statement {} [{}..{}]",
                            i, spans[i].start, spans[i].end, j, spans[j].start, spans[j].end
                        );
                    }
                    eprintln!();
                }
            }
            Err(e) => {
                eprintln!("Parse error: {}", e.kind.message());
                eprintln!("  Span: {}..{}", e.span.start, e.span.end);
                let (loc, _) = lexega_core::span_to_line_col(input, e.span);
                eprintln!("  Location: line {}, col {}", loc.line, loc.col);
                process::exit(1);
            }
        }
        return;
    }

    // Try to parse as a script (multiple statements) first using Result-based API
    let formatted = match parse_sql_with_dialect(input, config.dialect.as_ref()) {
        Ok(script) => {
            // Format
            let mut fmt_ctx = RenderContext::from_source(input);
            if has_jinja {
                fmt_ctx = fmt_ctx.mark_as_template();
            }
            let formatter = Formatter::with_config(config.clone());
            let formatted_ctx = formatter
                .format_script(fmt_ctx, &script)
                .unwrap_or_else(|e| {
                    eprintln!("Format error: {}", e);
                    process::exit(1);
                });
            formatted_ctx
                .formatted()
                .unwrap_or_else(|| {
                    eprintln!("Format error: no output generated");
                    process::exit(1);
                })
                .formatted_sql()
                .to_string()
        }
        Err(script_err) => {
            // Script parsing failed - use rich error formatting
            let file_display = input_file.as_deref();
            let rich_error = script_err.format_rich(input, file_display);
            eprint!("{}", rich_error);

            // Check for encoding issues at start of file
            let (start, _) = lexega_core::span_to_line_col(input, script_err.span);
            if start.line == 1 && start.col <= 3 {
                let first_chars: String = input.chars().take(3).collect();
                if first_chars
                    .chars()
                    .any(|c| !c.is_ascii() && c != '\u{FEFF}')
                {
                    eprintln!("⚠️  Warning: File starts with non-ASCII characters - possible encoding/BOM issue.");
                    eprintln!("   Ensure file is saved as UTF-8 without BOM.\n");
                }
            }

            eprintln!("The input contains syntax errors that must be fixed before formatting.");
            eprintln!("This prevents partial formatting that could corrupt your SQL.");
            process::exit(1);
        }
    };

    // Apply reverse mapping if Jinja was used
    // For render mode (with variables), output is rendered SQL
    // For normal format mode, output is the formatted input (with Jinja preserved)
    let final_output = formatted.clone();

    // Perform verification AFTER formatting to catch any data loss
    // ALWAYS verify in both debug and release builds unless explicitly skipped
    // This catches token loss and data corruption before outputting malformed SQL
    let verification_needed = !config.skip_verification;

    if verification_needed {
        // Verify formatting safety (token count, comment preservation, etc.)
        match lexega_core::verify_formatting_safe_with_dialect(
            input,
            &formatted,
            config.dialect.as_ref(),
        ) {
            Ok(()) => {
                if verify_only_mode {
                    if has_jinja {
                        eprintln!("✓ Jinja template formatting verified safe");
                    } else {
                        eprintln!("✓ Formatting verified safe");
                    }
                    process::exit(0);
                } else if check_mode {
                    // Check mode: verify formatting is safe AND check if content would change
                    // Normalize trailing newlines for comparison since we always ensure
                    // output ends with a newline when writing (see println! below)
                    let input_normalized = input.strip_suffix('\n').unwrap_or(input);
                    let formatted_normalized = formatted.strip_suffix('\n').unwrap_or(&formatted);
                    if formatted_normalized != input_normalized {
                        eprintln!(
                            "Would reformat: {}",
                            input_file.as_deref().unwrap_or("<stdin>")
                        );
                        process::exit(1);
                    }
                    if has_jinja {
                        eprintln!("✓ Already formatted (Jinja template)");
                    } else {
                        eprintln!("✓ Already formatted");
                    }
                    process::exit(0);
                }
            }
            Err(msg) => {
                eprintln!("❌ Formatting verification failed:");
                eprintln!("{}", msg);
                eprintln!("\nThis indicates potential data loss or corruption.");
                eprintln!("Original SQL was NOT modified.");
                process::exit(1);
            }
        }
    } else if verify_only_mode {
        // Verify-only mode but verification is skipped (debug with --no-verify)
        eprintln!("⚠ Verification skipped (--no-verify)");
        process::exit(0);
    } else if check_mode {
        // Check mode without verification - still check if content would change
        // Normalize trailing newlines for comparison since we always ensure
        // output ends with a newline when writing (see println! below)
        let input_normalized = input.strip_suffix('\n').unwrap_or(input);
        let formatted_normalized = formatted.strip_suffix('\n').unwrap_or(&formatted);
        if formatted_normalized != input_normalized {
            eprintln!(
                "Would reformat: {}",
                input_file.as_deref().unwrap_or("<stdin>")
            );
            process::exit(1);
        }
        eprintln!("✓ Already formatted (verification skipped)");
        process::exit(0);
    }

    if check_mode {
        // Check mode but no verification (release build without check/verify flags)
        eprintln!("✓ Formatting completed (verification skipped in release mode)");
        process::exit(0);
    }

    // Determine where to write output
    // Priority: -o flag > -w flag (write back to input) > stdout
    let write_path = if let Some(ref out_path) = output_path {
        Some(out_path.clone())
    } else if write_back {
        // Write back to input file (single file mode)
        input_file.clone()
    } else {
        None
    };

    if let Some(out_path) = write_path {
        fs::write(&out_path, &final_output).unwrap_or_else(|e| {
            eprintln!("Error writing to '{}': {}", out_path, e);
            process::exit(1);
        });
        if !quiet_mode {
            eprintln!("Formatted SQL written to '{}'", out_path);
        }
    } else {
        // Use print! to avoid double newlines, but ensure output ends with newline
        if final_output.ends_with('\n') {
            print!("{}", final_output);
        } else {
            println!("{}", final_output);
        }
    }
}
