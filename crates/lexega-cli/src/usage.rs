// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Usage and help text.

use super::cmd_catalog::BUNDLED_PULL_PROVIDERS;
use super::extension::{Capability, Extension};

pub fn print_top_usage(program: &str) {
    eprintln!("Usage: {} <COMMAND> [OPTIONS]", program);
    eprintln!();
    eprintln!("Pre-execution SQL analysis for Snowflake, Databricks, BigQuery, PostgreSQL, MySQL and SQL Server");
    eprintln!();
    eprintln!("Commands:");
    eprintln!(
        "  analyze      Pre-execution risk analysis (see: {} analyze --help)",
        program
    );
    eprintln!(
        "  review       Analyze the SQL files a commit range changes (see: {} review --help)",
        program
    );
    eprintln!(
        "  ci           CI entry point — review (PRs) or analyze (pushes), picked from the pipeline event (see: {} ci --help)",
        program
    );
    eprintln!(
        "  catalog      Catalog snapshot operations (see: {} catalog --help)",
        program
    );
    eprintln!(
        "  fmt          Format SQL files (see: {} fmt --help)",
        program
    );
    eprintln!();
    eprintln!("Global Options:");
    eprintln!(
        "  --dialect <DIALECT>  SQL dialect: snowflake (default), postgresql, bigquery, mysql, mssql, databricks, redshift"
    );
    eprintln!("  -h, --help          Show this help message");
    eprintln!("  -V, --version       Show the version");
    eprintln!("  --licenses          Show third-party licenses");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} analyze query.sql", program);
    eprintln!(
        "  {} analyze models/ -r --format sarif > results.sarif",
        program
    );
    eprintln!("  {} review main..HEAD --pr-comment", program);
    eprintln!("  {} fmt query.sql", program);
}

pub fn print_fmt_usage(program: &str, ext: &dyn Extension) {
    let renders = ext.offers(Capability::TemplateRendering);
    eprintln!("Usage: {} fmt [OPTIONS] <FILE|DIRECTORY|GLOB>", program);
    eprintln!();
    eprintln!("Format SQL files (Snowflake and PostgreSQL)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --dialect <DIALECT>      SQL dialect: snowflake (default), postgresql, bigquery, mysql, mssql, databricks, redshift");
    eprintln!("  -o, --output <file>     Write output to file instead of stdout");
    eprintln!("  -r, --recursive         Recursively format all *.sql files in directory");
    eprintln!("  -w, --write             Write formatted output back to source files");
    eprintln!("  -j, --jobs <n>          Parallel jobs (default: CPU count)");
    #[cfg(debug_assertions)]
    {
        eprintln!("  --config <file>         Use specific .lexega.toml config file");
        eprintln!("  --no-config             Ignore .lexega.toml config file");
    }
    eprintln!("  -s, --style <style>     Formatting style (compact, readable, ultra)");
    #[cfg(debug_assertions)]
    {
        eprintln!("  --keyword-case <case>   Keyword casing (upper, lower, title, preserve)");
        eprintln!("  --identifier-case <case>");
        eprintln!("                          Identifier casing (upper, lower, preserve)");
        eprintln!("  --alias-align-max-width <n>");
        eprintln!(
            "                          Max width for alias alignment (0=unlimited, default=60)"
        );
        eprintln!("  -Q, --normalize-quoted-identifiers");
        eprintln!("                          Apply identifier casing to quoted identifiers");
        eprintln!("                          (matches QUOTED_IDENTIFIERS_IGNORE_CASE=TRUE)");
    }
    eprintln!("  --check                 Check if files would be reformatted (CI mode, exit 0=no changes, 1=would change)");
    eprintln!("  --verify-only           Verify formatting safety without writing (exit 0=safe, 1=unsafe)");
    eprintln!("  -q, --quiet             Suppress progress output (for scripting)");
    #[cfg(debug_assertions)]
    eprintln!("  --verify                Enable verification (always on in release builds)");
    #[cfg(debug_assertions)]
    eprintln!("  --no-verify             Skip verification step (faster, less safe)");
    #[cfg(debug_assertions)]
    eprintln!("  --debug-tokens          Dump lexer tokens and trivia for debugging");
    #[cfg(debug_assertions)]
    eprintln!("  --debug-stmts           Dump parsed statements with spans and types");
    eprintln!("  -h, --help              Show this help message");
    eprintln!();
    eprintln!("Styles:");
    eprintln!("  compact        Minimal whitespace, longer lines");
    eprintln!("  readable       Balanced formatting (default)");
    eprintln!("  ultra          Maximum clarity with extra indentation");
    eprintln!();
    #[cfg(debug_assertions)]
    {
        eprintln!("Casing:");
        eprintln!("  upper          UPPERCASE (default for keywords)");
        eprintln!("  lower          lowercase");
        eprintln!("  title          TitleCase (keywords only)");
        eprintln!("  preserve       Keep original casing (default for identifiers)");
        eprintln!();
    }
    if renders {
        eprintln!("Jinja/dbt Template Support:");
    } else {
        eprintln!("Jinja Template Support:");
    }
    eprintln!(
        "  --jinja                   Enable Jinja template support (preserves templates in output)"
    );
    if renders {
        eprintln!(
            "  --render-jinja            Render/execute Jinja templates (converts to pure SQL)"
        );
        eprintln!("  --dbt-project <path>      Path to dbt project directory");
        eprintln!("  --dbt-profile <name>      Use specific dbt profile");
        eprintln!("  --load-macros             Load macros from dbt project (dbt_packages/)");
        eprintln!("  --fail-on-missing-packages  Fail if required dbt package macros are missing");
        eprintln!(
            "  --var KEY=VALUE           Set Jinja variable (repeatable, auto-enables rendering)"
        );
        eprintln!("  --var-file <file>         Load variables from JSON/YAML");
    }
    #[cfg(debug_assertions)]
    {
        eprintln!("  --jinja-preserve          Preserve original Jinja block formatting");
        eprintln!("  --jinja-format-sql <v>    Format SQL inside Jinja blocks (true/false)");
        eprintln!("  --jinja-indent-delim <v>  Indent {{% %}} relative to SQL (true/false)");
        eprintln!("  --jinja-content-indent N  Extra indent for SQL in Jinja branches");
    }
    eprintln!();
    eprintln!("Safety:");
    eprintln!("  --check        CI mode: Check if formatting would change files (no writes)");
    eprintln!("  --verify-only  Verify formatting safety only (checks token/comment preservation)");
    #[cfg(not(debug_assertions))]
    {
        eprintln!("  Verification   Always enabled in release builds to prevent data loss.");
        eprintln!("                 Release builds refuse to write output if formatting cannot be proven safe.");
    }
    #[cfg(debug_assertions)]
    eprintln!(
        "  --verify       Enable verification (default). Use --no-verify to skip for testing."
    );
    eprintln!();
    #[cfg(debug_assertions)]
    {
        eprintln!("Configuration:");
        eprintln!("  Lexega automatically discovers .lexega.toml in your project directory.");
        eprintln!("  All 89 formatting options available via .lexega.toml configuration.");
        eprintln!("  Use the 3 style presets (compact, readable, ultra) as starting points.");
        eprintln!();
        eprintln!("  Debug builds: Use --config <path> for custom config file location");
        eprintln!("               Use --no-config to disable auto-discovery");
        eprintln!("               All granular CLI flags available for testing");
        eprintln!();
    }
    eprintln!();
    eprintln!("Examples:");
    eprintln!(
        "  {} fmt query.sql                      Format to stdout",
        program
    );
    eprintln!(
        "  {} fmt query.sql -o formatted.sql     Format to file",
        program
    );
    eprintln!(
        "  {} fmt query.sql -w                   Format in-place",
        program
    );
    eprintln!(
        "  {} fmt models/ -r -w                  Format directory recursively",
        program
    );
    eprintln!(
        "  {} fmt query.sql --verify-only        Verify formatting is safe",
        program
    );
    eprintln!(
        "  {} fmt query.sql -s compact           Use compact style",
        program
    );
    eprintln!(
        "  {} fmt query.sql -s ultra             Ultra style",
        program
    );
    eprintln!(
        "  cat query.sql | {} fmt --stdin        Read from stdin",
        program
    );
    #[cfg(debug_assertions)]
    {
        eprintln!(
            "  {} fmt query.sql -s ultra -Q          Ultra style, normalize quoted IDs",
            program
        );
    }
    if renders {
        eprintln!("  {} fmt model.sql --jinja --var region=US", program);
        eprintln!("                                       Format Jinja template with variable");
    }
    eprintln!(
        "  {} fmt models/ -r -w --jinja          Format dbt project",
        program
    );
}

pub fn print_catalog_usage(program: &str) {
    eprintln!("Usage: {} catalog <COMMAND> [ARGS]", program);
    eprintln!();
    eprintln!("Manage multi-provider catalog snapshots for metadata-aware analysis");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  pull     Generate a catalog snapshot by invoking the sidecar (networked)");
    eprintln!("  inspect  Show a deterministic summary of a snapshot (offline)");
    eprintln!("  diff     Show a deterministic diff summary between snapshots (offline)");
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  --provider <NAME>  Catalog provider for pull: {} (default snowflake)",
        lexega_core::builtin_catalog_provider_names().join("|")
    );
    eprintln!(
        "                     Extractors are bundled for {}; any other provider needs --sidecar <PATH>",
        BUNDLED_PULL_PROVIDERS.join(", ")
    );
    eprintln!("  -h, --help   Show this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} catalog inspect .lexega/catalog.json", program);
    eprintln!("  {} catalog diff old.json new.json", program);
    eprintln!("  {} catalog pull --provider snowflake --out catalog.json -- --account ACCT --user USER --auth externalbrowser", program);
}

pub fn print_ci_usage(program: &str, ext: &dyn Extension) {
    println!("Usage: {} ci [PATHS...] [OPTIONS]", program);
    println!();
    println!("CI entry point: selects the analysis scope from the pipeline's event,");
    println!("so the same command line works under every trigger:");
    println!();
    println!("  Pull/merge request events  ->  review <detected-base>..HEAD");
    println!("  Push and scheduled events  ->  analyze (snapshot of the tree)");
    println!();
    println!("Paths must come BEFORE options. With no paths, the whole tree is");
    println!("analyzed recursively. All OPTIONS are forwarded unchanged to the");
    println!(
        "underlying command (see: {} analyze --help / review --help).",
        program
    );
    println!();
    println!("ci-only options:");
    println!("  --snapshot              Force snapshot mode (skip detection)");
    println!("  --range <BASE..HEAD>    Force change mode with an explicit range");
    println!("  -h, --help              Show this help message");
    println!();
    println!("Supported platforms: GitHub Actions, GitLab CI, Azure DevOps,");
    println!("Bitbucket Pipelines. Outside CI, ci exits with guidance instead of");
    println!("guessing; use analyze or review directly.");
    println!();
    println!("Examples:");
    if ext.offers(Capability::PolicyGate) {
        println!(
            "  {} ci --policy .lexega/policy.yml --env prod --decision-out s3://bucket/lexega-data/decisions/$GITHUB_RUN_ID/",
            program
        );
        println!("  {} ci models/ --pr-comment", program);
    } else {
        println!("  {} ci --pr-comment", program);
        println!("  {} ci models/ --report-out results.sarif", program);
    }
}

pub fn print_risk_usage(program: &str, ext: &dyn Extension) {
    let gates = ext.offers(Capability::PolicyGate);
    let renders = ext.offers(Capability::TemplateRendering);
    println!("Usage: {} analyze [OPTIONS] <FILE|DIRECTORY>", program);
    println!();
    println!("Analyze SQL for pre-execution risk assessment");
    println!();
    println!("Input:");
    println!("  <FILE|DIRECTORY>         SQL file or directory to analyze");
    println!("  --stdin                  Read SQL from stdin (auto-detected when piped)");
    println!("  -r, --recursive          Analyze all *.sql files in directory");
    if ext.offers(Capability::CrossScript) {
        println!("  --cross-script           Analyze a non-dbt directory as a connected set (cross-script resolution + ordering hazards)");
    }
    println!(
        "  --scan-embedded          Also extract SQL from .py and .ipynb files (Spark/Databricks)"
    );
    println!();
    println!("Dialect:");
    println!("  --dialect <DIALECT>      SQL dialect: snowflake (default), postgresql, bigquery, mysql, mssql, databricks, redshift");
    println!();
    println!("Strict Analysis (experimental):");
    println!("  --strict [<MODE>]        Fail on unparsed/unsupported statements.");
    println!("                           MODE: off (default) | strict | pedantic");
    println!("                           Bare --strict is equivalent to --strict strict.");
    println!("                           Also settable via LEXEGA_STRICT env var.");
    println!();
    println!("Output:");
    println!("  --format <FORMAT>        Stdout format: text (default), json, yaml, sarif, markdown, both");
    println!("  --color <WHEN>           Colorize text output: auto (default), always, never (--no-color = never)");
    println!("  --report-artifact-format <FMT>");
    println!(
        "                           Report/summary artifact format: json (default), yaml, sarif"
    );
    if gates {
        println!("  --decision-artifact-format <FMT>");
        println!("                           Decision artifact format: json (default), yaml");
        println!("                           (SARIF has no schema for policy decisions)");
    }
    println!("  --report-out <URI>       Write analysis report (local, s3://, gs://, az://)");
    println!("  --trace                  Full trace mode (no truncation, includes all signals)");
    println!(
        "  --render-diagnostics <L> Placeholder verbosity: none (default), summary, impacted, all"
    );
    println!();
    println!("Output Filtering:");
    println!("  --min-severity <LEVEL>   Filter signals by level (info|low|medium|high|critical) [default: high]");
    println!();
    if gates {
        println!("Policy Enforcement (the only way to block - set LEXEGA_CI=1 for strict mode):");
        println!("  --policy <URI>           Evaluate policy bundle (local, s3://, gs://, az://)");
        println!("  --env <NAME>             Environment context (required with --policy)");
        println!("  --decision-out <URI>     Write decision artifact (local, s3://, gs://, az://)");
        println!("                       Tip: use a unique per-run directory/prefix (e.g. .../$GITHUB_RUN_ID/) to avoid overwriting previous runs");
        println!(
            "  --exceptions <URI>       Optional exception grants file (local, s3://, gs://, az://)"
        );
        println!();
    }
    println!("Custom Rules:");
    println!(
        "  --custom-rules <URI>     Load rules from YAML/JSON/TOML (local, s3://, gs://, az://)"
    );
    println!("  --no-builtin             Disable built-in rules (custom rules only)");
    println!("  --list-signals           Show catalog of available signal types");
    println!("  --explain-signals        Show extracted signals by statement");
    println!("  --verbose                Show per-statement rule-evaluation trace (matched + rejection reasons)");
    println!();
    if renders {
        println!("Jinja/dbt:");
        println!("  --dbt-project <PATH>     Path to dbt project directory");
        println!("  --dbt-profile <NAME>     Use specific dbt profile for rendering");
        println!("  --load-macros            Load macros from dbt project (dbt_packages/)");
        println!("  --fail-on-missing-packages  Fail if required dbt package macros are missing");
        println!("  --var KEY=VALUE          Set Jinja variable (repeatable)");
    } else {
        println!("Variables:");
        println!("  --var KEY=VALUE          Set a substitution variable (repeatable)");
    }
    println!("  --var-file <FILE>        Load variables from JSON/YAML (repeatable)");
    println!(
        "  --snowsql-config <FILE>  Load SnowSQL &var values from a config [variables] section (repeatable)"
    );
    println!("  --var-env <NAME>         Read a variable's value from the environment (explicit allowlist; repeatable)");
    println!("  --var-syntax <SYNTAX>    Recognize a deployment-variable syntax: dollar-brace (default), dollar-paren, or a marker shape such as '%%NAME%%' (repeatable)");
    println!();
    println!("Catalog:");
    println!("  --catalog <FILE>         Catalog snapshot for metadata-aware analysis");
    println!(
        "  --provider <NAME>        Catalog provider override ({})",
        lexega_core::builtin_catalog_provider_names().join("|")
    );
    println!();
    if gates {
        println!("Policy Metadata (optional):");
        println!("  --team <NAME>            Team name");
        println!("  --job-type <TYPE>        Job type (ad_hoc, scheduled)");
    } else {
        println!("Report Metadata (optional):");
    }
    println!("  --change-id <ID>         CI build/change ID");
    println!("  --repo <NAME>            Repository name");
    println!("  --commit <SHA>           Commit SHA");
    println!("  --run-id <ID>            CI run identifier");
    println!("  (metadata flags are auto-detected from the CI environment when omitted; --repo also falls back to the git remote)");
    println!();
    println!("  -q, --quiet              Suppress progress output (for scripting)");
    println!("  -h, --help               Show this help message");
    println!();
    println!("Examples:");
    println!("  {} analyze query.sql", program);
    println!("  {} analyze models/ -r", program);
    println!(
        "  {} analyze models/ -r --scan-embedded     # Also scan .py/.ipynb files",
        program
    );
    println!("  cat query.sql | {} analyze", program);
    println!(
        "  {} analyze --format json --min-severity high query.sql",
        program
    );
    println!(
        "  {} analyze --format sarif query.sql > results.sarif",
        program
    );
    println!(
        "  {} analyze --format gl-sast models/ -r > gl-sast-report.json",
        program
    );
    println!(
        "  {} analyze --custom-rules org_rules.yaml query.sql",
        program
    );
    if gates {
        println!("  {} analyze --policy policy.yaml --env prod --decision-out .lexega/decisions/$GITHUB_RUN_ID/ query.sql", program);
    }
    println!();
    println!("Schema Documentation (for IDE validation):");
    if gates {
        println!("  Policy:     https://lexega.com/schemas/v1/policy.schema.json");
    }
    println!("  Rules:      https://lexega.com/schemas/v1/custom_rules.schema.json");
    if gates {
        println!("  Exceptions: https://lexega.com/schemas/v1/exceptions.schema.json");
        println!("  Decision:   https://lexega.com/schemas/v1/decision.schema.json");
    }
}

pub fn print_review_usage(program: &str) {
    println!("Usage: {} review <BASE..HEAD> [PATH...] [OPTIONS]", program);
    println!();
    println!("Analyze the SQL files a commit range changes, as of its head commit");
    println!();
    println!("Arguments:");
    println!("  <BASE..HEAD>             Commit range (e.g. main..HEAD)");
    println!("  [PATH...]                Limit the review to these paths (default: .)");
    println!();
    println!("Options:");
    println!("  --pr-comment             Post the review as a pull/merge-request comment (CI)");
    println!("  --format <FORMAT>        Stdout format: markdown (default), text, json, yaml, sarif, gl-sast, both");
    println!("  --min-severity <LEVEL>   Filter signals by level (info|low|medium|high|critical) [default: high]");
    println!("  -h, --help               Show this help message");
    println!();
    println!(
        "The options of `{} analyze` apply here too (see: {} analyze --help).",
        program, program
    );
    println!();
    println!("Examples:");
    println!("  {} review main..HEAD", program);
    println!(
        "  {} review origin/main..HEAD models/ --pr-comment",
        program
    );
}

/// Print the custom-rule authoring primer (`--list-signals`).
///
/// Built-in rules are identified by `rule_id` (e.g. `DML-WRITE-UNBOUNDED`,
/// `GRT-TO-PUBLIC`). Customers author rules in YAML whose `triggers:`
/// predicate against extracted facts. This help text documents the
/// predicate DSL and points at the full schemas / rule catalog.
pub fn print_signal_catalog(program: &str, ext: &dyn Extension) {
    let gates = ext.offers(Capability::PolicyGate);
    println!("Custom Rule Syntax");
    println!("==================");
    println!();
    println!("Lexega rules emit signals identified by `rule_id` (e.g.");
    println!("DML-WRITE-UNBOUNDED, Q-NULL-NOTIN, GRT-TO-PUBLIC). Use");
    println!("`--explain-signals` to see which rules fire on a given query.");
    println!();
    println!("Authoring custom rules:");
    println!();
    println!("  - id: MY-CUSTOM-001");
    println!("    risk_level: high");
    println!("    message: \"Avoid SELECT * in production models\"");
    println!("    triggers:");
    println!("      all_of:");
    println!("        - kind: select");
    println!("        - query.scopes:");
    println!("            exists:");
    println!("              star_projections:");
    println!("                count: {{ gt: 0 }}");
    println!();

    println!("TRIGGERS");
    println!("========");
    println!();
    println!("  kind:              Statement kind: select, insert, update,");
    println!("                     delete, merge, grant, revoke, ...");
    println!("  all_of: [P1, P2]   Every sub-predicate must match.");
    println!("  any_of: [P1, P2]   At least one sub-predicate must match.");
    println!("  not: P             Sub-predicate must not match.");
    println!();

    println!("SCALAR OPS");
    println!("==========");
    println!();
    println!("Paths walk the public StatementFacts surface. Examples:");
    println!();
    println!("  kind: grant                          # equality sugar");
    println!("  kind: {{ in: [grant, revoke] }}        # set membership");
    println!("  ddl.target.name.database.normalized: {{ matches: 'PROD_*' }}");
    println!("                                       # glob (* and ?)");
    println!("  query.implicit_cross_product_estimate: {{ gt: 1000000 }}");
    println!("                                       # gt / lt / gte / lte");
    println!("  ddl.target.name.database: {{ exists: true }}");
    println!("                                       # path resolves non-null");
    println!();
    println!("Identifier matches: predicate against `name.normalized`, never");
    println!("`name.raw` — normalization is dialect-aware (Snowflake upper-folds,");
    println!("PostgreSQL lower-folds, etc.).");
    println!();

    println!("QUANTIFIERS (over Vec paths)");
    println!("============================");
    println!();
    println!("  privilege.privileges:");
    println!("    contains: ownership               # Vec contains literal");
    println!();
    println!("  privilege.grantees:");
    println!("    exists:                           # at least one element matches");
    println!("      kind: share");
    println!();
    println!("  query.scopes:");
    println!("    all:                              # every element matches");
    println!("      where_predicates:");
    println!("        count: {{ gt: 0 }}              # element count");
    println!();
    println!("  privilege.grantees:");
    println!("    none:                             # no element matches");
    println!("      name.normalized: PUBLIC");
    println!();
    println!("  query.scopes:");
    println!("    each:                             # per-witness signal emission");
    println!("      has_distinct: true");
    println!();

    println!("DISCOVERY");
    println!("=========");
    println!();
    println!("  1. {} analyze query.sql --explain-signals", program);
    println!("     Lists matched rule_ids per statement.");
    println!();
    println!("  2. {} analyze query.sql --explain-facts", program);
    println!("     Dumps the structured facts each rule predicates against.");
    println!();
    println!("  3. Author your rule against those same paths.");
    println!();

    println!("REFERENCE");
    println!("=========");
    println!();
    println!("  Rule catalog:   https://lexega.com/docs/rule-reference");
    println!("  Authoring:      https://lexega.com/docs/custom-rules");
    println!("  Custom rules:   https://lexega.com/schemas/v1/custom_rules.schema.json");
    if gates {
        println!("  Policy schema:  https://lexega.com/schemas/v1/policy.schema.json");
        println!("  Exceptions:     https://lexega.com/schemas/v1/exceptions.schema.json");
    }
}
