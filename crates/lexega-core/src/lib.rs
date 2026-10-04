// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! # lexega-core
//!
//! Recognition engine for SQL governance: lowers parsed statements to a
//! relational plan, projects each statement onto a typed fact base, and
//! evaluates a YAML rule corpus against those facts.
//!
//! ## Pipeline
//!
//! `lexega-syntax` (lexer, parser, AST) → [`ir`] (plan and lowering) →
//! [`facts`] (the statement fact base) → [`rules`] (predicate evaluation)
//! → [`analyzer`] (reports, SARIF, GitLab SAST).
//!
//! ## Depth
//!
//! [`Engine`] runs the pipeline against a [`facts::reasoning::Reasoning`]
//! provider. [`Engine::recognition`] uses no provider: every fact a
//! statement's own structure determines is produced, and every fact that
//! needs semantic analysis across scopes, statements or scripts is left
//! at its default, so a rule that reads one stays silent or reports more
//! coarsely. [`facts::reasoning::REASONING_FIELDS`] lists those facts.
//!
//! [`api`] holds function-style entry points over the recognition engine.

pub mod analyzer;
pub mod api;
pub mod catalog;
pub mod catalog_schema;
pub mod context;
pub mod engine;
pub mod extract;
pub mod facts;
pub mod ir;
pub mod rules;
pub mod template;

// Lexing, parsing, AST/CST and formatting live in `lexega-syntax`;
// re-exported here so `crate::ast`, `crate::parser`, … resolve.
pub use lexega_syntax::{ast, cst, dialect, error, formatter, lexer, parser, span_utils, syntax};
pub use lexega_syntax::{
    format_script_with_config, format_sql, format_sql_with_config, parse_sql,
    parse_sql_with_dialect, parse_stmt_from_str, try_parse_script_from_str,
    try_parse_stmt_from_str, verify_formatting_safe, verify_formatting_safe_with_dialect,
};

/// Conditional debug macro for template rendering - only prints in debug builds with LEXEGA_DEBUG env var
#[macro_export]
macro_rules! debug_template {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        if std::env::var("LEXEGA_DEBUG").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

pub use ast::{AstExpr, AstScript, AstSelect, AstStmt};
pub use catalog::{
    builtin_provider_names as builtin_catalog_provider_names,
    default_provider as default_catalog_provider, enrich_policy_dependencies,
    extract_tables_from_policy_body, provider_by_name as catalog_provider_by_name, CatalogError,
    CatalogIdent, CatalogIndex, CatalogObjectName, CatalogPolicy, CatalogPolicyKind,
    CatalogPolicyReference, CatalogProvider, CatalogSnapshot, UnquotedIdentCase,
    CATALOG_SCHEMA_VERSION,
};
pub use cst::{Cst, TokenId};
pub use dialect::{
    dialect_from_name, BigQueryDialect, DatabricksDialect, Dialect, DialectRef, MsSqlDialect,
    MySqlDialect, PostgresDialect, RedshiftDialect, SnowflakeDialect,
};
pub use error::{ParseError, ParseErrorKind, ParseResult};
pub use formatter::config::{
    ArrayLiteralStyle, BooleanOperatorPosition, CommaStyle, CopyIntoOptionsStyle,
    CreateStageClauseStyle, CteIndentStyle, FlattenStyle, FormatterConfig, IdentifierCase,
    IndentStyle, KeywordCase, MatchRecognizeDefineStyle, MatchRecognizeFormat,
    MatchRecognizeMeasuresStyle, NewlineStyle, ObjectLiteralStyle, ParamListStyle,
    ParenthesizedExprStyle, PipeChainStyle, SubqueryParenStyle, WindowFrameStyle,
};
pub use formatter::Formatter;
pub use parser::core::MIN_PARSE_STACK_BYTES;
// New CST-based formatter (v2)
pub use crate::context::node_metadata::IdentKey;
pub use crate::ir::normalize_identifier;
pub use crate::ir::reset_identifier_case_mode_cache;
pub use crate::ir::set_normalization_dialect;
pub use lexer::token::{
    IdentifierKind, Keyword, LiteralKind, Operator, Punctuation, Span, Token, TokenKind, Trivia,
    TriviaKind,
};
pub use lexer::tokenize;
pub use lexer::Lexer;
pub use parser::{parse_script, parse_select_from_tokens, parse_stmt, Parser};
pub use span_utils::{offset_to_line_col, span_to_line_col, LineCol};

// Strict-analysis plumbing. Re-exported for CLI / external consumers.
pub use engine::Engine;
pub use ir::{AnalysisOptions, OpaqueReason, StrictMode};

use std::borrow::Cow;

/// Parse SQL source with optional dialect override.
///
/// If `dialect` is `Some`, uses dialect-aware tokenization and parsing.
/// If `None`, falls back to the default Snowflake dialect.
pub fn parse_with_optional_dialect(
    src: &str,
    dialect: &Option<dialect::DialectRef>,
    placeholder_spans: &[lexer::token::Span],
) -> ParseResult<AstScript> {
    if let Some(ref d) = dialect {
        let tokens = lexer::tokenize_with_dialect(src, d.as_ref()).tokens;
        parser::try_parse_script_with_placeholders(
            src,
            &tokens,
            Some(d.as_ref()),
            placeholder_spans,
        )
    } else {
        let tokens = lexer::tokenize(src).tokens;
        parser::try_parse_script_with_placeholders(src, &tokens, None, placeholder_spans)
    }
}

/// Configure identifier normalization based on the dialect.
///
/// Must be called BEFORE lowering and analysis — `normalize_identifier()`
/// reads this ambient dialect state during the IR fold, so fold direction
/// and quote-style recognition must be set first.
pub(crate) fn apply_dialect_normalization(
    dialect: &Option<dialect::DialectRef>,
    reasoning: &dyn facts::reasoning::Reasoning,
) {
    if let Some(ref d) = dialect {
        ir::set_normalization_dialect(d.name());
        ir::dynamic_sql::set_ambient_format_builds_sql(d.format_function_builds_sql());
    } else {
        // Explicit Snowflake default — ensures a prior non-Snowflake run
        // in the same process doesn't leak into this analysis.
        ir::set_normalization_dialect("snowflake");
        // Snowflake has no SQL-building FORMAT scalar.
        ir::dynamic_sql::set_ambient_format_builds_sql(false);
    }
    reasoning.configure_dialect(dialect.as_deref());
}

//
// Risk Analysis APIs
//

/// Build CatalogInfo from loaded catalog index for trust assessment in reports.
/// Computes staleness warnings and identifies tables not found in catalog.
fn build_catalog_info(
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    tables_referenced: &[String],
) -> analyzer::CatalogInfo {
    let mut info = analyzer::CatalogInfo::default();

    if let Some(catalog) = catalog_index {
        info.catalog_loaded = true;
        info.catalog_path = catalog_path.map(|s| s.to_string());
        info.catalog_sha256 = Some(catalog.snapshot_sha256().to_string());

        let snapshot = catalog.snapshot();

        // Count tables in catalog
        let table_count: usize = snapshot
            .databases
            .iter()
            .flat_map(|db| db.schemas.iter())
            .map(|schema| schema.tables.len())
            .sum();
        info.catalog_table_count = Some(table_count);

        // Extract generated_at timestamp and compute age
        if let Some(generated) = &snapshot.generated_at {
            info.generated_at = Some(generated.to_rfc3339());

            let now = chrono::Utc::now();
            let age = now.signed_duration_since(*generated);
            let age_hours = age.num_minutes() as f64 / 60.0;
            info.age_hours = Some(age_hours);

            // Warn if catalog is stale (>24h old)
            if age_hours > 24.0 {
                info.stale_warning = Some(format!(
                    "Catalog is {:.1} hours old (>24h). Consider refreshing for accurate FK/PK analysis.",
                    age_hours
                ));
            }
        }

        // Identify referenced tables not found in catalog (gaps)
        for table_name in tables_referenced {
            // Extract just the table name (last part after dots)
            let parts: Vec<&str> = table_name.split('.').collect();
            let simple_name = parts.last().copied().unwrap_or(table_name.as_str());

            // Check if table exists in catalog using folded key lookup
            if catalog
                .table_location_candidates_by_key(simple_name)
                .is_none()
            {
                info.missing_tables.push(table_name.clone());
            }
        }
    } else {
        info.catalog_loaded = false;
    }

    info
}

/// Find the largest valid char boundary less than or equal to `index`.
/// Safely handles multi-byte UTF-8 characters to prevent panics on string slicing.
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    if s.is_char_boundary(index) {
        return index;
    }
    // Walk backwards to find the start of the character
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn convert_facts_risk_level(rl: facts::RiskLevel) -> analyzer::RiskLevel {
    match rl {
        facts::RiskLevel::Info => analyzer::RiskLevel::Info,
        facts::RiskLevel::Low => analyzer::RiskLevel::Low,
        facts::RiskLevel::Medium => analyzer::RiskLevel::Medium,
        facts::RiskLevel::High => analyzer::RiskLevel::High,
        facts::RiskLevel::Critical => analyzer::RiskLevel::Critical,
    }
}

/// Wrap a `rules::Signal` (the v1 fact-based output shape) inside the
/// `AnalysisReport.signals` envelope. Customer JSON-output contracts
/// (line numbers, evidence, role context) read off `AnalysisSignal`, so
/// every fact-engine signal is converted into one `RuleMatch::Analysis`
/// at the `analyze_risk_core` seam.
///
/// When a Jinja source-map is available, the rendered byte span on
/// `signal.source_span` is mapped back to the **template** line so
/// downstream surfaces (SARIF, JSON, `--explain-signals`) point at
/// the line the user actually wrote. Without this mapping, all line
/// numbers in dbt / Jinja-templated SQL drift by the number of lines
/// inserted during rendering.
fn fact_signal_to_rule_match(
    signal: rules::Signal,
    line_index: &analyzer::LineIndex,
    source_map: Option<&template::SourceMap>,
    source_file: Option<&str>,
    fold: &ScriptContextFold,
    src: &str,
) -> analyzer::RuleMatch {
    let resolved = signal
        .source_span
        .map(|sp| line_index.resolve_span(sp, source_map));
    let rendered_line = resolved.as_ref().map(|r| r.rendered_line);
    let template_line_number = resolved.as_ref().and_then(|r| r.template_line);
    // `display_line` is what surfaces in user-facing reports
    // (SARIF fallback, JSON `statement_line_number`, --explain-signals
    // text). Prefer the template line so a dbt user reads the line
    // they actually wrote; fall back to the rendered-source line
    // when no source map is available (raw .sql input).
    let display_line = template_line_number.or(rendered_line);
    let is_generated = resolved.as_ref().map(|r| r.is_generated);
    let macro_name = resolved.as_ref().and_then(|r| r.macro_name.clone());
    let statement_preview = signal.source_span.and_then(|sp| {
        let start = (sp.start as usize).min(src.len());
        let end = (sp.end as usize).min(src.len());
        src.get(start..end).map(|t| {
            let trimmed = t.trim();
            let preview: String = trimmed.chars().take(80).collect();
            preview
        })
    });
    // Role active at this signal's own position (not the whole-script
    // last role): the role in effect when the flagged statement runs.
    let assumed_role = signal
        .source_span
        .and_then(|sp| fold.role_at(sp.start))
        .map(|r| r.raw.clone());

    // Compute the witness's column number from the source span, and
    // emit a `location` string in the `path:line:column` format the
    // SARIF emitter parses (`sarif.rs::get_location_from_evidence`).
    // This is what gives merged-by-dedup signals their per-witness
    // SARIF locations: each pre-merge witness's `RiskEvidence` keeps
    // its own `location`, so the SARIF `get_all_locations_from_evidence`
    // walk produces one SARIF result per witness — preserving the
    // structural per-witness span the rule engine emitted, even
    // through the dedup aggregation pass.
    let column_number = signal
        .source_span
        .map(|sp| line_index.get_column_number(sp));
    let location = match (source_file, display_line, column_number) {
        (Some(path), Some(line), Some(col)) => Some(format!("{}:{}:{}", path, line, col)),
        (None, Some(line), Some(col)) => Some(format!(":{}:{}", line, col)),
        _ => None,
    };

    let evidence = vec![analyzer::RiskEvidence::RuleMatch {
        signal_type: "v1_fact".to_string(),
        resolution_status: None,
        signal_value: signal.rule_id.clone(),
        line_number: rendered_line,
        column_number,
        template_line_number,
        is_generated,
        macro_name,
        statement_preview: statement_preview.clone(),
        source_file: source_file.map(String::from),
        location,
        assumed_role: assumed_role.clone(),
    }];

    let analysis = analyzer::AnalysisSignal {
        message: signal.message,
        risk_level: convert_facts_risk_level(signal.risk_level),
        matched_rule: signal.rule_id,
        signal_type: "v1_fact".to_string(),
        signals_merged: None,
        // Count entries in our local `evidence` Vec (always 1 pre-dedup —
        // each rule fire produces one `RiskEvidence::RuleMatch`). The
        // post-dedup pass in `deduplicate()` overrides this to the
        // deduplicated count when signals aggregate. We deliberately do
        // NOT use `signal.evidence.witnesses.len()` here — that's the
        // rules-engine's quantifier-match count, which is 0 for
        // property-only predicates (no `each:`/`exists:`) and would
        // surface as `evidence_count = 0` for the SNW-UNKNOWN path
        // (excluded from dedup-aggregation override).
        evidence_count: Some(evidence.len()),
        scope: Some("statement".to_string()),
        statement_line_number: display_line,
        statement_lines: None,
        topic_key: None,
        source: Some(analyzer::SignalSource::BuiltIn),
        contributors: None,
        parent_context: None,
        evidence,
        scan_type: None,
        affected_tables: None,
        tables_modified: None,
        statement_cross_schema: None,
        statement_cross_database: None,
        unbounded_write: None,
        assumed_role,
    };
    analyzer::RuleMatch::Analysis(analysis)
}

/// Internal core risk analysis - single implementation used by all public APIs.
/// This prevents duplication and ensures consistent behavior.
///
/// `render.sql` must be the exact text `script` was parsed from — redaction
/// spans, the line index, and the script-context fold all index it.
pub(crate) fn analyze_risk_core(
    render: &template::RenderArtifacts,
    script: &ast::AstScript,
    policy_config: &analyzer::AnalysisConfig,
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    source_file: Option<&str>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
    let src = render.sql.as_str();
    // Redacted view of the source for OUTPUT surfaces only (finding previews /
    // evidence / SARIF). Analysis runs on the original `src` so value-pattern
    // detectors (e.g. hardcoded-AWS-key rules) still see the real credential;
    // only the quoted-back preview is masked. Offset-preserving, so the signal
    // source spans index it identically.
    let redacted_src = redact_secret_spans(src, &script.redaction_spans);

    // Build line index ONCE for O(log n) lookups (replaces thousands of O(n) scans)
    let line_index = analyzer::LineIndex::new(src);

    // Fold USE ROLE transitions into the script-level session context,
    // overlaid onto each statement's facts before rule evaluation.
    let script_fold = build_script_context_fold(script, src);
    let dialect_name = policy_config
        .dialect
        .as_ref()
        .map(|d| d.name())
        .unwrap_or("snowflake");
    // Script-wide reasoning state, shared by every family evaluator
    // below.
    let mut script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
        script,
        source: src,
        dialect_name,
        fold: &script_fold,
        catalog: catalog_index,
        model_catalog,
    });

    let mut report = analyzer::AnalysisReport::new();
    report.assumed_role = script_fold.last_role().map(|r| r.raw.clone());

    // SourceMap available for template line mapping in custom-rules evaluator

    // `rules::evaluate_rules` is the authoritative rule-evaluation
    // seam. Resolve the corpus once: caller-supplied custom rules take
    // precedence (the CLI loader pre-merges them with built-ins per
    // `--no-builtin` and override-by-id semantics); otherwise fall
    // back to the unmodified built-in corpus.
    //
    // The dispatch is split across four family-specific
    // `evaluate_*_rules_for_script` helpers. Each runs over the same
    // pre-parsed `AstScript` so we lower the statement tree once and
    // every family's facts projection rides the same parse.
    let corpus: &[rules::Rule] = match policy_config.custom_rules.as_deref() {
        Some(custom) => custom,
        None => rules::all_builtin_rules().map_err(builtin_load_failure_to_risk_error)?,
    };

    // The DDL/query evaluators flatten procedure/function bodies into
    // the fact stream so inner statements are rule-evaluated. Collect
    // each body region up front so the ledger fold can suppress the
    // body's Opaque control-flow scaffolding (counted via
    // `statements_in_bodies`) rather than miscounting it as
    // unrecognized top-level SQL.
    let body_flat = flat_stmts_for_rules(script);
    let mut body_regions: Vec<lexer::token::Span> = Vec::new();
    for s in &body_flat {
        if let ast::AstStmt::CreateProcedure(p) = s {
            if let Some(body) = p.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::CreateFunction(f) = s {
            if let Some(body) = f.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::DoBlock(d) = s {
            // Anonymous DO bodies are flattened like proc/func bodies, so their
            // control-flow scaffolding must likewise be accounted as in-body
            // (suppressed from `statements_skipped`) rather than top-level SQL.
            if let Some(body) = d.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::CreateEvent(e) = s {
            if let Some(body) = e.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::AlterEvent(e) = s {
            if let Some(body) = e.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::CreateMysqlTrigger(t) = s {
            if let Some(body) = t.body_stmt.as_deref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::CreateTask(t) = s {
            if let Some(Ok(body)) = t.body.as_ref() {
                body_regions.push(body.span());
            }
        } else if let ast::AstStmt::CreateMssqlTrigger(t) = s {
            for stmt in &t.body {
                body_regions.push(stmt.span());
            }
        }
    }

    // IR-native ledger, folded one statement at a time from the same
    // fact stream the rule evaluators read (via `evaluate_facts_into`'s
    // sink slot). No whole-script `Vec<StatementFacts>` accumulator is
    // kept — its retention would dominate peak memory on
    // statement-heavy scripts.
    let mut metrics = analyzer::MetricsCollector::new();
    let mut facts_sink =
        StatementFactsSink::new(&mut metrics, &body_regions, policy_config.trace_mode);
    let mut explanations_buf: Vec<analyzer::StatementExplanation> = Vec::new();

    if !corpus.is_empty() {
        let mut fact_signals: Vec<rules::Signal> = Vec::new();
        // Each per-family evaluator borrows the trace buffer
        // mutably in turn; can't share one `&mut` across all
        // four, so we run them sequentially and pass the buffer
        // by re-borrow each time. Same pattern for `facts_sink`.
        fact_signals.extend(evaluate_privilege_rules_for_script(
            script,
            src,
            &script_fold,
            catalog_index,
            corpus,
            reasoning,
            Some(&mut facts_sink),
            if policy_config.trace_mode {
                Some(&mut explanations_buf)
            } else {
                None
            },
        ));
        fact_signals.extend(evaluate_ddl_rules_for_script(
            script,
            src,
            &script_fold,
            corpus,
            reasoning,
            script_reasoning.as_ref(),
            Some(&mut facts_sink),
            if policy_config.trace_mode {
                Some(&mut explanations_buf)
            } else {
                None
            },
        ));
        fact_signals.extend(evaluate_query_rules_for_script(
            script,
            src,
            &script_fold,
            catalog_index,
            model_catalog,
            corpus,
            reasoning,
            script_reasoning.as_mut(),
            Some(&mut facts_sink),
            if policy_config.trace_mode {
                Some(&mut explanations_buf)
            } else {
                None
            },
        ));
        fact_signals.extend(evaluate_policy_attachment_rules_for_script(
            script,
            src,
            &script_fold,
            corpus,
            Some(&mut facts_sink),
            if policy_config.trace_mode {
                Some(&mut explanations_buf)
            } else {
                None
            },
        ));
        if policy_config.trace_mode {
            report.statement_explanations.extend(explanations_buf);
        }
        for signal in fact_signals {
            let rule_match = fact_signal_to_rule_match(
                signal,
                &line_index,
                render.source_map.as_ref(),
                source_file,
                &script_fold,
                &redacted_src,
            );
            report.add_signal(rule_match);
        }
    }

    // End the sink's `&mut` ledger borrow. `retained_facts` is
    // `Some(_)` only in trace mode; the hot path retains nothing.
    let (procedure_bodies_analyzed, retained_facts, lost_analysis) = facts_sink.finish();

    // Coverage tally — the single source of truth for the statement-count
    // summary fields. Counts every statement node at every depth (top-level
    // plus all proc/func/block/control-flow bodies) from the same flatten
    // already built above for `body_regions`, so it is consistent across
    // layouts (a DML buried in IF/WHILE counts the same as a top-level one).
    //
    // Bucketing is by AST shape, mode-independent:
    //   - `OpaqueContent` / `Error` (genuine parse coverage loss) -> skipped
    //   - `Jinja*` placeholder statements                          -> jinja
    //   - `Block` (BEGIN/END grouping) is structural punctuation, not a
    //     statement -> not counted (its inner statements already are)
    //   - everything else (DML/DDL/security/control-flow)          -> analyzed
    //
    // Genuine opacity therefore surfaces in `statements_skipped` and degrades
    // confidence regardless of strict mode; control-flow scaffolding counts as
    // an analyzed statement rather than being silently dropped.
    let mut cov_analyzed = 0usize;
    let mut cov_partial = 0usize;
    let mut cov_skipped = 0usize;
    let mut cov_jinja = 0usize;
    let mut cov_in_bodies = 0usize;
    for s in &body_flat {
        // Single source of truth: the exhaustive `coverage_class` classifier.
        // `Excluded` nodes (BEGIN/END grouping, GO separators) are structural
        // and not counted; their inner statements are counted on their own.
        let class = coverage_class(s);
        if class == CoverageClass::Excluded {
            continue;
        }
        let sp = s.span();
        if body_regions
            .iter()
            .any(|r| sp.start >= r.start && sp.end <= r.end)
        {
            cov_in_bodies += 1;
        }
        match class {
            CoverageClass::Skipped => cov_skipped += 1,
            CoverageClass::Jinja => cov_jinja += 1,
            CoverageClass::Analyzed => cov_analyzed += 1,
            // Partial is a recognized statement (verb + target known), so it
            // still counts toward analyzed — the dropped payload is surfaced
            // via the separate `cov_partial` tally and a confidence downgrade.
            CoverageClass::Partial => {
                cov_analyzed += 1;
                cov_partial += 1;
            }
            // Already `continue`d above; no-op keeps the match exhaustive
            // without a panic.
            CoverageClass::Excluded => {}
        }
    }

    // In trace mode, populate `report.statement_signals` with the
    // per-statement fact carriers so an explain-facts surface can
    // render them. Plan types are intentionally not exposed — the
    // public schema is facts-only.
    if policy_config.trace_mode {
        for fact in retained_facts.as_deref().unwrap_or(&[]) {
            let span = fact
                .source_span
                .unwrap_or(lexer::token::Span { start: 0, end: 0 });
            let safe_start = floor_char_boundary(src, (span.start as usize).min(src.len()));
            let line_number = src[..safe_start].matches('\n').count() + 1;
            let end_pos =
                floor_char_boundary(src, (span.end as usize).min(safe_start + 80).min(src.len()));
            // Slice the redacted view so a credential value never reaches the
            // statement-signal preview (offsets are identical to `src`).
            let statement_preview = redacted_src[safe_start..end_pos]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            report.statement_signals.push(analyzer::StatementSignals {
                line_number,
                statement_preview,
                matched_rules: Vec::new(),
                evaluation_summary: None,
                evaluated_but_not_matched: Vec::new(),
                almost_matched: Vec::new(),
                rejected_summary: None,
                resolution_warnings: Vec::new(),
                facts: Some(fact.clone()),
            });
        }
    }

    // PROCEDURE/FUNCTION BODY ANALYSIS: per-(procedure|function) body
    // counts folded by the sink from `ddl.procedure.body` /
    // `ddl.function.body` presence — one per `Some(body)`. CREATE
    // without parseable body and ALTER/DROP statements without bodies
    // contribute zero — they surface as `body: None` on the carrier.
    report.summary.procedure_bodies_analyzed = procedure_bodies_analyzed;
    // Body-nested statement count from the coverage tally — every node whose
    // span falls within a proc/func/DO body region (consistent with the
    // top-level partition below; both come from the same flatten).
    report.summary.statements_in_bodies = cov_in_bodies;

    // Deduplicate policy signals by topic_key (custom rules take precedence over built-in)
    report.deduplicate_by_topic();

    // INVARIANT CHECK: Verify ledger consistency before deriving counts
    if let Err(msg) = metrics.verify_invariant() {
        eprintln!("WARNING: {}", msg);
        #[cfg(debug_assertions)]
        panic!("{}", msg);
    }

    // Statement counts from the coverage tally (single source of truth) — a
    // count of every statement node at every depth, not just top-level. The
    // ledger still drives the data-operation metrics below (tables read/
    // written, DDL/security operation counts), but the statement-coverage
    // partition is the AST tally so it stays consistent regardless of how
    // facts deduplicate or which inner statements lower to a typed plan.
    //
    // `jinja_blocks` folds the renderer's standalone-Jinja count (blocks that
    // rendered to nothing, never reaching the AST) with any residual Jinja
    // statement nodes from a partial render.
    // INVARIANT: statements_analyzed + statements_skipped + jinja_blocks == statements_parsed
    report.summary.jinja_blocks = render.jinja_blocks + cov_jinja;
    report.summary.statements_analyzed = cov_analyzed;
    report.summary.statements_partial = cov_partial;
    report.summary.statements_skipped = cov_skipped;
    report.summary.statements_parsed = cov_analyzed + cov_skipped + report.summary.jinja_blocks;

    // Placeholder/taint tracking - set render completeness and baseline confidence
    let mut analysis_confidence = analyzer::ConfidenceLevel::High;
    if render.render_failed() {
        // Template present but not rendered: analysis ran on the template
        // text, so the rendered shape — and every zone classification — is
        // unknown. Never report this as a full, confident render.
        report.summary.render_completeness = analyzer::RenderCompleteness::NotRendered;
        analysis_confidence = analyzer::ConfidenceLevel::Low;
    } else if render.placeholders.total > 0 {
        // Use high_impact to determine render completeness level
        if render.placeholders.high_impact == 0 {
            report.summary.render_completeness = analyzer::RenderCompleteness::PartialLowImpactOnly;
        } else {
            report.summary.render_completeness = analyzer::RenderCompleteness::Partial;
        }
        report.summary.placeholders = Some(analyzer::PlaceholderSummary {
            total: render.placeholders.total,
            statements_impacted: 0, // Not tracked at this level yet
            high_impact: render.placeholders.high_impact,
            low_impact: render.placeholders.low_impact,
            top_sources: render.placeholders.top_sources(),
            top_kinds: render.placeholders.top_kinds(),
        });
        // Degraded confidence when high-impact placeholders present
        analysis_confidence = if render.placeholders.high_impact > 0 {
            analyzer::ConfidenceLevel::Medium
        } else {
            analyzer::ConfidenceLevel::High // Low-impact only = still high confidence
        };
    } else {
        report.summary.render_completeness = analyzer::RenderCompleteness::Full;
    }

    // Degrade confidence when SQL statements were skipped/unrecognized.
    // This captures parser/analyzer coverage loss even when rendering was complete.
    let sql_total = report.summary.statements_analyzed + report.summary.statements_skipped;
    if report.summary.statements_skipped > 0 && sql_total > 0 {
        let skipped = report.summary.statements_skipped;
        analysis_confidence = if skipped >= sql_total {
            analyzer::ConfidenceLevel::Low
        } else {
            match analysis_confidence {
                analyzer::ConfidenceLevel::High => analyzer::ConfidenceLevel::Medium,
                analyzer::ConfidenceLevel::Medium => analyzer::ConfidenceLevel::Low,
                analyzer::ConfidenceLevel::Low => analyzer::ConfidenceLevel::Low,
            }
        };
    }

    // Degrade confidence when a recognized statement's payload was only
    // partially parsed (an Unknown action / Unparsed grant shape): the verb is
    // known but some of its meaning was dropped, so we cannot claim a full
    // reading. Never escalates below the skipped-based level above.
    if report.summary.statements_partial > 0 {
        analysis_confidence = match analysis_confidence {
            analyzer::ConfidenceLevel::High => analyzer::ConfidenceLevel::Medium,
            other => other,
        };
    }

    // Degrade confidence when a statement parsed cleanly but its
    // analysis was lost afterwards, so findings it would have produced
    // were not. The coverage counts cannot express this — they are
    // defined by what the parser achieved, and the parser succeeded —
    // but confidence exists precisely to say how far the report can be
    // trusted, and a report that read nothing from a statement must not
    // claim a full reading of it.
    if !lost_analysis.is_empty() {
        let sql_total = report.summary.statements_analyzed + report.summary.statements_skipped;
        analysis_confidence = if sql_total > 0 && lost_analysis.len() >= sql_total {
            analyzer::ConfidenceLevel::Low
        } else {
            match analysis_confidence {
                analyzer::ConfidenceLevel::High => analyzer::ConfidenceLevel::Medium,
                other => other,
            }
        };
    }

    report.summary.analysis_confidence = analysis_confidence;

    if !reasoning.provides_analysis() {
        let rules_limited = corpus
            .iter()
            .filter(|rule| rule.triggers.reads_reasoning())
            .count();
        if rules_limited > 0 {
            report.summary.analysis_depth = Some(analyzer::AnalysisDepth {
                rules_total: corpus.len(),
                rules_limited,
            });
        }
    }

    // Populate skipped_details for transparency.
    // Also surface skipped statements as explicit analysis limitations, so users can see
    // the full set of statements we could not analyze (not only inner-construct limitations).
    {
        // Helper: accumulate limitations per statement (merge if same line+preview).
        let mut push_analysis_limitation =
            |line_number: usize, statement_preview: String, limitation: String| {
                if let Some(existing) = report.analysis_limitations.iter_mut().find(|x| {
                    x.line_number == line_number && x.statement_preview == statement_preview
                }) {
                    existing.limitations.push(limitation);
                    existing.limitations.sort();
                    existing.limitations.dedup();
                } else {
                    report
                        .analysis_limitations
                        .push(analyzer::AnalysisLimitation {
                            line_number,
                            statement_preview,
                            limitations: vec![limitation],
                        });
                }
            };

        // Statements that parsed but whose analysis was lost afterwards.
        // These are deliberately absent from `skipped_details` and from
        // `statements_skipped`: both are parse-defined, and these parsed.
        // They surface here — the channel for "what we could not fully
        // analyze" — so the confidence drop above is explainable.
        for stmt in &body_flat {
            let stmt_span = stmt.span();
            if !lost_analysis.contains(&stmt_span.start) {
                continue;
            }
            if stmt_span.start as usize >= src.len() {
                continue;
            }
            let line_number = line_index.get_line_number(stmt_span);
            let safe_start = floor_char_boundary(src, stmt_span.start as usize);
            let end_pos = floor_char_boundary(
                src,
                (stmt_span.end as usize).min(safe_start + 60).min(src.len()),
            );
            // Slice the redacted view — offsets match `src`.
            let statement_prefix = redacted_src[safe_start..end_pos]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            push_analysis_limitation(
                line_number,
                statement_prefix,
                "analysis_gave_up:statement:parsed:reason=not_analyzable".to_string(),
            );
        }

        // Skipped-statement detection derives from the same `coverage_class`
        // classifier that produces the summary's `statements_skipped`, over the
        // same flattened statement set (`body_flat`) — so `skipped_details` and
        // `summary.statements_skipped` agree by construction. A statement is
        // "skipped" only when it is genuine parse-coverage loss
        // (`CoverageClass::Skipped` = OpaqueContent / Error / ClauseFragment).
        // Recognized statements with no applicable rule (transaction control,
        // DESCRIBE, SET, …) lower to a real plan and are analyzed-with-zero-
        // findings, not skipped — they must not surface here or trip strict mode.
        {
            for stmt in &body_flat {
                if coverage_class(stmt) != CoverageClass::Skipped {
                    continue;
                }
                let stmt_span = stmt.span();
                // Defensive: skip statements with invalid spans
                if stmt_span.start as usize >= src.len() {
                    continue;
                }

                // O(log n) line lookup via the index built once at function entry
                // (line 698), instead of an O(offset) newline scan per skipped
                // statement — keeps the skip path linear in statement count.
                let line_number = line_index.get_line_number(stmt_span);
                // Use floor_char_boundary to safely handle multi-byte UTF-8 characters
                let safe_start = floor_char_boundary(src, stmt_span.start as usize);
                // Calculate end position safely: min of (stmt end, start+60, src length)
                let start_pos = safe_start;
                let end_pos = floor_char_boundary(
                    src,
                    (stmt_span.end as usize).min(start_pos + 60).min(src.len()),
                );
                // Slice the redacted view so a credential value never reaches
                // the skipped-statement prefix (offsets are identical to `src`).
                let stmt_text = &redacted_src[start_pos..end_pos];
                let statement_prefix = stmt_text.lines().next().unwrap_or("").trim().to_string();

                let impact_category =
                    analyzer::SkippedStatement::guess_impact_category(&statement_prefix);

                // `CoverageClass::Skipped` is exactly the unparsed-construct
                // bucket (OpaqueContent / Error / ClauseFragment). Signals are
                // not counted per statement: the limitation string says
                // `false` and the record below carries `None`.
                let mut limitation = format!(
                    "analysis_gave_up:statement:skipped:reason=unparsed_construct:impact={}:signals_extracted=false",
                    impact_category
                );
                limitation.retain(|c| c != '\n' && c != '\r');
                push_analysis_limitation(line_number, statement_prefix.clone(), limitation);

                report.skipped_details.push(analyzer::SkippedStatement {
                    reason: analyzer::SkipReason::UnparsedConstruct,
                    statement_prefix,
                    line_number,
                    impact_category: Some(impact_category),
                    signals_extracted: None,
                });
            }
        }
    }

    // The v1 fact-based engine exposes its explanation surface via
    // `Signal.explanation` (populated by `evaluate_rules` when
    // explain-mode is on).
    let trace_mode = policy_config.trace_mode;

    // Set trace_mode flag
    report.trace_mode = Some(trace_mode);

    // Derive all metrics from ledger (never stored, always computed)
    let derived = metrics.derive_metrics();

    // Apply derived metrics to summary. Keep the name SETS (not just the
    // counts) so the dynamic-SQL literal-body pass can union the tables read /
    // written inside executed literal bodies, then recompute the counts.
    report.summary.tables_read_names = derived.tables_read;
    report.summary.tables_read = report.summary.tables_read_names.len();
    report.summary.tables_written_names = derived.tables_written;
    report.summary.tables_written = report.summary.tables_written_names.len();
    report.summary.cross_schema = derived.cross_schema;
    report.summary.cross_database = derived.cross_database;
    report.summary.databases_accessed = derived.databases_accessed.into_iter().collect();

    report.summary.ddl_operations = derived.ddl_operations;
    report.summary.security_operations = derived.security_operations;
    report.summary.control_operations = derived.control_operations;

    // Set role context in summary\n    report.summary.assumed_role = report.assumed_role.clone();\n\n    // Deduplicate identical signals
    // Recurse into static dynamic-SQL literal bodies: parse each and run the
    // full rule corpus on the inner statements, mapping findings back to the
    // literal's position in source. Appended before dedup/sort so inner
    // findings are ordered and de-duplicated alongside the rest.
    let dynamic_bodies =
        reasoning.dynamic_sql_literal_bodies(src, script, policy_config, source_file);
    report.signals.extend(dynamic_bodies.signals);
    // Merge the tables read/written inside executed literal bodies into the
    // summary (set semantics dedupe against the top-level reads), then
    // recompute the counts — so `Tables Read` reflects SQL run via dynamic SQL.
    if !dynamic_bodies.tables_read.is_empty() || !dynamic_bodies.tables_written.is_empty() {
        report
            .summary
            .tables_read_names
            .extend(dynamic_bodies.tables_read);
        report
            .summary
            .tables_written_names
            .extend(dynamic_bodies.tables_written);
        report.summary.tables_read = report.summary.tables_read_names.len();
        report.summary.tables_written = report.summary.tables_written_names.len();
    }

    let per_statement_rules: std::collections::HashSet<String> = corpus
        .iter()
        .filter(|r| r.per_statement)
        .map(|r| r.id.clone())
        .collect();
    report.deduplicate_with_per_statement_rules(&per_statement_rules);

    // Sort signals by severity then by blast radius priority
    report.signals.sort_by(|a, b| {
        use std::cmp::Ordering;

        let severity_cmp = b.risk_level().cmp(&a.risk_level());
        if severity_cmp != Ordering::Equal {
            return severity_cmp;
        }

        fn get_priority(signal: &analyzer::RuleMatch) -> u8 {
            let msg = signal.message().to_uppercase();
            if msg.contains("PUBLIC") {
                100
            } else if msg.contains("SHARE") {
                90
            } else if msg.contains("ACCOUNTADMIN") || msg.contains("PRIVILEGE ESCALATION") {
                80
            } else if msg.contains("COPY INTO") || msg.contains("EXFILTRATION") {
                70
            } else if msg.contains("OWNERSHIP") {
                60
            } else if msg.contains("CLONE") {
                50
            } else if msg.contains("UNBOUNDED") {
                40
            } else {
                0
            }
        }

        // Total-order tie-break so the final order is deterministic regardless
        // of the dedup's `HashMap` iteration order: rule id, then message.
        // (Truly-identical signals render identically, so byte output is stable
        // even when these are equal.)
        get_priority(b)
            .cmp(&get_priority(a))
            .then_with(|| a.rule_id().cmp(&b.rule_id()))
            .then_with(|| a.message().cmp(b.message()))
    });

    // Recalculate signal counts (after dedupe)
    report.summary.recalculate_from_signals(&report.signals);

    // Populate catalog_info for trust assessment
    // Collect all tables referenced for gap detection. Pulls reads,
    // DML writes, and DDL targets from the IR-native ledger so the
    // catalog gap-detector sees every table the script touches.
    let tables_referenced: Vec<String> = metrics
        .entries
        .values()
        .flat_map(|e| {
            e.tables_read()
                .iter()
                .chain(e.tables_written_dml().iter())
                .chain(e.tables_modified_ddl().iter())
        })
        .map(|t| t.canonical())
        .collect();
    report.catalog_info = build_catalog_info(catalog_index, catalog_path, &tables_referenced);

    // Validate invariants in debug builds
    #[cfg(debug_assertions)]
    {
        if let Err(errors) = report.validate() {
            eprintln!("⚠️  Risk report validation failed:");
            for error in &errors {
                eprintln!("  - {}", error);
            }
            eprintln!("⚠️  Report may be incorrect - please file a bug report");
        }
    }

    // Trace explanations build their preview from the original source; rebuild
    // each from the redacted view so the `--explain-signals` surface never
    // reproduces a credential value either.
    for explanation in &mut report.statement_explanations {
        if let Some(sp) = explanation.source_span {
            explanation.statement_preview = statement_preview_from_span(Some(sp), &redacted_src);
        }
    }

    Ok(report)
}

/// Map a built-in rule corpus load failure to the `RiskError` surface
/// used by every public `analyze_risk*` entry point. Strictly an
/// invariant-violation arm — the YAML is `include_str!`d at compile
/// time, so this path only fires on a malformed build artifact —
/// surfaced as a typed error rather than a panic so customers / IDEs
/// see a structured diagnostic instead of a stack trace.
fn builtin_load_failure_to_risk_error(err: rules::LoadError) -> analyzer::RiskError {
    analyzer::RiskError::AnalysisError(format!(
        "built-in rule corpus failed to load (build artifact bug): {}",
        err
    ))
}

/// Like [`builtin_load_failure_to_risk_error`] but for the
/// `analyze_*_facts` entry points which return `error::ParseError`
/// rather than `RiskError`. Uses [`error::ParseErrorKind::Internal`]
/// — semantically "internal parser error" but the slot fits the
/// invariant-violation contract (build-time programming error).
#[doc(hidden)]
pub fn builtin_load_failure_to_parse_error(err: rules::LoadError) -> error::ParseError {
    error::ParseError::new(
        lexer::Span::default(),
        error::ParseErrorKind::Internal {
            message: format!(
                "built-in rule corpus failed to load (build artifact bug): {}",
                err
            ),
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Jinja Rendering Helper for Risk Analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Render `src` when it is a template; plain SQL passes through
/// untouched. Unrendered, `{{ ref('customers') }}` is literal text and
/// macros like `{{ config(...) }}` are invisible to analysis.
///
/// If `file_path` is provided, the template's project is discovered from
/// that file's directory; otherwise from the current directory.
pub(crate) fn prepare_sql_for_analysis_with_context(
    src: &str,
    file_path: Option<&std::path::Path>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Result<template::RenderArtifacts, analyzer::RiskError> {
    // Fast string heuristic before provisioning — plain SQL must not pay
    // for project discovery or macro loading.
    if !template::has_jinja_syntax(src) {
        return Ok(template::RenderArtifacts::raw(src.to_string()));
    }
    Ok(reasoning.render_template(src, file_path))
}

/// Per-statement dispatch for the privilege family. Operates on a
/// pre-parsed `Script` and an explicit `rules_corpus` so the same
/// dispatch arms can evaluate built-in rules (via the public
/// `analyze_privilege_facts*` entry points) and customer rules (via
/// the unified driver in `analyze_risk_core`) without duplicating
/// the AST → IR → facts lowering.
///
/// When `trace_out` is `Some(&mut Vec<StatementExplanation>)`, the
/// engine's explain-mode introspection runs and per-statement
/// rule-evaluation outcomes (matched + rejection-reason paths) are
/// appended. When `None`, the hot path runs `evaluate_rules` only.
pub(crate) fn evaluate_privilege_rules_for_script(
    script: &ast::AstScript,
    sql: &str,
    fold: &ScriptContextFold,
    catalog: Option<&crate::catalog::CatalogIndex>,
    rules_corpus: &[rules::Rule],
    reasoning: &dyn facts::reasoning::Reasoning,
    mut facts_out: Option<&mut StatementFactsSink<'_>>,
    mut trace_out: Option<&mut Vec<analyzer::StatementExplanation>>,
) -> Vec<rules::Signal> {
    let mut signals = Vec::new();
    if rules_corpus.is_empty() {
        return signals;
    }
    // Enumerate every statement at every depth — GRANT / REVOKE / DENY inside a
    // proc / trigger / task / event body is a privilege statement too.
    for stmt in flat_stmts_for_rules(script) {
        let plan = match stmt {
            ast::AstStmt::Grant(g) => Some(ir::lower_grant_to_privilege_plan(g)),
            ast::AstStmt::Revoke(r) => Some(ir::lower_revoke_to_privilege_plan(r)),
            ast::AstStmt::Deny(d) => Some(ir::lower_deny_to_privilege_plan(d)),
            ast::AstStmt::AlterAuthorization(a) => {
                Some(ir::lower_alter_authorization_to_privilege_plan(a))
            }
            _ => None,
        };
        if let Some(plan) = plan {
            let facts = match catalog {
                Some(_) => facts::extract::derive_facts_from_privilege_plan_with_reasoning(
                    &plan, sql, reasoning,
                ),
                None => facts::extract::derive_facts_from_privilege_plan(&plan, sql),
            };
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
        }
    }
    signals
}

/// Per-statement sink at the `evaluate_facts_into` seam.
///
/// Folds the summary ledger and body tallies incrementally instead of
/// retaining every `StatementFacts` for the whole script — the carrier
/// is ~24KB inline, so whole-stream retention made peak RSS scale with
/// statement count at a huge constant (~98MB for a 4000-statement
/// script before the fold). Masked carriers are retained only in trace
/// mode, whose explain surfaces render them per statement.
pub(crate) struct StatementFactsSink<'a> {
    metrics: &'a mut analyzer::MetricsCollector,
    body_regions: &'a [lexer::token::Span],
    procedure_bodies_analyzed: usize,
    retained: Option<Vec<facts::StatementFacts>>,
    /// Span starts whose query lowering collapsed for a reason meaning
    /// findings were lost (`OpaqueReason::indicates_lost_analysis`).
    /// Drives the report's confidence level; the statement-coverage
    /// counts are parse-defined and deliberately untouched. Always on —
    /// confidence must not depend on trace mode.
    lost_analysis: std::collections::BTreeSet<u32>,
}

impl<'a> StatementFactsSink<'a> {
    fn new(
        metrics: &'a mut analyzer::MetricsCollector,
        body_regions: &'a [lexer::token::Span],
        retain: bool,
    ) -> Self {
        StatementFactsSink {
            metrics,
            body_regions,
            procedure_bodies_analyzed: 0,
            retained: if retain { Some(Vec::new()) } else { None },
            lost_analysis: std::collections::BTreeSet::new(),
        }
    }

    /// Record that the query lowering for `span` produced an opaque
    /// terminal whose reason means findings for it were lost.
    fn record_lost_analysis(&mut self, span: lexer::token::Span) {
        self.lost_analysis.insert(span.start);
    }

    /// Record one statement's facts: fold the ledger entry and the
    /// procedure/function body tally. In retain (trace) mode also push
    /// a credential-masked clone and return the masked values — the
    /// scrub list for rendered rule explanations. The ledger reads only
    /// structural fields (kind / spans / table refs), never credential
    /// values, so it folds from the unmasked carrier.
    fn record(&mut self, facts: &facts::StatementFacts) -> Vec<String> {
        self.metrics.populate_from_fact(facts, self.body_regions);
        if let Some(ddl) = &facts.ddl {
            if let Some(proc_facts) = &ddl.procedure {
                if proc_facts.body.is_some() {
                    self.procedure_bodies_analyzed += 1;
                }
            }
            if let Some(fn_facts) = &ddl.function {
                if fn_facts.body.is_some() {
                    self.procedure_bodies_analyzed += 1;
                }
            }
        }
        match &mut self.retained {
            Some(out) => {
                let mut masked = facts.clone();
                let secrets = masked.mask_credential_values();
                out.push(masked);
                secrets
            }
            None => Vec::new(),
        }
    }

    /// Consume the sink, ending its `&mut` ledger borrow: the
    /// procedure/function body tally, the retained (trace-mode only)
    /// masked carriers, and the span starts whose findings were lost.
    fn finish(
        self,
    ) -> (
        usize,
        Option<Vec<facts::StatementFacts>>,
        std::collections::BTreeSet<u32>,
    ) {
        (
            self.procedure_bodies_analyzed,
            self.retained,
            self.lost_analysis,
        )
    }
}

/// Single seam for v1 rule evaluation against a `StatementFacts`
/// snapshot, used by every per-family evaluator above.
///
/// Hot path (`trace_out: None`): runs `evaluate_rules` and appends
/// emitted signals into `signals_out`.
///
/// Explain path (`trace_out: Some(_)`): runs `evaluate_rules_with_explain`,
/// extracts the emitted `Signal`s from the per-rule results so the
/// hot-path return value (the signal stream) stays identical, and
/// pushes one `StatementExplanation` per statement onto `trace_out`.
///
/// `stmt_span` is the span of the statement (or sub-statement, e.g. a
/// nested `DECLARE HANDLER`) the facts derive from. Used purely for
/// the explain surface — passed through to `build_statement_explanation`.
fn evaluate_facts_into(
    fold: &ScriptContextFold,
    facts: &facts::StatementFacts,
    rules_corpus: &[rules::Rule],
    stmt_span: lexer::token::Span,
    sql: &str,
    signals_out: &mut Vec<rules::Signal>,
    facts_out: Option<&mut StatementFactsSink<'_>>,
    trace_out: Option<&mut Vec<analyzer::StatementExplanation>>,
) {
    // Overlay this statement's folded session context (active role, …)
    // so rule predicates can compose it. No overlay (and no clone) when
    // no session state is in effect — the common no-`USE ROLE` case.
    let overlaid;
    let facts = {
        let ctx = fold.context_for(stmt_span);
        if ctx == facts::ScriptContext::default() {
            facts
        } else {
            let mut f = facts.clone();
            f.script_context = ctx;
            overlaid = f;
            &overlaid
        }
    };

    // Fold the facts into the optional sink before evaluating rules.
    // `analyze_risk_core` uses this to derive summary metrics
    // (tables_read / written / cross_schema / cross_database) from the
    // same per-statement fact stream the rule evaluators read. Any
    // carrier the sink retains (trace mode) is credential-masked: it
    // feeds report output (`statement_signals` / fact explanations),
    // which must never reproduce a secret value — evaluation below
    // still reads the unmasked `facts`. The masked values double as
    // the scrub list for the rendered rule explanations, whose
    // predicate paths quote compared values.
    let collect_secrets = trace_out.is_some();
    let mut secret_values: Vec<String> = Vec::new();
    if let Some(sink) = facts_out {
        let collected = sink.record(facts);
        if collect_secrets {
            secret_values = collected;
        }
    } else if collect_secrets {
        secret_values = facts.clone().mask_credential_values();
    }
    match trace_out {
        Some(trace) => {
            let evaluated = rules::evaluate_rules_with_explain(facts, rules_corpus);
            for e in &evaluated {
                signals_out.extend(e.signals.iter().cloned());
            }
            let mut explanation = build_statement_explanation(stmt_span, sql, evaluated);
            mask_secrets_in_explanation(&mut explanation, &secret_values);
            trace.push(explanation);
        }
        None => {
            signals_out.extend(rules::evaluate_rules(facts, rules_corpus));
        }
    }
}

/// Scrub known credential values out of a rendered rule explanation: the
/// predicate-path strings quote each compared fact value verbatim
/// (`… (actual: "<value>")`), so every collected secret — plus its
/// upper-cased twin, covering normalized copies — is replaced with the
/// fixed mask. Values shorter than 3 bytes are skipped: replacing an
/// empty or single-character "secret" would shred unrelated text.
fn mask_secrets_in_explanation(
    explanation: &mut analyzer::StatementExplanation,
    secret_values: &[String],
) {
    let mut needles: Vec<String> = Vec::new();
    for s in secret_values {
        if s.len() < 3 {
            continue;
        }
        if !needles.contains(s) {
            needles.push(s.clone());
        }
        let upper = s.to_uppercase();
        if upper != *s && !needles.contains(&upper) {
            needles.push(upper);
        }
    }
    if needles.is_empty() {
        return;
    }
    let scrub = |text: &mut String| {
        for n in &needles {
            if text.contains(n.as_str()) {
                *text = text.replace(n.as_str(), facts::MASKED_VALUE);
            }
        }
    };
    for r in &mut explanation.rejected_rules {
        for p in &mut r.explanation.matched_paths {
            scrub(p);
        }
        for p in &mut r.explanation.unmatched_paths {
            scrub(p);
        }
    }
}

/// Build a v1-shape `StatementExplanation` from the engine's per-rule
/// explain results. Splits matched-vs-rejected, attaches each
/// rejected rule's `RuleExplanation` (rendered path strings), and
/// captures a short preview of the statement source for human
/// navigation.
fn build_statement_explanation(
    stmt_span: lexer::token::Span,
    sql: &str,
    evaluated: Vec<rules::engine::EvaluatedRule>,
) -> analyzer::StatementExplanation {
    let statement_preview = statement_preview_from_span(Some(stmt_span), sql);
    let mut matched_rules = Vec::new();
    let mut rejected_rules = Vec::new();
    for e in evaluated {
        if e.matched {
            matched_rules.push(e.rule_id);
        } else {
            rejected_rules.push(analyzer::RejectedRuleExplanation {
                rule_id: e.rule_id,
                explanation: e.explanation,
            });
        }
    }
    analyzer::StatementExplanation {
        source_span: Some(stmt_span),
        statement_preview,
        matched_rules,
        rejected_rules,
    }
}

/// Mask secret value spans (passwords, credential keys, secret strings) out of
/// the source so no credential value can reach an output surface (finding
/// previews / evidence / SARIF). Each span is overwritten with same-byte-length
/// `*`, so all byte offsets are preserved and the result is a drop-in for the
/// original wherever the source is sliced for display. Borrows the source
/// unchanged in the common no-credentials case — no file-sized copy.
fn redact_secret_spans<'a>(src: &'a str, spans: &[lexer::token::Span]) -> Cow<'a, str> {
    if spans.is_empty() {
        return Cow::Borrowed(src);
    }
    let mut bytes = src.as_bytes().to_vec();
    let len = bytes.len();
    for sp in spans {
        let start = (sp.start as usize).min(len);
        let end = (sp.end as usize).min(len).max(start);
        for b in &mut bytes[start..end] {
            *b = b'*';
        }
    }
    // `from_utf8_lossy` never reproduces the original bytes for a masked range
    // (they are all `*`); a span that splits a multi-byte char degrades to the
    // replacement char, never the secret.
    Cow::Owned(String::from_utf8_lossy(&bytes).into_owned())
}

/// Redact secret values (credential properties, password literals) in `sql` so
/// it is safe to quote in any source-display surface (e.g. diff previews built
/// outside `analyze_risk`). Parses `sql` to locate the secret spans, then masks
/// them offset-preservingly. Best-effort: unparseable input is returned as-is.
pub fn redact_secrets_for_display(sql: &str) -> String {
    match try_parse_script_from_str(sql) {
        Ok(script) => redact_secret_spans(sql, &script.redaction_spans).into_owned(),
        Err(_) => sql.to_string(),
    }
}

fn statement_preview_from_span(span: Option<lexer::token::Span>, sql: &str) -> String {
    const PREVIEW_LEN: usize = 80;
    let Some(span) = span else {
        return String::new();
    };
    let start = span.start as usize;
    let end = span.end as usize;
    let bounded_start = start.min(sql.len());
    let bounded_end = end.min(sql.len()).max(bounded_start);
    let raw = &sql[bounded_start..bounded_end];
    let trimmed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() <= PREVIEW_LEN {
        trimmed
    } else {
        let truncated: String = trimmed.chars().take(PREVIEW_LEN).collect();
        format!("{}…", truncated)
    }
}

/// Per-statement dispatch for every DDL family. Operates on a
/// pre-parsed `Script` and an explicit `rules_corpus` so the same
/// dispatch arms can evaluate built-in rules (via the public
/// `analyze_ddl_facts*` entry points) and customer rules (via the
/// unified driver in `analyze_risk_core`) without duplicating the
/// AST → IR → facts lowering.
///
/// `trace_out` follows the same explain-mode contract as
/// [`evaluate_privilege_rules_for_script`].
pub(crate) fn evaluate_ddl_rules_for_script(
    script: &ast::AstScript,
    sql: &str,
    fold: &ScriptContextFold,
    rules_corpus: &[rules::Rule],
    reasoning: &dyn facts::reasoning::Reasoning,
    script_reasoning: &dyn facts::reasoning::ScriptReasoning,
    mut facts_out: Option<&mut StatementFactsSink<'_>>,
    mut trace_out: Option<&mut Vec<analyzer::StatementExplanation>>,
) -> Vec<rules::Signal> {
    let mut signals = Vec::new();
    if rules_corpus.is_empty() {
        return signals;
    }
    // Dynamic-SQL argument classifier over the whole script: a bare
    // variable argument resolves to the shape it was assigned, so
    // via-variable injection patterns classify as the built shape.
    let dynamic_sql = script_reasoning.dynamic_sql();
    // Iterate the depth-first flatten so inner-body statements of
    // CREATE PROCEDURE / CREATE FUNCTION / control-flow blocks are
    // analyzed alongside top-level statements. Mirrors the dispatch
    // pattern used by `evaluate_query_rules_for_script` and is what
    // lets rules like TBL-TRUNCATE / TBL-DROP fire on inner DDL
    // statements within a procedure body.
    let flat_stmts = flat_stmts_for_rules(script);
    for stmt in &flat_stmts {
        let stmt = *stmt;
        let stage_plan = match stmt {
            ast::AstStmt::CreateStage(s) => Some(ir::lower_create_stage_to_stage_plan(s, sql)),
            ast::AstStmt::AlterStage(s) => Some(ir::lower_alter_stage_to_stage_plan(s, sql)),
            ast::AstStmt::CopyIntoLocation {
                node_id,
                span,
                from_span,
                location_url,
                credentials,
                copy_options,
                ..
            } => Some(ir::lower_copy_into_location_to_stage_plan(
                *span,
                *node_id,
                *from_span,
                sql,
                location_url.as_deref(),
                credentials,
                copy_options,
            )),
            ast::AstStmt::CopyIntoTable {
                node_id,
                span,
                table_name_span,
                copy_options,
                from_location_url,
                credentials,
                ..
            } => Some(ir::lower_copy_into_table_to_stage_plan(
                *span,
                *node_id,
                *table_name_span,
                sql,
                from_location_url.as_deref(),
                credentials,
                copy_options,
            )),
            ast::AstStmt::Unload {
                node_id,
                span,
                location_url,
                credentials,
                ..
            } => Some(ir::lower_unload_to_stage_plan(
                *span,
                *node_id,
                sql,
                location_url.as_deref(),
                credentials,
            )),
            ast::AstStmt::RedshiftCopy {
                node_id,
                span,
                location_url,
                credentials,
                ..
            } => Some(ir::lower_redshift_copy_to_stage_plan(
                *span,
                *node_id,
                location_url.as_deref(),
                credentials,
            )),
            ast::AstStmt::Drop(s) => ir::lower_drop_stage_to_stage_plan(s, sql),
            _ => None,
        };
        if let Some(plan) = stage_plan {
            let mut facts = facts::extract::derive_facts_from_stage_plan(&plan, sql);
            // Enrich a COPY INTO <location> with the classification of the
            // columns its source unloads out of the warehouse — the
            // egress-taint surface. Needs the catalog / cross-script registry,
            // which only this pass now threads in.
            if let ast::AstStmt::CopyIntoLocation {
                source: Some(src), ..
            } = stmt
            {
                let session = fold.session_context_at(stmt.span().start);
                let exported = script_reasoning.exported_columns(src, &session);
                if let Some(stage) = facts.ddl.as_mut().and_then(|d| d.stage.as_mut()) {
                    stage.exported_columns = exported;
                }
            }
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let dynamic_table_plan = match stmt {
            ast::AstStmt::CreateDynamicTable(s) => {
                Some(ir::lower_create_dynamic_table_to_dynamic_table_plan(s, sql))
            }
            ast::AstStmt::AlterDynamicTable(s) => {
                Some(ir::lower_alter_dynamic_table_to_dynamic_table_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => ir::lower_drop_dynamic_table_to_dynamic_table_plan(s, sql),
            _ => None,
        };
        if let Some(plan) = dynamic_table_plan {
            let facts = facts::extract::derive_facts_from_dynamic_table_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Table dispatch must come AFTER the dynamic-table dispatch
        // because both can claim a generic `AstStmt::Drop`; the
        // dynamic-table lowering returns `Some` only for `DROP DYNAMIC
        // TABLE`, so falling through here to the table lowering
        // (`DROP TABLE`) is correct.
        let table_plan = match stmt {
            ast::AstStmt::CreateTable(s) => Some(ir::lower_create_table_to_table_plan(s, sql)),
            ast::AstStmt::AlterTable(s) => Some(ir::lower_alter_table_to_table_plan(s, sql)),
            ast::AstStmt::MysqlRenameTable(s) => {
                Some(ir::lower_mysql_rename_table_to_table_plan(s, sql))
            }
            ast::AstStmt::Truncate(s) => Some(ir::lower_truncate_to_table_plan(s, sql)),
            ast::AstStmt::DropAllRowAccessPolicies(s) => {
                Some(ir::lower_drop_all_row_access_policies_to_table_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => ir::lower_drop_table_to_table_plan(s, sql),
            _ => None,
        };
        if let Some(plan) = table_plan {
            let facts = facts::extract::derive_facts_from_table_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let table_maintenance_plan = match stmt {
            ast::AstStmt::Vacuum(s) => Some(ir::lower_vacuum_to_table_maintenance_plan(s, sql)),
            ast::AstStmt::Optimize(s) => Some(ir::lower_optimize_to_table_maintenance_plan(s, sql)),
            ast::AstStmt::Restore(s) => Some(ir::lower_restore_to_table_maintenance_plan(s, sql)),
            ast::AstStmt::DescribeHistory(s) => {
                Some(ir::lower_describe_history_to_table_maintenance_plan(s, sql))
            }
            ast::AstStmt::RepairTable(s) => {
                Some(ir::lower_repair_table_to_table_maintenance_plan(s, sql))
            }
            ast::AstStmt::CacheTable(s) => {
                Some(ir::lower_cache_table_to_table_maintenance_plan(s, sql))
            }
            ast::AstStmt::UncacheTable(s) => {
                Some(ir::lower_uncache_table_to_table_maintenance_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = table_maintenance_plan {
            let facts = facts::extract::derive_facts_from_table_maintenance_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // View DDL (cross-dialect CREATE / ALTER / DROP VIEW and
        // ALTER MATERIALIZED VIEW). Same dispatch-filter pattern as
        // `MssqlDdlKind` / `PgDdlKind` / `BqDdlKind`: the AST variant
        // resolves the [`facts::extract::ViewDdlKind`], `lower_ddl_stmt`
        // produces a generic [`ir::DdlPlan`], and
        // `derive_facts_from_view_ddl_plan` projects to public
        // `StatementFacts`. Drives VIEW-REPLACE / VIEW-CHG / VIEW-DROP
        // / VIEW-CASCADE-DROP.
        //
        // Sits after the table/stage/dynamic-table dispatch so a
        // generic `AstStmt::Drop` with object_type=VIEW reaches us
        // (those dispatchers return `None` for non-matching object
        // types) — the earlier table dispatcher's `lower_drop_table_to_table_plan`
        // gates on `object_type == TABLE`, so DROP VIEW falls through.
        let view_kind: Option<facts::extract::ViewDdlKind> = match stmt {
            ast::AstStmt::CreateView(_) => Some(facts::extract::ViewDdlKind::CreateView),
            ast::AstStmt::AlterView(_) => Some(facts::extract::ViewDdlKind::AlterView),
            ast::AstStmt::AlterMaterializedView(_) => {
                Some(facts::extract::ViewDdlKind::AlterMaterializedView)
            }
            ast::AstStmt::Drop(s) => {
                drop_target_is_view(s, sql).then_some(facts::extract::ViewDdlKind::DropView)
            }
            _ => None,
        };
        if let Some(kind) = view_kind {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                let mut facts = facts::extract::derive_facts_from_view_ddl_plan(&plan, kind);
                // The view lowers through the generic DdlPlan, so the MySQL
                // security-context prelude (DEFINER / SQL SECURITY) is projected
                // straight from the AST here and attached to `ddl.view`.
                if let ast::AstStmt::CreateView(cv) = stmt {
                    if let Some(ddl) = facts.ddl.as_mut() {
                        ddl.view = facts::extract::project_view_prelude_facts(cv, sql);
                    }
                }
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }

        let pipe_plan = match stmt {
            ast::AstStmt::CreatePipe(s) => Some(ir::lower_create_pipe_to_pipe_plan(s, sql)),
            ast::AstStmt::AlterPipe(s) => Some(ir::lower_alter_pipe_to_pipe_plan(s, sql)),
            ast::AstStmt::DropPipe(s) => Some(ir::lower_drop_pipe_to_pipe_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = pipe_plan {
            let facts = facts::extract::derive_facts_from_pipe_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake TAG lifecycle. CREATE / ALTER / UNDROP arrive as
        // typed variants; DROP TAG arrives as a generic `AstStmt::Drop`
        // gated on the object type (same pattern as the view family).
        // Surfaces `ddl.tag.*` facts — masking-policy attach/detach,
        // allowed-value changes, propagation.
        let tag_plan = match stmt {
            ast::AstStmt::CreateTag(s) => Some(ir::lower_create_tag_to_tag_plan(s, sql)),
            ast::AstStmt::AlterTag(s) => Some(ir::lower_alter_tag_to_tag_plan(s, sql)),
            ast::AstStmt::UndropTag(s) => Some(ir::lower_undrop_tag_to_tag_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_tag(s, sql).then(|| ir::lower_drop_tag_to_tag_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = tag_plan {
            let facts = facts::extract::derive_facts_from_tag_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake CREATE / ALTER / DROP FILE FORMAT — surfaces
        // `ddl.file_format.*` facts (recognized type, rename target).
        let file_format_plan = match stmt {
            ast::AstStmt::CreateFileFormat(s) => Some(ir::lower_create_file_format_to_plan(s, sql)),
            ast::AstStmt::AlterFileFormat(s) => Some(ir::lower_alter_file_format_to_plan(s, sql)),
            ast::AstStmt::Drop(s) => drop_target_is_file_format(s, sql)
                .then(|| ir::lower_drop_file_format_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = file_format_plan {
            let facts = facts::extract::derive_facts_from_file_format_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake ALTER SESSION SET/UNSET — session-parameter mutation.
        // Surfaces `ddl.session.*` facts (parameters configured / reset).
        let session_plan = match stmt {
            ast::AstStmt::AlterSession(s) => Some(ir::lower_alter_session_to_session_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = session_plan {
            let facts = facts::extract::derive_facts_from_session_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let stream_plan = match stmt {
            ast::AstStmt::CreateStream(s) => Some(ir::lower_create_stream_to_stream_plan(s, sql)),
            ast::AstStmt::DropStream(s) => Some(ir::lower_drop_stream_to_stream_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = stream_plan {
            let facts = facts::extract::derive_facts_from_stream_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake NETWORK RULE — the destinations/origins that network
        // policies and external-access integrations reference by name
        // (`ddl.network_rule.*`). DROP arrives as a generic Drop gated
        // on the two-word object type.
        let network_rule_plan = match stmt {
            ast::AstStmt::CreateNetworkRule(s) => {
                Some(ir::lower_create_network_rule_to_network_rule_plan(s, sql))
            }
            ast::AstStmt::AlterNetworkRule(s) => {
                Some(ir::lower_alter_network_rule_to_network_rule_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_network_rule(s, sql)
                .then(|| ir::lower_drop_network_rule_to_network_rule_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = network_rule_plan {
            let facts = facts::extract::derive_facts_from_network_rule_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake RESOURCE MONITOR — compute cost-governance object
        // (`ddl.resource_monitor.*`). Its triggers decide whether crossing
        // a credit-usage threshold halts compute or merely notifies. DROP
        // arrives as a generic Drop gated on the two-word object type.
        let resource_monitor_plan = match stmt {
            ast::AstStmt::CreateResourceMonitor(s) => Some(
                ir::lower_create_resource_monitor_to_resource_monitor_plan(s, sql),
            ),
            ast::AstStmt::AlterResourceMonitor(s) => Some(
                ir::lower_alter_resource_monitor_to_resource_monitor_plan(s, sql),
            ),
            ast::AstStmt::Drop(s) => drop_target_is_resource_monitor(s, sql)
                .then(|| ir::lower_drop_resource_monitor_to_resource_monitor_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = resource_monitor_plan {
            let facts = facts::extract::derive_facts_from_resource_monitor_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake COMPUTE POOL — Snowpark Container Services compute
        // capacity (`ddl.compute_pool.*`). Its instance family and node
        // counts drive cost; DROP arrives as a generic Drop gated on the
        // two-word object type.
        let compute_pool_plan = match stmt {
            ast::AstStmt::CreateComputePool(s) => {
                Some(ir::lower_create_compute_pool_to_compute_pool_plan(s, sql))
            }
            ast::AstStmt::AlterComputePool(s) => {
                Some(ir::lower_alter_compute_pool_to_compute_pool_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_compute_pool(s, sql)
                .then(|| ir::lower_drop_compute_pool_to_compute_pool_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = compute_pool_plan {
            let facts = facts::extract::derive_facts_from_compute_pool_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake GIT REPOSITORY — connects Snowflake to an external git
        // remote (`ddl.git_repository.*`); code from it runs via EXECUTE
        // IMMEDIATE FROM. DROP arrives as a generic Drop gated on the
        // two-word object type.
        let git_repository_plan = match stmt {
            ast::AstStmt::CreateGitRepository(s) => Some(
                ir::lower_create_git_repository_to_git_repository_plan(s, sql),
            ),
            ast::AstStmt::AlterGitRepository(s) => Some(
                ir::lower_alter_git_repository_to_git_repository_plan(s, sql),
            ),
            ast::AstStmt::Drop(s) => drop_target_is_git_repository(s, sql)
                .then(|| ir::lower_drop_git_repository_to_git_repository_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = git_repository_plan {
            let facts = facts::extract::derive_facts_from_git_repository_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake EXTERNAL FUNCTION — a UDF that ships row data to an
        // external HTTPS endpoint via an API integration (`ddl.external_function.*`),
        // a data-egress surface. ALTER/DROP route through the regular function
        // paths; only CREATE carries the egress recognition surface.
        if let ast::AstStmt::CreateExternalFunction(s) = stmt {
            let plan = ir::lower_create_external_function_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_external_function_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake IMAGE REPOSITORY — SPCS container-image registry
        // (`ddl.image_repository.*`). DROP arrives as a generic Drop gated on
        // the two-word object type.
        let image_repository_plan = match stmt {
            ast::AstStmt::CreateImageRepository(s) => Some(
                ir::lower_create_image_repository_to_image_repository_plan(s, sql),
            ),
            ast::AstStmt::AlterImageRepository(s) => Some(
                ir::lower_alter_image_repository_to_image_repository_plan(s, sql),
            ),
            ast::AstStmt::Drop(s) => drop_target_is_image_repository(s, sql)
                .then(|| ir::lower_drop_image_repository_to_image_repository_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = image_repository_plan {
            let facts = facts::extract::derive_facts_from_image_repository_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake STREAMLIT — Python-app object (`ddl.streamlit.*`); the
        // recognition surface is EXTERNAL_ACCESS_INTEGRATIONS (egress). DROP
        // arrives as a generic Drop gated on the object type.
        let streamlit_plan = match stmt {
            ast::AstStmt::CreateStreamlit(s) => {
                Some(ir::lower_create_streamlit_to_streamlit_plan(s, sql))
            }
            ast::AstStmt::AlterStreamlit(s) => {
                Some(ir::lower_alter_streamlit_to_streamlit_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_streamlit(s, sql)
                .then(|| ir::lower_drop_streamlit_to_streamlit_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = streamlit_plan {
            let facts = facts::extract::derive_facts_from_streamlit_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake SERVICE — SPCS container service (`ddl.service.*`); the
        // recognition surface is the compute-pool binding and
        // EXTERNAL_ACCESS_INTEGRATIONS (egress). DROP arrives as a generic Drop
        // gated on the object type.
        let service_plan = match stmt {
            ast::AstStmt::CreateService(s) => {
                Some(ir::lower_create_service_to_service_plan(s, sql))
            }
            ast::AstStmt::AlterService(s) => Some(ir::lower_alter_service_to_service_plan(s, sql)),
            ast::AstStmt::Drop(s) => drop_target_is_service(s, sql)
                .then(|| ir::lower_drop_service_to_service_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = service_plan {
            let facts = facts::extract::derive_facts_from_service_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake NOTEBOOK — code-from-stage object (`ddl.notebook.*`); the
        // recognition surface is EXTERNAL_ACCESS_INTEGRATIONS (egress). DROP
        // arrives as a generic Drop gated on the object type.
        let notebook_plan = match stmt {
            ast::AstStmt::CreateNotebook(s) => {
                Some(ir::lower_create_notebook_to_notebook_plan(s, sql))
            }
            ast::AstStmt::AlterNotebook(s) => {
                Some(ir::lower_alter_notebook_to_notebook_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_notebook(s, sql)
                .then(|| ir::lower_drop_notebook_to_notebook_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = notebook_plan {
            let facts = facts::extract::derive_facts_from_notebook_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake SEMANTIC VIEW — a named model over base tables
        // (`ddl.semantic_view.*`); the recognition surface is the base-table
        // access surface. DROP SEMANTIC VIEW arrives as a generic Drop gated
        // on the object type.
        let semantic_view_plan = match stmt {
            ast::AstStmt::CreateSemanticView(s) => {
                Some(ir::lower_create_semantic_view_to_semantic_view_plan(s, sql))
            }
            ast::AstStmt::AlterSemanticView(s) => {
                Some(ir::lower_alter_semantic_view_to_semantic_view_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_semantic_view(s, sql)
                .then(|| ir::lower_drop_semantic_view_to_semantic_view_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = semantic_view_plan {
            let facts = facts::extract::derive_facts_from_semantic_view_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake CORTEX SEARCH SERVICE — AI search index over a source
        // query (`ddl.cortex_search_service.*`); the recognition surface is the
        // embedding model and that a source query is indexed. DROP arrives as a
        // generic Drop gated on the object type.
        let cortex_search_service_plan = match stmt {
            ast::AstStmt::CreateCortexSearchService(s) => {
                Some(ir::lower_create_cortex_search_service_to_plan(s, sql))
            }
            ast::AstStmt::AlterCortexSearchService(s) => {
                Some(ir::lower_alter_cortex_search_service_to_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_cortex_search_service(s, sql)
                .then(|| ir::lower_drop_cortex_search_service_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = cortex_search_service_plan {
            let facts = facts::extract::derive_facts_from_cortex_search_service_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake Native Apps: APPLICATION PACKAGE (provider container,
        // `ddl.application_package.*`). Checked before APPLICATION so the
        // two-word DROP routes here. DROP arrives as a generic Drop gated on
        // the object type.
        let application_package_plan = match stmt {
            ast::AstStmt::CreateApplicationPackage(s) => {
                Some(ir::lower_create_application_package_to_plan(s, sql))
            }
            ast::AstStmt::AlterApplicationPackage(s) => {
                Some(ir::lower_alter_application_package_to_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_application_package(s, sql)
                .then(|| ir::lower_drop_application_package_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = application_package_plan {
            let facts = facts::extract::derive_facts_from_application_package_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake Native Apps: APPLICATION (consumer-installed app,
        // `ddl.application.*`); the recognition surface is the install-source
        // provenance and DEBUG_MODE. DROP arrives as a generic Drop gated on
        // the object type.
        let application_plan = match stmt {
            ast::AstStmt::CreateApplication(s) => {
                Some(ir::lower_create_application_to_plan(s, sql))
            }
            ast::AstStmt::AlterApplication(s) => Some(ir::lower_alter_application_to_plan(s, sql)),
            ast::AstStmt::Drop(s) => drop_target_is_application(s, sql)
                .then(|| ir::lower_drop_application_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = application_plan {
            let facts = facts::extract::derive_facts_from_application_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake LISTING — Marketplace / data-exchange exposure
        // (`ddl.listing.*`); the recognition surface is whether it is external
        // (public) and published. DROP arrives as a generic Drop gated on the
        // object type.
        let listing_plan = match stmt {
            ast::AstStmt::CreateListing(s) => Some(ir::lower_create_listing_to_plan(s, sql)),
            ast::AstStmt::AlterListing(s) => Some(ir::lower_alter_listing_to_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_listing(s, sql).then(|| ir::lower_drop_listing_to_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = listing_plan {
            let facts = facts::extract::derive_facts_from_listing_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake MANAGED ACCOUNT — reader account that consumes shares from
        // outside the org (`ddl.managed_account.*`). Checked before the bare
        // ACCOUNT path so the two-word DROP routes here. Admin credentials are
        // never carried.
        let managed_account_plan = match stmt {
            ast::AstStmt::CreateManagedAccount(s) => {
                Some(ir::lower_create_managed_account_to_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_managed_account(s, sql)
                .then(|| ir::lower_drop_managed_account_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = managed_account_plan {
            let facts = facts::extract::derive_facts_from_managed_account_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake CREATE / DROP ACCOUNT — org-level account provisioning
        // (recognition only). Distinct from ALTER ACCOUNT parameter changes.
        let org_account_plan = match stmt {
            ast::AstStmt::CreateAccount(s) => Some(ir::lower_create_account_to_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_account(s, sql).then(|| ir::lower_drop_account_to_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = org_account_plan {
            let facts = facts::extract::derive_facts_from_org_account_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake client file commands: PUT / GET / REMOVE / LIST. The
        // operation kind is the recognition surface (GET = data egress to the
        // client; REMOVE = stage file deletion).
        if let ast::AstStmt::StageFileCommand(s) = stmt {
            let plan = ir::lower_stage_file_command_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_stage_file_command_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake SECRET — credential-object lifecycle (`ddl.secret.*`).
        // Property names only; secret values are never carried. DROP
        // SECRET arrives as a generic Drop gated on the object type.
        let secret_plan = match stmt {
            ast::AstStmt::CreateSecret(s) => Some(ir::lower_create_secret_to_secret_plan(s, sql)),
            ast::AstStmt::AlterSecret(s) => Some(ir::lower_alter_secret_to_secret_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_secret(s, sql).then(|| ir::lower_drop_secret_to_secret_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = secret_plan {
            let facts = facts::extract::derive_facts_from_secret_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake SHARE — consumer-account changes are the cross-account
        // exposure primitives (`ddl.share.*`). DROP SHARE arrives as a
        // generic Drop gated on the object type. GRANT … TO SHARE flows
        // through the privilege substrate, not here.
        let share_plan = match stmt {
            ast::AstStmt::CreateShare(s) => Some(ir::lower_create_share_to_share_plan(s, sql)),
            ast::AstStmt::AlterShare(s) => Some(ir::lower_alter_share_to_share_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_share(s, sql).then(|| ir::lower_drop_share_to_share_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = share_plan {
            let facts = facts::extract::derive_facts_from_share_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Redshift datashare — dedicated plan path that surfaces typed
        // `ddl.datashare.*` facts. Intercepts before the generic minimal-DDL
        // path (which would yield `ddl: None`, exposing no exposure primitives).
        let datashare_plan = match stmt {
            ast::AstStmt::CreateDatashare(s) => {
                Some(ir::lower_create_datashare_to_datashare_plan(s, sql))
            }
            ast::AstStmt::AlterDatashare(s) => {
                Some(ir::lower_alter_datashare_to_datashare_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = datashare_plan {
            let facts = facts::extract::derive_facts_from_datashare_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let schema_plan = match stmt {
            ast::AstStmt::CreateSchema(s) => Some(ir::lower_create_schema_to_schema_plan(s, sql)),
            ast::AstStmt::AlterSchema(s) => Some(ir::lower_alter_schema_to_schema_plan(s, sql)),
            ast::AstStmt::DropSchema(s) => Some(ir::lower_drop_schema_to_schema_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = schema_plan {
            let facts = facts::extract::derive_facts_from_schema_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let catalog_plan = match stmt {
            ast::AstStmt::CreateCatalog(s) => {
                Some(ir::lower_create_catalog_to_catalog_plan(s, sql))
            }
            ast::AstStmt::AlterCatalog(s) => Some(ir::lower_alter_catalog_to_catalog_plan(s, sql)),
            ast::AstStmt::DropCatalog(s) => Some(ir::lower_drop_catalog_to_catalog_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = catalog_plan {
            let facts = facts::extract::derive_facts_from_catalog_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let use_plan = match stmt {
            ast::AstStmt::Use(s) => Some(ir::lower_use_to_use_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = use_plan {
            let facts = facts::extract::derive_facts_from_use_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let task_plan = match stmt {
            ast::AstStmt::CreateTask(s) => Some(ir::lower_create_task_to_task_plan(s, sql)),
            ast::AstStmt::AlterTask(s) => Some(ir::lower_alter_task_to_task_plan(s, sql)),
            ast::AstStmt::DropTask(s) => Some(ir::lower_drop_task_to_task_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = task_plan {
            let facts = facts::extract::derive_facts_from_task_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake ALERT — scheduled SQL condition+action run under the
        // owner's role (`ddl.alert.*`). Same risk shape as TASK. DROP
        // ALERT arrives as a generic Drop gated on the object type.
        let alert_plan = match stmt {
            ast::AstStmt::CreateAlert(s) => Some(ir::lower_create_alert_to_alert_plan(s, sql)),
            ast::AstStmt::AlterAlert(s) => Some(ir::lower_alter_alert_to_alert_plan(s, sql)),
            ast::AstStmt::Drop(s) => {
                drop_target_is_alert(s, sql).then(|| ir::lower_drop_alert_to_alert_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = alert_plan {
            let facts = facts::extract::derive_facts_from_alert_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake DATA METRIC FUNCTION lifecycle (`ddl.data_metric_function`).
        // The table attachment is on the ALTER TABLE side; this is the
        // CREATE/DROP of the function object. DROP arrives as a generic Drop
        // gated on the three-word object type.
        let dmf_plan = match stmt {
            ast::AstStmt::CreateDataMetricFunction(s) => {
                Some(ir::lower_create_data_metric_function_to_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_target_is_data_metric_function(s, sql)
                .then(|| ir::lower_drop_data_metric_function_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = dmf_plan {
            let facts = facts::extract::derive_facts_from_data_metric_function_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Snowflake REPLICATION / FAILOVER GROUP (`ddl.replication_failover_group`).
        // ALLOWED_ACCOUNTS is the cross-account egress primitive. DROP arrives
        // as a generic Drop gated on the two-word object type, which also
        // resolves the group kind.
        let repl_group_plan = match stmt {
            ast::AstStmt::CreateReplicationFailoverGroup(s) => {
                Some(ir::lower_create_replication_failover_group_to_plan(s, sql))
            }
            ast::AstStmt::Drop(s) => drop_replication_failover_group_type(s, sql)
                .map(|kind| ir::lower_drop_replication_failover_group_to_plan(s, kind, sql)),
            _ => None,
        };
        if let Some(plan) = repl_group_plan {
            let facts =
                facts::extract::derive_facts_from_replication_failover_group_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Function dispatch. Generic `AstStmt::Drop` with object
        // type == `FUNCTION` is claimed here; the lowering returns
        // `None` for any other object type so the dispatch falls
        // through to the next family (procedure).
        let function_plan =
            match stmt {
                ast::AstStmt::CreateFunction(s) => Some(
                    ir::lower_create_function_to_function_plan(s, sql, script_reasoning),
                ),
                ast::AstStmt::CreateTableFunction(s) => Some(
                    ir::lower_create_table_function_to_function_plan(s, sql, script_reasoning),
                ),
                ast::AstStmt::AlterFunction(s) => {
                    Some(ir::lower_alter_function_to_function_plan(s, sql))
                }
                ast::AstStmt::Drop(s) => ir::lower_drop_function_to_function_plan(s, sql),
                _ => None,
            };
        if let Some(plan) = function_plan {
            let facts = facts::extract::derive_facts_from_function_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Procedure dispatch. Generic `AstStmt::Drop` with object
        // type == `PROCEDURE` is claimed here; the earlier table /
        // stage / dynamic-table / function lowerings return `None`
        // for non-matching object types so this dispatch reliably
        // catches it.
        let procedure_plan =
            match stmt {
                ast::AstStmt::CreateProcedure(s) => Some(
                    ir::lower_create_procedure_to_procedure_plan(s, sql, script_reasoning),
                ),
                ast::AstStmt::AlterProcedure(s) => {
                    Some(ir::lower_alter_procedure_to_procedure_plan(s, sql))
                }
                ast::AstStmt::Drop(s) => ir::lower_drop_procedure_to_procedure_plan(s, sql),
                _ => None,
            };
        if let Some(mut plan) = procedure_plan {
            // Inject inter-procedural findings into the procedure-body
            // dynamic-SQL-call list so the DYNSQL family's
            // `ddl.procedure.body.dynamic_sql_calls.exists` predicate
            // fires on multi-procedure laundering chains.
            if let ast::AstStmt::CreateProcedure(s) = stmt {
                if let Some(body) = s.body_stmt.as_deref() {
                    let inter_proc = script_reasoning.inter_procedural_calls(body);
                    if let Some(body_shape) = plan.create_body.as_mut() {
                        body_shape.dynamic_sql_calls.extend(inter_proc);
                    }
                }
            }
            let facts = facts::extract::derive_facts_from_procedure_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let database_plan = match stmt {
            ast::AstStmt::CreateDatabase(s) => {
                Some(ir::lower_create_database_to_database_plan(s, sql))
            }
            ast::AstStmt::AlterDatabase(s) => {
                Some(ir::lower_alter_database_to_database_plan(s, sql))
            }
            ast::AstStmt::DropDatabase(s) => Some(ir::lower_drop_database_to_database_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = database_plan {
            let facts = facts::extract::derive_facts_from_database_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let warehouse_plan = match stmt {
            ast::AstStmt::CreateWarehouse(s) => {
                Some(ir::lower_create_warehouse_to_warehouse_plan(s, sql))
            }
            ast::AstStmt::AlterWarehouse(s) => {
                Some(ir::lower_alter_warehouse_to_warehouse_plan(s, sql))
            }
            ast::AstStmt::DropWarehouse(s) => {
                Some(ir::lower_drop_warehouse_to_warehouse_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = warehouse_plan {
            let facts = facts::extract::derive_facts_from_warehouse_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let storage_credential_plan = match stmt {
            ast::AstStmt::CreateStorageCredential(s) => {
                Some(ir::lower_create_storage_credential_to_storage_credential_plan(s))
            }
            ast::AstStmt::AlterStorageCredential(s) => {
                Some(ir::lower_alter_storage_credential_to_storage_credential_plan(s))
            }
            ast::AstStmt::DropStorageCredential(s) => {
                Some(ir::lower_drop_storage_credential_to_storage_credential_plan(s))
            }
            _ => None,
        };
        if let Some(plan) = storage_credential_plan {
            let facts = facts::extract::derive_facts_from_storage_credential_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let volume_plan = match stmt {
            ast::AstStmt::CreateVolume(s) => Some(ir::lower_create_volume_to_volume_plan(s, sql)),
            ast::AstStmt::AlterVolume(s) => Some(ir::lower_alter_volume_to_volume_plan(s, sql)),
            ast::AstStmt::DropVolume(s) => Some(ir::lower_drop_volume_to_volume_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = volume_plan {
            let facts = facts::extract::derive_facts_from_volume_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let external_location_plan = match stmt {
            ast::AstStmt::CreateExternalLocation(s) => {
                Some(ir::lower_create_external_location_to_external_location_plan(s, sql))
            }
            ast::AstStmt::AlterExternalLocation(s) => Some(
                ir::lower_alter_external_location_to_external_location_plan(s, sql),
            ),
            ast::AstStmt::DropExternalLocation(s) => Some(
                ir::lower_drop_external_location_to_external_location_plan(s, sql),
            ),
            _ => None,
        };
        if let Some(plan) = external_location_plan {
            let facts = facts::extract::derive_facts_from_external_location_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let connection_plan = match stmt {
            ast::AstStmt::CreateConnection(s) => {
                Some(ir::lower_create_connection_to_connection_plan(s, sql))
            }
            ast::AstStmt::AlterConnection(s) => {
                Some(ir::lower_alter_connection_to_connection_plan(s, sql))
            }
            ast::AstStmt::DropConnection(s) => {
                Some(ir::lower_drop_connection_to_connection_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = connection_plan {
            let facts = facts::extract::derive_facts_from_connection_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::MssqlCreateExternalDataSource(s) = stmt {
            let plan = ir::lower_create_external_data_source_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_external_data_source_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::MssqlAlterExternalDataSource(s) = stmt {
            let plan = ir::lower_alter_external_data_source_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_external_data_source_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let foreign_server_plan = match stmt {
            ast::AstStmt::CreateForeignServer(s) => {
                Some(ir::lower_create_foreign_server_to_plan(s, sql))
            }
            ast::AstStmt::AlterForeignServer(s) => {
                Some(ir::lower_alter_foreign_server_to_plan(s, sql))
            }
            _ => None,
        };
        if let Some(plan) = foreign_server_plan {
            let facts = facts::extract::derive_facts_from_foreign_server_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::MssqlAlterServerConfiguration(s) = stmt {
            let plan = ir::lower_mssql_alter_server_configuration_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_server_configuration_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::MysqlLoadData(s) = stmt {
            let plan = ir::lower_mysql_load_data_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_mysql_load_data_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let event_plan = match stmt {
            ast::AstStmt::CreateEvent(s) => Some(ir::lower_create_event_to_plan(s, sql)),
            ast::AstStmt::AlterEvent(s) => Some(ir::lower_alter_event_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = event_plan {
            let facts = facts::extract::derive_facts_from_event_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            // `continue` advances to the next flat entry; the DO body was
            // flattened in as its own subsequent entry, so it is still
            // rule-evaluated independently (not skipped by this continue).
            continue;
        }

        if let ast::AstStmt::CreateMysqlTrigger(s) = stmt {
            let plan = ir::lower_create_mysql_trigger_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_trigger_create_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            // The trigger body was flattened in as a later entry — it analyzes
            // on its own iteration, so this continue does not skip it.
            continue;
        }

        if let ast::AstStmt::CreateForeignTable(s) = stmt {
            let plan = ir::lower_create_foreign_table_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_foreign_table_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::ImportForeignSchema(s) = stmt {
            let plan = ir::lower_import_foreign_schema_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_import_foreign_schema_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let user_mapping_plan = match stmt {
            ast::AstStmt::CreateUserMapping(s) => {
                Some(ir::lower_create_user_mapping_to_plan(s, sql))
            }
            ast::AstStmt::AlterUserMapping(s) => Some(ir::lower_alter_user_mapping_to_plan(s, sql)),
            ast::AstStmt::DropUserMapping(s) => Some(ir::lower_drop_user_mapping_to_plan(s, sql)),
            _ => None,
        };
        if let Some(plan) = user_mapping_plan {
            let facts = facts::extract::derive_facts_from_user_mapping_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let flow_plan = match stmt {
            ast::AstStmt::CreateFlow(s) => Some(ir::lower_create_flow_to_flow_plan(s)),
            _ => None,
        };
        if let Some(plan) = flow_plan {
            let facts = facts::extract::derive_facts_from_flow_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Tag the dialect-of-origin at the AST-variant match site —
        // each `AstStmt::*Policy` variant is constructed by exactly
        // one dialect's parser, so the variant itself carries the
        // dialect signal. The IR plan stays dialect-clean; the tag is
        // recovered here and threaded into the projection. Same
        // pattern as `PgDdlKind` / `MssqlDdlKind` for DDL statements.
        let policy_plan: Option<(ir::PolicyPlan, facts::extract::PolicyDialectOrigin)> = match stmt
        {
            ast::AstStmt::CreatePasswordPolicy(p) => Some((
                ir::lower_create_password_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterPasswordPolicy(p) => Some((
                ir::lower_alter_password_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropPasswordPolicy(p) => Some((
                ir::lower_drop_password_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateSessionPolicy(p) => Some((
                ir::lower_create_session_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterSessionPolicy(p) => Some((
                ir::lower_alter_session_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropSessionPolicy(p) => Some((
                ir::lower_drop_session_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateNetworkPolicy(p) => Some((
                ir::lower_create_network_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterNetworkPolicy(p) => Some((
                ir::lower_alter_network_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropNetworkPolicy(p) => Some((
                ir::lower_drop_network_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateAuthenticationPolicy(p) => Some((
                ir::lower_create_authentication_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterAuthenticationPolicy(p) => Some((
                ir::lower_alter_authentication_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropAuthenticationPolicy(p) => Some((
                ir::lower_drop_authentication_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateAggregationPolicy(p) => Some((
                ir::lower_create_aggregation_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterAggregationPolicy(p) => Some((
                ir::lower_alter_aggregation_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropAggregationPolicy(p) => Some((
                ir::lower_drop_aggregation_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateProjectionPolicy(p) => Some((
                ir::lower_create_projection_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterProjectionPolicy(p) => Some((
                ir::lower_alter_projection_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropProjectionPolicy(p) => Some((
                ir::lower_drop_projection_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateJoinPolicy(p) => Some((
                ir::lower_create_join_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterJoinPolicy(p) => Some((
                ir::lower_alter_join_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropJoinPolicy(p) => Some((
                ir::lower_drop_join_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateMaskingPolicy(p) => Some((
                ir::lower_create_masking_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterMaskingPolicy(p) => Some((
                ir::lower_alter_masking_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropMaskingPolicy(p) => Some((
                ir::lower_drop_masking_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreateRowAccessPolicy(p) => Some((
                ir::lower_create_row_access_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::AlterRowAccessPolicy(p) => Some((
                ir::lower_alter_row_access_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::DropRowAccessPolicy(p) => Some((
                ir::lower_drop_row_access_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Standard,
            )),
            ast::AstStmt::CreatePgPolicy(p) => Some((
                ir::lower_create_pg_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Postgres,
            )),
            ast::AstStmt::AlterPgPolicy(p) => Some((
                ir::lower_alter_pg_policy_to_policy_plan(p, sql),
                facts::extract::PolicyDialectOrigin::Postgres,
            )),
            ast::AstStmt::DropPgPolicy(p) => Some((
                ir::lower_drop_pg_policy_to_policy_plan(p),
                facts::extract::PolicyDialectOrigin::Postgres,
            )),
            _ => None,
        };
        if let Some((plan, origin)) = policy_plan {
            let facts = facts::extract::derive_facts_from_policy_plan(&plan, origin, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        let integration_plan = match stmt {
            ast::AstStmt::CreateApiIntegration(p) => {
                Some(ir::lower_create_api_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::AlterApiIntegration(p) => {
                Some(ir::lower_alter_api_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::DropApiIntegration(p) => {
                Some(ir::lower_drop_api_integration_to_integration_plan(p))
            }
            ast::AstStmt::CreateStorageIntegration(p) => Some(
                ir::lower_create_storage_integration_to_integration_plan(p, sql),
            ),
            ast::AstStmt::AlterStorageIntegration(p) => Some(
                ir::lower_alter_storage_integration_to_integration_plan(p, sql),
            ),
            ast::AstStmt::DropStorageIntegration(p) => {
                Some(ir::lower_drop_storage_integration_to_integration_plan(p))
            }
            ast::AstStmt::CreateExternalAccessIntegration(p) => {
                Some(ir::lower_create_external_access_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::AlterExternalAccessIntegration(p) => {
                Some(ir::lower_alter_external_access_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::DropExternalAccessIntegration(p) => {
                Some(ir::lower_drop_external_access_integration_to_integration_plan(p))
            }
            ast::AstStmt::CreateNotificationIntegration(p) => {
                Some(ir::lower_create_notification_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::AlterNotificationIntegration(p) => {
                Some(ir::lower_alter_notification_integration_to_integration_plan(p, sql))
            }
            ast::AstStmt::DropNotificationIntegration(p) => Some(
                ir::lower_drop_notification_integration_to_integration_plan(p),
            ),
            ast::AstStmt::CreateSecurityIntegration(p) => Some(
                ir::lower_create_security_integration_to_integration_plan(p, sql),
            ),
            ast::AstStmt::AlterSecurityIntegration(p) => Some(
                ir::lower_alter_security_integration_to_integration_plan(p, sql),
            ),
            // DROP SECURITY INTEGRATION arrives as a generic Drop (no
            // typed drop AST for this kind) — gate on the object type.
            ast::AstStmt::Drop(s) => drop_target_is_security_integration(s, sql)
                .then(|| ir::lower_drop_security_integration_to_integration_plan(s)),
            _ => None,
        };
        if let Some(plan) = integration_plan {
            let facts = facts::extract::derive_facts_from_integration_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // Postgres DOMAIN DDL (CREATE / ALTER / DROP DOMAIN). The
        // DdlPlan covers many statement kinds; we filter to the PG
        // family here via the narrow [`facts::extract::PgDdlKind`]
        // enum so the downstream projection avoids a `_ =>` catch-all
        // on the wide public `StatementKind` taxonomy.
        let pg_kind: Option<facts::extract::PgDdlKind> = match stmt {
            ast::AstStmt::CreateDomain(_) => Some(facts::extract::PgDdlKind::CreateDomain),
            ast::AstStmt::AlterDomain(_) => Some(facts::extract::PgDdlKind::AlterDomain),
            ast::AstStmt::DropDomain(_) => Some(facts::extract::PgDdlKind::DropDomain),
            ast::AstStmt::CreateExtension(_) => Some(facts::extract::PgDdlKind::CreateExtension),
            ast::AstStmt::PgRefreshMatview(_) => Some(facts::extract::PgDdlKind::RefreshMatview),
            ast::AstStmt::Reindex(_) => Some(facts::extract::PgDdlKind::Reindex),
            ast::AstStmt::CreateIndex(_) => Some(facts::extract::PgDdlKind::CreateIndex),
            ast::AstStmt::AlterIndex(_) => Some(facts::extract::PgDdlKind::AlterIndex),
            ast::AstStmt::DoBlock(_) => Some(facts::extract::PgDdlKind::DoBlock),
            ast::AstStmt::CreatePgTrigger(_) => Some(facts::extract::PgDdlKind::CreatePgTrigger),
            ast::AstStmt::AlterPgTrigger(_) => Some(facts::extract::PgDdlKind::AlterPgTrigger),
            ast::AstStmt::DropPgTrigger(_) => Some(facts::extract::PgDdlKind::DropPgTrigger),
            ast::AstStmt::PgDropIndex(_) => Some(facts::extract::PgDdlKind::DropPgIndex),
            ast::AstStmt::PgDropExtension(_) => Some(facts::extract::PgDdlKind::DropPgExtension),
            ast::AstStmt::PgAlterTableTriggerState(_) => {
                Some(facts::extract::PgDdlKind::AlterPgTableTriggerState)
            }
            // CREATE / ALTER / DROP { USER | ROLE | LOGIN } now flow
            // through the dialect-neutral `AstStmt::CreatePrincipal` /
            // `AlterPrincipal` / `DropPrincipal` substrate; their
            // StatementKind mapping happens via `DdlPlan::statement_kind`
            // rather than the PG-prefixed `PgDdlKind` enum.
            ast::AstStmt::PgSet(_) => Some(facts::extract::PgDdlKind::PgSet),
            ast::AstStmt::PgDiscard(_) => Some(facts::extract::PgDdlKind::PgDiscard),
            ast::AstStmt::PgCreateRule(_) => Some(facts::extract::PgDdlKind::CreatePgRule),
            ast::AstStmt::PgAlterRule(_) => Some(facts::extract::PgDdlKind::AlterPgRule),
            ast::AstStmt::PgDropRule(_) => Some(facts::extract::PgDdlKind::DropPgRule),
            ast::AstStmt::PgDropOwned(_) => Some(facts::extract::PgDdlKind::PgDropOwned),
            ast::AstStmt::PgReassignOwned(_) => Some(facts::extract::PgDdlKind::PgReassignOwned),
            ast::AstStmt::PgCreateTablespace(_) => {
                Some(facts::extract::PgDdlKind::PgCreateTablespace)
            }
            ast::AstStmt::PgAlterTablespace(_) => {
                Some(facts::extract::PgDdlKind::PgAlterTablespace)
            }
            ast::AstStmt::PgDropTablespace(_) => Some(facts::extract::PgDdlKind::PgDropTablespace),
            ast::AstStmt::PgPublication(_) => Some(facts::extract::PgDdlKind::PgPublication),
            ast::AstStmt::PgSubscription(_) => Some(facts::extract::PgDdlKind::PgSubscription),
            ast::AstStmt::PgAlterSystem(_) => Some(facts::extract::PgDdlKind::PgAlterSystem),
            ast::AstStmt::PgLockTable(_) => Some(facts::extract::PgDdlKind::PgLockTable),
            ast::AstStmt::PgDropSequence(_) => Some(facts::extract::PgDdlKind::PgDropSequence),
            ast::AstStmt::PgDropType(_) => Some(facts::extract::PgDdlKind::PgDropType),
            ast::AstStmt::CreateSequence(_) => Some(facts::extract::PgDdlKind::CreateSequence),
            ast::AstStmt::AlterSequence(_) => Some(facts::extract::PgDdlKind::AlterSequence),
            ast::AstStmt::CreateType(_) => Some(facts::extract::PgDdlKind::CreateType),
            ast::AstStmt::AlterType(_) => Some(facts::extract::PgDdlKind::AlterType),
            ast::AstStmt::CreateSynonym(_) => Some(facts::extract::PgDdlKind::CreateSynonym),
            _ => None,
        };
        if let Some(kind) = pg_kind {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                let facts = facts::extract::derive_facts_from_pg_ddl_plan(&plan, kind, sql);
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }

        // T-SQL BACKUP (data-protection utility — target Database/Log +
        // destination Disk/Url/Tape). Top-level `StatementFacts.mssql_backup`
        // (parallel to `pg_copy`) since BACKUP is not DDL. Drives
        // MSSQL-BACKUP-TO-URL / INFO-MSSQL-BACKUP.
        if let ast::AstStmt::MssqlBackup(s) = stmt {
            let plan = ir::lower_backup_to_backup_plan(s, sql);
            let facts = facts::extract::derive_facts_from_backup_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL DBCC (database console / maintenance command). Top-level
        // `StatementFacts.mssql_dbcc` (parallel to `mssql_backup`) since DBCC is
        // not DDL. The command verb is the recognition primitive; which command
        // is dangerous is a YAML verdict. Drives MSSQL-DBCC-SENSITIVE /
        // INFO-MSSQL-DBCC.
        if let ast::AstStmt::MssqlDbcc(s) = stmt {
            let plan = ir::lower_dbcc_to_dbcc_plan(s, sql);
            let facts = facts::extract::derive_facts_from_dbcc_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL encryption-key activation (OPEN/CLOSE { MASTER | SYMMETRIC }
        // KEY). Top-level `StatementFacts.mssql_key_management` (parallel to
        // `mssql_dbcc`) since key activation is a session context switch, not
        // DDL. Verb + key kind + inline-password presence are the recognition
        // primitives; severity is a YAML verdict. Drives
        // MSSQL-KEY-OPEN-INLINE-PASSWORD / MSSQL-OPEN-MASTER-KEY /
        // INFO-MSSQL-KEY-MANAGEMENT.
        if let ast::AstStmt::MssqlKeyManagement(s) = stmt {
            let plan = ir::lower_key_management_to_plan(s);
            let facts = facts::extract::derive_facts_from_key_management_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL Row-Level Security (CREATE/ALTER SECURITY POLICY). Top-level
        // `StatementFacts.mssql_security_policy`. Verb + STATE + filter/block
        // predicate presence are the recognition primitives; the disabled-
        // control verdict is a YAML rule. Drives MSSQL-RLS-POLICY-DISABLED /
        // MSSQL-RLS-POLICY-CREATED-DISABLED / INFO-MSSQL-SECURITY-POLICY.
        if let ast::AstStmt::MssqlSecurityPolicy(s) = stmt {
            let plan = ir::lower_security_policy_to_plan(s);
            let facts = facts::extract::derive_facts_from_security_policy_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL key-material protection (BACKUP/RESTORE { SERVICE MASTER KEY |
        // MASTER KEY | CERTIFICATE | ASYMMETRIC KEY }). Top-level
        // `StatementFacts.mssql_key_backup`. Verb + key object + inline-password
        // presence are the recognition primitives; the root-key export/restore
        // and credential verdicts are YAML rules. Drives MSSQL-MASTER-KEY-EXPORT
        // / MSSQL-MASTER-KEY-RESTORE / MSSQL-KEY-BACKUP-INLINE-PASSWORD /
        // INFO-MSSQL-KEY-BACKUP.
        if let ast::AstStmt::MssqlKeyBackup(s) = stmt {
            let plan = ir::lower_key_backup_to_plan(s);
            let facts = facts::extract::derive_facts_from_key_backup_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL CLR assembly (CREATE/ALTER ASSEMBLY). Top-level
        // `StatementFacts.mssql_assembly`. Verb + permission set +
        // filesystem-source flag are the recognition primitives; the UNSAFE /
        // EXTERNAL_ACCESS verdict is a YAML rule. Drives MSSQL-CLR-ASSEMBLY-UNSAFE
        // / MSSQL-CLR-ASSEMBLY-EXTERNAL-ACCESS / INFO-MSSQL-CLR-ASSEMBLY.
        if let ast::AstStmt::MssqlAssembly(s) = stmt {
            let plan = ir::lower_assembly_to_plan(s);
            let facts = facts::extract::derive_facts_from_assembly_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL module signing (ADD [COUNTER] SIGNATURE). Top-level
        // `StatementFacts.mssql_add_signature`. Counter + signer kind +
        // inline-password presence are the recognition primitives; the
        // privilege-delegation / credential verdict is a YAML rule. Drives
        // MSSQL-MODULE-SIGNATURE-ADDED / MSSQL-SIGNATURE-INLINE-PASSWORD.
        if let ast::AstStmt::MssqlAddSignature(s) = stmt {
            let plan = ir::lower_add_signature_to_plan(s);
            let facts = facts::extract::derive_facts_from_add_signature_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL Service Master Key rotation (ALTER SERVICE MASTER KEY). Top-level
        // `StatementFacts.mssql_service_master_key`. Operation + force +
        // inline-password presence are the recognition primitives; the re-key /
        // data-loss / credential verdicts are YAML rules. Drives
        // MSSQL-SERVICE-MASTER-KEY-REGENERATE / -FORCE-REGENERATE /
        // -INLINE-PASSWORD / INFO-MSSQL-SERVICE-MASTER-KEY.
        if let ast::AstStmt::MssqlAlterServiceMasterKey(s) = stmt {
            let plan = ir::lower_service_master_key_to_plan(s);
            let facts = facts::extract::derive_facts_from_service_master_key_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // PostgreSQL ALTER DEFAULT PRIVILEGES (default-grant policy on future
        // objects). Top-level `StatementFacts.pg_default_privileges`. Action +
        // object class + privileges + grantees + role/schema scope are the
        // recognition primitives; the default-to-PUBLIC / global-scope verdicts
        // are YAML rules. Drives PG-DEFAULT-PRIV-* / INFO-PG-DEFAULT-PRIVILEGES.
        if let ast::AstStmt::PgAlterDefaultPrivileges(s) = stmt {
            let plan = ir::lower_pg_default_privileges_to_plan(s);
            let facts = facts::extract::derive_facts_from_pg_default_privileges_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // T-SQL RESTORE (data-protection utility — target Database/Log +
        // source Disk/Url/Tape). Top-level `StatementFacts.mssql_restore`
        // (parallel to `mssql_backup`) since RESTORE is not DDL. Drives
        // MSSQL-RESTORE-FROM-URL / MSSQL-RESTORE-REPLACE / INFO-MSSQL-RESTORE.
        if let ast::AstStmt::MssqlRestore(s) = stmt {
            let plan = ir::lower_restore_db_to_plan(s, sql);
            let facts = facts::extract::derive_facts_from_restore_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // PG COPY (data-movement utility — direction FROM/TO + target
        // File/Program/Stdin/Stdout). Sits at the top level of
        // `StatementFacts` (parallel to `use_stmt`) since COPY is not
        // DDL. Drives PG-COPY-FROM / PG-COPY-TO / PG-COPY-PROGRAM.
        if let ast::AstStmt::PgCopy(s) = stmt {
            let plan = ir::lower_pg_copy_to_pg_copy_plan(s, sql);
            let facts = facts::extract::derive_facts_from_pg_copy_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // BigQuery DDL (EXPORT DATA / LOAD DATA / ASSERT / MODEL /
        // SNAPSHOT TABLE / SEARCH INDEX / VECTOR INDEX). Same filter
        // pattern as the PG and MSSQL blocks: narrow
        // [`facts::extract::BqDdlKind`] enum picks the variant from the
        // AST, [`crate::ir::lower_ddl_stmt`] produces a generic
        // [`crate::ir::DdlPlan`], and
        // [`facts::extract::derive_facts_from_bq_ddl_plan`] projects to
        // public `StatementFacts` exhaustively.
        let bq_kind: Option<facts::extract::BqDdlKind> = match stmt {
            ast::AstStmt::BqExportData(_) => Some(facts::extract::BqDdlKind::ExportData),
            ast::AstStmt::BqLoadData(_) => Some(facts::extract::BqDdlKind::LoadData),
            ast::AstStmt::BqAssert(_) => Some(facts::extract::BqDdlKind::Assert),
            ast::AstStmt::BqCreateModel(_) => Some(facts::extract::BqDdlKind::CreateModel),
            ast::AstStmt::BqAlterModel(_) => Some(facts::extract::BqDdlKind::AlterModel),
            ast::AstStmt::BqDropModel(_) => Some(facts::extract::BqDdlKind::DropModel),
            ast::AstStmt::BqExportModel(_) => Some(facts::extract::BqDdlKind::ExportModel),
            ast::AstStmt::BqCreateSnapshotTable(_) => {
                Some(facts::extract::BqDdlKind::CreateSnapshotTable)
            }
            ast::AstStmt::BqDropSnapshotTable(_) => {
                Some(facts::extract::BqDdlKind::DropSnapshotTable)
            }
            ast::AstStmt::BqCreateSearchIndex(_) => {
                Some(facts::extract::BqDdlKind::CreateSearchIndex)
            }
            ast::AstStmt::BqDropSearchIndex(_) => Some(facts::extract::BqDdlKind::DropSearchIndex),
            ast::AstStmt::BqCreateVectorIndex(_) => {
                Some(facts::extract::BqDdlKind::CreateVectorIndex)
            }
            ast::AstStmt::BqAlterVectorIndex(_) => {
                Some(facts::extract::BqDdlKind::AlterVectorIndex)
            }
            ast::AstStmt::BqDropVectorIndex(_) => Some(facts::extract::BqDdlKind::DropVectorIndex),
            // Cross-dialect — only routed here so the BQ-EXTTBL-*-LEAK
            // rules can fire on BQ-style external tables. The lowering
            // populates `bq_options: None` for Snowflake-style external
            // tables (LOCATION / INTEGRATION) so the BQ-side rules
            // correctly stay silent on the non-BQ shape.
            ast::AstStmt::CreateExternalTable(_) => {
                Some(facts::extract::BqDdlKind::CreateExternalTable)
            }
            ast::AstStmt::CreateExternalSchema(_) => {
                Some(facts::extract::BqDdlKind::CreateExternalSchema)
            }
            _ => None,
        };
        if let Some(kind) = bq_kind {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                let facts = facts::extract::derive_facts_from_bq_ddl_plan(&plan, kind, sql);
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }

        // MSSQL DDL (T-SQL Bulk Insert / External Model / Login / User /
        // SET option). The DdlPlan covers many statement kinds; we filter
        // to the MSSQL family here via the narrow
        // [`facts::extract::MssqlDdlKind`] enum so the downstream
        // projection avoids a `_ =>` catch-all on the wide public
        // `StatementKind` taxonomy.
        let mssql_kind: Option<facts::extract::MssqlDdlKind> = match stmt {
            ast::AstStmt::MssqlBulkInsert(_) => Some(facts::extract::MssqlDdlKind::BulkInsert),
            ast::AstStmt::MssqlCreateExternalModel(_) => {
                Some(facts::extract::MssqlDdlKind::CreateExternalModel)
            }
            ast::AstStmt::MssqlAlterExternalModel(_) => {
                Some(facts::extract::MssqlDdlKind::AlterExternalModel)
            }
            ast::AstStmt::MssqlDropExternalModel(_) => {
                Some(facts::extract::MssqlDdlKind::DropExternalModel)
            }
            // CREATE LOGIN / CREATE USER (MSSQL) parse to the
            // dialect-neutral `AstStmt::CreatePrincipal`. The
            // MSSQL-specific source-clause classifier rides on
            // `options.mssql_source`; those statements go through the
            // MssqlDdlKind dispatch so rules keyed on
            // `kind: mssql_create_login` / `kind: mssql_create_user`
            // fire.
            ast::AstStmt::CreatePrincipal(p) if p.options.mssql_source.is_some() => {
                match p.principal_kind {
                    ast::types::PrincipalKind::Login => {
                        Some(facts::extract::MssqlDdlKind::CreateLogin)
                    }
                    ast::types::PrincipalKind::User => {
                        Some(facts::extract::MssqlDdlKind::CreateUser)
                    }
                    ast::types::PrincipalKind::Role => None,
                    // A Redshift GROUP is never an MSSQL principal — it has no
                    // MSSQL DDL kind. (Only reachable when mssql_source is Some,
                    // which never holds for GROUP; the arm keeps the match total.)
                    ast::types::PrincipalKind::Group => None,
                    // Application roles ride the neutral principal path
                    // (kind discriminated via ddl.principal.kind).
                    ast::types::PrincipalKind::ApplicationRole => None,
                    // A Snowflake DATABASE ROLE is never an MSSQL principal
                    // (mssql_source never holds for it); keeps the match total.
                    ast::types::PrincipalKind::DatabaseRole => None,
                }
            }
            // ALTER / DROP LOGIN — LOGIN statements are T-SQL-shaped in
            // every dialect that parses them, so they keep the
            // mssql_-prefixed kinds for naming consistency with
            // `mssql_create_login`.
            ast::AstStmt::AlterPrincipal(p)
                if p.principal_kind == ast::types::PrincipalKind::Login =>
            {
                Some(facts::extract::MssqlDdlKind::AlterLogin)
            }
            ast::AstStmt::DropPrincipal(p)
                if p.principal_kind == ast::types::PrincipalKind::Login =>
            {
                Some(facts::extract::MssqlDdlKind::DropLogin)
            }
            ast::AstStmt::MssqlSetOption(_) => Some(facts::extract::MssqlDdlKind::SetOption),
            ast::AstStmt::DropMssqlTrigger(_) => Some(facts::extract::MssqlDdlKind::DropTrigger),
            _ => None,
        };
        if let Some(kind) = mssql_kind {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                let facts = facts::extract::derive_facts_from_mssql_ddl_plan(&plan, kind, sql);
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }

        // CREATE / ALTER / DROP { USER | ROLE | LOGIN } —
        // dialect-neutral principal substrate. Only routed here for the
        // non-MSSQL forms (MSSQL principal statements route through the
        // `MssqlDdlKind` dispatcher above so their existing
        // `kind: mssql_create_login` / `mssql_create_user` YAML
        // predicates keep firing). The neutral path projects the
        // `principal_options` typed bag (kind + password_literal +
        // mysql_host) under `ddl.principal.*`.
        if matches!(
            stmt,
            ast::AstStmt::CreatePrincipal(_)
                | ast::AstStmt::AlterPrincipal(_)
                | ast::AstStmt::DropPrincipal(_)
        ) {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                let facts = facts::extract::derive_facts_from_principal_plan(&plan, sql);
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }

        // `COMMENT ON <target-kind> <name>` — cross-dialect metadata
        // statement. Drives INFO-COMMENT-CHG (predicates `kind: comment`)
        // and the Databricks Unity Catalog target-specific variants
        // INFO-DBX-CAT/VOL/CONN-COMMENT-CHG (predicate
        // `comment.target_kind: catalog | volume | connection`). Sits
        // before the stmt-kind-only dispatch so the target_kind
        // discriminator reaches the rule corpus.
        if let ast::AstStmt::CommentOn(c) = stmt {
            let facts = facts::extract::derive_facts_from_comment_on(c, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        // SHOW <objects> — metadata introspection. Lowers to a generic
        // DDL plan carrying the typed `show` recognition sibling; the
        // facts projection exposes it under `ddl.show.*`.
        if let ast::AstStmt::Show(_) = stmt {
            let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);
            let session = ir::types::SessionContext::default();
            let inputs = ir::IrLowerInputs {
                source: sql,
                strict: ir::StrictMode::Permissive,
                func_catalog: &function_catalog,
                session: &session,
                catalog: None,
                model_catalog: None,
                reasoning,
                flatten_body_into: None,
            };
            if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
                if let Some(facts) = facts::extract::derive_facts_from_show_plan(&plan) {
                    evaluate_facts_into(
                        fold,
                        &facts,
                        rules_corpus,
                        stmt.span(),
                        sql,
                        &mut signals,
                        facts_out.as_deref_mut(),
                        trace_out.as_deref_mut(),
                    );
                }
            }
            continue;
        }

        // Statement-kind-only dispatch: UNDROP TABLE / UNDROP TYPE /
        // EXECUTE IMMEDIATE / UNDROP DATABASE / UNDROP SCHEMA / ANALYZE /
        // CLUSTER / LISTEN / NOTIFY / UNLISTEN / CREATE AGGREGATE /
        // CREATE OPERATOR / CREATE VECTOR INDEX / EXEC. No per-element
        // detail surface needed — the rules predicate purely on
        // `kind:`. Drives INFO-TBL-UNDROP / INFO-TYPE-UNDROP / DYNSQL
        // / INFO-DB-UNDROP / INFO-SCHEMA-UNDROP / INFO-PG-MAINT-* /
        // INFO-PG-NOTIFY-* / INFO-PG-AGG-NEW / INFO-PG-OP-NEW /
        // INFO-MSSQL-VECIDX-NEW / INFO-MSSQL-EXEC-PROC.
        //
        // `EXECUTE IMMEDIATE` and `MssqlExec` additionally attach a
        // typed `DynamicSqlCall` so DYNSQL-* rules can predicate on
        // argument shape and parameterization at the statement level
        // (not just kind).
        if let ast::AstStmt::ExecuteImmediate {
            span,
            sql_expr,
            using_span,
            using_args,
            node_id,
            ..
        } = stmt
        {
            let call_ir = ir::dynamic_sql::DynamicSqlCallIr {
                surface: ir::dynamic_sql::DynamicSqlSurfaceIr::ExecuteImmediate,
                // Resolve a bare variable argument through the script's
                // classifier so via-variable laundering
                // (`v := '…' || x; EXECUTE v;`) reports the built shape.
                argument: dynamic_sql.classify_arg(sql_expr, sql),
                splices: dynamic_sql.classify_arg_splices(sql_expr, sql),
                parameterization: ir::dynamic_sql::classify_execute_immediate_parameterization(
                    using_args,
                    *using_span,
                ),
                node_id: *node_id,
                source_span: *span,
                argument_span: Some(sql_expr.span()),
                provenance: Vec::new(),
            };
            let call = facts::extract::project_dynamic_sql_call(&call_ir);
            let facts = facts::extract::derive_facts_dynamic_sql_stmt(
                facts::StatementKind::ExecuteImmediate,
                *span,
                call,
            );
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        if let ast::AstStmt::ExecuteImmediateFrom(e) = stmt {
            // Snowflake `EXECUTE IMMEDIATE FROM <stage_file>` — executes SQL
            // loaded from a stage file (external/file-based code execution).
            // Distinct surface from inline `EXECUTE IMMEDIATE <expr>`: the
            // recognition primitive is the file location + whether it runs,
            // not an injected string shape.
            let eif_ir = ir::dynamic_sql::lower_execute_immediate_from(e, sql);
            let eif_facts = facts::extract::project_execute_immediate_from(&eif_ir);
            let facts = facts::extract::derive_facts_execute_immediate_from(e.span, eif_facts);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        if let ast::AstStmt::PgPrepare(p) = stmt {
            // Top-level `PREPARE`. PG form (`PREPARE … AS <stmt>`)
            // carries a parsed body and is not itself a dynamic-SQL
            // surface (the AS branch executes a known statement). MySQL
            // form (`PREPARE … FROM <expr>`) IS a dynamic-SQL surface
            // — classify the FROM expression's shape and attach.
            let call = p
                .from_expr
                .as_ref()
                .map(|from_expr| ir::dynamic_sql::DynamicSqlCallIr {
                    surface: ir::dynamic_sql::DynamicSqlSurfaceIr::Prepare,
                    // Resolve a bare variable argument through the script's
                    // classifier, same as the EXECUTE IMMEDIATE arm above —
                    // `SET @s = '…' || x; PREPARE p FROM @s;` reports the built shape.
                    argument: dynamic_sql.classify_arg(from_expr, sql),
                    splices: dynamic_sql.classify_arg_splices(from_expr, sql),
                    parameterization: ir::dynamic_sql::DynamicSqlParameterizationIr::NotApplicable,
                    node_id: p.node_id,
                    source_span: p.span,
                    argument_span: Some(from_expr.span()),
                    provenance: Vec::new(),
                });
            let facts = match call {
                Some(c) => facts::extract::derive_facts_dynamic_sql_stmt(
                    facts::StatementKind::PgPrepare,
                    p.span,
                    facts::extract::project_dynamic_sql_call(&c),
                ),
                None => facts::extract::derive_facts_stmt_kind_only(
                    facts::StatementKind::PgPrepare,
                    p.span,
                ),
            };
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        // T-SQL impersonation statements — `EXECUTE AS LOGIN/USER = …`
        // and `REVERT`. Typed facts drive the MSSQL-EXECAS-* rules.
        if let ast::AstStmt::MssqlExecuteAs(e) = stmt {
            let raw = sql
                .get(e.principal_span.start as usize..e.principal_span.end as usize)
                .unwrap_or("");
            // Strip surrounding string-literal quotes (the value may
            // also be a bare @variable, left as-is).
            let inner = raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(raw);
            let impersonation = facts::ddl::ImpersonationFacts {
                principal_kind: match e.principal_kind {
                    ast::types::AstImpersonationPrincipalKind::Login => {
                        facts::ddl::ImpersonationPrincipalKind::Login
                    }
                    ast::types::AstImpersonationPrincipalKind::User => {
                        facts::ddl::ImpersonationPrincipalKind::User
                    }
                },
                principal: facts::identity::IdentName::new(inner),
                no_revert: e.no_revert,
            };
            let facts = facts::extract::derive_facts_mssql_impersonation(
                facts::StatementKind::MssqlExecuteAs,
                e.span,
                Some(impersonation),
            );
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        if let ast::AstStmt::MssqlRevert { span, .. } = stmt {
            let facts = facts::extract::derive_facts_mssql_impersonation(
                facts::StatementKind::MssqlRevert,
                *span,
                None,
            );
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        // T-SQL `SETUSER ['username']` — the legacy, database-scoped equivalent
        // of `EXECUTE AS USER`. Reuses the shared `ImpersonationFacts` carrier
        // (principal kind is always User); a bare `SETUSER` is the revert form
        // (no principal). Drives MSSQL-SETUSER-IMPERSONATION / INFO-MSSQL-SETUSER.
        if let ast::AstStmt::MssqlSetuser(s) = stmt {
            let impersonation = s.principal_span.map(|p| {
                let raw = sql.get(p.start as usize..p.end as usize).unwrap_or("");
                let inner = raw
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                    .unwrap_or(raw);
                facts::ddl::ImpersonationFacts {
                    principal_kind: facts::ddl::ImpersonationPrincipalKind::User,
                    principal: facts::identity::IdentName::new(inner),
                    no_revert: false,
                }
            });
            let facts = facts::extract::derive_facts_mssql_impersonation(
                facts::StatementKind::MssqlSetuser,
                s.span,
                impersonation,
            );
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        if let ast::AstStmt::MssqlAuditDdl(a) = stmt {
            let kind = match a.action {
                ast::types::AstMssqlAuditAction::Create => facts::StatementKind::MssqlCreateAudit,
                ast::types::AstMssqlAuditAction::Alter => facts::StatementKind::MssqlAlterAudit,
                ast::types::AstMssqlAuditAction::Drop => facts::StatementKind::MssqlDropAudit,
            };
            let name = sql
                .get(a.name_span.start as usize..a.name_span.end as usize)
                .unwrap_or("");
            let audit = facts::ddl::AuditFacts {
                scope: match a.scope {
                    ast::types::AstMssqlAuditScope::ServerAudit => {
                        facts::ddl::AuditScope::ServerAudit
                    }
                    ast::types::AstMssqlAuditScope::ServerAuditSpecification => {
                        facts::ddl::AuditScope::ServerAuditSpecification
                    }
                    ast::types::AstMssqlAuditScope::DatabaseAuditSpecification => {
                        facts::ddl::AuditScope::DatabaseAuditSpecification
                    }
                },
                name: facts::identity::IdentName::new(name),
                state: a.state.map(|s| match s {
                    ast::types::AstMssqlAuditState::On => facts::ddl::DatabaseSwitchValue::On,
                    ast::types::AstMssqlAuditState::Off => facts::ddl::DatabaseSwitchValue::Off,
                }),
            };
            let facts = facts::extract::derive_facts_mssql_audit(kind, a.span, audit);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        if let ast::AstStmt::MssqlSecurityObjectDdl(s) = stmt {
            let kind = match s.action {
                ast::types::AstMssqlAuditAction::Create => {
                    facts::StatementKind::MssqlCreateSecurityObject
                }
                ast::types::AstMssqlAuditAction::Alter => {
                    facts::StatementKind::MssqlAlterSecurityObject
                }
                ast::types::AstMssqlAuditAction::Drop => {
                    facts::StatementKind::MssqlDropSecurityObject
                }
            };
            let slice = |sp: lexer::token::Span| {
                sql.get(sp.start as usize..sp.end as usize)
                    .unwrap_or("")
                    .to_string()
            };
            let security_object = facts::ddl::SecurityObjectFacts {
                kind: match s.object {
                    ast::types::AstMssqlSecurityObjectKind::MasterKey => {
                        facts::ddl::SecurityObjectKind::MasterKey
                    }
                    ast::types::AstMssqlSecurityObjectKind::SymmetricKey => {
                        facts::ddl::SecurityObjectKind::SymmetricKey
                    }
                    ast::types::AstMssqlSecurityObjectKind::AsymmetricKey => {
                        facts::ddl::SecurityObjectKind::AsymmetricKey
                    }
                    ast::types::AstMssqlSecurityObjectKind::Certificate => {
                        facts::ddl::SecurityObjectKind::Certificate
                    }
                    ast::types::AstMssqlSecurityObjectKind::Credential => {
                        facts::ddl::SecurityObjectKind::Credential
                    }
                },
                name: s
                    .name_span
                    .map(|sp| facts::identity::IdentName::new(slice(sp))),
                database_scoped: s.database_scoped,
                password_literal: s.password_literal.map(slice),
                secret_literal: s.secret_literal.map(slice),
            };
            let facts =
                facts::extract::derive_facts_mssql_security_object(kind, s.span, security_object);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }

        if let ast::AstStmt::MssqlExec(e) = stmt {
            // Distinguish dynamic-SQL surfaces (`EXEC(@sql)` and
            // `EXEC sp_executesql ...`) from ordinary stored-procedure
            // calls (`EXEC proc_name args`). Also capture the typed
            // `mssql_exec` facts (lowercased procedure_name + args_text)
            // so rules like MSSQL-XP-CMDSHELL can predicate on the
            // specific procedure being invoked.
            // Base name part only (`xp_cmdshell` in `master.dbo.xp_cmdshell`),
            // quote-stripped via the central normalizer, then lowercased per
            // the facts contract — qualified and bracket-quoted invocations
            // must match the same rule predicate.
            let procedure_name_lower = e.procedure_base_name_span.map(|s| {
                ir::normalize::normalize_identifier(
                    sql.get(s.start as usize..s.end as usize).unwrap_or(""),
                )
                .to_ascii_lowercase()
            });
            let args_text_lower = e.args_span.map(|s| {
                sql.get(s.start as usize..s.end as usize)
                    .unwrap_or("")
                    .to_ascii_lowercase()
            });
            let mssql_exec_facts = Some(facts::ddl::MssqlExecFacts {
                procedure_name: procedure_name_lower.clone(),
                args_text: args_text_lower,
                args: facts::extract::project_mssql_exec_args(&e.args, sql),
            });

            let surface = match e.procedure_name_span {
                None => Some((
                    ir::dynamic_sql::DynamicSqlSurfaceIr::MssqlExecDynamic,
                    ir::dynamic_sql::DynamicSqlParameterizationIr::NotApplicable,
                )),
                Some(_) => {
                    if procedure_name_lower.as_deref() == Some("sp_executesql") {
                        Some((
                            ir::dynamic_sql::DynamicSqlSurfaceIr::MssqlSpExecutesql,
                            ir::dynamic_sql::classify_sp_executesql_parameterization(&e.args),
                        ))
                    } else {
                        None
                    }
                }
            };
            if let Some((s, param)) = surface {
                // `sp_executesql` carries its @stmt SQL string as the first
                // argument; the dynamic `EXEC(...)` form now also lifts its
                // parenthesised argument. Classify the first argument through
                // the shared taint taxonomy (a bare @var resolves via the map,
                // an inline literal is Literal not Unknown, a concat is Concat)
                // and recover its splice positions. Fall back to the bare-`@var`
                // span resolver only for a dynamic form the parser could not lift.
                let (argument, splices) = match e.args.first() {
                    Some(a) => (
                        dynamic_sql.classify_arg(&a.value, sql),
                        dynamic_sql.classify_arg_splices(&a.value, sql),
                    ),
                    None => ir::dynamic_sql::mssql_exec_bare_variable(e.args_span, sql)
                        .and_then(|name| dynamic_sql.variable_shape(name))
                        .unwrap_or((ir::dynamic_sql::DynamicSqlArgIr::Unknown, Vec::new())),
                };
                let call_ir = ir::dynamic_sql::DynamicSqlCallIr {
                    surface: s,
                    argument,
                    splices,
                    parameterization: param,
                    node_id: e.node_id,
                    source_span: e.span,
                    argument_span: e.args_span,
                    provenance: Vec::new(),
                };
                let call = facts::extract::project_dynamic_sql_call(&call_ir);
                let mut facts = facts::extract::derive_facts_dynamic_sql_stmt(
                    facts::StatementKind::MssqlExec,
                    e.span,
                    call,
                );
                facts.mssql_exec = mssql_exec_facts;
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            } else {
                // Ordinary EXEC <proc_name> — no dynamic SQL at the
                // call itself, but the callee's body may pass an
                // argument on to a sink. Emit one row per call the
                // script's reasoning reports, each carrying its
                // provenance chain. Always also surface `mssql_exec`
                // facts so procedure-name-keyed rules (xp_cmdshell, …)
                // fire.
                let inter_proc_calls =
                    script_reasoning.call_site_calls(&facts::reasoning::CallSite {
                        span: e.span,
                        callee_name_span: e.procedure_name_span,
                        args_span: e.args_span,
                        args: &e.args,
                        node_id: e.node_id,
                        kind: facts::reasoning::CallSiteKind::MssqlExec,
                    });
                for call_ir in &inter_proc_calls {
                    let call = facts::extract::project_dynamic_sql_call(call_ir);
                    let mut facts = facts::extract::derive_facts_dynamic_sql_stmt(
                        facts::StatementKind::MssqlExec,
                        e.span,
                        call,
                    );
                    facts.mssql_exec = mssql_exec_facts.clone();
                    evaluate_facts_into(
                        fold,
                        &facts,
                        rules_corpus,
                        stmt.span(),
                        sql,
                        &mut signals,
                        facts_out.as_deref_mut(),
                        trace_out.as_deref_mut(),
                    );
                }
                let mut facts = facts::extract::derive_facts_stmt_kind_only(
                    facts::StatementKind::MssqlExec,
                    e.span,
                );
                facts.mssql_exec = mssql_exec_facts;
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
            continue;
        }
        if let ast::AstStmt::Call {
            span,
            procedure_name_span,
            args_span,
            args,
            node_id,
            ..
        } = stmt
        {
            let inter_proc_calls = script_reasoning.call_site_calls(&facts::reasoning::CallSite {
                span: *span,
                callee_name_span: Some(*procedure_name_span),
                args_span: *args_span,
                args,
                node_id: *node_id,
                kind: facts::reasoning::CallSiteKind::Call,
            });
            for call_ir in &inter_proc_calls {
                let call = facts::extract::project_dynamic_sql_call(call_ir);
                let facts = facts::extract::derive_facts_dynamic_sql_stmt(
                    facts::StatementKind::Call,
                    *span,
                    call,
                );
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
        }

        let kind_only: Option<(facts::StatementKind, lexer::Span)> = match stmt {
            ast::AstStmt::UndropTable(s) => Some((facts::StatementKind::UndropTable, s.span)),
            ast::AstStmt::UndropType(s) => Some((facts::StatementKind::UndropType, s.span)),
            ast::AstStmt::UndropDatabase(s) => Some((facts::StatementKind::UndropDatabase, s.span)),
            ast::AstStmt::UndropSchema(s) => Some((facts::StatementKind::UndropSchema, s.span)),
            ast::AstStmt::AnalyzeStmt(s) => Some((facts::StatementKind::AnalyzeStmt, s.span)),
            ast::AstStmt::PgCluster(s) => Some((facts::StatementKind::PgCluster, s.span)),
            ast::AstStmt::PgListen(s) => Some((facts::StatementKind::PgListen, s.span)),
            ast::AstStmt::PgNotify(s) => Some((facts::StatementKind::PgNotify, s.span)),
            ast::AstStmt::PgUnlisten(s) => Some((facts::StatementKind::PgUnlisten, s.span)),
            ast::AstStmt::PgCreateAggregate(s) => {
                Some((facts::StatementKind::PgCreateAggregate, s.span))
            }
            ast::AstStmt::PgCreateOperator(s) => {
                Some((facts::StatementKind::PgCreateOperator, s.span))
            }
            ast::AstStmt::MssqlCreateVectorIndex(s) => {
                Some((facts::StatementKind::MssqlCreateVectorIndex, s.span))
            }
            // Scripting locals: scalar `DECLARE @var <type>` and T-SQL table
            // variable `DECLARE @t TABLE(...)`. Both lower to the IR's
            // (ControlFlow, Declare|DeclareTable) DdlPlan but don't have
            // per-family fact projections — emit a kind-only stub so they
            // classify as CONTROL in the ledger instead of falling through
            // to the query evaluator's Opaque RelPlan fallback.
            ast::AstStmt::Declare { span, .. } => Some((facts::StatementKind::Declare, *span)),
            ast::AstStmt::DeclareTable { span, .. } => {
                Some((facts::StatementKind::DeclareTable, *span))
            }
            // PostgreSQL prepared-statement lifecycle. PgPrepare itself
            // wraps a query body and lowers via the query path; the two
            // siblings have no relational body and reach the ledger via
            // this kind-only stub.
            ast::AstStmt::PgExecute(s) => Some((facts::StatementKind::PgExecute, s.span)),
            ast::AstStmt::PgDeallocate(s) => Some((facts::StatementKind::PgDeallocate, s.span)),
            ast::AstStmt::Reconfigure { span, .. } => {
                Some((facts::StatementKind::Reconfigure, *span))
            }
            _ => None,
        };
        if let Some((kind, span)) = kind_only {
            let facts = facts::extract::derive_facts_stmt_kind_only(kind, span);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
        }
    }

    // Scripting-handler scan. `AstStmt::DeclareHandler` may appear at the
    // top level OR nested inside any body-bearing scripting statement
    // (CREATE PROCEDURE / CREATE FUNCTION / BEGIN…END / IF / WHILE / FOR
    // / LOOP / REPEAT / CASE / nested handler / MSSQL TRY-CATCH / etc.).
    // Recursively gather every reachable handler so SCRIPT-* rules fire
    // on every such surface.
    let mut handlers: Vec<&ast::AstDeclareHandlerStmt> = Vec::new();
    for stmt in &script.stmts {
        collect_declare_handlers(stmt, &mut handlers);
    }
    for h in &handlers {
        let plan = ir::lower_declare_handler_to_handler_plan(h, sql);
        let facts = facts::extract::derive_facts_from_handler_plan(&plan, sql);
        evaluate_facts_into(
            fold,
            &facts,
            rules_corpus,
            h.span,
            sql,
            &mut signals,
            facts_out.as_deref_mut(),
            trace_out.as_deref_mut(),
        );
    }

    signals
}

/// How a single statement node contributes to the coverage counts
/// (`statements_parsed` / `analyzed` / `skipped`, plus `jinja_blocks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageClass {
    /// A real, recognized statement — counted as analyzed.
    Analyzed,
    /// The statement's kind was recognized but its payload could not be fully
    /// parsed — an `ALTER TABLE` action that fell through to `Unknown`, or a
    /// `GRANT`/`REVOKE` that degraded to an `Unparsed` shape. Still counted as
    /// analyzed (the verb and target are known), but tracked separately and
    /// lowers analysis confidence so silently-dropped payloads are visible.
    Partial,
    /// Parse-coverage loss — the parser could not recognize the statement.
    /// Counted as skipped (lowers analysis confidence).
    Skipped,
    /// A Jinja/template directive, not SQL — counted toward `jinja_blocks`.
    Jinja,
    /// Structural punctuation that is not itself a statement (the BEGIN/END
    /// grouping wrapper, a `GO` batch separator). Not counted at all — its
    /// inner statements are counted on their own.
    Excluded,
}

/// Classify a statement node for coverage counting.
///
/// **Closed-enum exhaustive — NO `_ =>` arm.** Every `AstStmt` variant is
/// listed, so adding a new variant breaks this build and forces a deliberate
/// coverage decision. This is the compile-time guarantee that the statement
/// counts can never silently mis-bucket a statement type (the failure mode
/// that let `ClauseFragment`/`GoBatchSeparator` slip through a `matches!`
/// fallthrough). Counts are derived from this single classifier.
pub fn coverage_class(stmt: &ast::AstStmt) -> CoverageClass {
    use ast::AstStmt as S;
    match stmt {
        // ── Structural punctuation — not a statement, not counted ──
        S::Block(_) | S::GoBatchSeparator { .. } => CoverageClass::Excluded,

        // ── Parse-coverage loss — counted as skipped ──
        S::OpaqueContent { .. } | S::Error { .. } | S::ClauseFragment { .. } => {
            CoverageClass::Skipped
        }

        // ── Template directives — counted toward jinja_blocks ──
        S::JinjaPlaceholder { .. } | S::JinjaConditionalStmt(_) => CoverageClass::Jinja,

        // ── Recognized kind, but payload degraded — counted as Partial ──
        // The statement parsed into its typed node, but a sub-part fell
        // through to a recognition sink. Pulled out of the analyzed group
        // below so the dropped payload is not reported as fully analyzed.
        // Zero actions means the action clause was swallowed (a valid ALTER
        // TABLE always carries at least one action); Unknown/GovernanceSpan
        // means an action fell through to a recognition sink.
        S::AlterTable(a)
            if a.actions.is_empty()
                || a.actions.iter().any(|act| {
                    matches!(
                        act.kind,
                        ast::AstAlterTableActionKind::Unknown { .. }
                            | ast::AstAlterTableActionKind::GovernanceSpan { .. }
                    )
                }) =>
        {
            CoverageClass::Partial
        }
        S::Grant(g) if matches!(g.shape, ast::AstGrantShape::Unparsed { .. }) => {
            CoverageClass::Partial
        }
        S::Revoke(r) if matches!(r.shape, ast::AstRevokeShape::Unparsed { .. }) => {
            CoverageClass::Partial
        }

        // ── Everything else is an analyzed statement. Enumerated in full
        //    (no catch-all) so a new `AstStmt` variant must be classified
        //    here explicitly rather than silently defaulting to analyzed. ──
        S::Select(_)
        | S::SetSelect(_)
        | S::ValuesQuery(_)
        | S::Insert(_)
        | S::ReplaceInto(_)
        | S::MultiInsert(_)
        | S::Update(_)
        | S::Delete(_)
        | S::Merge(_)
        | S::CreateTable(_)
        | S::CreateView(_)
        | S::CreateDynamicTable(_)
        | S::CreateTask(_)
        | S::CreateStage(_)
        | S::CreateIndex(_)
        | S::CreateSynonym(_)
        | S::MssqlBackup(_)
        | S::MssqlRestore(_)
        | S::MssqlDbcc(_)
        | S::MssqlKeyManagement(_)
        | S::MssqlSecurityPolicy(_)
        | S::MssqlKeyBackup(_)
        | S::MssqlAssembly(_)
        | S::MssqlAddSignature(_)
        | S::MssqlSetuser(_)
        | S::MssqlAlterServiceMasterKey(_)
        | S::PgAlterDefaultPrivileges(_)
        | S::CommentOn(_)
        | S::DoBlock(_)
        | S::Vacuum(_)
        | S::AnalyzeStmt(_)
        | S::Explain(_)
        | S::CreateRowAccessPolicy(_)
        | S::CreateMaskingPolicy(_)
        | S::CreateNetworkPolicy(_)
        | S::CreateSessionPolicy(_)
        | S::CreateAuthenticationPolicy(_)
        | S::CreateApiIntegration(_)
        | S::CreateNotificationIntegration(_)
        | S::CreatePasswordPolicy(_)
        | S::CreateAggregationPolicy(_)
        | S::CreateProjectionPolicy(_)
        | S::CreateJoinPolicy(_)
        | S::CreateStorageIntegration(_)
        | S::CreateExternalAccessIntegration(_)
        | S::AlterRowAccessPolicy(_)
        | S::AlterMaskingPolicy(_)
        | S::AlterNetworkPolicy(_)
        | S::AlterSessionPolicy(_)
        | S::AlterSession(_)
        | S::AlterAuthenticationPolicy(_)
        | S::AlterApiIntegration(_)
        | S::AlterNotificationIntegration(_)
        | S::AlterPasswordPolicy(_)
        | S::AlterAggregationPolicy(_)
        | S::AlterProjectionPolicy(_)
        | S::AlterJoinPolicy(_)
        | S::AlterStorageIntegration(_)
        | S::AlterExternalAccessIntegration(_)
        | S::CreateShare(_)
        | S::AlterShare(_)
        | S::CreateDatashare(_)
        | S::AlterDatashare(_)
        | S::CreateSecurityIntegration(_)
        | S::AlterSecurityIntegration(_)
        | S::AlterReplicationGroup(_)
        | S::AlterFailoverGroup(_)
        | S::AlterUser(_)
        | S::AlterAccount(_)
        | S::DropRowAccessPolicy(_)
        | S::DropAllRowAccessPolicies(_)
        | S::DropMaskingPolicy(_)
        | S::DropNetworkPolicy(_)
        | S::DropSessionPolicy(_)
        | S::DropAuthenticationPolicy(_)
        | S::DropApiIntegration(_)
        | S::DropNotificationIntegration(_)
        | S::DropPasswordPolicy(_)
        | S::DropAggregationPolicy(_)
        | S::DropProjectionPolicy(_)
        | S::DropJoinPolicy(_)
        | S::DropStorageIntegration(_)
        | S::DropExternalAccessIntegration(_)
        | S::AlterTable(_)
        | S::AlterView(_)
        | S::AlterMaterializedView(_)
        | S::AlterDynamicTable(_)
        | S::AlterFunction(_)
        | S::AlterProcedure(_)
        | S::AlterStage(_)
        | S::AlterTask(_)
        | S::DropTask(_)
        | S::Drop(_)
        | S::Truncate(_)
        | S::CreateWarehouse(_)
        | S::AlterWarehouse(_)
        | S::DropWarehouse(_)
        | S::CreatePipe(_)
        | S::AlterPipe(_)
        | S::DropPipe(_)
        | S::CreateStream(_)
        | S::AlterStream(_)
        | S::DropStream(_)
        | S::CreateDatabase(_)
        | S::AlterDatabase(_)
        | S::DropDatabase(_)
        | S::UndropDatabase(_)
        | S::CreateSchema(_)
        | S::AlterSchema(_)
        | S::DropSchema(_)
        | S::UndropSchema(_)
        | S::UndropTable(_)
        | S::UndropType(_)
        | S::CreateTag(_)
        | S::AlterTag(_)
        | S::UndropTag(_)
        | S::CreateFileFormat(_)
        | S::AlterFileFormat(_)
        | S::CreateSecret(_)
        | S::AlterSecret(_)
        | S::CreateNetworkRule(_)
        | S::AlterNetworkRule(_)
        | S::CreateResourceMonitor(_)
        | S::AlterResourceMonitor(_)
        | S::CreateComputePool(_)
        | S::AlterComputePool(_)
        | S::CreateGitRepository(_)
        | S::CreateExternalFunction(_)
        | S::AlterGitRepository(_)
        | S::CreateImageRepository(_)
        | S::AlterImageRepository(_)
        | S::CreateStreamlit(_)
        | S::AlterStreamlit(_)
        | S::CreateService(_)
        | S::AlterService(_)
        | S::CreateNotebook(_)
        | S::AlterNotebook(_)
        | S::CreateSemanticView(_)
        | S::AlterSemanticView(_)
        | S::CreateCortexSearchService(_)
        | S::AlterCortexSearchService(_)
        | S::CreateApplication(_)
        | S::AlterApplication(_)
        | S::CreateApplicationPackage(_)
        | S::AlterApplicationPackage(_)
        | S::CreateListing(_)
        | S::AlterListing(_)
        | S::CreateManagedAccount(_)
        | S::CreateAccount(_)
        | S::StageFileCommand(_)
        | S::CreateAlert(_)
        | S::CreateDataMetricFunction(_)
        | S::CreateReplicationFailoverGroup(_)
        | S::AlterAlert(_)
        | S::Show(_)
        | S::Describe(_)
        | S::Use(_)
        | S::If(_)
        | S::CaseStmt(_)
        | S::For(_)
        | S::ForEach(_)
        | S::While(_)
        | S::Repeat(_)
        | S::Loop(_)
        | S::DeclareHandler(_)
        | S::CreateType(_)
        | S::AlterType(_)
        | S::CreateExtension(_)
        | S::CreateSequence(_)
        | S::AlterSequence(_)
        | S::CreateProcedure(_)
        | S::CreateFunction(_)
        | S::CreateTableFunction(_)
        | S::CreatePgTrigger(_)
        | S::AlterPgTrigger(_)
        | S::DropPgTrigger(_)
        | S::CreateDomain(_)
        | S::AlterDomain(_)
        | S::DropDomain(_)
        | S::CreatePgPolicy(_)
        | S::AlterPgPolicy(_)
        | S::DropPgPolicy(_)
        | S::AlterIndex(_)
        | S::Reindex(_)
        | S::PgPrepare(_)
        | S::PgExecute(_)
        | S::PgDeallocate(_)
        | S::PgCopy(_)
        | S::PgRefreshMatview(_)
        | S::PgListen(_)
        | S::PgNotify(_)
        | S::PgUnlisten(_)
        | S::PgLockTable(_)
        | S::PgCreateRule(_)
        | S::PgCreateAggregate(_)
        | S::PgCreateOperator(_)
        | S::PgAlterSystem(_)
        | S::PgAlterTablespace(_)
        | S::PgDropOwned(_)
        | S::PgReassignOwned(_)
        | S::PgDiscard(_)
        | S::PgCluster(_)
        | S::PgPublication(_)
        | S::PgSubscription(_)
        | S::CreatePrincipal(_)
        | S::AlterPrincipal(_)
        | S::DropPrincipal(_)
        | S::PgDropExtension(_)
        | S::PgAlterRule(_)
        | S::PgDropRule(_)
        | S::PgAlterTableTriggerState(_)
        | S::PgSet(_)
        | S::PgDropSequence(_)
        | S::PgDropType(_)
        | S::PgDropIndex(_)
        | S::PgCreateTablespace(_)
        | S::PgDropTablespace(_)
        | S::BqExportData(_)
        | S::BqLoadData(_)
        | S::MysqlLoadData(_)
        | S::MysqlRenameTable(_)
        | S::CreateEvent(_)
        | S::AlterEvent(_)
        | S::CreateMysqlTrigger(_)
        | S::BqAssert(_)
        | S::BqCreateSnapshotTable(_)
        | S::BqDropSnapshotTable(_)
        | S::BqCreateSearchIndex(_)
        | S::BqDropSearchIndex(_)
        | S::BqCreateVectorIndex(_)
        | S::BqDropVectorIndex(_)
        | S::BqAlterVectorIndex(_)
        | S::BqCreateModel(_)
        | S::BqAlterModel(_)
        | S::BqExportModel(_)
        | S::BqDropModel(_)
        | S::CreateExternalTable(_)
        | S::CreateExternalSchema(_)
        | S::Optimize(_)
        | S::DescribeHistory(_)
        | S::Restore(_)
        | S::CacheTable(_)
        | S::UncacheTable(_)
        | S::RepairTable(_)
        | S::CreateCatalog(_)
        | S::AlterCatalog(_)
        | S::DropCatalog(_)
        | S::CreateVolume(_)
        | S::AlterVolume(_)
        | S::DropVolume(_)
        | S::CreateExternalLocation(_)
        | S::AlterExternalLocation(_)
        | S::DropExternalLocation(_)
        | S::CreateStorageCredential(_)
        | S::AlterStorageCredential(_)
        | S::DropStorageCredential(_)
        | S::AlterUserMapping(_)
        | S::DropUserMapping(_)
        | S::CreateUserMapping(_)
        | S::CreateForeignTable(_)
        | S::ImportForeignSchema(_)
        | S::CreateForeignServer(_)
        | S::AlterForeignServer(_)
        | S::MssqlAlterServerConfiguration(_)
        | S::MssqlCreateExternalDataSource(_)
        | S::MssqlAlterExternalDataSource(_)
        | S::CreateConnection(_)
        | S::AlterConnection(_)
        | S::DropConnection(_)
        | S::CreateFlow(_)
        | S::MssqlExec(_)
        | S::MssqlTryCatch(_)
        | S::MssqlIf(_)
        | S::MssqlWhile(_)
        | S::MssqlPrint(_)
        | S::MssqlThrow(_)
        | S::MssqlRaiserror(_)
        | S::MssqlSetOption(_)
        | S::Reconfigure { .. }
        | S::MysqlSet(_)
        | S::MssqlWaitfor(_)
        | S::MssqlGoto(_)
        | S::MssqlLabel(_)
        | S::CreateMssqlTrigger(_)
        | S::DropMssqlTrigger(_)
        | S::MssqlBulkInsert(_)
        | S::MssqlCreateExternalModel(_)
        | S::MssqlAlterExternalModel(_)
        | S::MssqlDropExternalModel(_)
        | S::MssqlCreateVectorIndex(_)
        | S::Grant(_)
        | S::Revoke(_)
        | S::Deny(_)
        | S::AlterAuthorization(_)
        | S::MssqlExecuteAs(_)
        | S::MssqlRevert { .. }
        | S::MssqlAuditDdl(_)
        | S::MssqlSecurityObjectDdl(_)
        | S::SetVariable { .. }
        | S::PipeChain { .. }
        | S::Assign { .. }
        | S::Declare { .. }
        | S::DeclareTable { .. }
        | S::DeclareCursor { .. }
        | S::Let { .. }
        | S::LetCursor { .. }
        | S::Return { .. }
        | S::Raise { .. }
        | S::Signal { .. }
        | S::Resignal { .. }
        | S::GetDiagnostics { .. }
        | S::DeclareCondition { .. }
        | S::Break { .. }
        | S::Continue { .. }
        | S::Null { .. }
        | S::OpenCursor { .. }
        | S::FetchCursor { .. }
        | S::CloseCursor { .. }
        | S::Await { .. }
        | S::Cancel { .. }
        | S::ExecuteImmediate { .. }
        | S::ExecuteImmediateFrom(_)
        | S::BeginTransaction { .. }
        | S::Commit { .. }
        | S::Rollback { .. }
        | S::Call { .. }
        | S::CopyIntoTable { .. }
        | S::CopyIntoLocation { .. }
        | S::Unload { .. }
        | S::RedshiftCopy { .. } => CoverageClass::Analyzed,
    }
}

/// The canonical statement enumeration for rule evaluation: every top-level
/// statement plus every statement nested at any depth (proc / function / task /
/// trigger / event / DO bodies and all control-flow blocks). EVERY per-family
/// rule evaluator must enumerate via this — a family that iterates
/// `script.stmts` directly silently skips every statement inside a body.
pub fn flat_stmts_for_rules(script: &ast::AstScript) -> Vec<&ast::AstStmt> {
    let mut flat = Vec::with_capacity(script.stmts.len());
    for s in &script.stmts {
        flatten_stmts_for_rules(s, &mut flat);
    }
    flat
}

/// Depth-first walk over an [`ast::AstStmt`] subtree, pushing every
/// reachable statement (the input + every statement nested in a
/// body-bearing scripting / procedural arm). Mirrors the recursion
/// pattern in `collect_declare_handlers` but pushes every stmt
/// rather than only `DeclareHandler` leaves.
///
/// The rule evaluators iterate the result so per-statement facts are
/// accumulated and rules are evaluated against inner-body statements.
/// Without this, e.g. `DECLARE c CURSOR FOR <SELECT>` inside a
/// `BEGIN ... END` block would silently fail to surface the cursor's
/// read set (the underlying SELECT only reaches the lowerer through the
/// wrapper's `decls` field, which the top-level `script.stmts`
/// iteration alone does not visit).
///
/// Closed-enum exhaustive: every `AstStmt` variant either descends
/// (body-bearing arms) or is treated as a leaf (no further children).
/// Adding a new `AstStmt` variant breaks the compile.
pub fn flatten_stmts_for_rules<'a>(stmt: &'a ast::AstStmt, out: &mut Vec<&'a ast::AstStmt>) {
    out.push(stmt);
    match stmt {
        ast::AstStmt::Block(b) => {
            for s in &b.decls {
                flatten_stmts_for_rules(s, out);
            }
            for s in &b.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::DeclareHandler(h) => {
            flatten_stmts_for_rules(&h.handler_action, out);
        }
        ast::AstStmt::If(i) => {
            for br in &i.branches {
                for s in &br.body {
                    flatten_stmts_for_rules(s, out);
                }
            }
            for s in &i.else_body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::CaseStmt(c) => {
            for br in &c.branches {
                for s in &br.body {
                    flatten_stmts_for_rules(s, out);
                }
            }
            for s in &c.else_body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::While(w) => {
            for s in &w.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::For(f) => {
            for s in &f.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::ForEach(f) => {
            for s in &f.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::Loop(l) => {
            for s in &l.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::Repeat(r) => {
            for s in &r.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::MssqlTryCatch(t) => {
            for s in &t.try_body {
                flatten_stmts_for_rules(s, out);
            }
            for s in &t.catch_body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::MssqlIf(i) => {
            for s in &i.then_body {
                flatten_stmts_for_rules(s, out);
            }
            for s in &i.else_body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::MssqlWhile(w) => {
            for s in &w.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        ast::AstStmt::CreateProcedure(p) => {
            if let Some(body) = p.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        ast::AstStmt::CreateFunction(f) => {
            if let Some(body) = f.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        // Anonymous `DO $$ … $$` block: recurse its sub-parsed body so inner
        // statements are rule-evaluated (parity with proc/func bodies).
        ast::AstStmt::DoBlock(d) => {
            if let Some(body) = d.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        // MySQL scheduled events: recurse the `DO` body so a recurring
        // scheduled DROP / GRANT / DELETE is rule-evaluated like any other
        // statement (parity with proc/func/DO bodies).
        ast::AstStmt::CreateEvent(e) => {
            if let Some(body) = e.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        ast::AstStmt::AlterEvent(e) => {
            if let Some(body) = e.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        // MySQL trigger: recurse the inline body so a trigger that GRANTs /
        // DROPs / writes on every row event is rule-evaluated like any other
        // statement.
        ast::AstStmt::CreateMysqlTrigger(t) => {
            if let Some(body) = t.body_stmt.as_deref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        // Snowflake task: recurse the `AS <body>` so a scheduled DROP / GRANT /
        // DELETE is rule-evaluated like any other statement (parity with
        // proc/event/trigger bodies). An unparseable body (`Err`) is a leaf.
        ast::AstStmt::CreateTask(t) => {
            if let Some(Ok(body)) = t.body.as_ref() {
                flatten_stmts_for_rules(body, out);
            }
        }
        // MSSQL trigger: recurse the inline `AS BEGIN … END` body.
        ast::AstStmt::CreateMssqlTrigger(t) => {
            for s in &t.body {
                flatten_stmts_for_rules(s, out);
            }
        }
        // T-SQL CETAS (`CREATE EXTERNAL TABLE … AS <query>`): recurse the egress
        // query so its reads/predicates are rule-evaluated — the query's results
        // are written out to external storage. Read-only external tables carry
        // no `AS` query (`None`) and are leaves.
        ast::AstStmt::CreateExternalTable(c) => {
            if let Some(Ok(q)) = c.as_query.as_ref() {
                flatten_stmts_for_rules(q, out);
            }
        }
        // Body-less leaves — listed exhaustively so the closed-enum
        // contract stays compiler-enforced. Adding a new `AstStmt`
        // variant breaks this build and forces a deliberate
        // recurse-or-leaf decision.
        ast::AstStmt::Select(_)
        | ast::AstStmt::SetSelect(_)
        | ast::AstStmt::ValuesQuery(_)
        | ast::AstStmt::Insert(_)
        | ast::AstStmt::ReplaceInto(_)
        | ast::AstStmt::MultiInsert(_)
        | ast::AstStmt::Update(_)
        | ast::AstStmt::Delete(_)
        | ast::AstStmt::Merge(_)
        | ast::AstStmt::Explain(_)
        | ast::AstStmt::ExecuteImmediate { .. }
        | ast::AstStmt::ExecuteImmediateFrom(_)
        | ast::AstStmt::OpaqueContent { .. }
        | ast::AstStmt::ClauseFragment { .. }
        | ast::AstStmt::JinjaPlaceholder { .. }
        | ast::AstStmt::JinjaConditionalStmt(_)
        | ast::AstStmt::Error { .. }
        | ast::AstStmt::GoBatchSeparator { .. }
        | ast::AstStmt::AlterAccount(_)
        | ast::AstStmt::AlterAggregationPolicy(_)
        | ast::AstStmt::AlterApiIntegration(_)
        | ast::AstStmt::AlterNotificationIntegration(_)
        | ast::AstStmt::CreateShare(_)
        | ast::AstStmt::AlterShare(_)
        | ast::AstStmt::CreateDatashare(_)
        | ast::AstStmt::AlterDatashare(_)
        | ast::AstStmt::CreateSecurityIntegration(_)
        | ast::AstStmt::AlterSecurityIntegration(_)
        | ast::AstStmt::AlterReplicationGroup(_)
        | ast::AstStmt::AlterFailoverGroup(_)
        | ast::AstStmt::AlterAuthenticationPolicy(_)
        | ast::AstStmt::AlterCatalog(_)
        | ast::AstStmt::AlterConnection(_)
        | ast::AstStmt::AlterDatabase(_)
        | ast::AstStmt::AlterDomain(_)
        | ast::AstStmt::AlterDynamicTable(_)
        | ast::AstStmt::AlterExternalAccessIntegration(_)
        | ast::AstStmt::AlterExternalLocation(_)
        | ast::AstStmt::AlterFunction(_)
        | ast::AstStmt::AlterIndex(_)
        | ast::AstStmt::AlterMaterializedView(_)
        | ast::AstStmt::AlterMaskingPolicy(_)
        | ast::AstStmt::AlterNetworkPolicy(_)
        | ast::AstStmt::AlterPasswordPolicy(_)
        | ast::AstStmt::AlterPgPolicy(_)
        | ast::AstStmt::AlterPgTrigger(_)
        | ast::AstStmt::AlterPipe(_)
        | ast::AstStmt::AlterProcedure(_)
        | ast::AstStmt::AlterProjectionPolicy(_)
        | ast::AstStmt::AlterJoinPolicy(_)
        | ast::AstStmt::AlterRowAccessPolicy(_)
        | ast::AstStmt::AlterSchema(_)
        | ast::AstStmt::AlterSequence(_)
        | ast::AstStmt::AlterSessionPolicy(_)
        | ast::AstStmt::AlterSession(_)
        | ast::AstStmt::AlterStage(_)
        | ast::AstStmt::AlterStorageCredential(_)
        | ast::AstStmt::AlterStorageIntegration(_)
        | ast::AstStmt::AlterStream(_)
        | ast::AstStmt::AlterTable(_)
        | ast::AstStmt::AlterTask(_)
        | ast::AstStmt::AlterType(_)
        | ast::AstStmt::AlterUser(_)
        | ast::AstStmt::AlterView(_)
        | ast::AstStmt::AlterVolume(_)
        | ast::AstStmt::AlterWarehouse(_)
        | ast::AstStmt::AnalyzeStmt(_)
        | ast::AstStmt::Assign { .. }
        | ast::AstStmt::Await { .. }
        | ast::AstStmt::BeginTransaction { .. }
        | ast::AstStmt::BqAlterModel(_)
        | ast::AstStmt::BqAlterVectorIndex(_)
        | ast::AstStmt::BqAssert(_)
        | ast::AstStmt::BqCreateModel(_)
        | ast::AstStmt::BqCreateSearchIndex(_)
        | ast::AstStmt::BqCreateSnapshotTable(_)
        | ast::AstStmt::BqCreateVectorIndex(_)
        | ast::AstStmt::BqDropModel(_)
        | ast::AstStmt::BqDropSearchIndex(_)
        | ast::AstStmt::BqDropSnapshotTable(_)
        | ast::AstStmt::BqDropVectorIndex(_)
        | ast::AstStmt::BqExportData(_)
        | ast::AstStmt::BqExportModel(_)
        | ast::AstStmt::BqLoadData(_)
        | ast::AstStmt::MysqlLoadData(_)
        | ast::AstStmt::MysqlRenameTable(_)
        | ast::AstStmt::Break { .. }
        | ast::AstStmt::CacheTable(_)
        | ast::AstStmt::Call { .. }
        | ast::AstStmt::Cancel { .. }
        | ast::AstStmt::CloseCursor { .. }
        | ast::AstStmt::CommentOn(_)
        | ast::AstStmt::Commit { .. }
        | ast::AstStmt::Continue { .. }
        | ast::AstStmt::CopyIntoLocation { .. }
        | ast::AstStmt::Unload { .. }
        | ast::AstStmt::RedshiftCopy { .. }
        | ast::AstStmt::CopyIntoTable { .. }
        | ast::AstStmt::CreateAggregationPolicy(_)
        | ast::AstStmt::CreateApiIntegration(_)
        | ast::AstStmt::CreateNotificationIntegration(_)
        | ast::AstStmt::CreateAuthenticationPolicy(_)
        | ast::AstStmt::CreateCatalog(_)
        | ast::AstStmt::AlterUserMapping(_)
        | ast::AstStmt::DropUserMapping(_)
        | ast::AstStmt::CreateUserMapping(_)
        | ast::AstStmt::CreateForeignTable(_)
        | ast::AstStmt::ImportForeignSchema(_)
        | ast::AstStmt::CreateForeignServer(_)
        | ast::AstStmt::AlterForeignServer(_)
        | ast::AstStmt::MssqlAlterServerConfiguration(_)
        | ast::AstStmt::MssqlCreateExternalDataSource(_)
        | ast::AstStmt::MssqlAlterExternalDataSource(_)
        | ast::AstStmt::CreateConnection(_)
        | ast::AstStmt::CreateDatabase(_)
        | ast::AstStmt::CreateDomain(_)
        | ast::AstStmt::CreateDynamicTable(_)
        | ast::AstStmt::CreateExtension(_)
        | ast::AstStmt::CreateExternalAccessIntegration(_)
        | ast::AstStmt::CreateExternalLocation(_)
        | ast::AstStmt::CreateExternalSchema(_)
        | ast::AstStmt::CreateFlow(_)
        | ast::AstStmt::CreateIndex(_)
        | ast::AstStmt::CreateSynonym(_)
        | ast::AstStmt::CreateMaskingPolicy(_)
        | ast::AstStmt::CreateNetworkPolicy(_)
        | ast::AstStmt::CreatePasswordPolicy(_)
        | ast::AstStmt::CreatePgPolicy(_)
        | ast::AstStmt::CreatePgTrigger(_)
        | ast::AstStmt::CreatePipe(_)
        | ast::AstStmt::CreateProjectionPolicy(_)
        | ast::AstStmt::CreateJoinPolicy(_)
        | ast::AstStmt::CreateRowAccessPolicy(_)
        | ast::AstStmt::CreateSchema(_)
        | ast::AstStmt::CreateSequence(_)
        | ast::AstStmt::CreateSessionPolicy(_)
        | ast::AstStmt::CreateStage(_)
        | ast::AstStmt::CreateStorageCredential(_)
        | ast::AstStmt::CreateStorageIntegration(_)
        | ast::AstStmt::CreateStream(_)
        | ast::AstStmt::CreateTable(_)
        | ast::AstStmt::CreateTableFunction(_)
        | ast::AstStmt::CreateType(_)
        | ast::AstStmt::CreateView(_)
        | ast::AstStmt::CreateVolume(_)
        | ast::AstStmt::CreateWarehouse(_)
        | ast::AstStmt::Declare { .. }
        | ast::AstStmt::DeclareCondition { .. }
        | ast::AstStmt::DeclareCursor { .. }
        | ast::AstStmt::DeclareTable { .. }
        | ast::AstStmt::Deny(_)
        | ast::AstStmt::AlterAuthorization(_)
        | ast::AstStmt::MssqlExecuteAs(_)
        | ast::AstStmt::MssqlRevert { .. }
        | ast::AstStmt::MssqlAuditDdl(_)
        | ast::AstStmt::MssqlSecurityObjectDdl(_)
        | ast::AstStmt::Describe(_)
        | ast::AstStmt::DescribeHistory(_)
        | ast::AstStmt::Drop(_)
        | ast::AstStmt::DropAggregationPolicy(_)
        | ast::AstStmt::DropAllRowAccessPolicies(_)
        | ast::AstStmt::DropApiIntegration(_)
        | ast::AstStmt::DropNotificationIntegration(_)
        | ast::AstStmt::DropAuthenticationPolicy(_)
        | ast::AstStmt::DropCatalog(_)
        | ast::AstStmt::DropConnection(_)
        | ast::AstStmt::DropDatabase(_)
        | ast::AstStmt::DropDomain(_)
        | ast::AstStmt::DropExternalAccessIntegration(_)
        | ast::AstStmt::DropExternalLocation(_)
        | ast::AstStmt::DropMaskingPolicy(_)
        | ast::AstStmt::DropMssqlTrigger(_)
        | ast::AstStmt::DropNetworkPolicy(_)
        | ast::AstStmt::DropPasswordPolicy(_)
        | ast::AstStmt::DropPgPolicy(_)
        | ast::AstStmt::DropPgTrigger(_)
        | ast::AstStmt::DropPipe(_)
        | ast::AstStmt::DropProjectionPolicy(_)
        | ast::AstStmt::DropJoinPolicy(_)
        | ast::AstStmt::DropRowAccessPolicy(_)
        | ast::AstStmt::DropSchema(_)
        | ast::AstStmt::DropSessionPolicy(_)
        | ast::AstStmt::DropStorageCredential(_)
        | ast::AstStmt::DropStorageIntegration(_)
        | ast::AstStmt::DropStream(_)
        | ast::AstStmt::DropTask(_)
        | ast::AstStmt::DropVolume(_)
        | ast::AstStmt::DropWarehouse(_)
        | ast::AstStmt::FetchCursor { .. }
        | ast::AstStmt::GetDiagnostics { .. }
        | ast::AstStmt::Grant(_)
        | ast::AstStmt::Let { .. }
        | ast::AstStmt::LetCursor { .. }
        | ast::AstStmt::MssqlAlterExternalModel(_)
        | ast::AstStmt::MssqlBulkInsert(_)
        | ast::AstStmt::MssqlCreateExternalModel(_)
        | ast::AstStmt::MssqlCreateVectorIndex(_)
        | ast::AstStmt::MssqlDropExternalModel(_)
        | ast::AstStmt::MssqlExec(_)
        | ast::AstStmt::MssqlGoto(_)
        | ast::AstStmt::MssqlLabel(_)
        | ast::AstStmt::MssqlPrint(_)
        | ast::AstStmt::MssqlRaiserror(_)
        | ast::AstStmt::MssqlSetOption(_)
        | ast::AstStmt::Reconfigure { .. }
        | ast::AstStmt::MysqlSet(_)
        | ast::AstStmt::MssqlThrow(_)
        | ast::AstStmt::MssqlWaitfor(_)
        | ast::AstStmt::Null { .. }
        | ast::AstStmt::OpenCursor { .. }
        | ast::AstStmt::Optimize(_)
        | ast::AstStmt::AlterPrincipal(_)
        | ast::AstStmt::PgAlterRule(_)
        | ast::AstStmt::PgAlterSystem(_)
        | ast::AstStmt::PgAlterTableTriggerState(_)
        | ast::AstStmt::PgAlterTablespace(_)
        | ast::AstStmt::PgCluster(_)
        | ast::AstStmt::PgCopy(_)
        | ast::AstStmt::PgCreateAggregate(_)
        | ast::AstStmt::PgCreateOperator(_)
        | ast::AstStmt::CreatePrincipal(_)
        | ast::AstStmt::PgCreateRule(_)
        | ast::AstStmt::PgCreateTablespace(_)
        | ast::AstStmt::PgDeallocate(_)
        | ast::AstStmt::PgDiscard(_)
        | ast::AstStmt::PgDropExtension(_)
        | ast::AstStmt::PgDropIndex(_)
        | ast::AstStmt::PgDropOwned(_)
        | ast::AstStmt::DropPrincipal(_)
        | ast::AstStmt::PgDropRule(_)
        | ast::AstStmt::PgDropSequence(_)
        | ast::AstStmt::PgDropTablespace(_)
        | ast::AstStmt::PgDropType(_)
        | ast::AstStmt::PgExecute(_)
        | ast::AstStmt::PgListen(_)
        | ast::AstStmt::PgLockTable(_)
        | ast::AstStmt::PgNotify(_)
        | ast::AstStmt::PgPrepare(_)
        | ast::AstStmt::PgPublication(_)
        | ast::AstStmt::PgReassignOwned(_)
        | ast::AstStmt::PgRefreshMatview(_)
        | ast::AstStmt::PgSet(_)
        | ast::AstStmt::PgSubscription(_)
        | ast::AstStmt::PgUnlisten(_)
        | ast::AstStmt::PipeChain { .. }
        | ast::AstStmt::Raise { .. }
        | ast::AstStmt::Reindex(_)
        | ast::AstStmt::RepairTable(_)
        | ast::AstStmt::Resignal { .. }
        | ast::AstStmt::Restore(_)
        | ast::AstStmt::MssqlBackup(_)
        | ast::AstStmt::MssqlRestore(_)
        | ast::AstStmt::MssqlDbcc(_)
        | ast::AstStmt::MssqlKeyManagement(_)
        | ast::AstStmt::MssqlSecurityPolicy(_)
        | ast::AstStmt::MssqlKeyBackup(_)
        | ast::AstStmt::MssqlAssembly(_)
        | ast::AstStmt::MssqlAddSignature(_)
        | ast::AstStmt::MssqlSetuser(_)
        | ast::AstStmt::MssqlAlterServiceMasterKey(_)
        | ast::AstStmt::PgAlterDefaultPrivileges(_)
        | ast::AstStmt::Return { .. }
        | ast::AstStmt::Revoke(_)
        | ast::AstStmt::Rollback { .. }
        | ast::AstStmt::SetVariable { .. }
        | ast::AstStmt::Show(_)
        | ast::AstStmt::Signal { .. }
        | ast::AstStmt::Truncate(_)
        | ast::AstStmt::UncacheTable(_)
        | ast::AstStmt::UndropDatabase(_)
        | ast::AstStmt::UndropSchema(_)
        | ast::AstStmt::UndropTable(_)
        | ast::AstStmt::UndropType(_)
        | ast::AstStmt::CreateTag(_)
        | ast::AstStmt::AlterTag(_)
        | ast::AstStmt::UndropTag(_)
        | ast::AstStmt::CreateFileFormat(_)
        | ast::AstStmt::AlterFileFormat(_)
        | ast::AstStmt::CreateSecret(_)
        | ast::AstStmt::AlterSecret(_)
        | ast::AstStmt::CreateNetworkRule(_)
        | ast::AstStmt::AlterNetworkRule(_)
        | ast::AstStmt::CreateResourceMonitor(_)
        | ast::AstStmt::AlterResourceMonitor(_)
        | ast::AstStmt::CreateComputePool(_)
        | ast::AstStmt::AlterComputePool(_)
        | ast::AstStmt::CreateGitRepository(_)
        | ast::AstStmt::CreateExternalFunction(_)
        | ast::AstStmt::AlterGitRepository(_)
        | ast::AstStmt::CreateImageRepository(_)
        | ast::AstStmt::AlterImageRepository(_)
        | ast::AstStmt::CreateStreamlit(_)
        | ast::AstStmt::AlterStreamlit(_)
        | ast::AstStmt::CreateService(_)
        | ast::AstStmt::AlterService(_)
        | ast::AstStmt::CreateNotebook(_)
        | ast::AstStmt::AlterNotebook(_)
        | ast::AstStmt::CreateSemanticView(_)
        | ast::AstStmt::AlterSemanticView(_)
        | ast::AstStmt::CreateCortexSearchService(_)
        | ast::AstStmt::AlterCortexSearchService(_)
        | ast::AstStmt::CreateApplication(_)
        | ast::AstStmt::AlterApplication(_)
        | ast::AstStmt::CreateApplicationPackage(_)
        | ast::AstStmt::AlterApplicationPackage(_)
        | ast::AstStmt::CreateListing(_)
        | ast::AstStmt::AlterListing(_)
        | ast::AstStmt::CreateManagedAccount(_)
        | ast::AstStmt::CreateAccount(_)
        | ast::AstStmt::StageFileCommand(_)
        | ast::AstStmt::CreateAlert(_)
        | ast::AstStmt::CreateDataMetricFunction(_)
        | ast::AstStmt::CreateReplicationFailoverGroup(_)
        | ast::AstStmt::AlterAlert(_)
        | ast::AstStmt::Use(_)
        | ast::AstStmt::Vacuum(_) => {}
    }
}

/// Recursively walk an [`ast::AstStmt`] subtree, collecting every
/// [`ast::AstDeclareHandlerStmt`] reachable through body-bearing
/// scripting / procedural statements.
fn collect_declare_handlers<'a>(
    stmt: &'a ast::AstStmt,
    out: &mut Vec<&'a ast::AstDeclareHandlerStmt>,
) {
    match stmt {
        ast::AstStmt::DeclareHandler(h) => {
            out.push(h.as_ref());
            collect_declare_handlers(&h.handler_action, out);
        }
        ast::AstStmt::Block(b) => {
            for s in &b.decls {
                collect_declare_handlers(s, out);
            }
            for s in &b.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::If(i) => {
            for br in &i.branches {
                for s in &br.body {
                    collect_declare_handlers(s, out);
                }
            }
            for s in &i.else_body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::CaseStmt(c) => {
            for br in &c.branches {
                for s in &br.body {
                    collect_declare_handlers(s, out);
                }
            }
            for s in &c.else_body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::While(w) => {
            for s in &w.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::For(f) => {
            for s in &f.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::ForEach(f) => {
            for s in &f.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::Loop(l) => {
            for s in &l.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::Repeat(r) => {
            for s in &r.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::MssqlTryCatch(t) => {
            for s in &t.try_body {
                collect_declare_handlers(s, out);
            }
            for s in &t.catch_body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::MssqlIf(i) => {
            for s in &i.then_body {
                collect_declare_handlers(s, out);
            }
            for s in &i.else_body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::MssqlWhile(w) => {
            for s in &w.body {
                collect_declare_handlers(s, out);
            }
        }
        ast::AstStmt::CreateProcedure(p) => {
            if let Some(body) = p.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::CreateFunction(f) => {
            if let Some(body) = f.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::DoBlock(d) => {
            if let Some(body) = d.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::CreateEvent(e) => {
            if let Some(body) = e.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::AlterEvent(e) => {
            if let Some(body) = e.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::CreateMysqlTrigger(t) => {
            if let Some(body) = t.body_stmt.as_deref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::CreateTask(t) => {
            if let Some(Ok(body)) = t.body.as_ref() {
                collect_declare_handlers(body, out);
            }
        }
        ast::AstStmt::CreateMssqlTrigger(t) => {
            for s in &t.body {
                collect_declare_handlers(s, out);
            }
        }

        // Non-body-bearing leaves — listed exhaustively so the
        // closed-enum contract remains compiler-enforced (no `_ =>`
        // arm on `AstStmt`). Adding a new `AstStmt`
        // variant breaks this build and forces a deliberate
        // recursion-or-leaf decision.
        ast::AstStmt::Select(_)
        | ast::AstStmt::SetSelect(_)
        | ast::AstStmt::ValuesQuery(_)
        | ast::AstStmt::Insert(_)
        | ast::AstStmt::ReplaceInto(_)
        | ast::AstStmt::MultiInsert(_)
        | ast::AstStmt::Update(_)
        | ast::AstStmt::Delete(_)
        | ast::AstStmt::Merge(_)
        | ast::AstStmt::Explain(_)
        | ast::AstStmt::ExecuteImmediate { .. }
        | ast::AstStmt::ExecuteImmediateFrom(_)
        | ast::AstStmt::OpaqueContent { .. }
        | ast::AstStmt::ClauseFragment { .. }
        | ast::AstStmt::JinjaPlaceholder { .. }
        | ast::AstStmt::JinjaConditionalStmt(_)
        | ast::AstStmt::Error { .. }
        | ast::AstStmt::GoBatchSeparator { .. }
        | ast::AstStmt::AlterAccount(_)
        | ast::AstStmt::AlterAggregationPolicy(_)
        | ast::AstStmt::AlterApiIntegration(_)
        | ast::AstStmt::AlterNotificationIntegration(_)
        | ast::AstStmt::CreateShare(_)
        | ast::AstStmt::AlterShare(_)
        | ast::AstStmt::CreateDatashare(_)
        | ast::AstStmt::AlterDatashare(_)
        | ast::AstStmt::CreateSecurityIntegration(_)
        | ast::AstStmt::AlterSecurityIntegration(_)
        | ast::AstStmt::AlterReplicationGroup(_)
        | ast::AstStmt::AlterFailoverGroup(_)
        | ast::AstStmt::AlterAuthenticationPolicy(_)
        | ast::AstStmt::AlterCatalog(_)
        | ast::AstStmt::AlterConnection(_)
        | ast::AstStmt::AlterDatabase(_)
        | ast::AstStmt::AlterDomain(_)
        | ast::AstStmt::AlterDynamicTable(_)
        | ast::AstStmt::AlterExternalAccessIntegration(_)
        | ast::AstStmt::AlterExternalLocation(_)
        | ast::AstStmt::AlterFunction(_)
        | ast::AstStmt::AlterIndex(_)
        | ast::AstStmt::AlterMaterializedView(_)
        | ast::AstStmt::AlterMaskingPolicy(_)
        | ast::AstStmt::AlterNetworkPolicy(_)
        | ast::AstStmt::AlterPasswordPolicy(_)
        | ast::AstStmt::AlterPgPolicy(_)
        | ast::AstStmt::AlterPgTrigger(_)
        | ast::AstStmt::AlterPipe(_)
        | ast::AstStmt::AlterProcedure(_)
        | ast::AstStmt::AlterProjectionPolicy(_)
        | ast::AstStmt::AlterJoinPolicy(_)
        | ast::AstStmt::AlterRowAccessPolicy(_)
        | ast::AstStmt::AlterSchema(_)
        | ast::AstStmt::AlterSequence(_)
        | ast::AstStmt::AlterSessionPolicy(_)
        | ast::AstStmt::AlterSession(_)
        | ast::AstStmt::AlterStage(_)
        | ast::AstStmt::AlterStorageCredential(_)
        | ast::AstStmt::AlterStorageIntegration(_)
        | ast::AstStmt::AlterStream(_)
        | ast::AstStmt::AlterTable(_)
        | ast::AstStmt::AlterTask(_)
        | ast::AstStmt::AlterType(_)
        | ast::AstStmt::AlterUser(_)
        | ast::AstStmt::AlterView(_)
        | ast::AstStmt::AlterVolume(_)
        | ast::AstStmt::AlterWarehouse(_)
        | ast::AstStmt::AnalyzeStmt(_)
        | ast::AstStmt::Assign { .. }
        | ast::AstStmt::Await { .. }
        | ast::AstStmt::BeginTransaction { .. }
        | ast::AstStmt::BqAlterModel(_)
        | ast::AstStmt::BqAlterVectorIndex(_)
        | ast::AstStmt::BqAssert(_)
        | ast::AstStmt::BqCreateModel(_)
        | ast::AstStmt::BqCreateSearchIndex(_)
        | ast::AstStmt::BqCreateSnapshotTable(_)
        | ast::AstStmt::BqCreateVectorIndex(_)
        | ast::AstStmt::BqDropModel(_)
        | ast::AstStmt::BqDropSearchIndex(_)
        | ast::AstStmt::BqDropSnapshotTable(_)
        | ast::AstStmt::BqDropVectorIndex(_)
        | ast::AstStmt::BqExportData(_)
        | ast::AstStmt::BqExportModel(_)
        | ast::AstStmt::BqLoadData(_)
        | ast::AstStmt::MysqlLoadData(_)
        | ast::AstStmt::MysqlRenameTable(_)
        | ast::AstStmt::Break { .. }
        | ast::AstStmt::CacheTable(_)
        | ast::AstStmt::Call { .. }
        | ast::AstStmt::Cancel { .. }
        | ast::AstStmt::CloseCursor { .. }
        | ast::AstStmt::CommentOn(_)
        | ast::AstStmt::Commit { .. }
        | ast::AstStmt::Continue { .. }
        | ast::AstStmt::CopyIntoLocation { .. }
        | ast::AstStmt::Unload { .. }
        | ast::AstStmt::RedshiftCopy { .. }
        | ast::AstStmt::CopyIntoTable { .. }
        | ast::AstStmt::CreateAggregationPolicy(_)
        | ast::AstStmt::CreateApiIntegration(_)
        | ast::AstStmt::CreateNotificationIntegration(_)
        | ast::AstStmt::CreateAuthenticationPolicy(_)
        | ast::AstStmt::CreateCatalog(_)
        | ast::AstStmt::AlterUserMapping(_)
        | ast::AstStmt::DropUserMapping(_)
        | ast::AstStmt::CreateUserMapping(_)
        | ast::AstStmt::CreateForeignTable(_)
        | ast::AstStmt::ImportForeignSchema(_)
        | ast::AstStmt::CreateForeignServer(_)
        | ast::AstStmt::AlterForeignServer(_)
        | ast::AstStmt::MssqlAlterServerConfiguration(_)
        | ast::AstStmt::MssqlCreateExternalDataSource(_)
        | ast::AstStmt::MssqlAlterExternalDataSource(_)
        | ast::AstStmt::CreateConnection(_)
        | ast::AstStmt::CreateDatabase(_)
        | ast::AstStmt::CreateDomain(_)
        | ast::AstStmt::CreateDynamicTable(_)
        | ast::AstStmt::CreateExtension(_)
        | ast::AstStmt::CreateExternalAccessIntegration(_)
        | ast::AstStmt::CreateExternalLocation(_)
        | ast::AstStmt::CreateExternalTable(_)
        | ast::AstStmt::CreateExternalSchema(_)
        | ast::AstStmt::CreateFlow(_)
        | ast::AstStmt::CreateIndex(_)
        | ast::AstStmt::CreateSynonym(_)
        | ast::AstStmt::CreateMaskingPolicy(_)
        | ast::AstStmt::CreateNetworkPolicy(_)
        | ast::AstStmt::CreatePasswordPolicy(_)
        | ast::AstStmt::CreatePgPolicy(_)
        | ast::AstStmt::CreatePgTrigger(_)
        | ast::AstStmt::CreatePipe(_)
        | ast::AstStmt::CreateProjectionPolicy(_)
        | ast::AstStmt::CreateJoinPolicy(_)
        | ast::AstStmt::CreateRowAccessPolicy(_)
        | ast::AstStmt::CreateSchema(_)
        | ast::AstStmt::CreateSequence(_)
        | ast::AstStmt::CreateSessionPolicy(_)
        | ast::AstStmt::CreateStage(_)
        | ast::AstStmt::CreateStorageCredential(_)
        | ast::AstStmt::CreateStorageIntegration(_)
        | ast::AstStmt::CreateStream(_)
        | ast::AstStmt::CreateTable(_)
        | ast::AstStmt::CreateTableFunction(_)
        | ast::AstStmt::CreateType(_)
        | ast::AstStmt::CreateView(_)
        | ast::AstStmt::CreateVolume(_)
        | ast::AstStmt::CreateWarehouse(_)
        | ast::AstStmt::Declare { .. }
        | ast::AstStmt::DeclareCondition { .. }
        | ast::AstStmt::DeclareCursor { .. }
        | ast::AstStmt::DeclareTable { .. }
        | ast::AstStmt::Deny(_)
        | ast::AstStmt::AlterAuthorization(_)
        | ast::AstStmt::MssqlExecuteAs(_)
        | ast::AstStmt::MssqlRevert { .. }
        | ast::AstStmt::MssqlAuditDdl(_)
        | ast::AstStmt::MssqlSecurityObjectDdl(_)
        | ast::AstStmt::Describe(_)
        | ast::AstStmt::DescribeHistory(_)
        | ast::AstStmt::Drop(_)
        | ast::AstStmt::DropAggregationPolicy(_)
        | ast::AstStmt::DropAllRowAccessPolicies(_)
        | ast::AstStmt::DropApiIntegration(_)
        | ast::AstStmt::DropNotificationIntegration(_)
        | ast::AstStmt::DropAuthenticationPolicy(_)
        | ast::AstStmt::DropCatalog(_)
        | ast::AstStmt::DropConnection(_)
        | ast::AstStmt::DropDatabase(_)
        | ast::AstStmt::DropDomain(_)
        | ast::AstStmt::DropExternalAccessIntegration(_)
        | ast::AstStmt::DropExternalLocation(_)
        | ast::AstStmt::DropMaskingPolicy(_)
        | ast::AstStmt::DropMssqlTrigger(_)
        | ast::AstStmt::DropNetworkPolicy(_)
        | ast::AstStmt::DropPasswordPolicy(_)
        | ast::AstStmt::DropPgPolicy(_)
        | ast::AstStmt::DropPgTrigger(_)
        | ast::AstStmt::DropPipe(_)
        | ast::AstStmt::DropProjectionPolicy(_)
        | ast::AstStmt::DropJoinPolicy(_)
        | ast::AstStmt::DropRowAccessPolicy(_)
        | ast::AstStmt::DropSchema(_)
        | ast::AstStmt::DropSessionPolicy(_)
        | ast::AstStmt::DropStorageCredential(_)
        | ast::AstStmt::DropStorageIntegration(_)
        | ast::AstStmt::DropStream(_)
        | ast::AstStmt::DropTask(_)
        | ast::AstStmt::DropVolume(_)
        | ast::AstStmt::DropWarehouse(_)
        | ast::AstStmt::FetchCursor { .. }
        | ast::AstStmt::GetDiagnostics { .. }
        | ast::AstStmt::Grant(_)
        | ast::AstStmt::Let { .. }
        | ast::AstStmt::LetCursor { .. }
        | ast::AstStmt::MssqlAlterExternalModel(_)
        | ast::AstStmt::MssqlBulkInsert(_)
        | ast::AstStmt::MssqlCreateExternalModel(_)
        | ast::AstStmt::MssqlCreateVectorIndex(_)
        | ast::AstStmt::MssqlDropExternalModel(_)
        | ast::AstStmt::MssqlExec(_)
        | ast::AstStmt::MssqlGoto(_)
        | ast::AstStmt::MssqlLabel(_)
        | ast::AstStmt::MssqlPrint(_)
        | ast::AstStmt::MssqlRaiserror(_)
        | ast::AstStmt::MssqlSetOption(_)
        | ast::AstStmt::Reconfigure { .. }
        | ast::AstStmt::MysqlSet(_)
        | ast::AstStmt::MssqlThrow(_)
        | ast::AstStmt::MssqlWaitfor(_)
        | ast::AstStmt::Null { .. }
        | ast::AstStmt::OpenCursor { .. }
        | ast::AstStmt::Optimize(_)
        | ast::AstStmt::AlterPrincipal(_)
        | ast::AstStmt::PgAlterRule(_)
        | ast::AstStmt::PgAlterSystem(_)
        | ast::AstStmt::PgAlterTableTriggerState(_)
        | ast::AstStmt::PgAlterTablespace(_)
        | ast::AstStmt::PgCluster(_)
        | ast::AstStmt::PgCopy(_)
        | ast::AstStmt::PgCreateAggregate(_)
        | ast::AstStmt::PgCreateOperator(_)
        | ast::AstStmt::CreatePrincipal(_)
        | ast::AstStmt::PgCreateRule(_)
        | ast::AstStmt::PgCreateTablespace(_)
        | ast::AstStmt::PgDeallocate(_)
        | ast::AstStmt::PgDiscard(_)
        | ast::AstStmt::PgDropExtension(_)
        | ast::AstStmt::PgDropIndex(_)
        | ast::AstStmt::PgDropOwned(_)
        | ast::AstStmt::DropPrincipal(_)
        | ast::AstStmt::PgDropRule(_)
        | ast::AstStmt::PgDropSequence(_)
        | ast::AstStmt::PgDropTablespace(_)
        | ast::AstStmt::PgDropType(_)
        | ast::AstStmt::PgExecute(_)
        | ast::AstStmt::PgListen(_)
        | ast::AstStmt::PgLockTable(_)
        | ast::AstStmt::PgNotify(_)
        | ast::AstStmt::PgPrepare(_)
        | ast::AstStmt::PgPublication(_)
        | ast::AstStmt::PgReassignOwned(_)
        | ast::AstStmt::PgRefreshMatview(_)
        | ast::AstStmt::PgSet(_)
        | ast::AstStmt::PgSubscription(_)
        | ast::AstStmt::PgUnlisten(_)
        | ast::AstStmt::PipeChain { .. }
        | ast::AstStmt::Raise { .. }
        | ast::AstStmt::Reindex(_)
        | ast::AstStmt::RepairTable(_)
        | ast::AstStmt::Resignal { .. }
        | ast::AstStmt::Restore(_)
        | ast::AstStmt::MssqlBackup(_)
        | ast::AstStmt::MssqlRestore(_)
        | ast::AstStmt::MssqlDbcc(_)
        | ast::AstStmt::MssqlKeyManagement(_)
        | ast::AstStmt::MssqlSecurityPolicy(_)
        | ast::AstStmt::MssqlKeyBackup(_)
        | ast::AstStmt::MssqlAssembly(_)
        | ast::AstStmt::MssqlAddSignature(_)
        | ast::AstStmt::MssqlSetuser(_)
        | ast::AstStmt::MssqlAlterServiceMasterKey(_)
        | ast::AstStmt::PgAlterDefaultPrivileges(_)
        | ast::AstStmt::Return { .. }
        | ast::AstStmt::Revoke(_)
        | ast::AstStmt::Rollback { .. }
        | ast::AstStmt::SetVariable { .. }
        | ast::AstStmt::Show(_)
        | ast::AstStmt::Signal { .. }
        | ast::AstStmt::Truncate(_)
        | ast::AstStmt::UncacheTable(_)
        | ast::AstStmt::UndropDatabase(_)
        | ast::AstStmt::UndropSchema(_)
        | ast::AstStmt::UndropTable(_)
        | ast::AstStmt::UndropType(_)
        | ast::AstStmt::CreateTag(_)
        | ast::AstStmt::AlterTag(_)
        | ast::AstStmt::UndropTag(_)
        | ast::AstStmt::CreateFileFormat(_)
        | ast::AstStmt::AlterFileFormat(_)
        | ast::AstStmt::CreateSecret(_)
        | ast::AstStmt::AlterSecret(_)
        | ast::AstStmt::CreateNetworkRule(_)
        | ast::AstStmt::AlterNetworkRule(_)
        | ast::AstStmt::CreateResourceMonitor(_)
        | ast::AstStmt::AlterResourceMonitor(_)
        | ast::AstStmt::CreateComputePool(_)
        | ast::AstStmt::AlterComputePool(_)
        | ast::AstStmt::CreateGitRepository(_)
        | ast::AstStmt::CreateExternalFunction(_)
        | ast::AstStmt::AlterGitRepository(_)
        | ast::AstStmt::CreateImageRepository(_)
        | ast::AstStmt::AlterImageRepository(_)
        | ast::AstStmt::CreateStreamlit(_)
        | ast::AstStmt::AlterStreamlit(_)
        | ast::AstStmt::CreateService(_)
        | ast::AstStmt::AlterService(_)
        | ast::AstStmt::CreateNotebook(_)
        | ast::AstStmt::AlterNotebook(_)
        | ast::AstStmt::CreateSemanticView(_)
        | ast::AstStmt::AlterSemanticView(_)
        | ast::AstStmt::CreateCortexSearchService(_)
        | ast::AstStmt::AlterCortexSearchService(_)
        | ast::AstStmt::CreateApplication(_)
        | ast::AstStmt::AlterApplication(_)
        | ast::AstStmt::CreateApplicationPackage(_)
        | ast::AstStmt::AlterApplicationPackage(_)
        | ast::AstStmt::CreateListing(_)
        | ast::AstStmt::AlterListing(_)
        | ast::AstStmt::CreateManagedAccount(_)
        | ast::AstStmt::CreateAccount(_)
        | ast::AstStmt::StageFileCommand(_)
        | ast::AstStmt::CreateAlert(_)
        | ast::AstStmt::CreateDataMetricFunction(_)
        | ast::AstStmt::CreateReplicationFailoverGroup(_)
        | ast::AstStmt::AlterAlert(_)
        | ast::AstStmt::Use(_)
        | ast::AstStmt::Vacuum(_) => {}
    }
}

/// Read the source slice covered by `AstDrop::object_type_span` and
/// classify whether the DROP target is a view (`VIEW` or
/// `MATERIALIZED VIEW`). Used by the view-DDL dispatch in
/// `Engine::analyze_ddl_facts` to claim generic `AstStmt::Drop`s that
/// target views — the table / stage / dynamic-table dispatchers return
/// `None` for non-matching object types so this check is the last gate.
fn drop_target_is_view(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase();
    matches!(normalized.as_str(), "VIEW" | "MATERIALIZED VIEW")
}

/// True when a generic `AstStmt::Drop` targets a TAG object.
fn drop_target_is_tag(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("TAG")
}

/// True when a generic `AstStmt::Drop` targets a FILE FORMAT object.
fn drop_target_is_file_format(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("FILE FORMAT")
}

/// True when a generic `AstStmt::Drop` targets a NETWORK RULE object.
fn drop_target_is_network_rule(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("NETWORK RULE")
}

/// True when a generic `AstStmt::Drop` targets a RESOURCE MONITOR object.
fn drop_target_is_resource_monitor(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("RESOURCE MONITOR")
}

/// True when a generic `AstStmt::Drop` targets a COMPUTE POOL object.
fn drop_target_is_compute_pool(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("COMPUTE POOL")
}

/// True when a generic `AstStmt::Drop` targets a GIT REPOSITORY object.
fn drop_target_is_git_repository(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("GIT REPOSITORY")
}

/// True when a generic `AstStmt::Drop` targets an IMAGE REPOSITORY object.
fn drop_target_is_image_repository(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("IMAGE REPOSITORY")
}

/// True when a generic `AstStmt::Drop` targets a STREAMLIT object.
fn drop_target_is_streamlit(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("STREAMLIT")
}

/// True when a generic `AstStmt::Drop` targets a SERVICE object.
fn drop_target_is_service(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("SERVICE")
}

/// True when a generic `AstStmt::Drop` targets a NOTEBOOK object.
fn drop_target_is_notebook(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("NOTEBOOK")
}

/// True when a generic `AstStmt::Drop` targets a SEMANTIC VIEW object.
fn drop_target_is_semantic_view(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("SEMANTIC VIEW")
}

/// True when a generic `AstStmt::Drop` targets a CORTEX SEARCH SERVICE object.
fn drop_target_is_cortex_search_service(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("CORTEX SEARCH SERVICE")
}

/// True when a generic `AstStmt::Drop` targets an APPLICATION object (the bare
/// single-word object, not APPLICATION PACKAGE).
fn drop_target_is_application(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("APPLICATION")
}

/// True when a generic `AstStmt::Drop` targets an APPLICATION PACKAGE object.
fn drop_target_is_application_package(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("APPLICATION PACKAGE")
}

/// True when a generic `AstStmt::Drop` targets a LISTING object.
fn drop_target_is_listing(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("LISTING")
}

/// True when a generic `AstStmt::Drop` targets a MANAGED ACCOUNT object.
fn drop_target_is_managed_account(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("MANAGED ACCOUNT")
}

/// True when a generic `AstStmt::Drop` targets an ACCOUNT object (the bare
/// single-word object, not MANAGED ACCOUNT).
fn drop_target_is_account(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("ACCOUNT")
}

/// True when a generic `AstStmt::Drop` targets an ALERT object.
fn drop_target_is_alert(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("ALERT")
}

/// True when a generic `AstStmt::Drop` targets a DATA METRIC FUNCTION object.
fn drop_target_is_data_metric_function(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("DATA METRIC FUNCTION")
}

/// Resolve the kind of a generic `AstStmt::Drop` targeting a REPLICATION
/// GROUP or FAILOVER GROUP object, or `None` if it targets neither.
fn drop_replication_failover_group_type(
    s: &ast::AstDrop,
    sql: &str,
) -> Option<ir::ReplicationGroupType> {
    let object_type_span = s.object_type_span?;
    let text = sql.get(object_type_span.start as usize..object_type_span.end as usize)?;
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.eq_ignore_ascii_case("REPLICATION GROUP") {
        Some(ir::ReplicationGroupType::Replication)
    } else if normalized.eq_ignore_ascii_case("FAILOVER GROUP") {
        Some(ir::ReplicationGroupType::Failover)
    } else {
        None
    }
}

/// True when a generic `AstStmt::Drop` targets a SECRET object.
fn drop_target_is_secret(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("SECRET")
}

/// True when a generic `AstStmt::Drop` targets a SHARE object.
fn drop_target_is_share(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    text.trim().eq_ignore_ascii_case("SHARE")
}

/// True when a generic `AstStmt::Drop` targets a SECURITY INTEGRATION.
fn drop_target_is_security_integration(s: &ast::AstDrop, sql: &str) -> bool {
    let Some(object_type_span) = s.object_type_span else {
        return false;
    };
    let Some(text) = sql.get(object_type_span.start as usize..object_type_span.end as usize) else {
        return false;
    };
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case("SECURITY INTEGRATION")
}

/// Per-statement dispatch for the query family. See
/// [`evaluate_privilege_rules_for_script`] for the design rationale.
///
/// `trace_out` follows the same explain-mode contract as
/// [`evaluate_privilege_rules_for_script`].
pub(crate) fn evaluate_query_rules_for_script(
    script: &ast::AstScript,
    sql: &str,
    fold: &ScriptContextFold,
    catalog: Option<&crate::catalog::CatalogIndex>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    rules_corpus: &[rules::Rule],
    reasoning: &dyn facts::reasoning::Reasoning,
    script_reasoning: &mut dyn facts::reasoning::ScriptReasoning,
    mut facts_out: Option<&mut StatementFactsSink<'_>>,
    mut trace_out: Option<&mut Vec<analyzer::StatementExplanation>>,
) -> Vec<rules::Signal> {
    if rules_corpus.is_empty() {
        return Vec::new();
    }
    let function_catalog = ir::FunctionCatalog::for_dialect(ir::CatalogDialect::Default);

    // Lower each query-bearing statement to RelPlan, derive
    // facts, attach what earlier statements made stale, and
    // evaluate rules. The iteration target is the depth-first flatten
    // of `script.stmts` — every top-level statement plus every inner
    // body-bearing statement (Block decls/body, control-flow bodies,
    // CreateProcedure/Function bodies). Without this, a script like
    // `DECLARE c CURSOR FOR <SELECT> ; BEGIN ... END;` would parse as
    // a single `AstStmt::Block` wrapping the cursor declaration; the
    // cursor's underlying SELECT lives in `Block.decls` and would
    // never reach the lower-facts-rules loop. Matches the diff
    // pipeline's `flatten_body_into` behavior.
    let flat_stmts = flat_stmts_for_rules(script);
    let mut signals = Vec::new();
    for (stmt_index, stmt) in flat_stmts.iter().enumerate() {
        // Qualify bare table references under the namespace
        // (USE DATABASE/SCHEMA) active at this statement's position.
        let session = fold.session_context_at(stmt.span().start);
        let lowered = ir::lower_query_full_with_bindings_and_models(
            stmt,
            sql,
            ir::StrictMode::Permissive,
            &function_catalog,
            &session,
            catalog,
            model_catalog,
        );
        let (rel_plan, catalog_ctx, bindings, stmt_facts) = match lowered {
            Ok(t) => t,
            Err(_) => continue,
        };
        // When lowering bottoms out in an opaque terminal whose reason
        // means findings were *lost* — not merely a non-query statement
        // the query path correctly declined — hand the statement span
        // to the sink, the only channel from here to the report. Drives
        // confidence; the coverage counts stay parse-defined.
        if let ir::RelPlan::Opaque { reason, .. } = &rel_plan {
            if reason.indicates_lost_analysis() {
                if let Some(sink) = facts_out.as_deref_mut() {
                    sink.record_lost_analysis(stmt.span());
                }
            }
        }
        let derived_facts = ir::derive_facts_from_plan(
            sql,
            &rel_plan,
            &bindings,
            &function_catalog,
            catalog
                .is_some()
                .then_some(&catalog_ctx as &dyn ir::catalog_context::CatalogContext),
            reasoning,
        );
        let catalog_for_facts = if catalog.is_some() {
            Some(&catalog_ctx)
        } else {
            None
        };
        // Pass the AST statement's outer span so root `RelPlan::Limit`
        // (top-level SELECT with TOP / LIMIT / OFFSET / FETCH) records
        // its `source_span` over the full statement bytes — not just the
        // limit-clause bytes. The analyzer ledger keys on
        // `source_span.start`; without the override, top-level row-cap
        // SELECTs end up mis-indexed and flagged as
        // `UnimplementedStatementType`.
        let mut facts = facts::extract::derive_facts_from_query_plan_with_catalog(
            &rel_plan,
            &bindings,
            &derived_facts,
            sql,
            &function_catalog,
            catalog_for_facts,
            Some(stmt.span()),
            reasoning,
        );

        // Cross-server dynamic-SQL detection: walk the IR plan for
        // `dblink_exec` / `OPENQUERY`-style function calls and attach
        // typed `DynamicSqlCall` entries so DYNSQL-CROSS-SERVER /
        // DYNSQL-CONCAT can fire at the statement level even though
        // the surface is an expression, not a dedicated statement type.
        let cross_server_calls = ir::dynamic_sql::collect_cross_server_dynamic_sql_calls(
            &rel_plan,
            script_reasoning.dynamic_sql(),
        );
        for call_ir in &cross_server_calls {
            facts
                .dynamic_sql_calls
                .push(facts::extract::project_dynamic_sql_call(call_ir));
        }

        // MySQL INTO OUTFILE / DUMPFILE file-export target: lower-time
        // sibling fact (not plan-derivable), projected onto the query
        // surface here. Powers MYSQL-INTO-OUTFILE.
        if let Some(query) = facts.query.as_mut() {
            facts::extract::project_file_export_into(query, stmt_facts.file_export.as_ref());
        }

        // References to tables / columns that earlier DDL in the script
        // dropped or renamed (Q-FLOW-DROP-REF / Q-FLOW-RENAME-REF /
        // Q-FLOW-COL-DROP).
        script_reasoning.attach_stale_references(
            &mut facts,
            stmt_index,
            &rel_plan,
            &bindings,
            catalog_for_facts,
        );

        evaluate_facts_into(
            fold,
            &facts,
            rules_corpus,
            stmt.span(),
            sql,
            &mut signals,
            facts_out.as_deref_mut(),
            trace_out.as_deref_mut(),
        );
    }
    signals
}

/// Per-statement dispatch for the AUTHPOL-attachment family. See
/// [`evaluate_privilege_rules_for_script`] for the design rationale.
///
/// `trace_out` follows the same explain-mode contract as
/// [`evaluate_privilege_rules_for_script`].
pub(crate) fn evaluate_policy_attachment_rules_for_script(
    script: &ast::AstScript,
    sql: &str,
    fold: &ScriptContextFold,
    rules_corpus: &[rules::Rule],
    mut facts_out: Option<&mut StatementFactsSink<'_>>,
    mut trace_out: Option<&mut Vec<analyzer::StatementExplanation>>,
) -> Vec<rules::Signal> {
    let mut signals = Vec::new();
    if rules_corpus.is_empty() {
        return signals;
    }
    for stmt in flat_stmts_for_rules(script) {
        let plan = match stmt {
            ast::AstStmt::AlterUser(u) => Some(ir::PolicyAttachmentPlan::from_alter_user(u)),
            ast::AstStmt::AlterAccount(a) => ir::PolicyAttachmentPlan::from_alter_account(a),
            _ => None,
        };
        if let Some(plan) = plan {
            let facts = facts::extract::derive_facts_from_policy_attachment_plan(&plan, sql);
            evaluate_facts_into(
                fold,
                &facts,
                rules_corpus,
                stmt.span(),
                sql,
                &mut signals,
                facts_out.as_deref_mut(),
                trace_out.as_deref_mut(),
            );
            continue;
        }
        // Generic `ALTER ACCOUNT SET/UNSET <param>` — account-level
        // parameter governance (the AUTHENTICATION POLICY attachment slice
        // is handled above via PolicyAttachmentPlan).
        if let ast::AstStmt::AlterAccount(a) = stmt {
            if let Some(plan) = ir::lower_alter_account_params_to_plan(a, sql) {
                let facts = facts::extract::derive_facts_from_account_plan(&plan, sql);
                evaluate_facts_into(
                    fold,
                    &facts,
                    rules_corpus,
                    stmt.span(),
                    sql,
                    &mut signals,
                    facts_out.as_deref_mut(),
                    trace_out.as_deref_mut(),
                );
            }
        }
    }
    signals
}

/// Fold one substitution stage's unresolved-variable placeholders (deployment
/// `${VAR}` or SnowSQL `&var`) into render artifacts so unresolved variables
/// lower analysis confidence — the same treatment the Jinja renderer gives an
/// unresolved ref. `sql` is that stage's own output text (the text the record
/// offsets index). No-op when there are no placeholders.
fn fold_substitution_placeholders(
    artifacts: &mut template::RenderArtifacts,
    sql: &str,
    placeholders: &[template::records::PlaceholderRecord],
) {
    if placeholders.is_empty() {
        return;
    }
    let stats = analyzer::compute_placeholder_stats(sql, placeholders);
    artifacts.placeholders.absorb(&stats);
    // Span attachment is gated on the substituted text being the analyzed
    // text — a later Jinja rewrite shifts offsets, so then only the counts
    // (confidence) carry over.
    artifacts.extend_placeholder_spans_if_current(sql, placeholders);
}

/// Everything `analyze_risk_core` needs, prepared identically at every
/// raw-source entry point. `script` is parsed from `artifacts.sql` — the
/// text/provenance pairing the core requires, by construction.
pub struct PreparedScript {
    pub artifacts: template::RenderArtifacts,
    pub script: ast::AstScript,
}

/// Shared pre-analysis seam: deployment-variable substitution, SnowSQL `&var`
/// substitution, Jinja render, unresolved-variable confidence folding,
/// dialect-aware parse, and ambient normalization setup — in that order, the
/// same at every entry point.
pub(crate) fn prepare_and_parse_for_analysis(
    src: &str,
    dialect: &Option<dialect::DialectRef>,
    file_path: Option<&std::path::Path>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Result<PreparedScript, analyzer::RiskError> {
    // Line-preserving substitution pre-passes: deployment-pipeline variables
    // first (the deployment tool runs before the client tool), then SnowSQL
    // `&var`. Each is a no-op without its markers.
    let deploy = template::deployvars::preprocess(
        src,
        dialect,
        &template::SubstitutionConfig::default(),
        None,
    );
    let prepared = template::snowsql::preprocess(&deploy.sql, dialect, None);
    let src: &str = &prepared.sql;
    let mut artifacts = prepare_sql_for_analysis_with_context(src, file_path, reasoning)?;
    fold_substitution_placeholders(&mut artifacts, src, &prepared.placeholders);
    fold_substitution_placeholders(&mut artifacts, &deploy.sql, &deploy.placeholders);

    let script =
        parse_with_optional_dialect(&artifacts.sql, dialect, &artifacts.placeholder_spans)?;
    apply_dialect_normalization(dialect, reasoning);
    Ok(PreparedScript { artifacts, script })
}

/// Fold the top-level statement sequence into the script-level session
/// context — the active-role transitions established by `USE ROLE`.
///
/// Reuses the typed `USE` recognition (`lower_use_to_use_plan`) and the
/// standard identifier normalization, so the role name matches the
/// `use_stmt` facts exactly. A role takes effect for statements after
/// its `USE ROLE`; a nested `USE ROLE` inside a body is session-scoped
/// and intentionally not tracked here.
pub fn build_script_context_fold(script: &ast::AstScript, sql: &str) -> ScriptContextFold {
    let mut role_changes: Vec<(u32, facts::IdentName)> = Vec::new();
    let mut db_changes: Vec<(u32, facts::IdentName)> = Vec::new();
    let mut schema_changes: Vec<(u32, facts::IdentName)> = Vec::new();
    for stmt in &script.stmts {
        if let ast::AstStmt::Use(u) = stmt {
            let plan = ir::lower_use_to_use_plan(u, sql);
            // The USE takes effect for statements after it.
            let pos = stmt.span().end;
            match plan.kind {
                ir::UseKind::Role => {
                    if let Some(target) = plan.target {
                        role_changes.push((
                            pos,
                            facts::IdentName::from_parts(target.raw, target.normalized),
                        ));
                    }
                }
                // `USE DATABASE`, `USE SCHEMA`, bare `USE <db>`, and the
                // qualified `USE <db>.<schema>` forms set the default
                // namespace that later bare table refs resolve under.
                ir::UseKind::Database | ir::UseKind::Schema => {
                    let comps = use_target_components(sql, u.object_span);
                    match (plan.kind, comps.as_slice()) {
                        // `db.schema` (qualified USE / USE SCHEMA db.schema): set both.
                        (_, [db, schema]) => {
                            db_changes.push((pos, db.clone()));
                            schema_changes.push((pos, schema.clone()));
                        }
                        (ir::UseKind::Database, [db]) => db_changes.push((pos, db.clone())),
                        (ir::UseKind::Schema, [schema]) => {
                            schema_changes.push((pos, schema.clone()))
                        }
                        // Empty, or more than two components: nothing usable.
                        _ => {}
                    }
                }
                ir::UseKind::Catalog | ir::UseKind::Warehouse | ir::UseKind::SecondaryRoles => {}
            }
        }
    }
    ScriptContextFold {
        role_changes,
        db_changes,
        schema_changes,
    }
}

/// Split a `USE` target span into its dot-separated identifier
/// components, each normalized via the standard identifier
/// normalization. Mirrors `use_plan::first_component_target`'s
/// slice-and-normalize but keeps every component (a namespace can be
/// `db.schema`).
fn use_target_components(sql: &str, span: lexer::token::Span) -> Vec<facts::IdentName> {
    let raw = match sql.get(span.start as usize..span.end as usize) {
        Some(s) => s.trim(),
        None => return Vec::new(),
    };
    raw.split('.')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(facts::IdentName::new)
        .collect()
}

/// Script-level session context, folded once over the top-level
/// statement sequence. Overlaid onto each statement's `ScriptContext`
/// before rule evaluation, and used to qualify bare table references at
/// lowering. Tracks the active session role and the active
/// database / schema namespace.
#[derive(Debug, Clone, Default)]
pub struct ScriptContextFold {
    /// (effect_position, role) — the role set by `USE ROLE`, in effect
    /// from this byte offset until the next change. Ordered ascending.
    role_changes: Vec<(u32, facts::IdentName)>,
    /// (effect_position, database) — the default database set by
    /// `USE DATABASE` / bare `USE <db>` / the db side of `USE <db>.<schema>`.
    db_changes: Vec<(u32, facts::IdentName)>,
    /// (effect_position, schema) — the default schema set by `USE SCHEMA`
    /// / the schema side of `USE <db>.<schema>`.
    schema_changes: Vec<(u32, facts::IdentName)>,
}

impl ScriptContextFold {
    /// Active role at a byte position: the last change at or before it.
    fn role_at(&self, position: u32) -> Option<&facts::IdentName> {
        last_change_at(&self.role_changes, position)
    }

    /// Last role established anywhere in the script (whole-script summary).
    fn last_role(&self) -> Option<&facts::IdentName> {
        self.role_changes.last().map(|(_, r)| r)
    }

    /// The session namespace (database / schema) in effect at `position`,
    /// for qualifying bare table references during lowering. The `raw`
    /// spelling is used so a session-filled ref reads the same as an
    /// explicitly-qualified one; canonicalization happens downstream.
    pub fn session_context_at(&self, position: u32) -> ir::SessionContext {
        ir::SessionContext {
            db: last_change_at(&self.db_changes, position).map(|d| d.raw.clone()),
            schema: last_change_at(&self.schema_changes, position).map(|s| s.raw.clone()),
        }
    }

    /// The `ScriptContext` to overlay onto the statement at `span`: its
    /// folded session context. Default (no overlay) when no session
    /// state is in effect — the common no-`USE ROLE` case.
    fn context_for(&self, span: lexer::token::Span) -> facts::ScriptContext {
        let active_role = self.role_at(span.start).cloned();
        facts::ScriptContext {
            session: active_role.map(|r| facts::SessionContextFacts {
                active_role: Some(r),
            }),
            ..facts::ScriptContext::default()
        }
    }
}

/// Last `(position, value)` change at or before `position` in an
/// ascending-ordered change list.
fn last_change_at(changes: &[(u32, facts::IdentName)], position: u32) -> Option<&facts::IdentName> {
    // `changes` is ascending by position, so the active value is the last
    // entry at or before `position` — binary-search the boundary rather than
    // scan, keeping the lookup O(log U) (USE/role-heavy scripts stay linear).
    let boundary = changes.partition_point(|(change_pos, _)| *change_pos <= position);
    boundary.checked_sub(1).map(|i| &changes[i].1)
}

// ────────────────────────────────────────────────────────────────────────
// Strict-mode enforcement.
//
// These helpers let the CLI apply `AnalysisOptions` post-analysis. Today
// they gate on skipped / opaque statements; additional gates will be
// enabled in later releases.
// ────────────────────────────────────────────────────────────────────────

/// A single strict-mode violation. Owned strings so callers can surface
/// these to stdout/stderr without borrowing from the report.
#[derive(Debug, Clone)]
pub struct StrictViolation {
    pub code: &'static str,
    pub message: String,
    /// 1-indexed line number where the violation was observed, if known.
    pub line: Option<usize>,
}

/// Check an [`analyzer::AnalysisReport`] against [`AnalysisOptions`].
///
/// Returns the list of strict-mode violations. Empty list means the report
/// satisfies the requested strictness.
///
/// Behavior per mode:
/// - [`StrictMode::Permissive`]: always empty.
/// - [`StrictMode::Strict`]: one violation per unparsed or unsupported
///   statement the analyzer had to skip. Unimplemented statement types
///   get a distinct error code so CI can accept-list them separately
///   from real regressions.
/// - [`StrictMode::Pedantic`]: every check from the previous mode, plus one
///   violation per statement whose analysis could not be completed (recorded
///   as an analysis limitation — post-parse coverage loss).
pub fn enforce_strict_mode(
    report: &analyzer::AnalysisReport,
    opts: &AnalysisOptions,
) -> Vec<StrictViolation> {
    use analyzer::SkipReason;

    let mut out = Vec::new();

    if matches!(opts.strict, StrictMode::Permissive) {
        return out;
    }

    // Strict / pedantic: flag unparsed or skipped constructs.
    for skipped in &report.skipped_details {
        match &skipped.reason {
            SkipReason::UnparsedConstruct => {
                out.push(StrictViolation {
                    code: "E_STRICT_OPAQUE",
                    message: format!(
                        "unparsed construct at line {}: {}",
                        skipped.line_number, skipped.statement_prefix
                    ),
                    line: Some(skipped.line_number),
                });
            }
            SkipReason::UnimplementedStatementType => {
                out.push(StrictViolation {
                    code: "E_STRICT_UNIMPLEMENTED",
                    message: format!(
                        "unimplemented statement at line {}: {}",
                        skipped.line_number, skipped.statement_prefix
                    ),
                    line: Some(skipped.line_number),
                });
            }
            SkipReason::Other(msg) => {
                out.push(StrictViolation {
                    code: "E_STRICT_SKIPPED",
                    message: format!(
                        "skipped statement at line {} ({})",
                        skipped.line_number, msg
                    ),
                    line: Some(skipped.line_number),
                });
            }
        }
    }

    // Pedantic additionally fails closed on post-parse analysis loss: a
    // statement that parsed (so it is absent from `skipped_details`) but whose
    // analysis could not be completed — recorded as an analysis limitation with
    // degraded confidence. This is the comprehensive coverage gate; `strict`
    // stays parse/skip-level so existing CI gates are unaffected. Only genuine
    // give-ups populate `analysis_limitations` — missing optional input (no
    // catalog, unresolved template, unknown function) does not, so pedantic
    // does not fail on inputs the engine was simply never given.
    if matches!(opts.strict, StrictMode::Pedantic) {
        for limitation in &report.analysis_limitations {
            out.push(StrictViolation {
                code: "E_STRICT_INCOMPLETE_ANALYSIS",
                message: format!(
                    "incomplete analysis at line {}: {}",
                    limitation.line_number,
                    limitation.limitations.join("; ")
                ),
                line: Some(limitation.line_number),
            });
        }
    }

    out
}

/// Parse a `--strict` CLI value / `LEXEGA_STRICT` env var value into
/// a [`StrictMode`]. Accepts case-insensitive values:
///
/// * `off` / `0` / `false` / `no` — no strict checks (default).
/// * `strict` / `on` / `1` / `true` / `yes` — fail on unparsed or
///   unsupported statements.
/// * `pedantic` — strictest; also fails on any statement whose analysis
///   could not be completed (post-parse coverage loss).
///
/// Returns `Err(invalid_value)` on unknown input so the CLI can surface a
/// clean error message.
pub fn parse_strict_mode(value: &str) -> Result<StrictMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "off" | "0" | "false" | "no" => Ok(StrictMode::Permissive),
        "strict" | "on" | "1" | "true" | "yes" => Ok(StrictMode::Strict),
        "pedantic" | "full" => Ok(StrictMode::Pedantic),
        other => Err(other.to_string()),
    }
}

/// Read `LEXEGA_STRICT` and translate it to a [`StrictMode`].
///
/// Unset or unparseable values yield `Permissive`. We deliberately do not
/// fail on unknown values here — an env var is an ambient control, not a
/// required flag; explicit `--strict <value>` is the place to surface
/// parse errors.
pub fn strict_mode_from_env() -> StrictMode {
    match std::env::var("LEXEGA_STRICT") {
        Ok(v) => parse_strict_mode(&v).unwrap_or(StrictMode::Permissive),
        Err(_) => StrictMode::Permissive,
    }
}
