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
    try_parse_stmt_from_str, verify_copied_spans, verify_formatting_safe,
    verify_formatting_safe_with_dialect,
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
    IndentStyle, KeywordCase, LineBreak, MatchRecognizeDefineStyle, MatchRecognizeFormat,
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

/// The dialect the current thread analyses under, for as long as this value
/// lives: how names fold, which quotes delimit an identifier, and what the
/// dynamic-SQL recognition reads of the dialect. Dropping it puts back what
/// the thread had before, so scopes nest and no dialect outlives the
/// analysis that adopted it.
///
/// Scopes are dropped innermost first. Dropping a scope while scopes opened
/// inside it are alive ends them too, innermost first, whichever engine
/// opened each: the thread goes back to what it had when the dropped scope
/// was opened, a scope ended that way changes nothing when it is dropped
/// later, and a debug build panics at the first drop. A scope that is
/// never dropped stays open until a scope around it is dropped or its
/// thread ends.
///
/// Keep no scope in a thread-local: dropped out of order by the thread's
/// own teardown, the debug build's panic comes from a destructor and
/// aborts the process.
///
/// A name is folded only inside a scope. A debug build panics on a fold
/// with none open; a release build folds it as Snowflake does.
///
/// The value is a token: what it puts back is kept by the thread that
/// opened it, so it can be neither sent to another thread nor shared with
/// one:
///
/// ```compile_fail
/// fn sent<T: Send>(_: T) {}
/// sent(lexega_core::Engine::recognition().apply_dialect(&None));
/// ```
///
/// ```compile_fail
/// fn shared<T: Sync>(_: &T) {}
/// shared(&lexega_core::Engine::recognition().apply_dialect(&None));
/// ```
#[must_use = "the thread gives the dialect up when this value is dropped"]
pub struct DialectScope {
    /// Its id among the scopes its thread has open.
    id: u64,
    // The thread that opened it keeps what it puts back.
    _thread: std::marker::PhantomData<*const ()>,
}

impl Drop for DialectScope {
    fn drop(&mut self) {
        let ended = ir::normalize::leave_dialect_scope(self.id);
        // Reported once the thread is back; a thread already unwinding is
        // not made to panic again.
        debug_assert!(
            ended <= 1 || std::thread::panicking(),
            "a dialect scope was dropped before a scope opened inside it"
        );
    }
}

/// Adopt `dialect` (Snowflake when none is named) for the current thread
/// until the returned scope is dropped. An entry point holds the scope for
/// the length of its analysis; one that adopts nothing folds names as the
/// scope it runs inside does, and must run inside one.
pub(crate) fn adopt_dialect(
    dialect: Option<&dyn dialect::Dialect>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> DialectScope {
    let name = dialect.map_or("snowflake", |d| d.name());
    // The scope is open before the provider is asked: a panic in the
    // provider unwinds through it.
    let scope = DialectScope {
        id: ir::normalize::enter_dialect_scope(name),
        _thread: std::marker::PhantomData,
    };
    ir::normalize::hold_in_dialect_scope(scope.id, reasoning.configure_dialect(dialect));
    scope
}

//
// Risk Analysis APIs
//

/// Build CatalogInfo from loaded catalog index for trust assessment in reports.
/// Computes staleness warnings and identifies tables not found in catalog.
/// `subjects` are the tables the script names, in the order it names them;
/// `fold` gives the session defaults in effect where it names each, and
/// `relations` the relations the statements before it made.
fn build_catalog_info(
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    subjects: &[&analyzer::CatalogSubject],
    fold: &ScriptContextFold,
    relations: &catalog::ScriptRelations,
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

        // The tables the catalog does not have, each once, by the answer
        // lowering got for it or, for a statement's target lowering asked
        // nothing of, the same question. A table an earlier statement
        // made, while it stands, is not one, nor is the table a statement
        // creates, nor one a catalog of named tables does not name, nor a
        // session's own table or a stage a query names. Each is listed as
        // the reference it is told apart by: its parts as written, the
        // session's defaults filling the parts it omits.
        let mut listed: std::collections::HashSet<crate::context::node_metadata::TableRef> =
            std::collections::HashSet::new();
        for subject in subjects.iter().filter(|subject| !subject.created) {
            // The reference as lowering resolves one: the session's
            // defaults fill the parts it omits.
            let session = fold.session_context_at(subject.at);
            let mut table = subject.table.clone();
            ir::span_extract::apply_session_defaults_to_table_ref(&mut table, &session);
            let in_catalog = subject.in_catalog.or_else(|| {
                (!subject.queried).then(|| {
                    relations
                        .at(subject.at)
                        .table_presence(catalog, &subject.table, &session)
                })?
            });
            if in_catalog == Some(false) && !listed.contains(&table) {
                info.missing_tables.push(table.canonical());
                listed.insert(table);
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

/// Where a report places a byte of the analyzed text.
#[derive(Clone, Copy)]
struct Placing<'a> {
    /// The analyzed text, and its line index.
    text: &'a str,
    lines: &'a analyzer::LineIndex,
    /// How the text was rendered from a template, where it was.
    source_map: Option<&'a template::SourceMap>,
    source_file: Option<&'a str>,
}

impl Placing<'_> {
    /// The template line of byte `offset` of the analyzed text, where a
    /// template was rendered, and its place in the file the user wrote (the
    /// template, else the text). A byte with no place of its own in the
    /// template is placed at the start of the template line its line maps
    /// to.
    fn written(&self, offset: usize) -> (Option<usize>, analyzer::TextPosition) {
        let at = lexer::token::Span {
            start: offset as u32,
            end: offset as u32,
        };
        let resolved = self.lines.resolve_span(at, self.source_map);
        match (self.source_map, resolved.template_line) {
            (Some(map), Some(line)) => match map.template_position(offset) {
                Some(at) => (Some(at.line), at),
                None => (Some(line), analyzer::TextPosition::line_start(line)),
            },
            (Some(_), None) | (None, _) => (None, self.lines.position(self.text, offset)),
        }
    }

    /// Place `evidence` at byte `offset` of the analyzed text: its line and
    /// column there, the template line and the macro that wrote it where a
    /// template was rendered, and its place in the file the user wrote (the
    /// template, else the text), which `location` names.
    fn place(&self, evidence: &mut analyzer::RiskEvidence, offset: usize) {
        let analyzer::RiskEvidence::RuleMatch {
            line_number,
            column_number,
            template_line_number,
            is_generated,
            macro_name,
            location,
            position,
            ..
        } = evidence
        else {
            return;
        };
        let (template_line, written) = self.written(offset);
        let at = lexer::token::Span {
            start: offset as u32,
            end: offset as u32,
        };
        let resolved = self.lines.resolve_span(at, self.source_map);
        let analyzed = self.lines.position(self.text, offset);
        *line_number = Some(resolved.rendered_line);
        *column_number = Some(analyzed.column);
        *template_line_number = template_line;
        *is_generated = Some(resolved.is_generated);
        *macro_name = resolved.macro_name;
        *location = Some(format!(
            "{}:{}:{}",
            self.source_file.unwrap_or_default(),
            written.line,
            written.column
        ));
        *position = Some(written);
    }
}

/// Wrap a `rules::Finding` (the v1 fact-based output shape) inside the
/// `AnalysisReport.findings` envelope. Customer JSON-output contracts
/// (line numbers, evidence, role context) read off `AnalysisFinding`, so
/// every fact-engine finding is converted into one `RuleMatch::Analysis`
/// at the `analyze_risk_core` seam.
///
/// The witness is placed by [`Placing::place`]: a dbt / Jinja finding at the
/// place in the template the user wrote, through the render's source map.
/// Each pre-merge witness keeps its own `location`, so a finding merged by
/// dedup still gives one SARIF result per witness.
fn rule_finding_to_report_finding(
    finding: rules::Finding,
    placing: Placing<'_>,
    fold: &ScriptContextFold,
    quoted: QuotedSource<'_>,
) -> analyzer::RuleMatch {
    let statement_preview = finding
        .source_span
        .and_then(|sp| quoted.finding_preview(sp));
    // Role active at this finding's own position (not the whole-script
    // last role): the role in effect when the flagged statement runs.
    let assumed_role = finding
        .source_span
        .and_then(|sp| fold.role_at(sp.start))
        .map(|r| r.raw.clone());

    let mut witness = analyzer::RiskEvidence::RuleMatch {
        finding_type: "v1_fact".to_string(),
        resolution_status: None,
        rule_id: finding.rule_id.clone(),
        line_number: None,
        column_number: None,
        template_line_number: None,
        is_generated: None,
        macro_name: None,
        statement_preview: statement_preview.clone(),
        source_file: placing.source_file.map(String::from),
        location: None,
        position: None,
        assumed_role: assumed_role.clone(),
    };
    if let Some(span) = finding.source_span {
        placing.place(&mut witness, span.start as usize);
    }
    // The line user-facing reports show: the template line where a render
    // maps one, else the line of the analyzed text.
    let display_line = match &witness {
        analyzer::RiskEvidence::RuleMatch {
            line_number,
            template_line_number,
            ..
        } => template_line_number.or(*line_number),
        analyzer::RiskEvidence::TableReference { .. }
        | analyzer::RiskEvidence::PredicateInfo { .. } => None,
    };
    let evidence = vec![witness];

    let analysis = analyzer::AnalysisFinding {
        message: finding.message,
        risk_level: convert_facts_risk_level(finding.risk_level),
        matched_rule: finding.rule_id,
        finding_type: "v1_fact".to_string(),
        findings_merged: None,
        // Count entries in our local `evidence` Vec (always 1 pre-dedup —
        // each rule fire produces one `RiskEvidence::RuleMatch`). The
        // post-dedup pass in `deduplicate()` overrides this to the
        // deduplicated count when findings aggregate. We deliberately do
        // NOT use `finding.evidence.witnesses.len()` here — that's the
        // rules-engine's quantifier-match count, which is 0 for
        // property-only predicates (no `each:`/`exists:`) and would
        // surface as `evidence_count = 0` for the SNW-UNKNOWN path
        // (excluded from dedup-aggregation override).
        evidence_count: Some(evidence.len()),
        scope: Some("statement".to_string()),
        statement_line_number: display_line,
        statement_lines: None,
        topic_key: None,
        source: Some(analyzer::FindingSource::BuiltIn),
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

/// The order a report lists its findings in: by severity, then by blast
/// radius priority, then by rule id, message and place in the script (the
/// lines of its statements, then the line and column of each witness), so
/// that it does not depend on the order deduplication left them in. Two
/// findings equal in all of these keep the order they were raised in.
fn finding_order(a: &analyzer::RuleMatch, b: &analyzer::RuleMatch) -> std::cmp::Ordering {
    fn get_priority(finding: &analyzer::RuleMatch) -> u8 {
        let msg = finding.message().to_uppercase();
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

    // The lines of the statements a finding was raised on.
    fn place(finding: &analyzer::RuleMatch) -> (Option<usize>, Option<&[usize]>) {
        let analyzer::RuleMatch::Analysis(finding) = finding;
        (
            finding.statement_line_number,
            finding.statement_lines.as_deref(),
        )
    }

    // The line and column of each witness a finding holds.
    fn witnesses(
        finding: &analyzer::RuleMatch,
    ) -> impl Iterator<Item = (Option<usize>, Option<usize>)> + '_ {
        let analyzer::RuleMatch::Analysis(finding) = finding;
        finding
            .evidence
            .iter()
            .filter_map(|evidence| match evidence {
                analyzer::RiskEvidence::RuleMatch {
                    line_number,
                    column_number,
                    ..
                } => Some((*line_number, *column_number)),
                analyzer::RiskEvidence::TableReference { .. }
                | analyzer::RiskEvidence::PredicateInfo { .. } => None,
            })
    }

    b.risk_level()
        .cmp(&a.risk_level())
        .then_with(|| get_priority(b).cmp(&get_priority(a)))
        .then_with(|| a.rule_id().cmp(&b.rule_id()))
        .then_with(|| a.message().cmp(b.message()))
        .then_with(|| place(a).cmp(&place(b)))
        .then_with(|| witnesses(a).cmp(witnesses(b)))
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
    analyze_with_run_bodies(
        render,
        script,
        None,
        policy_config,
        catalog_index,
        catalog_path,
        source_file,
        model_catalog,
        None,
        reasoning,
        false,
        None,
    )
    .map(|(report, ..)| report)
}

/// [`analyze_risk_core`], `read_last` reading the script's last statement
/// as the analysis lowers it ([`LastStatement`]).
#[allow(clippy::too_many_arguments)] // mirrors `analyze_risk_core`
pub(crate) fn analyze_reading_last(
    render: &template::RenderArtifacts,
    script: &ast::AstScript,
    policy_config: &analyzer::AnalysisConfig,
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    source_file: Option<&str>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    reasoning: &dyn facts::reasoning::Reasoning,
    read_last: &mut ReadsLast<'_>,
) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
    analyze_with_run_bodies(
        render,
        script,
        None,
        policy_config,
        catalog_index,
        catalog_path,
        source_file,
        model_catalog,
        None,
        reasoning,
        false,
        Some(read_last),
    )
    .map(|(report, ..)| report)
}

/// [`analyze_risk_core`], `carried` the relations the scripts run before
/// it leave, which then holds those this script leaves for the script run
/// after it ([`CarriedRelations`]); unchanged where the analysis fails.
#[allow(clippy::too_many_arguments)] // mirrors `analyze_risk_core`
pub(crate) fn analyze_carrying(
    render: &template::RenderArtifacts,
    script: &ast::AstScript,
    policy_config: &analyzer::AnalysisConfig,
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    source_file: Option<&str>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    carried: &mut CarriedRelations,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
    analyze_with_run_bodies(
        render,
        script,
        None,
        policy_config,
        catalog_index,
        catalog_path,
        source_file,
        model_catalog,
        Some(carried),
        reasoning,
        false,
        None,
    )
    .map(|(report, ..)| report)
}

/// [`analyze_risk_core`], keeping what comparing the script with another
/// reads: each statement's facts and the report's findings occurrence by
/// occurrence.
#[allow(clippy::too_many_arguments)] // mirrors `analyze_risk_core`
pub(crate) fn analyze_for_comparison(
    render: &template::RenderArtifacts,
    script: &ast::AstScript,
    policy_config: &analyzer::AnalysisConfig,
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    source_file: Option<&str>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Result<ScriptAnalysis, analyzer::RiskError> {
    let (report, kept, quoted) = analyze_with_run_bodies(
        render,
        script,
        None,
        policy_config,
        catalog_index,
        catalog_path,
        source_file,
        model_catalog,
        None,
        reasoning,
        true,
        None,
    )?;
    let (statement_facts, kept) = kept.unwrap_or_default();
    Ok(ScriptAnalysis {
        report,
        render: render.clone(),
        statement_facts,
        masked_sql: facts::secrets::masked_fixed(
            &render.sql,
            0,
            render.sql.len(),
            &quoted.masked_runs,
        )
        .into_owned(),
        masked_runs: quoted.masked_runs,
        shown_literals: quoted.shown,
        comment_spans: quoted.comments,
        kept,
    })
}

/// [`analyze_risk_core`], `read` the script's fold and the SQL text it runs
/// where they were read with the text that runs the script (a body of
/// dynamic SQL); `None` reads them here. `carried`, where given, is the
/// relations the scripts run before leave, and then those this script
/// leaves ([`analyze_carrying`]). With `keep`, also each statement's facts
/// and the findings before they are folded into the report. Last, the text
/// analysed as the report quotes it ([`QuotedText`]).
#[allow(clippy::too_many_arguments)] // the analysis inputs, and what was read with the script
fn analyze_with_run_bodies(
    render: &template::RenderArtifacts,
    script: &ast::AstScript,
    read: Option<(&ScriptContextFold, &DynamicBodies)>,
    policy_config: &analyzer::AnalysisConfig,
    catalog_index: Option<&crate::catalog::CatalogIndex>,
    catalog_path: Option<&str>,
    source_file: Option<&str>,
    model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    mut carried: Option<&mut CarriedRelations>,
    reasoning: &dyn facts::reasoning::Reasoning,
    keep: bool,
    read_last: Option<&mut ReadsLast<'_>>,
) -> Result<(analyzer::AnalysisReport, Option<KeptAnalysis>, QuotedText), analyzer::RiskError> {
    // Everything below folds names as the script's dialect does.
    let _dialect = adopt_dialect(policy_config.dialect.as_deref(), reasoning);
    let src = render.sql.as_str();

    let parse_dialect = policy_config
        .dialect
        .clone()
        .unwrap_or_else(dialect::snowflake);
    // Fold USE ROLE transitions into the script-level session context,
    // overlaid onto each statement's facts before rule evaluation. The
    // session starts in the database and schema the run is given.
    let script_fold = match read {
        Some((fold, _)) => fold.clone(),
        None => script_context_fold_reading(script, src, parse_dialect.as_ref(), reasoning),
    }
    .starting_under(&ir::SessionContext {
        db: policy_config.session_db.clone(),
        schema: policy_config.session_schema.clone(),
        search_path: Vec::new(),
    });

    let functions = script_functions(
        &script_fold,
        parse_dialect.as_ref(),
        &policy_config.function_catalogs,
    );
    // The relations the script's statements make, which the catalog is
    // asked beside, and the SQL text it runs, read with them where it was
    // not read with the text that runs the script.
    let (relations, runs_read) = script_relations(
        script,
        src,
        &render.placeholder_spans,
        &script_fold,
        &functions,
        parse_dialect.as_ref(),
        catalog_index,
        reasoning,
        model_catalog,
        carried.as_deref_mut().map(|carried| &mut carried.relations),
        &render.session_sql,
        match read {
            Some((_, bodies)) => RunTexts::Recorded(bodies),
            None => RunTexts::Read {
                dialect: &parse_dialect,
                analysed: reasoning.provides_analysis(),
            },
        },
    );
    // The secrets a report masks: the credential values the script and the
    // SQL text it runs write.
    let read_here;
    let dynamic_bodies = match read {
        Some((_, bodies)) => bodies,
        None => {
            read_here = runs_read.unwrap_or_else(|| DynamicBodies::lending(&parse_dialect));
            &read_here
        }
    };
    let body_flat = flat_stmts_for_rules(script);
    let unread: Vec<lexer::token::Span> = body_flat
        .iter()
        .flat_map(|stmt| unparsed_spans(stmt))
        .collect();
    // What every report surface prints of the text's string literals: a
    // literal is printed only where a walk shows it safe, each statement's
    // walk showing its own as the statement is read.
    let reported = std::rc::Rc::new(reported_literals(
        Some(script),
        src,
        parse_dialect.as_ref(),
        read.is_some(),
        Some(dynamic_bodies),
    ));

    // Build line index ONCE for O(log n) lookups (replaces thousands of O(n) scans)
    let line_index = analyzer::LineIndex::new(src);

    let mut report = analyzer::AnalysisReport::new();
    report.assumed_role = script_fold.last_role().map(|r| r.raw.clone());

    // SourceMap available for template line mapping in custom-rules evaluator

    // `rules::evaluate_rules` is the authoritative rule-evaluation
    // seam. Resolve the corpus once: caller-supplied custom rules take
    // precedence (the CLI loader pre-merges them with built-ins per
    // `--no-builtin` and override-by-id semantics); otherwise fall
    // back to the unmodified built-in corpus.
    //
    // Every family's facts projection rides the same parse, and each
    // statement's are one record ([`evaluate_statements`]).
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
    // A routine's, trigger's, event's, task's or DO block's body.
    let body_regions: Vec<lexer::token::Span> = body_flat
        .iter()
        .flat_map(|s| s.bodies())
        .filter(|body| is_routine_body(body.role))
        .flat_map(|body| body.stmts.iter().map(ast::AstStmt::span))
        .collect();

    // IR-native ledger, folded one statement at a time from the same
    // fact stream the rule evaluators read (via `evaluate_facts_into`'s
    // sink slot). No whole-script `Vec<StatementFacts>` accumulator is
    // kept — its retention would dominate peak memory on
    // statement-heavy scripts.
    let mut metrics = analyzer::MetricsCollector::new();
    let mut facts_sink =
        StatementFactsSink::new(&mut metrics, &body_regions, policy_config.trace_mode);
    if keep {
        facts_sink = facts_sink.keeping_facts();
    }
    let mut explanations_buf: Vec<analyzer::StatementExplanation> = Vec::new();

    let mut rule_findings: Vec<rules::Finding> = Vec::new();
    let read_last = read_last
        .zip(script.stmts.last())
        .map(|(read, stmt)| ReadLast {
            stmt,
            read: std::cell::Cell::new(Some(read)),
        });
    // Script-wide reasoning state: one reading of the script, shared by
    // every rule family and by the analysis of the SQL text it runs.
    let mut script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
        script,
        source: src,
        dialect_name: parse_dialect.name(),
        fold: &script_fold,
        catalog: catalog_index,
        model_catalog,
        bodies: dynamic_bodies,
        functions: &functions,
        earlier: relations.relations.earlier(),
        temporary_drops: relations.relations.temporary_drops(),
    });
    if !corpus.is_empty() {
        rule_findings = evaluate_script_families(
            ScriptRead {
                script,
                render,
                fold: &script_fold,
                dialect: parse_dialect.as_ref(),
                functions: &functions,
                relations: &relations,
                catalog: catalog_index,
                model_catalog,
                last: read_last
                    .as_ref()
                    .map(|read| read as &dyn ReadsLastStatement),
                shown_tags: &policy_config.masking.shown_column_tags,
            },
            corpus,
            reasoning,
            script_reasoning.as_mut(),
            &mut facts_sink,
            if policy_config.trace_mode {
                Some(&mut explanations_buf)
            } else {
                None
            },
            &reported,
        );
        if policy_config.trace_mode {
            report.statement_explanations.extend(explanations_buf);
        }
    }
    if let Some(carried) = carried {
        *carried = CarriedRelations {
            relations: relations.relations.left(source_file),
        };
    }
    // Redacted view of the source for OUTPUT surfaces only (finding previews /
    // evidence / SARIF). Analysis runs on the original `src` so value-pattern
    // detectors (e.g. hardcoded-AWS-key rules) still see the real credential;
    // only the quoted-back preview is masked. Offset-preserving, so the finding
    // source spans index it identically.
    let redacted_src = reported.quote(src);
    let masked_runs = reported.masked_runs();
    // The comments a preview leaves out: the script's, and those of the SQL
    // text it runs.
    let comments = quoted_comments(&script.comment_spans, &dynamic_bodies.comment_spans);
    let quoted = QuotedSource {
        text: &redacted_src,
        comments: &comments,
        masked: &masked_runs,
    };
    let placing = Placing {
        text: src,
        lines: &line_index,
        source_map: render.source_map.as_ref(),
        source_file,
    };
    let to_report =
        |finding| rule_finding_to_report_finding(finding, placing, &script_fold, quoted);
    // With `keep`, each statement's facts, and each rule finding raised on
    // its statement.
    let (statement_facts, raised) = facts_sink.take_kept().unzip();
    let mut kept = raised.map(|raised| KeptFindings {
        occurrences: raised
            .into_iter()
            .map(|(statement, finding)| (vec![statement], to_report(finding)))
            .collect(),
        per_statement_rules: std::collections::HashSet::new(),
    });
    for finding in rule_findings {
        report.add_finding(to_report(finding));
    }

    // End the sink's `&mut` ledger borrow. `retained_facts` is
    // `Some(_)` only in trace mode; the hot path retains nothing. The
    // trace's facts copies and rule explanations were masked as each
    // statement was read.
    let (procedure_bodies_analyzed, retained_facts, lost_analysis) = facts_sink.finish();

    // Coverage tally — the single source of truth for the statement-count
    // summary fields. Counts every statement node at every depth (top-level
    // plus all proc/func/block/control-flow bodies) from the same flatten
    // already built above for `body_regions`, so it is consistent across
    // layouts (a DML buried in IF/WHILE counts the same as a top-level one).
    //
    // Bucketing is by AST shape, mode-independent:
    //   - `OpaqueContent` / `Error` (genuine parse coverage loss) -> skipped
    //   - a compound statement's header that did not parse -> one more skipped
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
    let in_body = |sp: lexer::token::Span| {
        body_regions
            .iter()
            .any(|r| sp.start >= r.start && sp.end <= r.end)
    };
    for s in &body_flat {
        // Single source of truth: the exhaustive `coverage_class` classifier.
        // `Excluded` nodes (BEGIN/END grouping, GO separators) are structural
        // and not counted; their inner statements are counted on their own.
        // A statement read only up to a token the parser does not bind is
        // partial; its unread tail is the skipped node after it.
        // A block's statement kept as written is not parsed either.
        let class = match kept_as_written(s) {
            true => CoverageClass::Skipped,
            false => coverage_class(s),
        };
        let class = if class == CoverageClass::Analyzed && script_fold.is_cut(s.span()) {
            CoverageClass::Partial
        } else {
            class
        };
        if class == CoverageClass::Excluded {
            continue;
        }
        if in_body(s.span()) {
            cov_in_bodies += 1;
        }
        // A header of the statement that did not parse is a piece skipped.
        if class != CoverageClass::Skipped {
            for header in unparsed_spans(s) {
                cov_skipped += 1;
                if in_body(header) {
                    cov_in_bodies += 1;
                }
            }
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
    // A statement of a string the script runs as SQL that does not parse.
    cov_skipped += dynamic_bodies.unparsed.len();

    // In trace mode, populate `report.statement_traces` with the
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
            let statement_preview = quoted.prefix(span, 80);
            report.statement_traces.push(analyzer::StatementTrace {
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

    // Deduplicate policy findings by topic_key (custom rules take precedence over built-in)
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
            let statement_prefix = quoted.prefix(stmt_span, 60);
            push_analysis_limitation(
                line_number,
                statement_prefix,
                "analysis_gave_up:statement:parsed:reason=not_analyzable".to_string(),
            );
        }

        // Skipped-statement detection derives from the same `unparsed_spans`
        // that produces the summary's `statements_skipped`, over the
        // same flattened statement set (`body_flat`) — so `skipped_details` and
        // `summary.statements_skipped` agree by construction. A piece is
        // "skipped" only when it is genuine parse-coverage loss
        // (`CoverageClass::Skipped` = OpaqueContent / Error / ClauseFragment,
        // or a compound statement's header that did not parse).
        // Recognized statements with no applicable rule (transaction control,
        // DESCRIBE, SET, …) lower to a real plan and are analyzed-with-zero-
        // findings, not skipped — they must not surface here or trip strict mode.
        {
            // With each statement a block keeps as written, and the
            // statements that do not parse of the strings the script runs
            // as SQL, each at its place in the string.
            let kept = body_flat
                .iter()
                .filter(|stmt| {
                    kept_as_written(stmt) && coverage_class(stmt) != CoverageClass::Skipped
                })
                .map(|stmt| stmt.span());
            let skipped_spans = unread
                .iter()
                .copied()
                .chain(kept)
                .chain(dynamic_bodies.unparsed.iter().copied());
            let sqlcmd_lines = unread_sqlcmd_lines(&body_flat);
            for stmt_span in skipped_spans {
                // Defensive: skip statements with invalid spans
                if stmt_span.start as usize >= src.len() {
                    continue;
                }

                // O(log n) line lookup via the index built once at function entry
                // (line 698), instead of an O(offset) newline scan per skipped
                // statement — keeps the skip path linear in statement count.
                let line_number = line_index.get_line_number(stmt_span);

                // A sqlcmd command parsed: what it runs is what was not read.
                if let Some((runs, quoted_span)) = sqlcmd_lines.get(&stmt_span.start) {
                    let statement_prefix = quoted.prefix(*quoted_span, 60);
                    push_analysis_limitation(
                        line_number,
                        statement_prefix.clone(),
                        format!(
                            "analysis_gave_up:statement:skipped:reason=sqlcmd_command:runs={}:findings_extracted=false",
                            runs.as_snake_case()
                        ),
                    );
                    report.skipped_details.push(analyzer::SkippedStatement {
                        reason: analyzer::SkipReason::SqlcmdCommand(*runs),
                        statement_prefix,
                        line_number,
                        impact_category: None,
                    });
                    continue;
                }

                let statement_prefix = quoted.prefix(stmt_span, 60);

                let impact_category =
                    analyzer::SkippedStatement::guess_impact_category(&statement_prefix);

                // `CoverageClass::Skipped` is exactly the unparsed-construct
                // bucket (OpaqueContent / Error / ClauseFragment). Findings are
                // not counted per statement: the limitation string says
                // `false` and the record below carries `None`.
                let mut limitation = format!(
                    "analysis_gave_up:statement:skipped:reason=unparsed_construct:impact={}:findings_extracted=false",
                    impact_category
                );
                limitation.retain(|c| c != '\n' && c != '\r');
                push_analysis_limitation(line_number, statement_prefix.clone(), limitation);

                report.skipped_details.push(analyzer::SkippedStatement {
                    reason: analyzer::SkipReason::UnparsedConstruct,
                    statement_prefix,
                    line_number,
                    impact_category: Some(impact_category),
                });
            }
        }
    }

    // The v1 fact-based engine exposes its explanation surface via
    // `Finding.explanation` (populated by `evaluate_rules` when
    // explain-mode is on).
    let trace_mode = policy_config.trace_mode;

    // Set trace_mode flag
    report.trace_mode = Some(trace_mode);

    // Derive all metrics from ledger (never stored, always computed); a
    // table the report masks the text of is named masked.
    let derived = metrics.derive_metrics_masking(&|span| reported.masks_name(span));

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

    // Set role context in summary\n    report.summary.assumed_role = report.assumed_role.clone();\n\n    // Deduplicate identical findings
    // Recurse into static dynamic-SQL literal bodies: parse each and run the
    // full rule corpus on the inner statements, mapping findings back to the
    // literal's position in source. Appended before dedup/sort so inner
    // findings are ordered and de-duplicated alongside the rest.
    // A body's previews are quoted from the body's analysis, which masks
    // every literal of SQL text a script runs ([`reported_literals`]).
    let mut body_outcome = script_reasoning.dynamic_sql_literal_bodies(script, policy_config);
    // A body's finding comes placed at its line and column in the analyzed
    // text; it is placed in the file the user wrote as any other is. With no
    // file it names no location.
    for (_, finding) in &mut body_outcome.findings {
        let analyzer::RuleMatch::Analysis(finding) = finding;
        for evidence in &mut finding.evidence {
            let analyzer::RiskEvidence::RuleMatch {
                line_number: Some(line),
                column_number: Some(column),
                ..
            } = evidence
            else {
                continue;
            };
            let Some(offset) = line_index.offset_at(src, *line, *column) else {
                continue;
            };
            placing.place(evidence, offset);
            if let analyzer::RiskEvidence::RuleMatch { location, .. } = evidence {
                if source_file.is_none() {
                    *location = None;
                }
            }
        }
    }
    if let Some(kept) = kept.as_mut() {
        // A body's finding is raised on the statement that runs the body and
        // on the innermost statement holding the position it is reported at
        // (the string's, where a statement before assigns it).
        let statements: Vec<lexer::token::Span> = body_flat.iter().map(|s| s.span()).collect();
        for (runs, finding) in &body_outcome.findings {
            let mut raised_on = vec![*runs];
            raised_on.extend(
                reported_position(finding)
                    .and_then(|(line, column)| line_index.offset_at(src, line, column))
                    .and_then(|offset| innermost_holding(&statements, offset))
                    .filter(|holding| holding != runs),
            );
            kept.occurrences.push((raised_on, finding.clone()));
        }
    }
    report.findings.extend(
        body_outcome
            .findings
            .into_iter()
            .map(|(_, finding)| finding),
    );
    // Merge the tables read/written inside executed literal bodies into the
    // summary (set semantics dedupe against the top-level reads), then
    // recompute the counts — so `Tables Read` reflects SQL run via dynamic SQL.
    if !body_outcome.tables_read.is_empty() || !body_outcome.tables_written.is_empty() {
        report
            .summary
            .tables_read_names
            .extend(body_outcome.tables_read);
        report
            .summary
            .tables_written_names
            .extend(body_outcome.tables_written);
        report.summary.tables_read = report.summary.tables_read_names.len();
        report.summary.tables_written = report.summary.tables_written_names.len();
    }

    let per_statement_rules: std::collections::HashSet<String> = corpus
        .iter()
        .filter(|r| r.per_statement)
        .map(|r| r.id.clone())
        .collect();
    fold_findings(&mut report, &per_statement_rules);
    if let Some(kept) = kept.as_mut() {
        kept.per_statement_rules = per_statement_rules;
    }

    // Context-level entries are listed apart from findings; recount.
    report.separate_context();

    // Populate catalog_info for trust assessment: the tables each statement
    // reads, writes or targets by DDL, in the order the script names them;
    // a table a statement creates comes after what that statement names.
    let mut catalog_subjects: Vec<&analyzer::CatalogSubject> = metrics
        .entries
        .values()
        .flat_map(|e| e.catalog_subjects.iter())
        .collect();
    catalog_subjects.sort_by_key(|subject| subject.script_order());
    report.catalog_info = build_catalog_info(
        catalog_index,
        catalog_path,
        &catalog_subjects,
        &script_fold,
        &relations.relations,
    );

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

    // Each trace explanation's preview, quoted as every preview is.
    for explanation in &mut report.statement_explanations {
        if let Some(sp) = explanation.source_span {
            explanation.statement_preview = quoted.statement_preview(sp);
        }
    }

    Ok((
        report,
        kept.map(|kept| (statement_facts.unwrap_or_default(), kept)),
        QuotedText {
            masked_runs,
            comments,
            shown: reported.shown_literals(),
        },
    ))
}

/// What a report masks of the analysed text and the comments no preview
/// quotes.
struct QuotedText {
    /// What the report masks, each run printed as one mask.
    masked_runs: Vec<lexer::token::Span>,
    comments: Vec<lexer::token::Span>,
    /// The span of each string literal printed.
    shown: Vec<lexer::token::Span>,
}

/// The comments a report's previews leave out, in source order, none
/// overlapping another: `script`'s, which the parser read, and `run`'s, those
/// of the SQL text the script runs.
fn quoted_comments(
    script: &[lexer::token::Span],
    run: &[lexer::token::Span],
) -> Vec<lexer::token::Span> {
    let mut all: Vec<lexer::token::Span> = script.iter().chain(run).copied().collect();
    all.sort_unstable_by_key(|span| (span.start, span.end));
    let mut out: Vec<lexer::token::Span> = Vec::with_capacity(all.len());
    for span in all {
        match out.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            Some(_) | None => out.push(span),
        }
    }
    out
}

/// The rendered line and column a finding is reported at: its first
/// evidence that has both.
fn reported_position(finding: &analyzer::RuleMatch) -> Option<(usize, usize)> {
    let analyzer::RuleMatch::Analysis(finding) = finding;
    finding.evidence.iter().find_map(|evidence| match evidence {
        analyzer::RiskEvidence::RuleMatch {
            line_number: Some(line),
            column_number: Some(column),
            ..
        } => Some((*line, *column)),
        analyzer::RiskEvidence::RuleMatch { .. }
        | analyzer::RiskEvidence::TableReference { .. }
        | analyzer::RiskEvidence::PredicateInfo { .. } => None,
    })
}

/// The span of the innermost of `statements` holding byte `offset`.
fn innermost_holding(
    statements: &[lexer::token::Span],
    offset: usize,
) -> Option<lexer::token::Span> {
    statements
        .iter()
        .filter(|span| (span.start as usize) <= offset && offset < span.end as usize)
        .min_by_key(|span| span.end - span.start)
        .copied()
}

/// One statement's facts as analysis derives them.
#[derive(Debug, Clone)]
pub struct StatementFactsAt {
    /// The span of the statement the facts were derived from.
    pub statement: lexer::token::Span,
    /// The facts, with the script context in force at the statement, as
    /// its rules were evaluated on them.
    pub facts: facts::StatementFacts,
    /// The database a bare name resolves under at the statement.
    pub database: Option<facts::IdentName>,
    /// The schema a bare name resolves under at the statement.
    pub schema: Option<facts::IdentName>,
}

/// An analysis of one script, with what comparing it with another reads:
/// the text analysed, the facts of each statement, and its findings
/// occurrence by occurrence, each with the statement it was raised on.
#[derive(Debug, Clone)]
pub struct ScriptAnalysis {
    /// The report, as the same analysis without a comparison gives it.
    pub report: analyzer::AnalysisReport,
    /// The text analysed, after the substitution pre-passes: every span of
    /// `statement_facts` indexes it.
    pub render: template::RenderArtifacts,
    /// Each statement's facts, in the order its rules were evaluated on
    /// them; none where the corpus holds no rule. A statement read by more
    /// than one fact family has the facts of each.
    pub statement_facts: Vec<StatementFactsAt>,
    /// `render`'s text as a report prints it whole: each run of what the
    /// report masks printed as one mask whatever its length, every line
    /// kept. Its offsets are not `render`'s: quote a span of `render`'s
    /// text through [`Self::finding_preview`].
    pub masked_sql: String,
    /// The span in `render`'s text of each string literal a report prints:
    /// every other one is masked.
    pub shown_literals: Vec<lexer::token::Span>,
    /// The comments the lexer read in `render`'s text and in the SQL text
    /// it runs, which no preview quotes.
    comment_spans: Vec<lexer::token::Span>,
    /// What the report masks of `render`'s text, each run printed as one
    /// mask.
    masked_runs: Vec<lexer::token::Span>,
    kept: KeptFindings,
}

impl ScriptAnalysis {
    /// Place `evidence` at byte `offset` of `render`'s text as the report
    /// places a finding there: its line and column, the template line and
    /// the macro that wrote it where a template was rendered, and its place
    /// in `source_file`, the file the user wrote.
    pub fn place_evidence(
        &self,
        evidence: &mut analyzer::RiskEvidence,
        offset: usize,
        source_file: &str,
    ) {
        let lines = analyzer::LineIndex::new(&self.render.sql);
        Placing {
            text: &self.render.sql,
            lines: &lines,
            source_map: self.render.source_map.as_ref(),
            source_file: Some(source_file),
        }
        .place(evidence, offset);
    }

    /// The line of the file the user wrote (the template, else the text)
    /// that byte `offset` of `render`'s text is placed at.
    pub fn written_line(&self, offset: usize) -> usize {
        let lines = analyzer::LineIndex::new(&self.render.sql);
        Placing {
            text: &self.render.sql,
            lines: &lines,
            source_map: self.render.source_map.as_ref(),
            source_file: None,
        }
        .written(offset)
        .1
        .line
    }

    /// A finding's preview of the statement at `span` of `render`'s text,
    /// quoted as the report quotes it: masked, its comments left out.
    pub fn finding_preview(&self, span: lexer::token::Span) -> Option<String> {
        QuotedSource {
            text: &self.render.sql,
            comments: &self.comment_spans,
            masked: &self.masked_runs,
        }
        .finding_preview(span)
    }
}

/// The findings of an analysis before they are folded into its report, each
/// with the spans of the statements it was raised on, and the rules reported
/// once per occurrence.
#[derive(Debug, Clone, Default)]
struct KeptFindings {
    occurrences: Vec<(Vec<lexer::token::Span>, analyzer::RuleMatch)>,
    per_statement_rules: std::collections::HashSet<String>,
}

/// What an analysis kept for a comparison: each statement's facts and the
/// findings before they are folded into the report.
type KeptAnalysis = (Vec<StatementFactsAt>, KeptFindings);

/// What the facts sink keeps for a comparison: each statement's facts as
/// recorded, and each rule finding with the statement it was raised on.
type KeptStatements = (
    Vec<StatementFactsAt>,
    Vec<(lexer::token::Span, rules::Finding)>,
);

impl ScriptAnalysis {
    /// The report's findings and context raised on the statements at
    /// `statements`, folded as the report folds them. A rule finding is
    /// raised on the statement whose facts raised it; a finding of SQL a
    /// statement runs from a string, on that statement and on the innermost
    /// statement holding the string.
    pub fn findings_of(
        &self,
        statements: &std::collections::HashSet<lexer::token::Span>,
    ) -> Vec<analyzer::RuleMatch> {
        let mut report = analyzer::AnalysisReport::new();
        report.findings = self
            .kept
            .occurrences
            .iter()
            .filter(|(raised_on, _)| raised_on.iter().any(|span| statements.contains(span)))
            .map(|(_, finding)| finding.clone())
            .collect();
        fold_findings(&mut report, &self.kept.per_statement_rules);
        report.findings
    }
}

/// Fold per-occurrence findings as a report lists them: one finding per
/// rule, each occurrence of a per-statement rule on its own, in report
/// order.
fn fold_findings(
    report: &mut analyzer::AnalysisReport,
    per_statement_rules: &std::collections::HashSet<String>,
) {
    report.deduplicate_with_per_statement_rules(per_statement_rules);
    report.findings.sort_by(finding_order);
}

/// The function catalogs of a script read under `fold`, in `dialect`,
/// over the dialect's catalog `catalogs` holds.
fn script_functions(
    fold: &ScriptContextFold,
    dialect: &dyn dialect::Dialect,
    catalogs: &ir::DialectCatalogs,
) -> ir::ScriptFunctions {
    ir::ScriptFunctions::from_catalogs(
        catalogs,
        ir::CatalogDialect::from_dialect_name(dialect.name()),
        fold,
    )
}

/// A script as analysis has read it before its statements' facts are
/// derived.
struct ScriptRead<'a> {
    script: &'a ast::AstScript,
    render: &'a template::RenderArtifacts,
    /// Its fold, under the session the run starts in.
    fold: &'a ScriptContextFold,
    /// The dialect it was parsed in.
    dialect: &'a dyn dialect::Dialect,
    functions: &'a ir::ScriptFunctions,
    /// The relations its statements make.
    relations: &'a ReadRelations,
    catalog: Option<&'a crate::catalog::CatalogIndex>,
    model_catalog: Option<&'a ir::model_catalog::ModelCatalog>,
    /// Its last statement and what reads it as the query evaluator lowers
    /// it.
    last: Option<&'a dyn ReadsLastStatement>,
    /// The catalog tags the organization lists as marking a column that
    /// holds no secret.
    shown_tags: &'a [rules::ShownColumnTag],
}

/// Derive the facts of every statement of `read.script` with every family,
/// hand each statement's record to `sink` and evaluate `corpus` on it: the
/// findings ([`evaluate_statements`]). `trace` collects the rule
/// explanations; `reported` is shown each literal a statement's walk
/// shows safe.
fn evaluate_script_families(
    read: ScriptRead<'_>,
    corpus: &[rules::Rule],
    reasoning: &dyn facts::reasoning::Reasoning,
    script_reasoning: &mut dyn facts::reasoning::ScriptReasoning,
    sink: &mut StatementFactsSink<'_>,
    trace: Option<&mut Vec<analyzer::StatementExplanation>>,
    reported: &std::rc::Rc<facts::secrets::ReportedLiterals>,
) -> Vec<rules::Finding> {
    let ScriptRead {
        script,
        render,
        fold,
        dialect,
        functions,
        relations,
        catalog,
        model_catalog,
        last,
        shown_tags,
    } = read;
    let src = render.sql.as_str();
    let query = QueryReading {
        sql: src,
        placeholders: &render.placeholder_spans,
        fold,
        functions,
        meaning: dialect.syntax_meaning(),
        catalog,
        relations,
        model_catalog,
        reasoning,
        output_columns: sink.compares(),
        last,
        shown_tags,
    };
    let ddl = DdlReading::new(
        script,
        src,
        &render.placeholder_spans,
        fold,
        functions,
        reasoning,
        &query,
        script_reasoning,
    );
    let mut tree = Vec::new();
    for stmt in &script.stmts {
        flatten_statement_tree(stmt, None, &mut tree);
    }
    let around = ctes_around(&tree);
    let flat: Vec<&ast::AstStmt> = tree.iter().map(|&(stmt, _)| stmt).collect();
    evaluate_statements(
        &flat,
        fold,
        reported,
        corpus,
        Some(sink),
        trace,
        |position, stmt, mut sink, readings| {
            readings
                .families
                .extend(privilege_facts(stmt, src, catalog, reasoning));
            ddl_facts(
                stmt,
                &ddl,
                &*script_reasoning,
                sink.as_deref_mut(),
                &mut readings.families,
            );
            // A write a CTE holds reads the CTEs around it.
            let in_scope = around
                .get(position)
                .and_then(Option::as_ref)
                .and_then(|around| with_ctes_around(stmt, around));
            if in_scope.is_some() {
                // What reading the relations lowered is the write alone.
                drop(query.relations.take_lowered(stmt.span()));
            }
            readings.query = query_facts(
                position,
                in_scope.as_ref().unwrap_or(stmt),
                &query,
                &mut *script_reasoning,
                sink,
                Some((dialect, &mut readings.shown)),
            );
            readings.families.extend(policy_attachment_facts(stmt, src));
        },
    )
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

/// The privilege facts of `stmt`: a GRANT, REVOKE, DENY or ALTER
/// AUTHORIZATION, read at any depth. With a catalog, the reasoning
/// provider answers what the grant reaches.
fn privilege_facts(
    stmt: &ast::AstStmt,
    sql: &str,
    catalog: Option<&crate::catalog::CatalogIndex>,
    reasoning: &dyn facts::reasoning::Reasoning,
) -> Option<facts::StatementFacts> {
    let plan = match stmt {
        ast::AstStmt::Grant(g) => ir::lower_grant_to_privilege_plan(g),
        ast::AstStmt::Revoke(r) => ir::lower_revoke_to_privilege_plan(r),
        ast::AstStmt::Deny(d) => ir::lower_deny_to_privilege_plan(d),
        ast::AstStmt::AlterAuthorization(a) => ir::lower_alter_authorization_to_privilege_plan(a),
        _ => return None,
    };
    Some(match catalog {
        Some(_) => {
            facts::extract::derive_facts_from_privilege_plan_with_reasoning(&plan, sql, reasoning)
        }
        None => facts::extract::derive_facts_from_privilege_plan(&plan, sql),
    })
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
    /// Each statement's facts as recorded, unmasked, and each rule finding
    /// with the statement it was raised on, in the order raised: kept only
    /// for a comparison.
    kept: Option<KeptStatements>,
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
            kept: None,
            lost_analysis: std::collections::BTreeSet::new(),
        }
    }

    /// The sink, keeping each statement's facts and the statement of each
    /// rule finding.
    fn keeping_facts(mut self) -> Self {
        self.kept = Some((Vec::new(), Vec::new()));
        self
    }

    /// Whether the sink keeps facts for a comparison.
    fn compares(&self) -> bool {
        self.kept.is_some()
    }

    /// Record `findings`, raised on the statement at `statement`.
    fn record_findings(&mut self, statement: lexer::token::Span, findings: &[rules::Finding]) {
        if let Some((_, raised)) = &mut self.kept {
            raised.extend(findings.iter().map(|finding| (statement, finding.clone())));
        }
    }

    /// Take what the sink kept: each statement's facts in the order
    /// recorded, and each rule finding with its statement in the order
    /// raised.
    fn take_kept(&mut self) -> Option<KeptStatements> {
        self.kept.take()
    }

    /// Record that the query lowering for `span` produced an opaque
    /// terminal whose reason means findings for it were lost.
    fn record_lost_analysis(&mut self, span: lexer::token::Span) {
        self.lost_analysis.insert(span.start);
    }

    /// Record that the DDL target of the statement at `span` is a
    /// session's own table or a stage, never asked of a catalog.
    fn record_uncatalogued_ddl_target(&mut self, span: lexer::token::Span) {
        self.metrics.record_uncatalogued_ddl_target(span.start);
    }

    /// Record the facts of the statement at `statement`: fold the ledger
    /// entry and the procedure/function body tally, and keep them when
    /// the sink keeps facts. In retain (trace) mode also push the facts
    /// as a report prints them, each string a literal fills masked where
    /// `reported` does not show it
    /// ([`facts::secrets::ReportedLiterals::printed`]); facts that cannot be
    /// masked are left out with a warning. The ledger reads only
    /// structural fields (kind / spans / table refs), never credential
    /// values, so it folds from the unmasked carrier.
    fn record(
        &mut self,
        statement: lexer::token::Span,
        facts: &facts::StatementFacts,
        fold: &ScriptContextFold,
        reported: &std::rc::Rc<facts::secrets::ReportedLiterals>,
    ) {
        self.metrics.populate_from_fact(facts, self.body_regions);
        if let Some((kept, _)) = &mut self.kept {
            let (database, schema) = fold.namespace_at(statement.start);
            kept.push(StatementFactsAt {
                statement,
                facts: facts.clone(),
                database: database.cloned(),
                schema: schema.cloned(),
            });
        }
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
        if let Some(out) = &mut self.retained {
            match reported.printed(statement, facts) {
                Ok(printed) => out.push(printed),
                Err(e) => eprintln!(
                    "WARNING: a statement's facts are left out of the trace: a secret they quote could not be masked ({e})"
                ),
            }
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

/// The facts the families of a run derive for one statement.
#[derive(Default)]
struct StatementReadings {
    /// What the privilege, DDL and policy-attachment families derive, in
    /// that order.
    families: Vec<facts::StatementFacts>,
    /// What the query family derives.
    query: Option<facts::StatementFacts>,
    /// The string literals the statement's walk shows safe, and the
    /// literals it finds to be a secret's value.
    shown: facts::secrets::ShownLiterals,
}

impl StatementReadings {
    /// The statement's one fact record: the first family record, holding
    /// every carrier the others and the query record derive
    /// ([`facts::StatementFacts::absorb`]), so its kind is the kind that
    /// family reads; the query record alone where no other family reads
    /// the statement; `None` where none does.
    fn into_record(self) -> Option<facts::StatementFacts> {
        let StatementReadings {
            families,
            query,
            shown: _,
        } = self;
        let mut families = families.into_iter();
        let Some(mut record) = families.next() else {
            return query;
        };
        for facts in families.chain(query) {
            record.absorb(facts);
        }
        Some(record)
    }
}

/// Evaluate `corpus` on the facts of each of `flat`, a script's flattened
/// statements: the findings, statement by statement.
///
/// Each statement is one fact record. `read` hands what every family it
/// reads derives for the statement at `position` to a
/// [`StatementReadings`], which makes them one record; the sink, the
/// trace and the rules see that record once. No family evaluates or
/// records facts of its own. `reported` is shown the literals each
/// statement's walk shows safe before its record is printed.
fn evaluate_statements<'s, 'k>(
    flat: &[&'s ast::AstStmt],
    fold: &ScriptContextFold,
    reported: &std::rc::Rc<facts::secrets::ReportedLiterals>,
    corpus: &[rules::Rule],
    mut sink: Option<&mut StatementFactsSink<'k>>,
    mut trace: Option<&mut Vec<analyzer::StatementExplanation>>,
    mut read: impl FnMut(
        usize,
        &'s ast::AstStmt,
        Option<&mut StatementFactsSink<'k>>,
        &mut StatementReadings,
    ),
) -> Vec<rules::Finding> {
    let mut findings = Vec::new();
    if corpus.is_empty() {
        return findings;
    }
    // The statements holding the current one, each with the range of
    // `findings` it raised. `flat` lists a holder before what it holds, and
    // a held statement's span lies inside its holder's.
    let mut holders: Vec<(lexer::token::Span, std::ops::Range<usize>)> = Vec::new();
    for (position, &stmt) in flat.iter().enumerate() {
        let span = stmt.span();
        while holders
            .last()
            .is_some_and(|(holder, _)| !(holder.start <= span.start && span.end <= holder.end))
        {
            holders.pop();
        }
        let mut readings = StatementReadings::default();
        read(position, stmt, sink.as_deref_mut(), &mut readings);
        reported.show(&readings.shown.spans);
        reported.veto(&readings.shown.vetoed);
        let raised_from = findings.len();
        if let Some(facts) = readings.into_record() {
            evaluate_facts_into(
                fold,
                reported,
                &facts,
                corpus,
                stmt.span(),
                &mut findings,
                sink.as_deref_mut(),
                trace.as_deref_mut(),
            );
        }
        // A holder whose query runs what it holds (a data-modifying CTE)
        // has already judged it: the same finding at the same place is
        // reported once.
        let mut raised = findings.split_off(raised_from);
        raised.retain(|finding| {
            finding.source_span.is_none()
                || !holders.iter().any(|(_, range)| {
                    findings[range.clone()].iter().any(|held| {
                        held.rule_id == finding.rule_id
                            && held.source_span == finding.source_span
                            && held.message == finding.message
                    })
                })
        });
        findings.extend(raised);
        holders.push((span, raised_from..findings.len()));
    }
    findings
}

/// Single seam for v1 rule evaluation against a `StatementFacts`
/// snapshot, one statement's record ([`evaluate_statements`]).
///
/// Hot path (`trace_out: None`): runs `evaluate_rules` and appends
/// emitted findings into `findings_out`.
///
/// Explain path (`trace_out: Some(_)`): runs `evaluate_rules_with_explain`,
/// extracts the emitted `Finding`s from the per-rule results so the
/// hot-path return value (the finding stream) stays identical, and
/// pushes one `StatementExplanation` per statement onto `trace_out`.
///
/// `stmt_span` is the span of the statement (or sub-statement, e.g. a
/// nested `DECLARE HANDLER`) the facts derive from. Used purely for
/// the explain surface — passed through to `build_statement_explanation`.
/// A message's placeholder values and an explanation's fact values are
/// printed as `reported` prints the statement's facts.
fn evaluate_facts_into(
    fold: &ScriptContextFold,
    reported: &std::rc::Rc<facts::secrets::ReportedLiterals>,
    facts: &facts::StatementFacts,
    rules_corpus: &[rules::Rule],
    stmt_span: lexer::token::Span,
    findings_out: &mut Vec<rules::Finding>,
    mut facts_out: Option<&mut StatementFactsSink<'_>>,
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
    // feeds report output (`statement_traces` / fact explanations),
    // which must never reproduce a secret value — evaluation below
    // still reads the unmasked `facts`. The rule explanations, whose
    // predicate paths quote compared values, print each value as that
    // carrier does.
    if let Some(sink) = facts_out.as_deref_mut() {
        sink.record(stmt_span, facts, fold, reported);
    }
    let raised_before = findings_out.len();
    match trace_out {
        Some(trace) => {
            let evaluated = rules::engine::evaluate_rules_with_explain_masking(
                facts,
                rules_corpus,
                Some(facts::secrets::PrintedAt {
                    literals: reported,
                    statement: stmt_span,
                }),
            );
            for e in &evaluated {
                findings_out.extend(e.findings.iter().cloned());
            }
            trace.push(build_statement_explanation(stmt_span, evaluated));
        }
        None => {
            findings_out.extend(rules::engine::evaluate_rules_masking(
                facts,
                rules_corpus,
                Some(facts::secrets::PrintedAt {
                    literals: reported,
                    statement: stmt_span,
                }),
            ));
        }
    }
    if let Some(sink) = facts_out {
        sink.record_findings(stmt_span, &findings_out[raised_before..]);
    }
}

/// Build a v1-shape `StatementExplanation` from the engine's per-rule
/// explain results. Splits matched-vs-rejected and attaches each
/// rejected rule's `RuleExplanation` (rendered path strings). Its preview
/// is quoted once the report's masked text is known
/// ([`QuotedSource::statement_preview`]).
fn build_statement_explanation(
    stmt_span: lexer::token::Span,
    evaluated: Vec<rules::engine::EvaluatedRule>,
) -> analyzer::StatementExplanation {
    let statement_preview = String::new();
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

/// Whether a script of `scripts`, each SQL text read in `dialect`, calls a
/// routine none of them defines whose definition decides what is run of
/// its arguments: a call statement into a routine that is no routine the
/// dialect defines ([`dialect::Dialect::system_routine`]), or, where a
/// function a user defines can run SQL text, a call of a function the
/// dialect does not define. A script that does not parse may call one.
pub fn calls_routine_defined_elsewhere(scripts: &[&str], dialect: &dialect::DialectRef) -> bool {
    let _scope = ir::set_normalization_dialect(dialect.name());
    let dialect = dialect.as_ref();
    let mut parsed = Vec::with_capacity(scripts.len());
    for sql in scripts {
        match parse_sql_with_dialect(sql, dialect) {
            Ok(script) => parsed.push((script, *sql)),
            Err(_) => return true,
        }
    }
    let mut defined: Vec<Vec<IdentKey>> = Vec::new();
    let mut calls: Vec<(bool, bool, Vec<IdentKey>)> = Vec::new();
    for (script, sql) in &parsed {
        for stmt in flat_stmts_for_rules(script) {
            if let Some((name, _)) = ir::dynamic_sql::created_routine(stmt) {
                defined.push(routine_name(name, sql));
            }
            for call in ir::dynamic_sql::routine_calls(stmt, sql) {
                calls.push((
                    call.node == stmt.node_id(),
                    call.table,
                    routine_name(call.name, sql),
                ));
            }
        }
    }
    calls.iter().any(|(statement, table, name)| {
        let held = defined
            .iter()
            .any(|routine| ir::lower::routine_names_agree(routine, name));
        let parts: Vec<&str> = name.iter().map(IdentKey::as_str).collect();
        let decided = dialect.system_routine(&parts).is_some()
            || (!statement
                && (!may_run_sql_text(dialect, *table) || names_builtin_function(name, dialect)));
        !name.is_empty() && !held && !decided
    })
}

/// `sql`, read under `dialect`, as every source-display surface quotes it:
/// what a recognition analysis of `sql` in `dialect` masks in its report,
/// overwritten offset-preservingly. Where the text does not parse or its
/// analysis fails, every string literal of it is masked, and every secret
/// the parse records.
pub fn redact_secrets_for_display(sql: &str, dialect: &dialect::DialectRef) -> String {
    let every_literal = |script: Option<&ast::AstScript>| {
        reported_literals(script, sql, dialect.as_ref(), true, None).quote_fixed(sql)
    };
    let Ok(script) = parse_sql_with_dialect(sql, dialect.as_ref()) else {
        return every_literal(None);
    };
    let config = analyzer::AnalysisConfig {
        dialect: Some(dialect.clone()),
        ..analyzer::AnalysisConfig::default()
    };
    analyze_for_comparison(
        &template::RenderArtifacts::raw(sql.to_string()),
        &script,
        &config,
        None,
        None,
        None,
        None,
        &facts::reasoning::RecognitionOnly,
    )
    .map_or_else(
        |_| every_literal(Some(&script)),
        |analysis| analysis.masked_sql,
    )
}

/// What a report prints of the string literals of `src`, read under
/// `dialect` ([`facts::secrets::ReportedLiterals`]): each string literal its
/// lexer reads, and each dollar-quoted string whole but a routine body
/// `script`, the parse of `src`, read as SQL statements
/// ([`ast::AstScript::read_bodies`]); those in a grammar slot the dialect
/// lists as shown ([`dialect::Dialect::shown_slots`]) shown, and every span
/// the parser records as a secret and every value a template block holds
/// masked whole. Where `src` is SQL text a script runs (`run_text`), or no
/// parse of it is given, no literal is shown. Each literal whose SQL text
/// `runs` read is quoted as that text's own statements are, its string
/// literals and secrets masked ([`DynamicBodies::run_texts`]).
fn reported_literals(
    script: Option<&ast::AstScript>,
    src: &str,
    dialect: &dyn dialect::Dialect,
    run_text: bool,
    runs: Option<&DynamicBodies>,
) -> facts::secrets::ReportedLiterals {
    use lexer::{LiteralKind, TokenKind};
    let lexed = lexer::tokenize_with_dialect(src, dialect);
    let tokens = lexed.tokens;
    let statements: Vec<&ast::AstStmt> = script.map(flat_stmts_for_rules).unwrap_or_default();
    let blocks: &[ast::TemplateBlock] = script.map_or(&[], |script| &script.template_blocks);
    let read_bodies: &[lexer::token::Span] = script.map_or(&[], |script| &script.read_bodies);
    let in_block = |span: lexer::token::Span| {
        blocks
            .iter()
            .any(|block| block.body.start <= span.start && span.end <= block.body.end)
    };
    // The routine bodies read as SQL, by their text, and every other
    // dollar-quoted string outside one of those strings, in source order.
    let mut code: Vec<lexer::token::Span> = Vec::new();
    let mut strings: Vec<lexer::DollarQuote> = Vec::new();
    for quote in &lexed.dollar_quotes {
        if strings
            .last()
            .is_some_and(|outer| quote.span.start < outer.span.end)
        {
            continue;
        }
        if read_bodies
            .binary_search_by_key(&quote.span.start, |body| body.start)
            .is_ok()
        {
            code.push(quote.content);
        } else {
            strings.push(*quote);
        }
    }
    // Whether the text at `span` is one character that opens no string.
    let holds_no_text = |span: lexer::token::Span| {
        let mut chars = src
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
            .chars();
        matches!(
            (chars.next(), chars.next()),
            (Some(c), None) if !matches!(c, '\'' | '"' | '`' | '$')
        )
    };
    let mut literals = Vec::new();
    let mut template_depth = 0usize;
    let mut next_string = 0usize;
    for tok in &tokens {
        while strings
            .get(next_string)
            .is_some_and(|string| string.span.end <= tok.span.start)
        {
            next_string += 1;
        }
        // A dollar-quoted string is one literal, whatever its text lexes as.
        if let Some(string) = strings
            .get(next_string)
            .filter(|string| string.span.start <= tok.span.start)
        {
            if literals
                .last()
                .is_none_or(|last: &facts::secrets::TextLiteral| last.span != string.span)
            {
                literals.push(facts::secrets::TextLiteral {
                    span: string.span,
                    content: string.content,
                    template: template_depth > 0 || in_block(string.span),
                    number: false,
                });
            }
            continue;
        }
        match &tok.kind {
            TokenKind::JinjaExprOpen | TokenKind::JinjaStmtOpen => template_depth += 1,
            TokenKind::JinjaExprClose | TokenKind::JinjaStmtClose => {
                template_depth = template_depth.saturating_sub(1)
            }
            // Text the lexer could not read is masked as a literal: a
            // string, a dollar-quoted text or a comment left open. A lone
            // character it reads no token for (`\`, `#`) holds no text.
            TokenKind::Unknown if holds_no_text(tok.span) => {}
            TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
            | TokenKind::Unknown => literals.push(facts::secrets::TextLiteral {
                span: tok.span,
                content: lexega_syntax::secrets::string_literal_content(tok.span, src, dialect),
                template: template_depth > 0 || in_block(tok.span),
                number: false,
            }),
            // A number prints where a walk knows where it goes
            // ([`facts::secrets::number_destinations`]), as a string does.
            TokenKind::Literal(LiteralKind::Number) => literals.push(facts::secrets::TextLiteral {
                span: tok.span,
                content: tok.span,
                template: template_depth > 0 || in_block(tok.span),
                number: true,
            }),
            TokenKind::Keyword(_)
            | TokenKind::Identifier { .. }
            | TokenKind::Literal(_)
            | TokenKind::Operator(_)
            | TokenKind::Punctuation(_)
            | TokenKind::LineComment
            | TokenKind::BlockComment
            | TokenKind::JinjaComment
            | TokenKind::JinjaPipe
            | TokenKind::JinjaTilde
            | TokenKind::JinjaDoubleStar
            | TokenKind::JinjaDoubleSlash
            | TokenKind::JinjaDoubleEq
            | TokenKind::JinjaAnd
            | TokenKind::JinjaOr
            | TokenKind::JinjaNot
            | TokenKind::JinjaIn
            | TokenKind::JinjaIs
            | TokenKind::JinjaTrue
            | TokenKind::JinjaFalse
            | TokenKind::JinjaNull
            | TokenKind::JinjaIf
            | TokenKind::JinjaElif
            | TokenKind::JinjaElse
            | TokenKind::JinjaEndIf
            | TokenKind::JinjaFor
            | TokenKind::JinjaEndFor
            | TokenKind::JinjaSet
            | TokenKind::JinjaEndSet
            | TokenKind::JinjaDocs
            | TokenKind::JinjaEndDocs
            | TokenKind::JinjaFilter
            | TokenKind::JinjaEndFilter
            | TokenKind::JinjaCall
            | TokenKind::JinjaEndCall
            | TokenKind::Placeholder
            | TokenKind::Eof => {}
        }
    }
    let mut whole: Vec<lexer::token::Span> = Vec::new();
    if let Some(script) = script {
        whole.extend_from_slice(&script.redaction_spans);
        // No quote reproduces a comment: a fact string made of text holding
        // one is masked.
        whole.extend_from_slice(&script.comment_spans);
        whole.extend(
            script
                .template_blocks
                .iter()
                .filter(|block| block.holds == ast::TemplateBlockHolds::Value)
                .map(|block| block.body),
        );
    }
    let mut slots = if run_text {
        SlotLiterals::default()
    } else {
        slot_literals(&statements, &code, &tokens, src, dialect, &literals)
    };
    // A bulk load's option the dialect lists, by the parser's record of its
    // option list: the literal written whole as its value.
    if !run_text {
        for option in script.into_iter().flat_map(|script| &script.bulk_options) {
            let name = src.get(option.name.start as usize..option.name.end as usize);
            let listed = dialect.shown_slots().iter().any(|slot| {
                slot.follows == dialect::SlotFollows::BulkOption
                    && matches!(slot.keyword, [keyword] if name.is_some_and(|name| name.eq_ignore_ascii_case(keyword)))
            });
            let whole = literals
                .iter()
                .any(|literal| literal.span == option.value && !literal.template);
            if listed && whole {
                slots.shown.push(option.value);
            }
        }
    }
    // A location's user information and query are masked where it is shown.
    whole.extend_from_slice(&slots.masked_parts);
    let mut shown = slots.shown.clone();
    // The types a statement declares: their lengths, precisions and
    // scales.
    for stmt in &statements {
        shown.extend(declared_type_spans(stmt));
    }
    // A number a definition gives a named option or setting goes to that
    // setting: shown where the name names no secret. A credential the
    // parser records at its place is masked whole whatever is shown.
    for stmt in &statements {
        let definition = match ir::lower_dispatch::route(stmt) {
            ir::lower_dispatch::StatementRoute::Ddl => true,
            ir::lower_dispatch::StatementRoute::Relational
            | ir::lower_dispatch::StatementRoute::Opaque
            | ir::lower_dispatch::StatementRoute::Separator => false,
        };
        // A statement holding bodies (a loop, a branch) is read by its own
        // statements; its header is no definition.
        if !definition || !stmt.bodies().is_empty() {
            continue;
        }
        let span = stmt.span();
        let first = tokens.partition_point(|tok| tok.span.end <= span.start);
        let mut named: Option<&str> = None;
        for tok in tokens[first..]
            .iter()
            .take_while(|tok| tok.span.start < span.end)
        {
            let text = src
                .get(tok.span.start as usize..tok.span.end as usize)
                .unwrap_or_default();
            match &tok.kind {
                TokenKind::Literal(LiteralKind::Number) => {
                    let setting = named.is_some_and(|name| {
                        !lexega_syntax::secrets::is_secret_name(name)
                            || shown_setting(dialect, name)
                    });
                    if setting {
                        shown.push(tok.span);
                    }
                    named = None;
                }
                // A column's default is a value it stores, no setting.
                TokenKind::Keyword(lexer::Keyword::Default) => named = None,
                TokenKind::Keyword(_) | TokenKind::Identifier { .. } => named = Some(text),
                TokenKind::Operator(lexer::Operator::Eq | lexer::Operator::EqGt) => {}
                TokenKind::Literal(_)
                | TokenKind::Operator(_)
                | TokenKind::Punctuation(_)
                | TokenKind::LineComment
                | TokenKind::BlockComment
                | TokenKind::JinjaComment
                | TokenKind::JinjaExprOpen
                | TokenKind::JinjaExprClose
                | TokenKind::JinjaStmtOpen
                | TokenKind::JinjaStmtClose
                | TokenKind::JinjaPipe
                | TokenKind::JinjaTilde
                | TokenKind::JinjaDoubleStar
                | TokenKind::JinjaDoubleSlash
                | TokenKind::JinjaDoubleEq
                | TokenKind::JinjaAnd
                | TokenKind::JinjaOr
                | TokenKind::JinjaNot
                | TokenKind::JinjaIn
                | TokenKind::JinjaIs
                | TokenKind::JinjaTrue
                | TokenKind::JinjaFalse
                | TokenKind::JinjaNull
                | TokenKind::JinjaIf
                | TokenKind::JinjaElif
                | TokenKind::JinjaElse
                | TokenKind::JinjaEndIf
                | TokenKind::JinjaFor
                | TokenKind::JinjaEndFor
                | TokenKind::JinjaSet
                | TokenKind::JinjaEndSet
                | TokenKind::JinjaDocs
                | TokenKind::JinjaEndDocs
                | TokenKind::JinjaFilter
                | TokenKind::JinjaEndFilter
                | TokenKind::JinjaCall
                | TokenKind::JinjaEndCall
                | TokenKind::Placeholder
                | TokenKind::Eof
                | TokenKind::Unknown => named = None,
            }
        }
    }
    if !run_text {
        for (literal, masked) in runs.into_iter().flat_map(DynamicBodies::run_texts) {
            shown.push(literal);
            whole.extend_from_slice(masked);
        }
        for query in statements
            .iter()
            .filter_map(|stmt| unload_query_literal(stmt, &literals))
        {
            if let Some(masked) = statements_literal_masked(query, src, dialect) {
                shown.push(query);
                whole.extend(masked);
            }
        }
    }
    // A sqlcmd command line is no SQL: of it a report shows what sqlcmd's
    // grammar gives as no secret, and of one inside a statement's body,
    // nothing.
    // Text inside a statement's body that the parser did not read as SQL
    // is masked after the keywords it starts with, which say what it is.
    for stmt in &statements {
        let top_level = script
            .is_some_and(|script| script.stmts.iter().any(|outer| std::ptr::eq(outer, *stmt)));
        if let ast::AstStmt::SqlcmdCommand {
            span,
            name_span,
            action,
            ..
        } = stmt
        {
            whole.extend(sqlcmd_masked_parts(
                *span, *name_span, action, src, top_level,
            ));
            if let Some(kept) = sqlcmd_kept_part(action).filter(|_| top_level) {
                shown.push(kept);
            }
        } else if is_unparsed_statement(stmt) {
            // Text no parser read prints its keywords and punctuation only.
            let span = stmt.span();
            let first = tokens.partition_point(|tok| tok.span.end <= span.start);
            whole.extend(
                tokens[first..]
                    .iter()
                    .take_while(|tok| tok.span.start < span.end)
                    .filter(|tok| !shown_unread(&tok.kind))
                    .map(|tok| tok.span),
            );
        } else if !top_level && kept_as_written(stmt) {
            let span = stmt.span();
            let first = tokens.partition_point(|tok| tok.span.end <= span.start);
            let start = tokens[first..]
                .iter()
                .take_while(|tok| tok.span.end <= span.end)
                .find(|tok| !matches!(tok.kind, TokenKind::Keyword(_)))
                .map_or(span.end, |tok| tok.span.start);
            if start < span.end {
                whole.push(lexer::token::Span {
                    start,
                    end: span.end,
                });
            }
        }
    }
    // The rows a `COPY … FROM STDIN` reads: data its table is loaded with,
    // masked whole.
    for stmt in &statements {
        if let Some(rows) = copy_rows(stmt) {
            whole.push(rows);
        }
    }
    // A number a statement gives a variable, a routine's argument or a
    // column's default reaches a column no walk follows: masked whole.
    for stmt in &statements {
        for value in values_given_names(stmt, src, dialect) {
            let first = tokens.partition_point(|tok| tok.span.end <= value.start);
            whole.extend(
                tokens[first..]
                    .iter()
                    .take_while(|tok| tok.span.start < value.end)
                    .filter(|tok| matches!(tok.kind, TokenKind::Literal(LiteralKind::Number)))
                    .map(|tok| tok.span),
            );
        }
    }
    // A setting's value is shown where the dialect documents the setting as
    // holding no secret, or the value is in a slot it documents (a user's
    // `DEFAULT_ROLE`), and masked whole, quoted or not, everywhere else.
    let mut slotted = slots.shown.clone();
    slotted.sort_by_key(|span| (span.start, span.end));
    let in_slot = |part: &lexer::token::Span| {
        let at = slotted.partition_point(|literal| literal.end <= part.start);
        slotted
            .get(at)
            .is_some_and(|literal| literal.start <= part.start && part.end <= literal.end)
    };
    for value in script.into_iter().flat_map(|script| &script.setting_values) {
        let documented = value
            .setting
            .and_then(|name| src.get(name.start as usize..name.end as usize))
            .is_some_and(|name| shown_setting(dialect, name));
        if documented {
            shown.extend(value.parts.iter().filter_map(|part| {
                let at = literals.partition_point(|literal| literal.span.end <= part.start);
                literals
                    .get(at)
                    .filter(|literal| {
                        literal.span.start <= part.start && part.end <= literal.span.end
                    })
                    .map(|literal| literal.span)
            }));
        } else {
            whole.extend(value.parts.iter().filter(|part| !in_slot(part)).copied());
        }
    }
    // A name a statement takes from a variable is masked where a fact
    // prints it: the variable's value is masked whole.
    let held = script.map_or_else(Vec::new, |script| script.held_names.clone());
    let reported = facts::secrets::ReportedLiterals::new(literals, whole, run_text).holding(held);
    reported.show(&shown);
    reported
}

/// The types `stmt` declares, where it reads them: of a table's columns
/// (`CREATE TABLE`, `ALTER TABLE … ADD COLUMN`, a column's changed type),
/// of a routine's or a policy's parameters and of what it returns, of the
/// variables a `DECLARE` names, of a domain. A number in one is the type's
/// length, precision or scale.
fn declared_type_spans(stmt: &ast::AstStmt) -> Vec<lexer::token::Span> {
    let params = |params: &[ast::AstProcedureParam]| -> Vec<lexer::token::Span> {
        params.iter().filter_map(|param| param.type_span).collect()
    };
    if let ast::AstStmt::CreateTable(table) = stmt {
        return table
            .columns
            .iter()
            .filter_map(|column| column.type_span)
            .collect();
    }
    if let ast::AstStmt::AlterTable(alter) = stmt {
        let mut types = Vec::new();
        for action in &alter.actions {
            if let ast::AstAlterTableActionKind::AddColumn { columns, .. } = &action.kind {
                types.extend(columns.iter().filter_map(|column| column.type_span));
            }
            if let ast::AstAlterTableActionKind::AlterColumn {
                altered_type:
                    ast::AstAlteredType::Changed {
                        type_span: Some(type_span),
                    },
                ..
            } = &action.kind
            {
                types.push(*type_span);
            }
            if let ast::AstAlterTableActionKind::AlterColumnSetDataType { data_type_span, .. } =
                &action.kind
            {
                types.push(*data_type_span);
            }
        }
        return types;
    }
    if let ast::AstStmt::CreateProcedure(procedure) = stmt {
        let mut types = params(&procedure.params);
        types.push(procedure.returns_span);
        return types;
    }
    if let ast::AstStmt::CreateFunction(function) = stmt {
        let mut types = params(&function.params);
        types.extend(function.returns.as_ref().map(|returns| returns.span));
        return types;
    }
    if let ast::AstStmt::CreateTableFunction(function) = stmt {
        let mut types = params(&function.params);
        types.push(function.returns_span);
        return types;
    }
    if let ast::AstStmt::Declare { variables, .. } = stmt {
        return variables
            .iter()
            .filter_map(|variable| variable.type_span)
            .collect();
    }
    if let ast::AstStmt::CreateMaskingPolicy(policy) = stmt {
        return policy
            .parameters
            .iter()
            .map(|parameter| parameter.type_span)
            .chain([policy.return_type_span])
            .collect();
    }
    if let ast::AstStmt::CreateRowAccessPolicy(policy) = stmt {
        return policy
            .parameters
            .iter()
            .map(|parameter| parameter.type_span)
            .collect();
    }
    if let ast::AstStmt::CreateDomain(domain) = stmt {
        return vec![domain.data_type_span];
    }
    Vec::new()
}

/// Whether a token of text no parser read prints as written: a keyword, an
/// operator or punctuation, which say what the text is and hold no value.
fn shown_unread(kind: &lexer::TokenKind) -> bool {
    use lexer::TokenKind;
    match kind {
        TokenKind::Keyword(_) | TokenKind::Operator(_) | TokenKind::Punctuation(_) => true,
        TokenKind::Identifier { .. }
        | TokenKind::Literal(_)
        | TokenKind::LineComment
        | TokenKind::BlockComment
        | TokenKind::JinjaComment
        | TokenKind::JinjaExprOpen
        | TokenKind::JinjaExprClose
        | TokenKind::JinjaStmtOpen
        | TokenKind::JinjaStmtClose
        | TokenKind::JinjaPipe
        | TokenKind::JinjaTilde
        | TokenKind::JinjaDoubleStar
        | TokenKind::JinjaDoubleSlash
        | TokenKind::JinjaDoubleEq
        | TokenKind::JinjaAnd
        | TokenKind::JinjaOr
        | TokenKind::JinjaNot
        | TokenKind::JinjaIn
        | TokenKind::JinjaIs
        | TokenKind::JinjaTrue
        | TokenKind::JinjaFalse
        | TokenKind::JinjaNull
        | TokenKind::JinjaIf
        | TokenKind::JinjaElif
        | TokenKind::JinjaElse
        | TokenKind::JinjaEndIf
        | TokenKind::JinjaFor
        | TokenKind::JinjaEndFor
        | TokenKind::JinjaSet
        | TokenKind::JinjaEndSet
        | TokenKind::JinjaDocs
        | TokenKind::JinjaEndDocs
        | TokenKind::JinjaFilter
        | TokenKind::JinjaEndFilter
        | TokenKind::JinjaCall
        | TokenKind::JinjaEndCall
        | TokenKind::Placeholder
        | TokenKind::Eof
        | TokenKind::Unknown => false,
    }
}

/// The rows `stmt` reads where it is a `COPY … FROM STDIN`: the data
/// written after it, through the line `\.` that ends them.
fn copy_rows(stmt: &ast::AstStmt) -> Option<lexer::token::Span> {
    let ast::AstStmt::PgCopy(copy) = stmt else {
        return None;
    };
    copy.data_span
}

/// Whether `dialect` documents the setting written `name` as holding no
/// secret ([`dialect::Dialect::shown_settings`]): read in any case, its
/// quotes left out.
fn shown_setting(dialect: &dyn dialect::Dialect, name: &str) -> bool {
    let name = name.trim_matches(|c| matches!(c, '"' | '`' | '\''));
    dialect
        .shown_settings()
        .iter()
        .any(|setting| setting.name.eq_ignore_ascii_case(name))
}

/// The parts a report masks of the sqlcmd command line `src` writes at
/// `span`, its command named at `name_span` doing `action`: all of it from
/// the command's name where it is not a statement of its own (a line inside
/// a routine's body); else what follows the name but what the parser reads
/// as no secret ("sqlcmd utility", "Commands"): the server `:connect` names,
/// the file `:r` reads, and what a command setting the client's state names
/// (`:setvar`'s name, `:out`'s file, `:on error`'s choice). Each part is a
/// run of text with no white space in it.
/// What sqlcmd's grammar gives as no secret of a command line: the name
/// `:setvar` sets and the file or choice a client command names, the file
/// `:r` reads, the server `:connect` connects to.
fn sqlcmd_kept_part(action: &ast::SqlcmdAction) -> Option<lexer::token::Span> {
    use ast::SqlcmdAction as A;
    match action {
        A::Client { named } => *named,
        A::Include { file_span } => *file_span,
        A::Connect { server_span } => *server_span,
        A::OsCommand | A::Edit | A::ExitQuery { .. } => None,
    }
}

fn sqlcmd_masked_parts(
    span: lexer::token::Span,
    name_span: lexer::token::Span,
    action: &ast::SqlcmdAction,
    src: &str,
    top_level: bool,
) -> Vec<lexer::token::Span> {
    if !top_level {
        return vec![lexer::token::Span {
            start: name_span.start,
            end: span.end,
        }];
    }
    let masked = match sqlcmd_kept_part(action) {
        Some(kept) => vec![
            lexer::token::Span {
                start: name_span.end,
                end: kept.start,
            },
            lexer::token::Span {
                start: kept.end,
                end: span.end,
            },
        ],
        None => vec![lexer::token::Span {
            start: name_span.end,
            end: span.end,
        }],
    };
    masked
        .into_iter()
        .flat_map(|part| unbroken_runs(part, src))
        .collect()
}

/// The values `stmt` gives a name rather than a column it writes at that
/// column's own place: a variable's value (`DECLARE`, `SET`, `LET`, `:=`,
/// a MySQL user variable, T-SQL `SELECT @v = …`, `SELECT … INTO` variables),
/// a routine's argument (`CALL`, `EXEC`, `EXECUTE p(…)`, a value
/// `EXECUTE IMMEDIATE … USING` binds), but one a documented routine of the
/// dialect reads as a name or a flag ([`dialect::ArgumentUse`]), a
/// routine parameter's default, a column's default or generated value (a
/// table variable's too, and T-SQL's `DEFAULT … FOR` constraint), and what
/// `LOAD DATA` sets. No walk follows such a value to the column it may reach, so a
/// number among them is never shown.
fn values_given_names(
    stmt: &ast::AstStmt,
    src: &str,
    dialect: &dyn dialect::Dialect,
) -> Vec<lexer::token::Span> {
    use ast::AstStmt as S;
    let documented = |routine: Option<lexer::token::Span>, args: &[ast::AstCallArg]| {
        let uses = routine
            .and_then(|routine| src.get(routine.start as usize..routine.end as usize))
            .and_then(|routine| {
                let parts = ir::lower::routine_name(routine);
                let parts: Vec<&str> = parts.iter().map(IdentKey::as_str).collect();
                let written: Vec<dialect::WrittenArgument<'_>> = args
                    .iter()
                    .map(|arg| dialect::WrittenArgument {
                        name: arg.name.as_ref().and_then(|name| {
                            src.get(name.span.start as usize..name.span.end as usize)
                        }),
                        value: dialect::WrittenValue::of(&arg.value),
                    })
                    .collect();
                Some(dialect.system_routine(&parts)?.argument_uses(&written))
            })
            .unwrap_or_default();
        args.iter()
            .enumerate()
            .filter(|(at, _)| {
                !matches!(
                    uses.get(*at).copied().flatten(),
                    Some(dialect::ArgumentUse::Name | dialect::ArgumentUse::Flag)
                )
            })
            .map(|(_, arg)| arg.value.span())
            .collect::<Vec<_>>()
    };
    let selected = |select: &ast::AstSelect| {
        let into_variables = matches!(
            select.into_target.as_deref(),
            Some(ast::AstSelectIntoTarget::ScriptingVars { .. })
        );
        let mut spans = Vec::new();
        if let ast::AstProjectionKind::Columns(items) = &select.projection.kind {
            for item in items {
                if let ast::ProjectionItemKind::SelectItem(item) = &item.kind {
                    if into_variables || item.assign_target.is_some() {
                        spans.push(item.expr.span());
                    }
                }
            }
        }
        spans
    };
    match stmt {
        S::Declare { variables, .. } => variables
            .iter()
            .filter_map(|variable| variable.default_expr.as_deref())
            .map(ast::AstExpr::span)
            .collect(),
        S::SetVariable { values, .. } => values.iter().map(ast::AstExpr::span).collect(),
        S::Assign { expr, .. } | S::Let { expr, .. } => vec![expr.span()],
        S::MysqlSet(set) => match &set.kind {
            ast::AstMysqlSetKind::Assignments(assignments) => assignments
                .iter()
                .filter(|assignment| {
                    matches!(assignment.target, ast::AstMysqlSetTarget::UserVar { .. })
                })
                .map(|assignment| assignment.value.span())
                .collect(),
            ast::AstMysqlSetKind::Names(_)
            | ast::AstMysqlSetKind::CharacterSet(_)
            | ast::AstMysqlSetKind::Password(_)
            | ast::AstMysqlSetKind::Role(_)
            | ast::AstMysqlSetKind::DefaultRole(_)
            | ast::AstMysqlSetKind::Transaction(_) => Vec::new(),
        },
        S::Select(select) => selected(select),
        S::Call {
            procedure_name_span,
            args,
            ..
        } => documented(Some(*procedure_name_span), args),
        S::MssqlExec(exec) => documented(exec.procedure_name_span, &exec.args),
        S::PgExecute(execute) => execute.args_span.into_iter().collect(),
        S::MysqlLoadData(load) => load.set_span.into_iter().collect(),
        S::CreateTable(table) => table
            .columns
            .iter()
            .flat_map(|column| [column.default_expr_span, column.virtual_expr_span])
            .flatten()
            .collect(),
        S::CreateProcedure(_) | S::CreateFunction(_) => {
            ir::dynamic_sql::created_routine_parts(stmt)
                .map(|routine| {
                    routine
                        .params
                        .iter()
                        .filter_map(|param| param.default_span)
                        .collect()
                })
                .unwrap_or_default()
        }
        S::ExecuteImmediate { using_args, .. } => {
            using_args.iter().map(|arg| arg.expr.span()).collect()
        }
        S::DeclareTable {
            column_defaults, ..
        } => column_defaults.clone(),
        S::AlterTable(alter) => alter
            .actions
            .iter()
            .flat_map(|action| match &action.kind {
                ast::AstAlterTableActionKind::AddColumn { columns, .. } => columns
                    .iter()
                    .filter_map(|column| column.definition.as_deref())
                    .flat_map(|definition| {
                        [definition.default_expr_span, definition.virtual_expr_span]
                    })
                    .flatten()
                    .collect(),
                ast::AstAlterTableActionKind::AddConstraint { default_span, .. } => {
                    default_span.iter().copied().collect()
                }
                ast::AstAlterTableActionKind::AlterColumnSetDefault { expr_span, .. } => {
                    vec![*expr_span]
                }
                ast::AstAlterTableActionKind::AlterColumn { default_span, .. } => {
                    default_span.iter().copied().collect()
                }
                ast::AstAlterTableActionKind::RenameTo { .. }
                | ast::AstAlterTableActionKind::RenameColumn { .. }
                | ast::AstAlterTableActionKind::ChangeColumn { .. }
                | ast::AstAlterTableActionKind::SwapWith { .. }
                | ast::AstAlterTableActionKind::DropColumn { .. }
                | ast::AstAlterTableActionKind::AlterColumnList { .. }
                | ast::AstAlterTableActionKind::DropConstraint { .. }
                | ast::AstAlterTableActionKind::ClusterBy { .. }
                | ast::AstAlterTableActionKind::DropClusteringKey { .. }
                | ast::AstAlterTableActionKind::SuspendRecluster { .. }
                | ast::AstAlterTableActionKind::ResumeRecluster { .. }
                | ast::AstAlterTableActionKind::Set { .. }
                | ast::AstAlterTableActionKind::Unset { .. }
                | ast::AstAlterTableActionKind::AddRowAccessPolicy { .. }
                | ast::AstAlterTableActionKind::DropRowAccessPolicy { .. }
                | ast::AstAlterTableActionKind::DropAllRowAccessPolicies { .. }
                | ast::AstAlterTableActionKind::SetRowFilter { .. }
                | ast::AstAlterTableActionKind::DropRowFilter { .. }
                | ast::AstAlterTableActionKind::SetAggregationPolicy { .. }
                | ast::AstAlterTableActionKind::UnsetAggregationPolicy { .. }
                | ast::AstAlterTableActionKind::SetJoinPolicy { .. }
                | ast::AstAlterTableActionKind::UnsetJoinPolicy { .. }
                | ast::AstAlterTableActionKind::SetColumnMaskingPolicy { .. }
                | ast::AstAlterTableActionKind::UnsetColumnMaskingPolicy { .. }
                | ast::AstAlterTableActionKind::SetColumnMask { .. }
                | ast::AstAlterTableActionKind::DropColumnMask { .. }
                | ast::AstAlterTableActionKind::SetColumnProjectionPolicy { .. }
                | ast::AstAlterTableActionKind::UnsetColumnProjectionPolicy { .. }
                | ast::AstAlterTableActionKind::SetTag { .. }
                | ast::AstAlterTableActionKind::UnsetTag { .. }
                | ast::AstAlterTableActionKind::SetColumnTag { .. }
                | ast::AstAlterTableActionKind::UnsetColumnTag { .. }
                | ast::AstAlterTableActionKind::AddSearchOptimization { .. }
                | ast::AstAlterTableActionKind::DropSearchOptimization { .. }
                | ast::AstAlterTableActionKind::SetDataMetricSchedule { .. }
                | ast::AstAlterTableActionKind::UnsetDataMetricSchedule { .. }
                | ast::AstAlterTableActionKind::AddDataMetricFunction { .. }
                | ast::AstAlterTableActionKind::DropDataMetricFunction { .. }
                | ast::AstAlterTableActionKind::AddStorageLifecyclePolicy { .. }
                | ast::AstAlterTableActionKind::DropStorageLifecyclePolicy { .. }
                | ast::AstAlterTableActionKind::SetOptions { .. }
                | ast::AstAlterTableActionKind::SetDefaultCollate { .. }
                | ast::AstAlterTableActionKind::DropPrimaryKey { .. }
                | ast::AstAlterTableActionKind::AlterColumnSetOptions { .. }
                | ast::AstAlterTableActionKind::AlterColumnDropNotNull { .. }
                | ast::AstAlterTableActionKind::AlterColumnSetDataType { .. }
                | ast::AstAlterTableActionKind::AlterColumnDropDefault { .. }
                | ast::AstAlterTableActionKind::SetTblProperties { .. }
                | ast::AstAlterTableActionKind::UnsetTblProperties { .. }
                | ast::AstAlterTableActionKind::RowLevelSecurity { .. }
                | ast::AstAlterTableActionKind::OwnerTo { .. }
                | ast::AstAlterTableActionKind::SetSchema { .. }
                | ast::AstAlterTableActionKind::AttachPartition { .. }
                | ast::AstAlterTableActionKind::DetachPartition { .. }
                | ast::AstAlterTableActionKind::SwitchTo { .. }
                | ast::AstAlterTableActionKind::GovernanceSpan { .. }
                | ast::AstAlterTableActionKind::Unknown { .. }
                | ast::AstAlterTableActionKind::NamedAction { .. } => Vec::new(),
            })
            .collect(),
        S::SetSelect { .. }
        | S::ValuesQuery { .. }
        | S::OpaqueContent { .. }
        | S::GoBatchSeparator { .. }
        | S::SqlcmdCommand { .. }
        | S::Reconfigure { .. }
        | S::MssqlServerCommand { .. }
        | S::MssqlExecuteAs { .. }
        | S::MssqlRevert { .. }
        | S::MssqlAuditDdl { .. }
        | S::MssqlSecurityObjectDdl { .. }
        | S::MssqlTryCatch { .. }
        | S::MssqlIf { .. }
        | S::MssqlWhile { .. }
        | S::MssqlPrint { .. }
        | S::MssqlThrow { .. }
        | S::MssqlRaiserror { .. }
        | S::MssqlSetOption { .. }
        | S::MysqlUnlockTables { .. }
        | S::MssqlWaitfor { .. }
        | S::MssqlGoto { .. }
        | S::MssqlLabel { .. }
        | S::CreateMssqlTrigger { .. }
        | S::DropMssqlTrigger { .. }
        | S::MssqlTriggerState { .. }
        | S::Savepoint { .. }
        | S::MssqlBulkInsert { .. }
        | S::MssqlCreateExternalModel { .. }
        | S::MssqlCreateExternalDataSource { .. }
        | S::MssqlAlterExternalDataSource { .. }
        | S::CreateForeignServer { .. }
        | S::AlterForeignServer { .. }
        | S::MssqlAlterServerConfiguration { .. }
        | S::CreateUserMapping { .. }
        | S::AlterUserMapping { .. }
        | S::DropUserMapping { .. }
        | S::CreateForeignTable { .. }
        | S::ImportForeignSchema { .. }
        | S::MssqlAlterExternalModel { .. }
        | S::MssqlDropExternalModel { .. }
        | S::MssqlCreateVectorIndex { .. }
        | S::ClauseFragment { .. }
        | S::CreateView { .. }
        | S::CreateDynamicTable { .. }
        | S::CreateTask { .. }
        | S::CreateStage { .. }
        | S::CreateRowAccessPolicy { .. }
        | S::CreateMaskingPolicy { .. }
        | S::CreateNetworkPolicy { .. }
        | S::CreateSessionPolicy { .. }
        | S::CreateAuthenticationPolicy { .. }
        | S::CreateApiIntegration { .. }
        | S::CreateNotificationIntegration { .. }
        | S::CreatePasswordPolicy { .. }
        | S::CreateAggregationPolicy { .. }
        | S::CreateProjectionPolicy { .. }
        | S::CreateStorageIntegration { .. }
        | S::AlterRowAccessPolicy { .. }
        | S::AlterMaskingPolicy { .. }
        | S::AlterNetworkPolicy { .. }
        | S::AlterSessionPolicy { .. }
        | S::AlterSession { .. }
        | S::AlterAuthenticationPolicy { .. }
        | S::AlterUser { .. }
        | S::AlterAccount { .. }
        | S::AlterApiIntegration { .. }
        | S::AlterNotificationIntegration { .. }
        | S::CreateShare { .. }
        | S::AlterShare { .. }
        | S::CreateDatashare { .. }
        | S::AlterDatashare { .. }
        | S::CreateSecurityIntegration { .. }
        | S::AlterSecurityIntegration { .. }
        | S::AlterReplicationGroup { .. }
        | S::AlterFailoverGroup { .. }
        | S::AlterPasswordPolicy { .. }
        | S::AlterAggregationPolicy { .. }
        | S::AlterProjectionPolicy { .. }
        | S::AlterStorageIntegration { .. }
        | S::AlterView { .. }
        | S::AlterMaterializedView { .. }
        | S::AlterDynamicTable { .. }
        | S::AlterFunction { .. }
        | S::AlterProcedure { .. }
        | S::AlterStage { .. }
        | S::AlterTask { .. }
        | S::Show { .. }
        | S::Describe { .. }
        | S::Use { .. }
        | S::Truncate { .. }
        | S::Drop { .. }
        | S::DropRowAccessPolicy { .. }
        | S::DropAllRowAccessPolicies { .. }
        | S::DropMaskingPolicy { .. }
        | S::DropNetworkPolicy { .. }
        | S::DropSessionPolicy { .. }
        | S::DropAuthenticationPolicy { .. }
        | S::DropApiIntegration { .. }
        | S::DropNotificationIntegration { .. }
        | S::DropPasswordPolicy { .. }
        | S::DropAggregationPolicy { .. }
        | S::DropProjectionPolicy { .. }
        | S::DropStorageIntegration { .. }
        | S::DropTask { .. }
        | S::CreateWarehouse { .. }
        | S::AlterWarehouse { .. }
        | S::DropWarehouse { .. }
        | S::CreatePipe { .. }
        | S::AlterPipe { .. }
        | S::DropPipe { .. }
        | S::CreateTag { .. }
        | S::AlterTag { .. }
        | S::UndropTag { .. }
        | S::CreateFileFormat { .. }
        | S::AlterFileFormat { .. }
        | S::CreateSecret { .. }
        | S::AlterSecret { .. }
        | S::CreateNetworkRule { .. }
        | S::AlterNetworkRule { .. }
        | S::CreateResourceMonitor { .. }
        | S::AlterResourceMonitor { .. }
        | S::CreateComputePool { .. }
        | S::AlterComputePool { .. }
        | S::CreateGitRepository { .. }
        | S::AlterGitRepository { .. }
        | S::CreateImageRepository { .. }
        | S::AlterImageRepository { .. }
        | S::CreateStreamlit { .. }
        | S::AlterStreamlit { .. }
        | S::CreateService { .. }
        | S::AlterService { .. }
        | S::CreateNotebook { .. }
        | S::AlterNotebook { .. }
        | S::CreateSemanticView { .. }
        | S::AlterSemanticView { .. }
        | S::CreateCortexSearchService { .. }
        | S::AlterCortexSearchService { .. }
        | S::CreateApplication { .. }
        | S::AlterApplication { .. }
        | S::CreateApplicationPackage { .. }
        | S::AlterApplicationPackage { .. }
        | S::CreateListing { .. }
        | S::AlterListing { .. }
        | S::CreateManagedAccount { .. }
        | S::CreateAccount { .. }
        | S::StageFileCommand { .. }
        | S::CreateAlert { .. }
        | S::AlterAlert { .. }
        | S::CreateJoinPolicy { .. }
        | S::AlterJoinPolicy { .. }
        | S::DropJoinPolicy { .. }
        | S::CreateDataMetricFunction { .. }
        | S::CreateReplicationFailoverGroup { .. }
        | S::CreateExternalAccessIntegration { .. }
        | S::AlterExternalAccessIntegration { .. }
        | S::DropExternalAccessIntegration { .. }
        | S::CreateStream { .. }
        | S::AlterStream { .. }
        | S::DropStream { .. }
        | S::CreateDatabase { .. }
        | S::AlterDatabase { .. }
        | S::DropDatabase { .. }
        | S::UndropDatabase { .. }
        | S::CreateSchema { .. }
        | S::AlterSchema { .. }
        | S::DropSchema { .. }
        | S::UndropSchema { .. }
        | S::UndropTable { .. }
        | S::UndropType { .. }
        | S::Insert { .. }
        | S::ReplaceInto { .. }
        | S::MultiInsert { .. }
        | S::Update { .. }
        | S::Delete { .. }
        | S::Merge { .. }
        | S::Explain { .. }
        | S::PsqlGexec { .. }
        | S::MysqlDo { .. }
        | S::ExecuteTask { .. }
        | S::MysqlCreateLoadableFunction { .. }
        | S::MysqlAdmin { .. }
        | S::CreateIndex { .. }
        | S::CreateSynonym { .. }
        | S::CommentOn { .. }
        | S::DoBlock { .. }
        | S::Perform { .. }
        | S::Vacuum { .. }
        | S::AnalyzeStmt { .. }
        | S::CreateType { .. }
        | S::AlterType { .. }
        | S::CreateExtension { .. }
        | S::CreateSequence { .. }
        | S::AlterSequence { .. }
        | S::CreatePgTrigger { .. }
        | S::AlterPgTrigger { .. }
        | S::DropPgTrigger { .. }
        | S::CreateDomain { .. }
        | S::AlterDomain { .. }
        | S::DropDomain { .. }
        | S::CreatePgPolicy { .. }
        | S::AlterPgPolicy { .. }
        | S::DropPgPolicy { .. }
        | S::AlterIndex { .. }
        | S::Reindex { .. }
        | S::PgPrepare { .. }
        | S::PgDeallocate { .. }
        | S::PgCopy { .. }
        | S::PgRefreshMatview { .. }
        | S::PgListen { .. }
        | S::PgNotify { .. }
        | S::PgUnlisten { .. }
        | S::PgLockTable { .. }
        | S::PgCreateRule { .. }
        | S::MssqlCreateRule { .. }
        | S::PgCreateAggregate { .. }
        | S::PgCreateOperator { .. }
        | S::PgAlterSystem { .. }
        | S::PgAlterTablespace { .. }
        | S::PgDropOwned { .. }
        | S::PgReassignOwned { .. }
        | S::PgDiscard { .. }
        | S::PgCluster { .. }
        | S::PgPublication { .. }
        | S::PgSubscription { .. }
        | S::CreatePrincipal { .. }
        | S::AlterPrincipal { .. }
        | S::DropPrincipal { .. }
        | S::PgDropExtension { .. }
        | S::PgAlterRule { .. }
        | S::PgDropRule { .. }
        | S::PgAlterTableTriggerState { .. }
        | S::PgSet { .. }
        | S::PgDropSequence { .. }
        | S::PgDropType { .. }
        | S::PgDropIndex { .. }
        | S::PgCreateTablespace { .. }
        | S::PgDropTablespace { .. }
        | S::BqExportData { .. }
        | S::BqLoadData { .. }
        | S::MysqlRenameTable { .. }
        | S::CreateEvent { .. }
        | S::AlterEvent { .. }
        | S::CreateMysqlTrigger { .. }
        | S::BqAssert { .. }
        | S::BqCreateSnapshotTable { .. }
        | S::BqDropSnapshotTable { .. }
        | S::BqCreateSearchIndex { .. }
        | S::BqDropSearchIndex { .. }
        | S::BqCreateVectorIndex { .. }
        | S::BqDropVectorIndex { .. }
        | S::BqAlterVectorIndex { .. }
        | S::BqCreateModel { .. }
        | S::BqAlterModel { .. }
        | S::BqExportModel { .. }
        | S::BqDropModel { .. }
        | S::Optimize { .. }
        | S::DescribeHistory { .. }
        | S::Restore { .. }
        | S::MssqlBackup { .. }
        | S::MssqlRestore { .. }
        | S::MssqlDbcc { .. }
        | S::MssqlKeyManagement { .. }
        | S::MssqlSecurityPolicy { .. }
        | S::MssqlKeyBackup { .. }
        | S::MssqlAssembly { .. }
        | S::MssqlAddSignature { .. }
        | S::MssqlSetuser { .. }
        | S::MssqlAlterServiceMasterKey { .. }
        | S::PgAlterDefaultPrivileges { .. }
        | S::CacheTable { .. }
        | S::UncacheTable { .. }
        | S::RepairTable { .. }
        | S::CreateCatalog { .. }
        | S::AlterCatalog { .. }
        | S::DropCatalog { .. }
        | S::CreateVolume { .. }
        | S::AlterVolume { .. }
        | S::DropVolume { .. }
        | S::CreateExternalLocation { .. }
        | S::AlterExternalLocation { .. }
        | S::DropExternalLocation { .. }
        | S::CreateStorageCredential { .. }
        | S::AlterStorageCredential { .. }
        | S::DropStorageCredential { .. }
        | S::CreateConnection { .. }
        | S::AlterConnection { .. }
        | S::DropConnection { .. }
        | S::CreateFlow { .. }
        | S::CreateExternalTable { .. }
        | S::CreateExternalSchema { .. }
        | S::PipeChain { .. }
        | S::Block { .. }
        | S::If { .. }
        | S::CaseStmt { .. }
        | S::DeclareCursor { .. }
        | S::LetCursor { .. }
        | S::Return { .. }
        | S::Raise { .. }
        | S::Signal { .. }
        | S::Resignal { .. }
        | S::GetDiagnostics { .. }
        | S::DeclareCondition { .. }
        | S::DeclareHandler { .. }
        | S::For { .. }
        | S::ForEach { .. }
        | S::While { .. }
        | S::Repeat { .. }
        | S::Loop { .. }
        | S::Await { .. }
        | S::Cancel { .. }
        | S::Break { .. }
        | S::Continue { .. }
        | S::Null { .. }
        | S::OpenCursor { .. }
        | S::FetchCursor { .. }
        | S::CloseCursor { .. }
        | S::CreateTableFunction { .. }
        | S::ExecuteImmediateFrom { .. }
        | S::CreateExternalFunction { .. }
        | S::BeginTransaction { .. }
        | S::Commit { .. }
        | S::Rollback { .. }
        | S::CopyIntoTable { .. }
        | S::CopyIntoLocation { .. }
        | S::Unload { .. }
        | S::RedshiftCopy { .. }
        | S::JinjaPlaceholder { .. }
        | S::JinjaConditionalStmt { .. }
        | S::Grant { .. }
        | S::Revoke { .. }
        | S::Deny { .. }
        | S::AlterAuthorization { .. }
        | S::Error { .. } => Vec::new(),
    }
}

/// The runs of `src` at `span` holding no white space.
fn unbroken_runs(span: lexer::token::Span, src: &str) -> Vec<lexer::token::Span> {
    let Some(text) = src.get(span.start as usize..span.end as usize) else {
        return if span.start < span.end {
            vec![span]
        } else {
            Vec::new()
        };
    };
    let mut runs = Vec::new();
    let mut start = None;
    for (offset, c) in text.char_indices() {
        let at = span.start + offset as u32;
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(at),
            (true, Some(from)) => {
                runs.push(lexer::token::Span {
                    start: from,
                    end: at,
                });
                start = None;
            }
            (false, Some(_)) | (true, None) => {}
        }
    }
    if let Some(from) = start {
        runs.push(lexer::token::Span {
            start: from,
            end: span.end,
        });
    }
    runs
}

/// The string literal of `literals` an `UNLOAD` writes its query as, where
/// `stmt` is one whose query was read.
fn unload_query_literal(
    stmt: &ast::AstStmt,
    literals: &[facts::secrets::TextLiteral],
) -> Option<lexer::token::Span> {
    let ast::AstStmt::Unload {
        query_span,
        source: Some(ast::AstUnloadSource::Subquery(_)),
        ..
    } = stmt
    else {
        return None;
    };
    literals
        .iter()
        .find(|literal| {
            query_span.start <= literal.span.start && literal.span.end <= query_span.end
        })
        .map(|literal| literal.span)
}

/// What a report masks of the string literal at `literal` of `src`, read
/// under `dialect`, where it quotes the literal as the SQL statements its
/// text holds: their string literals, secrets and comments, each mapped
/// back to `src`. `None` where the text is not statements that each parse.
fn statements_literal_masked(
    literal: lexer::token::Span,
    src: &str,
    dialect: &dyn dialect::Dialect,
) -> Option<Vec<lexer::token::Span>> {
    let (text, map) = src
        .get(literal.start as usize..literal.end as usize)
        .and_then(|raw| ir::span_extract::decode_string_literal_text_with_map_in(raw, dialect))?;
    let script = parse_sql_with_dialect(&text, dialect).ok()?;
    let statements = flat_stmts_for_rules(&script);
    if statements.is_empty()
        || statements
            .iter()
            .any(|stmt| kept_as_written(stmt) || is_unparsed_statement(stmt))
    {
        return None;
    }
    masked_in_literal(&script, &text, &map, literal, dialect)
}

/// What a report masks of `text`, the SQL text the literal at `literal`
/// holds, parsed to `script` and read under `dialect`, each span mapped
/// back through `map` (an offset of `text` to one of the literal's); `None`
/// where a span does not map.
fn masked_in_literal(
    script: &ast::AstScript,
    text: &str,
    map: &[u32],
    literal: lexer::token::Span,
    dialect: &dyn dialect::Dialect,
) -> Option<Vec<lexer::token::Span>> {
    reported_literals(Some(script), text, dialect, true, None)
        .masked_spans()
        .into_iter()
        .map(
            |span| match (map.get(span.start as usize), map.get(span.end as usize)) {
                (Some(start), Some(end)) => Some(lexer::token::Span {
                    start: literal.start + start,
                    end: literal.start + end,
                }),
                (Some(_), None) | (None, Some(_)) | (None, None) => None,
            },
        )
        .collect()
}

/// The literals a text writes in grammar slots its dialect lists as shown
/// ([`slot_literals`]).
#[derive(Debug, Default)]
struct SlotLiterals {
    /// The span of each.
    shown: Vec<lexer::token::Span>,
    /// The parts of a location shown that may carry a secret: a URL's user
    /// information and its query.
    masked_parts: Vec<lexer::token::Span>,
}

/// The parts of the location `content` writes that may carry a secret: a
/// URL's user information (`user:password@`), and its query and fragment
/// (a signature, a token). A file path has none.
fn location_secret_parts(content: lexer::token::Span, src: &str) -> Vec<lexer::token::Span> {
    let Some(text) = src.get(content.start as usize..content.end as usize) else {
        return vec![content];
    };
    let at = |offset: usize| content.start + offset as u32;
    let mut parts = Vec::new();
    let authority = text.find("://").map(|scheme| scheme + 3);
    if let Some(start) = authority {
        let end = text[start..]
            .find('/')
            .map_or(text.len(), |slash| start + slash);
        if let Some(user) = text[start..end].rfind('@') {
            parts.push(lexer::token::Span {
                start: at(start),
                end: at(start + user),
            });
        }
    }
    if let Some(query) = text.find(['?', '#']) {
        parts.push(lexer::token::Span {
            start: at(query + 1),
            end: content.end,
        });
    }
    parts
}

/// What a report prints of the string literals of `sql`, parsed to
/// `script` and read under `dialect` (Snowflake where none is given), where
/// no statement's walk shows a literal safe: those in a grammar slot the
/// dialect lists as shown, and no other ([`reported_literals`]).
pub(crate) fn reported_unwalked(
    script: &ast::AstScript,
    sql: &str,
    dialect: Option<&dyn dialect::Dialect>,
) -> std::rc::Rc<facts::secrets::ReportedLiterals> {
    let snowflake = dialect::snowflake();
    let dialect = dialect.unwrap_or_else(|| snowflake.as_ref());
    std::rc::Rc::new(reported_literals(Some(script), sql, dialect, false, None))
}

/// Of `literals`, those written in a grammar slot `dialect` lists as
/// shown ([`dialect::Dialect::shown_slots`]), as the slot's whole value, in
/// a statement of `statements` that parses, `tokens` being `src`'s; with
/// the parts of each location among them that are masked. A literal in a
/// dollar-quoted region the parser read statements in (`code`) is read in
/// the statement of that region holding it, not in the one the region is
/// part of.
fn slot_literals(
    statements: &[&ast::AstStmt],
    code: &[lexer::token::Span],
    tokens: &[lexer::Token],
    src: &str,
    dialect: &dyn dialect::Dialect,
    literals: &[facts::secrets::TextLiteral],
) -> SlotLiterals {
    use lexer::{Operator, Punctuation, TokenKind};
    let mut out = SlotLiterals::default();
    let slots = dialect.shown_slots();
    if slots.is_empty() {
        return out;
    }
    let word = |tok: &lexer::Token| src.get(tok.span.start as usize..tok.span.end as usize);
    // A slot's value: a string, or a number.
    let string = |tok: &lexer::Token| {
        matches!(
            tok.kind,
            TokenKind::Literal(lexer::LiteralKind::String | lexer::LiteralKind::Number)
        )
    };
    let punctuation =
        |tok: &lexer::Token, mark: Punctuation| tok.kind == TokenKind::Punctuation(mark);
    let equals = |tok: &lexer::Token| tok.kind == TokenKind::Operator(Operator::Eq);
    // Each statement's span, and the statement where it parses, outer
    // before inner.
    let mut spans: Vec<(lexer::token::Span, Option<&ast::AstStmt>)> = statements
        .iter()
        .map(|stmt| (stmt.span(), (!kept_as_written(stmt)).then_some(*stmt)))
        .collect();
    spans.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut next = 0;
    // The statements open at the literal read, innermost last.
    let mut open: Vec<(lexer::token::Span, Option<&ast::AstStmt>)> = Vec::new();
    let code_tokens: Vec<&lexer::Token> = tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::LineComment | TokenKind::BlockComment))
        .collect();
    // By a statement's first code token and a list item's (a literal) or a
    // pair's key's, where the items or pairs written apart by commas before
    // it start: each walk back stops at the last one read.
    let mut item_starts: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    let pair_starts: std::cell::RefCell<std::collections::HashMap<(usize, usize), usize>> =
        std::cell::RefCell::default();
    for literal in literals.iter().filter(|literal| !literal.template) {
        let span = literal.span;
        while let Some(&(stmt, parsed)) =
            spans.get(next).filter(|(stmt, _)| stmt.start <= span.start)
        {
            while open.last().is_some_and(|(top, _)| top.end <= stmt.start) {
                open.pop();
            }
            open.push((stmt, parsed));
            next += 1;
        }
        while open.last().is_some_and(|(top, _)| top.end < span.end) {
            open.pop();
        }
        let Some(&(at, Some(stmt))) = open.last().filter(|(top, _)| top.start <= span.start) else {
            continue;
        };
        // A region of code the statement holds but did not read itself.
        if code.iter().any(|region| {
            region.start <= span.start && span.end <= region.end && at.start < region.start
        }) {
            continue;
        }
        // The statement's code tokens; the literal's first among them (a
        // dollar-quoted string's opener) at `index`, the first after it at
        // `after`.
        let first = code_tokens.partition_point(|t| t.span.end <= at.start);
        let last = code_tokens.partition_point(|t| t.span.start < at.end);
        let statement = &code_tokens[first..last];
        let index = statement.partition_point(|t| t.span.start < span.start);
        if index == statement.len() {
            continue;
        }
        let after = statement.partition_point(|t| t.span.start < span.end);
        // Where the comma-separated literal items before the literal start.
        let items_start = {
            let mut end = index;
            while end >= 2
                && punctuation(statement[end - 1], Punctuation::Comma)
                && string(statement[end - 2])
            {
                if let Some(&start) = item_starts.get(&(first, end - 2)) {
                    end = start;
                    break;
                }
                end -= 2;
            }
            item_starts.insert((first, index), end);
            end
        };
        // Whether the words `keyword` end just before token `end`.
        let keyword_before =
            |end: usize, keyword: &[&str]| {
                end >= keyword.len()
                    && statement[end - keyword.len()..end].iter().zip(keyword).all(
                        |(tok, keyword)| word(tok).is_some_and(|w| w.eq_ignore_ascii_case(keyword)),
                    )
            };
        // The literal is the whole value: no operator joins another to it.
        let whole_value = statement.get(after).is_none_or(|after| {
            !matches!(
                after.kind,
                TokenKind::Operator(
                    Operator::PipePipe
                        | Operator::Plus
                        | Operator::Minus
                        | Operator::Star
                        | Operator::Slash
                        | Operator::Percent
                )
            )
        });
        let shown_by = slots.iter().find(|slot| {
            if !slot.statement.holds(stmt) {
                return false;
            }
            match slot.follows {
                dialect::SlotFollows::Option => {
                    let end = match index.checked_sub(1).map(|at| statement[at]) {
                        Some(tok) if equals(tok) => index - 1,
                        Some(_) | None => index,
                    };
                    whole_value && keyword_before(end, slot.keyword)
                }
                dialect::SlotFollows::Call => {
                    whole_value
                        && index
                            .checked_sub(1)
                            .is_some_and(|at| punctuation(statement[at], Punctuation::LParen))
                        && keyword_before(index - 1, slot.keyword)
                }
                dialect::SlotFollows::List => {
                    // Back over the items before the literal.
                    let mut end = items_start;
                    if end >= 1
                        && (punctuation(statement[end - 1], Punctuation::LParen)
                            || punctuation(statement[end - 1], Punctuation::LBracket))
                    {
                        end -= 1;
                    }
                    if end >= 1 && equals(statement[end - 1]) {
                        end -= 1;
                    }
                    whole_value && keyword_before(end, slot.keyword)
                }
                dialect::SlotFollows::Assignments => {
                    // The literal is a pair's value: the pair's name, a
                    // name of parts written apart by dots, before its `=`.
                    let name_part = |tok: &lexer::Token| {
                        matches!(
                            tok.kind,
                            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                        )
                    };
                    let dot = |tok: &lexer::Token| punctuation(tok, Punctuation::Dot);
                    // Where the pair ending before token `end` starts: back
                    // over its value, its `=` and its name.
                    let pair_start = |end: usize| {
                        let mut at = end.checked_sub(1)?;
                        if !string(statement[at]) {
                            return None;
                        }
                        at = at.checked_sub(1)?;
                        if !equals(statement[at]) {
                            return None;
                        }
                        at = at.checked_sub(1)?;
                        if !name_part(statement[at]) {
                            return None;
                        }
                        while at >= 2 && dot(statement[at - 1]) && name_part(statement[at - 2]) {
                            at -= 2;
                        }
                        Some(at)
                    };
                    // Back over the pairs written apart by commas before it.
                    let Some(mut start) = pair_start(index + 1) else {
                        return false;
                    };
                    // A pair named for a credential holds one.
                    let named = src.get(
                        statement[start].span.start as usize
                            ..statement[index - 1].span.start as usize,
                    );
                    if named.is_some_and(lexega_syntax::secrets::is_secret_name) {
                        return false;
                    }
                    while start >= 1 && punctuation(statement[start - 1], Punctuation::Comma) {
                        match pair_start(start - 1) {
                            Some(earlier) => start = earlier,
                            None => break,
                        }
                    }
                    if start >= 1 && punctuation(statement[start - 1], Punctuation::LParen) {
                        start -= 1;
                    }
                    whole_value && keyword_before(start, slot.keyword)
                }
                // Read from the parser's record of bulk options below.
                dialect::SlotFollows::BulkOption => false,
                dialect::SlotFollows::Properties => {
                    // The key the literal is, or the key of the value it is.
                    let key = match (index.checked_sub(1), statement.get(after)) {
                        (_, Some(after)) if equals(after) => Some(index),
                        (Some(before), _)
                            if equals(statement[before])
                                && before >= 1
                                && string(statement[before - 1]) =>
                        {
                            let key = lexega_syntax::secrets::string_literal_content(
                                statement[before - 1].span,
                                src,
                                dialect,
                            );
                            src.get(key.start as usize..key.end as usize)
                                .filter(|text| !lexega_syntax::secrets::is_secret_name(text))
                                .map(|_| before - 1)
                        }
                        (Some(_) | None, Some(_) | None) => None,
                    };
                    // Back over the `key = value` pairs before it.
                    let Some(key) = key else {
                        return false;
                    };
                    let mut end = key;
                    while end >= 4
                        && punctuation(statement[end - 1], Punctuation::Comma)
                        && equals(statement[end - 3])
                        && string(statement[end - 4])
                    {
                        if let Some(&start) = pair_starts.borrow().get(&(first, end - 4)) {
                            end = start;
                            break;
                        }
                        end -= 4;
                    }
                    pair_starts.borrow_mut().insert((first, key), end);
                    whole_value
                        && end >= 1
                        && punctuation(statement[end - 1], Punctuation::LParen)
                        && keyword_before(end - 1, slot.keyword)
                }
            }
        });
        if let Some(slot) = shown_by {
            out.shown.push(span);
            match slot.holds {
                dialect::SlotHolds::Text => {}
                dialect::SlotHolds::Location => out
                    .masked_parts
                    .extend(location_secret_parts(literal.content, src)),
            }
        }
    }
    out
}

/// What one run may spend reading the SQL text a script runs, the text that
/// text runs in turn included: bodies parsed, their decoded bytes, and
/// statements reporting the findings of a body they run. The depth bound
/// caps nesting but not total work: a body fanning out to K bodies, each
/// fanning out to K more, would read K^N bodies; the body and byte counts
/// bound that fan-out independent of depth, each body charged once, when it
/// is parsed or, a text the script builds, when it is analysed. Far above
/// any legitimate script.
#[derive(Debug, Clone, Copy)]
struct BodyBudget {
    bodies: u32,
    bytes: u64,
    sinks: u32,
}

impl BodyBudget {
    /// Levels of dynamic SQL inside dynamic SQL parsed.
    const MAX_DEPTH: usize = 3;
    const FULL: BodyBudget = BodyBudget {
        bodies: 256,
        bytes: 2_000_000,
        sinks: 256,
    };
}

/// The SQL text a script runs as string literals, each literal read once,
/// statement by statement as a script is, and its text parsed once for
/// what the reading takes of it: the secret values written in that text,
/// its statements that do not parse, and the string literals of the SQL text
/// it makes. The parse is not kept: the analysis of the text parses it
/// again ([`Self::analyze_literal`]). The literals the text of each runs in
/// turn are read with it, to three levels, and every level spends one
/// budget: a text past it, or past the depth, is not parsed. The texts the
/// script and that SQL build are parsed through it too, each parse shared
/// by the readers that hold it ([`Self::built`]). Read with a relation
/// reading of the script, the parse of each text a statement runs whole
/// decides what that text writes (`RelationReading::decide_read`).
pub struct DynamicBodies {
    /// Levels of dynamic SQL this reading is inside of.
    depth: usize,
    /// What every level of the run shares.
    run: std::rc::Rc<RunReading>,
    /// Whether the texts are kept for an analysis of them: a reading for
    /// masking and coverage alone keeps none.
    analysed: bool,
    unparsed: Vec<lexer::token::Span>,
    /// Each literal the script runs, by its span: the parts of it a report
    /// masks where it quotes the literal's SQL text, as that text's own
    /// statements are quoted; `None` where a run of it is not read.
    run_texts: std::collections::BTreeMap<(u32, u32), Option<Vec<lexer::token::Span>>>,
    /// The comments the lexer reads in the SQL text each literal the script
    /// runs makes (its own decoded, or that of a run of literal operands
    /// joined), mapped back onto the source.
    comment_spans: Vec<lexer::token::Span>,
    /// Each literal the script runs whole whose text was parsed and holds a
    /// statement that parses, cut from the rest where the literal cuts it
    /// ([`holds_a_statement`]), by its span, where the texts are kept.
    read: std::collections::BTreeMap<(u32, u32), RunBody>,
    /// What the text of each literal a statement of the script runs whole
    /// writes, the texts it runs in turn included, as decided where the
    /// statement runs, by the literal's span, where a relation reading met
    /// the statement.
    run_writes: std::collections::BTreeMap<(u32, u32), facts::secrets::WrittenColumns>,
    /// Each argument a routine of the dialect runs as SQL.
    routine_runs: Vec<RoutineRun>,
}

/// The text of a string literal a script runs, decoded once, with what the
/// reading took of its parse. The parse is not kept: its analysis parses the
/// text again.
struct RunBody {
    text: String,
    /// The offset in the literal of each byte of `text`, and of its end.
    map: Vec<u32>,
    fold: ScriptContextFold,
    /// The literals the text runs in turn.
    bodies: DynamicBodies,
}

/// What every level of one run's reading shares: the dialect it reads as,
/// its budget, and the texts it builds, parsed.
struct RunReading {
    dialect: dialect::DialectRef,
    budget: std::cell::Cell<BodyBudget>,
    built: BuiltTexts,
}

/// A text the script or the SQL it runs builds, parsed
/// ([`DynamicBodies::built`]).
pub struct BuiltText {
    text: String,
    /// Its parse; `None` where it does not parse.
    script: Option<ast::AstScript>,
}

impl BuiltText {
    /// The statement the text parses to, where it is exactly one statement
    /// and that statement parses.
    pub fn single_statement(&self) -> Option<&ast::AstStmt> {
        match self.script.as_ref()?.stmts.as_slice() {
            [stmt] if !is_unparsed_statement(stmt) => Some(stmt),
            [..] => None,
        }
    }

    /// The statements the text parses to, where it holds at least one and
    /// each parses.
    pub fn statements(&self) -> Option<&[ast::AstStmt]> {
        let stmts = self.script.as_ref()?.stmts.as_slice();
        (!stmts.is_empty() && !stmts.iter().any(is_unparsed_statement)).then_some(stmts)
    }
}

/// Bytes of built text one run holds. Past it a text is not read: a reader
/// of it learns nothing of its statements.
const BUILT_TEXT_BYTES: usize = 16 * 1024 * 1024;

/// The texts one run builds, found by a hash of the text four bits a
/// level, each with the parse its readers hold. Insert-only.
#[derive(Default)]
struct BuiltTexts {
    root: BuiltSlots,
    /// Bytes of text held, of [`BUILT_TEXT_BYTES`].
    held: std::cell::Cell<usize>,
}

#[derive(Default)]
struct BuiltSlots([std::cell::OnceCell<Box<BuiltNode>>; 16]);

struct BuiltNode {
    text: String,
    /// The text's parse, while a reader holds it.
    parse: std::cell::RefCell<std::rc::Weak<BuiltText>>,
    /// The texts whose hash this node's path also leads to.
    below: BuiltSlots,
}

impl BuiltTexts {
    /// The parse of `text`: the one a reader holds, else made by `parse`;
    /// `None` where `text` is met first past [`BUILT_TEXT_BYTES`].
    fn get_or_parse(
        &self,
        text: &str,
        parse: &dyn Fn(&str) -> Option<ast::AstScript>,
    ) -> Option<std::rc::Rc<BuiltText>> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut hasher);
        let mut hash = hasher.finish();
        let mut slots = &self.root;
        loop {
            let slot = &slots.0[(hash & 0xF) as usize];
            let node = match slot.get() {
                Some(node) => node,
                None => {
                    let held = self.held.get() + text.len();
                    if held > BUILT_TEXT_BYTES {
                        return None;
                    }
                    self.held.set(held);
                    slot.get_or_init(|| {
                        Box::new(BuiltNode {
                            text: text.to_string(),
                            parse: std::cell::RefCell::default(),
                            below: BuiltSlots::default(),
                        })
                    })
                }
            };
            if node.text == text {
                if let Some(held) = node.parse.borrow().upgrade() {
                    return Some(held);
                }
                let built = std::rc::Rc::new(BuiltText {
                    text: text.to_string(),
                    script: parse(text),
                });
                *node.parse.borrow_mut() = std::rc::Rc::downgrade(&built);
                return Some(built);
            }
            slots = &node.below;
            hash >>= 4;
        }
    }
}

impl DynamicBodies {
    /// The SQL text the string literals `fold` holds as the dynamic SQL
    /// the script `src` runs, read under `dialect` with the whole budget,
    /// its texts kept for analysis where it is `analysed`; `deciding`, where
    /// given, the relation reading of the script, which decides what the
    /// text of each run it met writes ([`MetRun`]).
    fn read(
        src: &str,
        fold: &ScriptContextFold,
        dialect: &dialect::DialectRef,
        analysed: bool,
        deciding: Option<(&mut RelationReading<'_>, &[MetRun])>,
    ) -> Self {
        let run = std::rc::Rc::new(RunReading {
            dialect: dialect.clone(),
            budget: std::cell::Cell::new(BodyBudget::FULL),
            built: BuiltTexts::default(),
        });
        Self::read_at(src, fold, 0, run, analysed, deciding)
    }

    /// A reading of no SQL text, under `dialect`: what it lends is the parse
    /// of each text built ([`Self::built`]), for an analysis of text no
    /// script runs (a routine another script of a run defines).
    pub fn lending(dialect: &dialect::DialectRef) -> Self {
        let run = std::rc::Rc::new(RunReading {
            dialect: dialect.clone(),
            budget: std::cell::Cell::new(BodyBudget::FULL),
            built: BuiltTexts::default(),
        });
        Self::read_literals(
            "",
            &[],
            &std::collections::BTreeSet::new(),
            0,
            run,
            false,
            None,
        )
    }

    fn read_at(
        src: &str,
        fold: &ScriptContextFold,
        depth: usize,
        run: std::rc::Rc<RunReading>,
        analysed: bool,
        deciding: Option<(&mut RelationReading<'_>, &[MetRun])>,
    ) -> Self {
        Self {
            routine_runs: fold.routine_runs.clone(),
            ..Self::read_literals(
                src,
                &fold.dynamic_sql_literals,
                &fold.run_as_written,
                depth,
                run,
                analysed,
                deciding,
            )
        }
    }

    /// What the text of the literal at `literal`, which a statement of the
    /// script runs whole, writes, as decided where the statement runs;
    /// `None` where no relation reading met that statement.
    fn run_writes(&self, literal: lexer::token::Span) -> Option<&facts::secrets::WrittenColumns> {
        self.run_writes.get(&(literal.start, literal.end))
    }

    /// Each argument of a call in the script that a routine of the dialect
    /// runs as SQL ([`dialect::Dialect::system_routine`]), with the
    /// statement that makes the call.
    pub fn routine_runs(&self) -> &[RoutineRun] {
        &self.routine_runs
    }

    /// Each literal the script runs whose every run is read, with the parts
    /// of it a report masks where it quotes the literal's SQL text.
    fn run_texts(&self) -> impl Iterator<Item = (lexer::token::Span, &[lexer::token::Span])> {
        self.run_texts.iter().filter_map(|((start, end), masked)| {
            masked.as_deref().map(|masked| {
                (
                    lexer::token::Span {
                        start: *start,
                        end: *end,
                    },
                    masked,
                )
            })
        })
    }

    /// Notes what a report masks of the literal at `literal` where one run
    /// of it is quoted: `None` where that run is not read.
    fn note_run_text(
        &mut self,
        literal: lexer::token::Span,
        masked: Option<Vec<lexer::token::Span>>,
    ) {
        let held = self
            .run_texts
            .entry((literal.start, literal.end))
            .or_insert_with(|| Some(Vec::new()));
        match (held.as_mut(), masked) {
            (Some(held), Some(masked)) => held.extend(masked),
            (Some(_), None) | (None, Some(_) | None) => *held = None,
        }
    }

    /// `text`, a value written into SQL text the script runs, as a report
    /// quotes it: each of its string literals masked, as every literal of
    /// SQL text a script runs is (`reported_literals`).
    pub fn quoted_operand(&self, text: &str) -> String {
        reported_literals(None, text, self.run.dialect.as_ref(), true, None).quote_fixed(text)
    }

    /// The SQL text `literals`, literals of `src` a script runs, are, read
    /// `depth` levels inside dynamic SQL; `run_as_written` are those run as
    /// written. Where `deciding` is given, the relation reading there
    /// decides what the text of each run of `src` it met writes: from the
    /// parse made here, else from its own ([`RelationReading::decide_unread`]).
    fn read_literals(
        src: &str,
        literals: &[ir::dynamic_sql::ExecutedLiteral],
        run_as_written: &std::collections::BTreeSet<(u32, u32)>,
        depth: usize,
        run: std::rc::Rc<RunReading>,
        analysed: bool,
        deciding: Option<(&mut RelationReading<'_>, &[MetRun])>,
    ) -> Self {
        let dialect = run.dialect.clone();
        let dialect = dialect.as_ref();
        let mut out = Self {
            depth,
            run,
            analysed,
            unparsed: Vec::new(),
            run_texts: std::collections::BTreeMap::new(),
            comment_spans: Vec::new(),
            read: std::collections::BTreeMap::new(),
            run_writes: std::collections::BTreeMap::new(),
            routine_runs: Vec::new(),
        };
        // The runs met, by the literal each runs.
        let (mut decider, met_runs) = match deciding {
            Some((decider, met)) => (Some(decider), met),
            None => (None, &[][..]),
        };
        let mut met: std::collections::BTreeMap<(u32, u32), Vec<&MetRun>> =
            std::collections::BTreeMap::new();
        for run in met_runs {
            met.entry((run.literal.start, run.literal.end))
                .or_default()
                .push(run);
        }
        // A literal run by two statements is read once, and decoded once for
        // every run that holds a part of it.
        let mut seen: std::collections::BTreeSet<(u32, u32)> = std::collections::BTreeSet::new();
        let mut decoded = DecodedLiterals::new();
        for executed in literals {
            match executed {
                // The whole text run: its statements, and the SQL they run.
                ir::dynamic_sql::ExecutedLiteral::Whole(literal) => {
                    if !seen.insert((literal.start, literal.end)) {
                        continue;
                    }
                    let Some((text, map)) = src
                        .get(literal.start as usize..literal.end as usize)
                        .and_then(|raw| {
                            ir::span_extract::decode_string_literal_text_with_map_in(raw, dialect)
                        })
                    else {
                        continue;
                    };
                    let outer = |span: lexer::token::Span| match (
                        map.get(span.start as usize),
                        map.get(span.end as usize),
                    ) {
                        (Some(start), Some(end)) => Some(lexer::token::Span {
                            start: literal.start + start,
                            end: literal.start + end,
                        }),
                        (Some(_), None) | (None, Some(_)) | (None, None) => None,
                    };
                    // The text is lexed once for everything the reading takes of it.
                    let tokens = lex_body(&text, dialect);
                    out.comment_spans
                        .extend(lexer::comment_spans(&tokens).into_iter().filter_map(outer));
                    // Only text run as written is a statement sequence; a literal
                    // a variable is built from is a piece of one.
                    let as_written = run_as_written.contains(&(literal.start, literal.end));
                    let runs = met.get(&(literal.start, literal.end));
                    let (script, tokens) = match out.parse(&text, tokens, dialect) {
                        BodyParse::Parsed(script, tokens) => (script, tokens),
                        BodyParse::Failed => {
                            if as_written {
                                out.unparsed.push(*literal);
                            }
                            out.note_run_text(*literal, None);
                            if let Some((decider, runs)) = decider.as_deref_mut().zip(runs) {
                                let (writes, _) = decider.decide_read(runs, &text, None);
                                out.run_writes.insert((literal.start, literal.end), writes);
                            }
                            continue;
                        }
                        BodyParse::NotRead => {
                            out.note_run_text(*literal, None);
                            continue;
                        }
                    };
                    // Text run as written that is statements, each of which
                    // parses, is quoted as its own statements are: their
                    // literals and secrets masked, each part mapped back.
                    let statements = as_written
                        && holds_a_statement(&script, &tokens)
                        && flat_stmts_for_rules(&script)
                            .into_iter()
                            .all(|stmt| !kept_as_written(stmt) && !is_unparsed_statement(stmt));
                    let masked = statements
                        .then(|| masked_in_literal(&script, &text, &map, *literal, dialect))
                        .flatten();
                    out.note_run_text(*literal, masked);
                    let kept = analysed && holds_a_statement(&script, &tokens);
                    drop(tokens);
                    // What the text writes, decided from this parse where a
                    // statement met runs it; the runs it holds, decided as
                    // its own literals are read.
                    let decided = decider
                        .as_deref_mut()
                        .zip(runs)
                        .map(|(decider, runs)| decider.decide_read(runs, &text, Some(&script)));
                    let body_fold = script_context_fold(&script, &text, dialect);
                    let inner = decider
                        .as_deref_mut()
                        .zip(decided.as_ref())
                        .map(|(decider, (_, inner))| (decider, inner.as_slice()));
                    let bodies = Self::read_at(
                        &text,
                        &body_fold,
                        depth + 1,
                        out.run.clone(),
                        analysed,
                        inner,
                    );
                    if let Some((mut writes, inner)) = decided {
                        for run in &inner {
                            match bodies.run_writes(run.literal) {
                                Some(theirs) => writes.merge(theirs),
                                None => writes.record_anything(),
                            }
                        }
                        out.run_writes.insert((literal.start, literal.end), writes);
                    }
                    out.comment_spans
                        .extend(bodies.comment_spans.iter().copied().filter_map(outer));
                    let own_unparsed = if as_written {
                        flat_stmts_for_rules(&script)
                            .into_iter()
                            .flat_map(unparsed_spans)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    out.unparsed.extend(
                        own_unparsed
                            .into_iter()
                            .chain(bodies.unparsed.iter().copied())
                            .map(|span| outer(span).unwrap_or(*literal)),
                    );
                    if kept {
                        out.read.insert(
                            (literal.start, literal.end),
                            RunBody {
                                text,
                                map,
                                fold: body_fold,
                                bodies,
                            },
                        );
                    }
                }
                // Pieces of a statement, cut anywhere: their text joined.
                // A part of a run is masked whole: what it writes into the
                // text is not read on its own.
                ir::dynamic_sql::ExecutedLiteral::Run(parts) => {
                    push_run_comment_spans(
                        src,
                        parts,
                        dialect,
                        &mut decoded,
                        &mut out.comment_spans,
                    );
                    for part in parts {
                        out.note_run_text(part.literal, None);
                    }
                }
            }
        }
        // A run met whose text was not parsed here (past the depth or the
        // budget, or not read as SQL text this text runs) is decided from
        // the relation reading's own parse.
        if let Some(decider) = decider {
            for (literal, runs) in &met {
                if !out.run_writes.contains_key(literal) {
                    let writes = decider.decide_unread(runs, src);
                    out.run_writes.insert(*literal, writes);
                }
            }
        }
        out
    }

    /// `text`, one level deeper than this reading, parsed under `dialect`
    /// from `tokens`, the tokens it lexes to, and charged to the budget; not
    /// read where it is blank or past the depth or the budget.
    fn parse(
        &self,
        text: &str,
        tokens: Vec<lexer::Token>,
        dialect: &dyn dialect::Dialect,
    ) -> BodyParse {
        if self.depth >= BodyBudget::MAX_DEPTH || text.trim().is_empty() || !self.charge(text) {
            return BodyParse::NotRead;
        }
        match parse_body(text, &tokens, dialect) {
            Some(script) => BodyParse::Parsed(script, tokens),
            None => BodyParse::Failed,
        }
    }

    /// Charge one body of `text`'s length to the budget: `false` past it,
    /// where nothing is charged.
    fn charge(&self, text: &str) -> bool {
        let mut left = self.run.budget.get();
        let bytes = text.len() as u64;
        if left.bodies == 0 || left.bytes < bytes {
            return false;
        }
        left.bodies -= 1;
        left.bytes -= bytes;
        self.run.budget.set(left);
        true
    }

    /// The parse of SQL text `text` the script or the SQL it runs builds,
    /// read as this run reads: lent to every reader, at any level, while one
    /// holds it, and freed when none does. It is not charged to the budget,
    /// and a level past the depth reads it too. `None` where `text` is
    /// blank, or met first once the run holds `BUILT_TEXT_BYTES` of built
    /// text.
    pub fn built(&self, text: &str) -> Option<std::rc::Rc<BuiltText>> {
        if text.trim().is_empty() {
            return None;
        }
        let dialect = self.run.dialect.as_ref();
        self.run.built.get_or_parse(text, &|text| {
            let tokens = lexer::tokenize_with_dialect(text, dialect).tokens;
            parser::try_parse_script_with_dialect(text, &tokens, dialect).ok()
        })
    }

    /// The analysis by `reasoning`, under `config`, of the text the string
    /// literal at `literal` runs, its text parsed again as the reading parsed
    /// it, the SQL text it runs in turn read with it; with the text and the
    /// offset in the literal of each of its bytes and of its end. `None`
    /// where the text was not parsed, holds no statement that parses cut
    /// from the rest where the literal cuts it, or could not be analysed.
    pub fn analyze_literal(
        &self,
        literal: lexer::token::Span,
        reasoning: &dyn facts::reasoning::Reasoning,
        config: &analyzer::AnalysisConfig,
    ) -> Option<(analyzer::AnalysisReport, &str, &[u32])> {
        let body = self.read.get(&(literal.start, literal.end))?;
        let dialect = self.run.dialect.as_ref();
        let tokens = lexer::tokenize_with_dialect(&body.text, dialect).tokens;
        let script = parse_body(&body.text, &tokens, dialect)?;
        drop(tokens);
        let report = analyze_with_run_bodies(
            &template::RenderArtifacts::raw(body.text.clone()),
            &script,
            Some((&body.fold, &body.bodies)),
            config,
            None,
            None,
            None,
            None,
            None,
            reasoning,
            false,
            None,
        )
        .ok()?;
        Some((report.0, body.text.as_str(), body.map.as_slice()))
    }

    /// The analysis by `reasoning`, under `config`, of the SQL text
    /// `built` the script builds and runs ([`Self::built`]), one level
    /// deeper than the text this reading is of: charged to the budget, and
    /// analysed where every statement of it parses, the SQL text it runs in
    /// turn read with it. `None` past the depth or the budget.
    pub fn analyze_built(
        &self,
        built: &BuiltText,
        reasoning: &dyn facts::reasoning::Reasoning,
        config: &analyzer::AnalysisConfig,
    ) -> Option<analyzer::AnalysisReport> {
        if self.depth >= BodyBudget::MAX_DEPTH || !self.charge(&built.text) {
            return None;
        }
        let script = built.script.as_ref()?;
        if script.stmts.is_empty() || script.stmts.iter().any(is_unparsed_statement) {
            return None;
        }
        let text = built.text.as_str();
        let dialect = config.dialect.clone().unwrap_or_else(dialect::snowflake);
        let fold = script_context_fold(script, text, dialect.as_ref());
        let bodies = Self::read_at(
            text,
            &fold,
            self.depth + 1,
            self.run.clone(),
            self.analysed,
            None,
        );
        analyze_with_run_bodies(
            &template::RenderArtifacts::raw(text.to_string()),
            script,
            Some((&fold, &bodies)),
            config,
            None,
            None,
            None,
            None,
            None,
            reasoning,
            false,
            None,
        )
        .ok()
        .map(|(report, ..)| report)
    }

    /// Charge one statement reporting the findings of a body it runs:
    /// `false` past the budget, where its body's findings are not reported.
    pub fn charge_sink(&self) -> bool {
        let mut left = self.run.budget.get();
        if left.sinks == 0 {
            return false;
        }
        left.sinks -= 1;
        self.run.budget.set(left);
        true
    }
}

#[cfg(test)]
std::thread_local! {
    /// How many texts of string literals a script runs this thread has
    /// parsed.
    static BODY_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many texts of string literals a script runs this thread has parsed.
#[cfg(test)]
fn body_parses() -> usize {
    BODY_PARSES.with(std::cell::Cell::get)
}

#[cfg(test)]
std::thread_local! {
    /// How many texts of string literals a script runs this thread has
    /// lexed for the run's reading of them.
    static BODY_LEXINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many texts of string literals a script runs this thread has lexed
/// for the run's reading of them.
#[cfg(test)]
fn body_lexings() -> usize {
    BODY_LEXINGS.with(std::cell::Cell::get)
}

/// The tokens `dialect`'s lexer reads the text of a string literal a script
/// runs as, for the run's reading of it.
fn lex_body(text: &str, dialect: &dyn dialect::Dialect) -> Vec<lexer::Token> {
    #[cfg(test)]
    BODY_LEXINGS.with(|lexings| lexings.set(lexings.get() + 1));
    lexer::tokenize_with_dialect(text, dialect).tokens
}

/// The text of a string literal a script runs, parsed under `dialect` from
/// `tokens`, the tokens it lexes to; `None` where it does not parse.
fn parse_body(
    text: &str,
    tokens: &[lexer::Token],
    dialect: &dyn dialect::Dialect,
) -> Option<ast::AstScript> {
    #[cfg(test)]
    BODY_PARSES.with(|parses| parses.set(parses.get() + 1));
    parser::try_parse_script_with_dialect(text, tokens, dialect).ok()
}

/// What [`DynamicBodies::parse`] made of a text.
enum BodyParse {
    /// Not parsed: blank, or past the depth or the budget.
    NotRead,
    /// It does not parse.
    Failed,
    /// Its parse, with the tokens it was read from.
    Parsed(ast::AstScript, Vec<lexer::Token>),
}

/// Whether the routine `stmt` defines runs what is not established: its
/// body is in a language the dialect does not read as SQL, no statement of
/// it was read, or one, at any depth, does not parse.
pub fn definition_unread(stmt: &ast::AstStmt) -> bool {
    if let ast::AstStmt::CreateProcedure(procedure) = stmt {
        match procedure.language {
            ast::AstRoutineLanguage::Sql => {}
            ast::AstRoutineLanguage::Other(_) => return true,
        }
    }
    let mut read = false;
    for body in stmt.bodies() {
        for inner in body.stmts {
            read = true;
            let mut held = Vec::new();
            flatten_stmts_for_rules(inner, &mut held);
            if held.iter().any(|held| kept_as_written(held)) {
                return true;
            }
        }
    }
    !read
}

/// Whether the parser kept `stmt` as written, reading nothing of what it
/// does: a statement that does not parse, or a block's statement read as
/// no assignment (`EXEC p @v` in a MySQL or BigQuery block).
fn kept_as_written(stmt: &ast::AstStmt) -> bool {
    coverage_class(stmt) == CoverageClass::Skipped
        || matches!(
            stmt,
            ast::AstStmt::Assign {
                assign_op_span: None,
                ..
            }
        )
}

fn is_unparsed_statement(stmt: &ast::AstStmt) -> bool {
    matches!(
        stmt,
        ast::AstStmt::OpaqueContent { .. } | ast::AstStmt::Error { .. }
    )
}

/// Whether the text a string literal runs, parsed to `script` from
/// `tokens`, holds a statement that parses, cut from the rest where the
/// literal cuts it. The literal is SQL the script runs, read statement by
/// statement as a script is. A statement that parses straight after one
/// that does not, with no `;` before it, is the parser's recovery, not the
/// literal's: such a text is a fragment (`col1, col2, drop table x`) or data
/// (a file path `C:\…\drop table.sql`), and holds none.
fn holds_a_statement(script: &ast::AstScript, tokens: &[lexer::Token]) -> bool {
    // The tokens are in source order: those ending by `start` lead the list.
    let cut_before = |start: u32| {
        tokens[..tokens.partition_point(|t| t.span.end <= start)]
            .iter()
            .rev()
            .filter(|t| {
                !matches!(
                    t.kind,
                    lexer::TokenKind::LineComment
                        | lexer::TokenKind::BlockComment
                        | lexer::TokenKind::Eof
                )
            })
            .map(|t| {
                matches!(
                    t.kind,
                    lexer::TokenKind::Punctuation(lexer::Punctuation::Semi)
                )
            })
            .next()
            .unwrap_or(true)
    };
    let mut parsed = false;
    let mut after_unparsed = false;
    for stmt in &script.stmts {
        if is_unparsed_statement(stmt) {
            after_unparsed = true;
            continue;
        }
        if after_unparsed && !cut_before(stmt.span().start) {
            return false;
        }
        after_unparsed = false;
        parsed = true;
    }
    parsed
}
/// Each string literal decoded, with the source offset of each decoded
/// byte, by its span; `None` for one that does not decode.
type DecodedLiterals = std::collections::BTreeMap<(u32, u32), Option<(String, Vec<u32>)>>;

/// The comments, onto `comments`, of the SQL text a run of literal operands
/// makes: the text of each part ([`ir::dynamic_sql::RunPart`]), decoded
/// (once per literal, in `decoded_literals`), joined in order and read by
/// [`lexer::comment_spans`], each span found mapped back onto the part or
/// parts it falls in.
fn push_run_comment_spans(
    src: &str,
    parts: &[ir::dynamic_sql::RunPart],
    dialect: &dyn dialect::Dialect,
    decoded_literals: &mut DecodedLiterals,
    comments: &mut Vec<lexer::token::Span>,
) {
    // The joined text; for each part, the range of it the part wrote, the
    // source offset of each of its bytes and of the end.
    let mut text = String::new();
    let mut pieces: Vec<(usize, Vec<u32>)> = Vec::new();
    for part in parts {
        let literal = part.literal;
        let Some(raw) = src.get(literal.start as usize..literal.end as usize) else {
            continue;
        };
        if part.quoted {
            // The literal as written, quotes and all.
            pieces.push((text.len(), (literal.start..=literal.end).collect()));
            text.push_str(raw);
            continue;
        }
        let Some((decoded, map)) = decoded_literals
            .entry((literal.start, literal.end))
            .or_insert_with(|| {
                ir::span_extract::decode_string_literal_text_with_map_in(raw, dialect)
            })
            .as_ref()
        else {
            continue;
        };
        let at = |k: usize| literal.start + map[k];
        let (from, to) = match part.within {
            None => (0, decoded.len()),
            Some(within) => ir::dynamic_sql::decoded_range(decoded, map, literal.start, within),
        };
        pieces.push((text.len(), (from..=to).map(at).collect()));
        text.push_str(&decoded[from..to]);
    }
    // Each span of the joined text, onto `into` as the source spans of the
    // parts it falls in.
    let map_back = |span: lexer::token::Span, into: &mut Vec<lexer::token::Span>| {
        let (start, end) = (span.start as usize, span.end as usize);
        // The parts the span falls in, from the first that ends after its start.
        let first = pieces.partition_point(|(offset, sources)| offset + sources.len() - 1 <= start);
        for (offset, sources) in pieces[first..]
            .iter()
            .take_while(|(offset, _)| *offset < end)
        {
            let len = sources.len() - 1;
            let from = start.max(*offset);
            let to = end.min(offset + len);
            if from < to {
                into.push(lexer::token::Span {
                    start: sources[from - offset],
                    end: sources[to - offset],
                });
            }
        }
    };
    let tokens = lexer::tokenize_with_dialect(&text, dialect).tokens;
    for span in lexer::comment_spans(&tokens) {
        map_back(span, comments);
    }
}

/// The analysed text as a report quotes it: the source with every span the
/// report masks overwritten byte for byte, and the comments the lexer read
/// in it, which no quote reproduces. Every preview, statement prefix and
/// trace preview of a report is cut from it.
#[derive(Clone, Copy)]
struct QuotedSource<'a> {
    text: &'a str,
    /// In source order, none overlapping another.
    comments: &'a [lexer::token::Span],
    /// What `text` overwrites, in source order, none touching another:
    /// each printed as one mask ([`facts::secrets::masked_fixed`]).
    masked: &'a [lexer::token::Span],
}

impl<'a> QuotedSource<'a> {
    /// The text from `start` to `end`, each comment in it left out with the
    /// whitespace around it, one space standing where it separated two
    /// tokens. `None` where a bound is not a char boundary of the text.
    fn text(&self, start: usize, end: usize) -> Option<Cow<'a, str>> {
        let text = self.text;
        let piece = |from: usize, to: usize| -> Option<Cow<'a, str>> {
            text.get(from..to)?;
            Some(facts::secrets::masked_fixed(text, from, to, self.masked))
        };
        let first = self
            .comments
            .partition_point(|comment| comment.end as usize <= start);
        let mut within = self.comments[first..]
            .iter()
            .take_while(|comment| (comment.start as usize) < end)
            .peekable();
        if within.peek().is_none() {
            return piece(start, end);
        }
        let mut out = String::with_capacity(end.saturating_sub(start));
        let mut at = start;
        for comment in within {
            let from = (comment.start as usize).clamp(at, end);
            let to = (comment.end as usize).clamp(from, end);
            out.push_str(&piece(at, from)?);
            out.truncate(out.trim_end().len());
            let rest = text.get(to..end)?;
            at = end - rest.trim_start().len();
            if !out.is_empty() && at < end {
                out.push(' ');
            }
        }
        out.push_str(&piece(at, end)?);
        Some(Cow::Owned(out))
    }

    /// A finding's preview of the statement at `span`: its words on one line,
    /// to 80 characters. Whitespace is collapsed before the text is cut, so
    /// re-indenting a statement leaves its preview, and the fingerprint read
    /// from it, as they were.
    fn finding_preview(&self, span: lexer::token::Span) -> Option<String> {
        let start = (span.start as usize).min(self.text.len());
        let end = (span.end as usize).min(self.text.len());
        self.text(start, end).map(|text| {
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(80)
                .collect()
        })
    }

    /// A trace's preview of the statement at `span`: its words on one line,
    /// to 80 characters and an ellipsis.
    fn statement_preview(&self, span: lexer::token::Span) -> String {
        const PREVIEW_LEN: usize = 80;
        let start = (span.start as usize).min(self.text.len());
        let end = (span.end as usize).min(self.text.len()).max(start);
        let raw = self.text(start, end).unwrap_or_default();
        let trimmed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        if trimmed.chars().count() <= PREVIEW_LEN {
            trimmed
        } else {
            let truncated: String = trimmed.chars().take(PREVIEW_LEN).collect();
            format!("{}…", truncated)
        }
    }

    /// The first line of the first `max` bytes of the statement at `span`,
    /// its comments left out, trimmed.
    fn prefix(&self, span: lexer::token::Span, max: usize) -> String {
        let start = floor_char_boundary(self.text, span.start as usize);
        let stop = (span.end as usize).min(self.text.len()).max(start);
        // Enough of the statement that `max` bytes are left once each comment
        // in it is left out.
        let mut end = (start + max).min(stop);
        let first = self
            .comments
            .partition_point(|comment| comment.end as usize <= start);
        for comment in &self.comments[first..] {
            if comment.start as usize >= end || end == stop {
                break;
            }
            end = (end + (comment.end - comment.start) as usize).min(stop);
        }
        let end = floor_char_boundary(self.text, end).max(start);
        let text = self.text(start, end).unwrap_or_default();
        let cut = floor_char_boundary(&text, max.min(text.len()));
        text[..cut].lines().next().unwrap_or("").trim().to_string()
    }
}

/// The facts the DDL families derive for `stmt`, read with `ddl`, onto
/// `out`: none for a statement no DDL family reads, one for most, and one
/// per sink a call of a routine reaches. `stmt` is read with the function
/// catalog in force at its start; `facts_out` is told of a DDL target no
/// catalog is asked for.
fn ddl_statement_facts(
    stmt: &ast::AstStmt,
    ddl: &DdlReading<'_>,
    script_reasoning: &dyn facts::reasoning::ScriptReasoning,
    facts_out: Option<&mut StatementFactsSink<'_>>,
    out: &mut Vec<facts::StatementFacts>,
) {
    let DdlReading {
        sql,
        placeholders,
        fold,
        functions,
        reasoning,
        query,
        handlers: _,
        ref routine_calls,
    } = *ddl;
    // Dynamic-SQL argument classifier over the whole script: a bare
    // variable argument resolves to the shape it was assigned, so
    // via-variable injection patterns classify as the built shape.
    let dynamic_sql = script_reasoning.dynamic_sql();
    // The texts its variables hold name what `IDENTIFIER($v)` names.
    let _values = fold.enter_statement(stmt.span().start);
    let function_catalog = functions.at(stmt.span().start);
    let stage_plan = match stmt {
        ast::AstStmt::CreateStage(s) => {
            Some(ir::lower_create_stage_to_stage_plan(s, sql, placeholders))
        }
        ast::AstStmt::AlterStage(s) => {
            Some(ir::lower_alter_stage_to_stage_plan(s, sql, placeholders))
        }
        ast::AstStmt::CopyIntoLocation {
            node_id,
            span,
            from_span,
            location_url,
            location_url_span,
            credentials,
            copy_options,
            ..
        } => Some(ir::lower_copy_into_location_to_stage_plan(
            *span,
            *node_id,
            *from_span,
            sql,
            ir::StageLocation {
                url: location_url.as_deref(),
                span: *location_url_span,
                placeholders,
            },
            credentials,
            copy_options,
        )),
        ast::AstStmt::CopyIntoTable {
            node_id,
            span,
            table_name,
            copy_options,
            from_location_url,
            from_location_url_span,
            credentials,
            ..
        } => Some(ir::lower_copy_into_table_to_stage_plan(
            *span,
            *node_id,
            table_name.span,
            sql,
            ir::StageLocation {
                url: from_location_url.as_deref(),
                span: *from_location_url_span,
                placeholders,
            },
            credentials,
            copy_options,
        )),
        ast::AstStmt::Unload {
            node_id,
            span,
            query_span,
            source,
            location_url,
            location_url_span,
            credentials,
            ..
        } => Some(ir::lower_unload_to_stage_plan(
            *span,
            *node_id,
            sql,
            *query_span,
            source.as_ref(),
            ir::StageLocation {
                url: location_url.as_deref(),
                span: *location_url_span,
                placeholders,
            },
            credentials,
        )),
        ast::AstStmt::RedshiftCopy {
            node_id,
            span,
            location_url,
            location_url_span,
            credentials,
            ..
        } => Some(ir::lower_redshift_copy_to_stage_plan(
            *span,
            *node_id,
            sql,
            ir::StageLocation {
                url: location_url.as_deref(),
                span: *location_url_span,
                placeholders,
            },
            credentials,
        )),
        ast::AstStmt::Drop(s) => ir::lower_drop_stage_to_stage_plan(s, sql),
        _ => None,
    };
    if let Some(plan) = stage_plan {
        let mut facts = facts::extract::derive_facts_from_stage_plan(&plan, sql);
        // A COPY INTO <location> or an UNLOAD: the columns its source
        // unloads out of the warehouse, each classified as the query it
        // reads is.
        if let ast::AstStmt::CopyIntoLocation {
            source: Some(src), ..
        }
        | ast::AstStmt::Unload {
            source: Some(src), ..
        } = stmt
        {
            let exported = unload_query_facts(src, query)
                .and_then(|read| read.query)
                .map(|read| script_reasoning.exported_columns(&read))
                .unwrap_or_default();
            if let Some(stage) = facts.ddl.as_mut().and_then(|d| d.stage.as_mut()) {
                stage.exported_columns = exported;
            }
        }
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Table dispatch must come AFTER the dynamic-table dispatch
    // because both can claim a generic `AstStmt::Drop`; the
    // dynamic-table lowering returns `Some` only for `DROP DYNAMIC
    // TABLE`, so falling through here to the table lowering
    // (`DROP TABLE`) is correct.
    // Each plan with the name the statement's existing table carries.
    let table_plan = match stmt {
        ast::AstStmt::CreateTable(s) => Some((ir::lower_create_table_to_table_plan(s, sql), None)),
        ast::AstStmt::AlterTable(s) => {
            Some((ir::lower_alter_table_to_table_plan(s, sql), Some(&s.name)))
        }
        ast::AstStmt::MysqlRenameTable(s) => {
            Some((ir::lower_mysql_rename_table_to_table_plan(s, sql), None))
        }
        ast::AstStmt::Truncate(s) => Some((
            ir::lower_truncate_to_table_plan(s, sql),
            s.target_table.as_ref(),
        )),
        ast::AstStmt::DropAllRowAccessPolicies(s) => Some((
            ir::lower_drop_all_row_access_policies_to_table_plan(s, sql),
            None,
        )),
        ast::AstStmt::Drop(s) => {
            ir::lower_drop_table_to_table_plan(s, sql).map(|plan| (plan, s.target_name.as_ref()))
        }
        _ => None,
    };
    if let Some((plan, existing_name)) = table_plan {
        if let Some(sink) = facts_out {
            if existing_name.is_some_and(|name| !ir::lower::names_a_catalog_object(name.name_kind))
            {
                sink.record_uncatalogued_ddl_target(stmt.span());
            }
        }
        let mut facts = facts::extract::derive_facts_from_table_plan(&plan, sql);
        // A table an earlier statement of the script made temporary; a
        // CREATE states its own. A `TRUNCATE` of a list truncates temporary
        // tables alone where each it lists is one.
        let start = stmt.span().start;
        let creates = matches!(stmt, ast::AstStmt::CreateTable(_));
        let targets = plan.tables();
        let made_temporary = !creates
            && !targets.is_empty()
            && targets.iter().all(|target| {
                let named = crate::context::node_metadata::TableRef {
                    server: None,
                    db: target.db.clone(),
                    schema: target.schema.clone(),
                    name: target.name.clone(),
                    span: None,
                };
                target.temporary
                    || query
                        .relations
                        .relations
                        .at(start)
                        .temporary(&named, &fold.session_context_at(start))
            });
        if made_temporary {
            if let Some(table) = facts.ddl.as_mut().and_then(|ddl| ddl.table.as_mut()) {
                table.temporary = true;
            }
        }
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            let mut facts = facts::extract::derive_facts_from_view_ddl_plan(&plan, kind);
            // The view lowers through the generic DdlPlan, so the MySQL
            // security-context prelude (DEFINER / SQL SECURITY) and the
            // action of an ALTER are projected straight from the AST here
            // and attached to `ddl.view`.
            if let ast::AstStmt::CreateView(cv) = stmt {
                if let Some(ddl) = facts.ddl.as_mut() {
                    ddl.view = facts::extract::project_view_prelude_facts(cv, sql);
                }
            }
            if let ast::AstStmt::AlterView(av) = stmt {
                if let Some(ddl) = facts.ddl.as_mut() {
                    ddl.view = Some(facts::extract::project_alter_view_facts(av));
                }
            }
            if let ast::AstStmt::AlterMaterializedView(mv) = stmt {
                if let Some(ddl) = facts.ddl.as_mut() {
                    ddl.view = Some(facts::extract::project_alter_materialized_view_facts(mv));
                }
            }
            out.push(facts);
        }
        return;
    }

    let pipe_plan = match stmt {
        ast::AstStmt::CreatePipe(s) => Some(ir::lower_create_pipe_to_pipe_plan(s, sql)),
        ast::AstStmt::AlterPipe(s) => Some(ir::lower_alter_pipe_to_pipe_plan(s, sql)),
        ast::AstStmt::DropPipe(s) => Some(ir::lower_drop_pipe_to_pipe_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = pipe_plan {
        let facts = facts::extract::derive_facts_from_pipe_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Snowflake CREATE / ALTER / DROP FILE FORMAT — surfaces
    // `ddl.file_format.*` facts (recognized type, rename target).
    let file_format_plan = match stmt {
        ast::AstStmt::CreateFileFormat(s) => Some(ir::lower_create_file_format_to_plan(s, sql)),
        ast::AstStmt::AlterFileFormat(s) => Some(ir::lower_alter_file_format_to_plan(s, sql)),
        ast::AstStmt::Drop(s) => {
            drop_target_is_file_format(s, sql).then(|| ir::lower_drop_file_format_to_plan(s, sql))
        }
        _ => None,
    };
    if let Some(plan) = file_format_plan {
        let facts = facts::extract::derive_facts_from_file_format_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // Snowflake ALTER SESSION SET/UNSET — session-parameter mutation.
    // Surfaces `ddl.session.*` facts (parameters configured / reset).
    let session_plan = match stmt {
        ast::AstStmt::AlterSession(s) => Some(ir::lower_alter_session_to_session_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = session_plan {
        let facts = facts::extract::derive_facts_from_session_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let stream_plan = match stmt {
        ast::AstStmt::CreateStream(s) => Some(ir::lower_create_stream_to_stream_plan(s, sql)),
        ast::AstStmt::DropStream(s) => Some(ir::lower_drop_stream_to_stream_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = stream_plan {
        let facts = facts::extract::derive_facts_from_stream_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Snowflake EXTERNAL FUNCTION — a UDF that ships row data to an
    // external HTTPS endpoint via an API integration (`ddl.external_function.*`),
    // a data-egress surface. ALTER/DROP route through the regular function
    // paths; only CREATE carries the egress recognition surface.
    if let ast::AstStmt::CreateExternalFunction(s) = stmt {
        let plan = ir::lower_create_external_function_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_external_function_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Snowflake SERVICE — SPCS container service (`ddl.service.*`); the
    // recognition surface is the compute-pool binding and
    // EXTERNAL_ACCESS_INTEGRATIONS (egress). DROP arrives as a generic Drop
    // gated on the object type.
    let service_plan = match stmt {
        ast::AstStmt::CreateService(s) => Some(ir::lower_create_service_to_service_plan(s, sql)),
        ast::AstStmt::AlterService(s) => Some(ir::lower_alter_service_to_service_plan(s, sql)),
        ast::AstStmt::Drop(s) => {
            drop_target_is_service(s, sql).then(|| ir::lower_drop_service_to_service_plan(s, sql))
        }
        _ => None,
    };
    if let Some(plan) = service_plan {
        let facts = facts::extract::derive_facts_from_service_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // Snowflake NOTEBOOK — code-from-stage object (`ddl.notebook.*`); the
    // recognition surface is EXTERNAL_ACCESS_INTEGRATIONS (egress). DROP
    // arrives as a generic Drop gated on the object type.
    let notebook_plan = match stmt {
        ast::AstStmt::CreateNotebook(s) => Some(ir::lower_create_notebook_to_notebook_plan(s, sql)),
        ast::AstStmt::AlterNotebook(s) => Some(ir::lower_alter_notebook_to_notebook_plan(s, sql)),
        ast::AstStmt::Drop(s) => drop_target_is_notebook(s, sql)
            .then(|| ir::lower_drop_notebook_to_notebook_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = notebook_plan {
        let facts = facts::extract::derive_facts_from_notebook_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Snowflake Native Apps: APPLICATION (consumer-installed app,
    // `ddl.application.*`); the recognition surface is the install-source
    // provenance and DEBUG_MODE. DROP arrives as a generic Drop gated on
    // the object type.
    let application_plan = match stmt {
        ast::AstStmt::CreateApplication(s) => Some(ir::lower_create_application_to_plan(s, sql)),
        ast::AstStmt::AlterApplication(s) => Some(ir::lower_alter_application_to_plan(s, sql)),
        ast::AstStmt::Drop(s) => {
            drop_target_is_application(s, sql).then(|| ir::lower_drop_application_to_plan(s, sql))
        }
        _ => None,
    };
    if let Some(plan) = application_plan {
        let facts = facts::extract::derive_facts_from_application_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    // Snowflake client file commands: PUT / GET / REMOVE / LIST. The
    // operation kind is the recognition surface (GET = data egress to the
    // client; REMOVE = stage file deletion).
    if let ast::AstStmt::StageFileCommand(s) = stmt {
        let plan = ir::lower_stage_file_command_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_stage_file_command_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    let schema_plan = match stmt {
        ast::AstStmt::CreateSchema(s) => Some(ir::lower_create_schema_to_schema_plan(s, sql)),
        ast::AstStmt::AlterSchema(s) => Some(ir::lower_alter_schema_to_schema_plan(s, sql)),
        ast::AstStmt::DropSchema(s) => Some(ir::lower_drop_schema_to_schema_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = schema_plan {
        let facts = facts::extract::derive_facts_from_schema_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let catalog_plan = match stmt {
        ast::AstStmt::CreateCatalog(s) => Some(ir::lower_create_catalog_to_catalog_plan(s, sql)),
        ast::AstStmt::AlterCatalog(s) => Some(ir::lower_alter_catalog_to_catalog_plan(s, sql)),
        ast::AstStmt::DropCatalog(s) => Some(ir::lower_drop_catalog_to_catalog_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = catalog_plan {
        let facts = facts::extract::derive_facts_from_catalog_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let use_plan = match stmt {
        ast::AstStmt::Use(s) => Some(ir::lower_use_to_use_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = use_plan {
        let facts = facts::extract::derive_facts_from_use_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let task_plan = match stmt {
        ast::AstStmt::CreateTask(s) => Some(ir::lower_create_task_to_task_plan(s, sql)),
        ast::AstStmt::AlterTask(s) => Some(ir::lower_alter_task_to_task_plan(s, sql)),
        ast::AstStmt::DropTask(s) => Some(ir::lower_drop_task_to_task_plan(s, sql)),
        ast::AstStmt::ExecuteTask(s) => Some(ir::lower_execute_task_to_task_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = task_plan {
        let facts = facts::extract::derive_facts_from_task_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        let facts = facts::extract::derive_facts_from_replication_failover_group_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // Function dispatch. Generic `AstStmt::Drop` with object
    // type == `FUNCTION` is claimed here; the lowering returns
    // `None` for any other object type so the dispatch falls
    // through to the next family (procedure).
    let function_plan = match stmt {
        ast::AstStmt::CreateFunction(s) => Some(ir::lower_create_function_to_function_plan(
            s,
            sql,
            script_reasoning,
        )),
        ast::AstStmt::CreateTableFunction(s) => Some(
            ir::lower_create_table_function_to_function_plan(s, sql, script_reasoning),
        ),
        ast::AstStmt::AlterFunction(s) => Some(ir::lower_alter_function_to_function_plan(s, sql)),
        ast::AstStmt::Drop(s) => ir::lower_drop_function_to_function_plan(s, sql),
        ast::AstStmt::MysqlCreateLoadableFunction(s) => {
            Some(ir::lower_loadable_function_to_function_plan(s, sql))
        }
        _ => None,
    };
    if let Some(mut plan) = function_plan {
        // The sinks a function's body reaches in the routines it calls
        // are its body's, as a procedure's are.
        if let ast::AstStmt::CreateFunction(s) = stmt {
            let body = ir::procedure_plan::parsed_body(s.body_stmt.as_deref());
            if let (Some(shape), Some(body)) = (plan.create_body.as_mut(), body) {
                shape
                    .dynamic_sql_calls
                    .extend(script_reasoning.inter_procedural_calls(body, &s.params));
            }
        }
        let facts = facts::extract::derive_facts_from_function_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // Procedure dispatch. Generic `AstStmt::Drop` with object
    // type == `PROCEDURE` is claimed here; the earlier table /
    // stage / dynamic-table / function lowerings return `None`
    // for non-matching object types so this dispatch reliably
    // catches it.
    let procedure_plan = match stmt {
        ast::AstStmt::CreateProcedure(s) => Some(ir::lower_create_procedure_to_procedure_plan(
            s,
            sql,
            script_reasoning,
        )),
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
            for body in s.body_stmt.as_deref().into_iter().chain(&s.body_statements) {
                let inter_proc = script_reasoning.inter_procedural_calls(body, &s.params);
                if let Some(body_shape) = plan.create_body.as_mut() {
                    body_shape.dynamic_sql_calls.extend(inter_proc);
                }
            }
        }
        let facts = facts::extract::derive_facts_from_procedure_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let database_plan = match stmt {
        ast::AstStmt::CreateDatabase(s) => Some(ir::lower_create_database_to_database_plan(s, sql)),
        ast::AstStmt::AlterDatabase(s) => Some(ir::lower_alter_database_to_database_plan(s, sql)),
        ast::AstStmt::DropDatabase(s) => Some(ir::lower_drop_database_to_database_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = database_plan {
        let facts = facts::extract::derive_facts_from_database_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let warehouse_plan = match stmt {
        ast::AstStmt::CreateWarehouse(s) => {
            Some(ir::lower_create_warehouse_to_warehouse_plan(s, sql))
        }
        ast::AstStmt::AlterWarehouse(s) => {
            Some(ir::lower_alter_warehouse_to_warehouse_plan(s, sql))
        }
        ast::AstStmt::DropWarehouse(s) => Some(ir::lower_drop_warehouse_to_warehouse_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = warehouse_plan {
        let facts = facts::extract::derive_facts_from_warehouse_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let storage_credential_plan = match stmt {
        ast::AstStmt::CreateStorageCredential(s) => Some(
            ir::lower_create_storage_credential_to_storage_credential_plan(s, sql, placeholders),
        ),
        ast::AstStmt::AlterStorageCredential(s) => Some(
            ir::lower_alter_storage_credential_to_storage_credential_plan(s, sql, placeholders),
        ),
        ast::AstStmt::DropStorageCredential(s) => {
            Some(ir::lower_drop_storage_credential_to_storage_credential_plan(s))
        }
        _ => None,
    };
    if let Some(plan) = storage_credential_plan {
        let facts = facts::extract::derive_facts_from_storage_credential_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let volume_plan = match stmt {
        ast::AstStmt::CreateVolume(s) => Some(ir::lower_create_volume_to_volume_plan(s, sql)),
        ast::AstStmt::AlterVolume(s) => Some(ir::lower_alter_volume_to_volume_plan(s, sql)),
        ast::AstStmt::DropVolume(s) => Some(ir::lower_drop_volume_to_volume_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = volume_plan {
        let facts = facts::extract::derive_facts_from_volume_plan(&plan, sql);
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }

    if let ast::AstStmt::MssqlCreateExternalDataSource(s) = stmt {
        let plan = ir::lower_create_external_data_source_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_external_data_source_plan(&plan, sql);
        out.push(facts);
        return;
    }

    if let ast::AstStmt::MssqlAlterExternalDataSource(s) = stmt {
        let plan = ir::lower_alter_external_data_source_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_external_data_source_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let foreign_server_plan = match stmt {
        ast::AstStmt::CreateForeignServer(s) => {
            Some(ir::lower_create_foreign_server_to_plan(s, sql))
        }
        ast::AstStmt::AlterForeignServer(s) => Some(ir::lower_alter_foreign_server_to_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = foreign_server_plan {
        let facts = facts::extract::derive_facts_from_foreign_server_plan(&plan, sql);
        out.push(facts);
        return;
    }

    if let ast::AstStmt::MssqlAlterServerConfiguration(s) = stmt {
        let plan = ir::lower_mssql_alter_server_configuration_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_server_configuration_plan(&plan, sql);
        out.push(facts);
        return;
    }

    if let ast::AstStmt::MysqlLoadData(s) = stmt {
        let plan = ir::lower_mysql_load_data_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_mysql_load_data_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let event_plan = match stmt {
        ast::AstStmt::CreateEvent(s) => Some(ir::lower_create_event_to_plan(s, sql)),
        ast::AstStmt::AlterEvent(s) => Some(ir::lower_alter_event_to_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = event_plan {
        let facts = facts::extract::derive_facts_from_event_plan(&plan, sql);
        out.push(facts);
        // The DO body was flattened in as later entries, each read on
        // its own.
        return;
    }

    if let ast::AstStmt::CreateMysqlTrigger(s) = stmt {
        let plan = ir::lower_create_mysql_trigger_to_plan(s, sql);
        let mut facts = facts::extract::derive_facts_from_trigger_create_plan(&plan, sql);
        // Its body is projected as a T-SQL trigger's is.
        let mut body = ir::procedure_plan::project_mysql_trigger_body(s, sql, script_reasoning);
        if let (Some(shape), Some(body_stmt)) = (body.as_mut(), s.body_stmt.as_deref()) {
            shape
                .dynamic_sql_calls
                .extend(script_reasoning.inter_procedural_calls(body_stmt, &[]));
        }
        if let Some(ddl) = facts.ddl.as_mut() {
            ddl.trigger_body = body.as_ref().map(facts::extract::project_procedure_body);
        }
        out.push(facts);
        // The trigger body was flattened in as later entries, each read on
        // its own.
        return;
    }

    // T-SQL `CREATE` / `ALTER` / `CREATE OR ALTER TRIGGER`; its body was
    // flattened in as later entries, and is projected as a procedure's
    // body is, inter-procedural findings included.
    if let ast::AstStmt::CreateMssqlTrigger(s) = stmt {
        let plan = ir::lower_ddl::lower_mssql_trigger_definition(s, sql);
        let or_alter = matches!(s.verb, ast::AstDefinitionVerb::CreateOrAlter);
        let mut body = ir::procedure_plan::project_mssql_trigger_body(s, sql, script_reasoning);
        if let Some(shape) = body.as_mut() {
            for body_stmt in &s.body {
                shape
                    .dynamic_sql_calls
                    .extend(script_reasoning.inter_procedural_calls(body_stmt, &[]));
            }
        }
        if let Some(facts) =
            facts::extract::derive_facts_from_mssql_trigger_plan(&plan, or_alter, body.as_ref())
        {
            out.push(facts);
        }
        return;
    }

    if let ast::AstStmt::CreateForeignTable(s) = stmt {
        let plan = ir::lower_create_foreign_table_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_foreign_table_plan(&plan, sql);
        out.push(facts);
        return;
    }

    if let ast::AstStmt::ImportForeignSchema(s) = stmt {
        let plan = ir::lower_import_foreign_schema_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_import_foreign_schema_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let user_mapping_plan = match stmt {
        ast::AstStmt::CreateUserMapping(s) => Some(ir::lower_create_user_mapping_to_plan(s, sql)),
        ast::AstStmt::AlterUserMapping(s) => Some(ir::lower_alter_user_mapping_to_plan(s, sql)),
        ast::AstStmt::DropUserMapping(s) => Some(ir::lower_drop_user_mapping_to_plan(s, sql)),
        _ => None,
    };
    if let Some(plan) = user_mapping_plan {
        let facts = facts::extract::derive_facts_from_user_mapping_plan(&plan, sql);
        out.push(facts);
        return;
    }

    let flow_plan = match stmt {
        ast::AstStmt::CreateFlow(s) => Some(ir::lower_create_flow_to_flow_plan(s)),
        _ => None,
    };
    if let Some(plan) = flow_plan {
        let facts = facts::extract::derive_facts_from_flow_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // Tag the dialect-of-origin at the AST-variant match site —
    // each `AstStmt::*Policy` variant is constructed by exactly
    // one dialect's parser, so the variant itself carries the
    // dialect. The IR plan stays dialect-clean; the tag is
    // recovered here and threaded into the projection. Same
    // pattern as `PgDdlKind` / `MssqlDdlKind` for DDL statements.
    let policy_plan: Option<(ir::PolicyPlan, facts::extract::PolicyDialectOrigin)> = match stmt {
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
        out.push(facts);
        return;
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
        out.push(facts);
        return;
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
        ast::AstStmt::PgCreateTablespace(_) => Some(facts::extract::PgDdlKind::PgCreateTablespace),
        ast::AstStmt::PgAlterTablespace(_) => Some(facts::extract::PgDdlKind::PgAlterTablespace),
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
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            let facts = facts::extract::derive_facts_from_pg_ddl_plan(&plan, kind, sql);
            out.push(facts);
        }
        return;
    }

    // T-SQL BACKUP (data-protection utility — target Database/Log +
    // destination Disk/Url/Tape). Top-level `StatementFacts.mssql_backup`
    // (parallel to `pg_copy`) since BACKUP is not DDL. Drives
    // MSSQL-BACKUP-TO-URL / INFO-MSSQL-BACKUP.
    if let ast::AstStmt::MssqlBackup(s) = stmt {
        let plan = ir::lower_backup_to_backup_plan(s, sql);
        let facts = facts::extract::derive_facts_from_backup_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL DBCC (database console / maintenance command). Top-level
    // `StatementFacts.mssql_dbcc` (parallel to `mssql_backup`) since DBCC is
    // not DDL. The command verb is the recognition primitive; which command
    // is dangerous is a YAML verdict. Drives MSSQL-DBCC-SENSITIVE /
    // INFO-MSSQL-DBCC.
    if let ast::AstStmt::MssqlDbcc(s) = stmt {
        let plan = ir::lower_dbcc_to_dbcc_plan(s, sql);
        let facts = facts::extract::derive_facts_from_dbcc_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL encryption-key activation (OPEN/CLOSE { MASTER | SYMMETRIC }
    // KEY). Top-level `StatementFacts.mssql_key_management` (parallel to
    // `mssql_dbcc`) since key activation is a session context switch, not
    // DDL. Verb + key kind + inline-password presence are the recognition
    // primitives; severity is a YAML verdict. Drives
    // MSSQL-KEY-OPEN-INLINE-PASSWORD / MSSQL-OPEN-MASTER-KEY /
    // INFO-MSSQL-KEY-MANAGEMENT.
    if let ast::AstStmt::MssqlKeyManagement(s) = stmt {
        let plan = ir::lower_key_management_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_key_management_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL Row-Level Security (CREATE/ALTER SECURITY POLICY). Top-level
    // `StatementFacts.mssql_security_policy`. Verb + STATE + filter/block
    // predicate presence are the recognition primitives; the disabled-
    // control verdict is a YAML rule. Drives MSSQL-RLS-POLICY-DISABLED /
    // MSSQL-RLS-POLICY-CREATED-DISABLED / INFO-MSSQL-SECURITY-POLICY.
    if let ast::AstStmt::MssqlSecurityPolicy(s) = stmt {
        let plan = ir::lower_security_policy_to_plan(s);
        let facts = facts::extract::derive_facts_from_security_policy_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL key-material protection (BACKUP/RESTORE { SERVICE MASTER KEY |
    // MASTER KEY | CERTIFICATE | ASYMMETRIC KEY }). Top-level
    // `StatementFacts.mssql_key_backup`. Verb + key object + inline-password
    // presence are the recognition primitives; the root-key export/restore
    // and credential verdicts are YAML rules. Drives MSSQL-MASTER-KEY-EXPORT
    // / MSSQL-MASTER-KEY-RESTORE / MSSQL-KEY-BACKUP-INLINE-PASSWORD /
    // INFO-MSSQL-KEY-BACKUP.
    if let ast::AstStmt::MssqlKeyBackup(s) = stmt {
        let plan = ir::lower_key_backup_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_key_backup_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL CLR assembly (CREATE/ALTER ASSEMBLY). Top-level
    // `StatementFacts.mssql_assembly`. Verb + permission set +
    // filesystem-source flag are the recognition primitives; the UNSAFE /
    // EXTERNAL_ACCESS verdict is a YAML rule. Drives MSSQL-CLR-ASSEMBLY-UNSAFE
    // / MSSQL-CLR-ASSEMBLY-EXTERNAL-ACCESS / INFO-MSSQL-CLR-ASSEMBLY.
    if let ast::AstStmt::MssqlAssembly(s) = stmt {
        let plan = ir::lower_assembly_to_plan(s);
        let facts = facts::extract::derive_facts_from_assembly_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL module signing (ADD [COUNTER] SIGNATURE). Top-level
    // `StatementFacts.mssql_add_signature`. Counter + signer kind +
    // inline-password presence are the recognition primitives; the
    // privilege-delegation / credential verdict is a YAML rule. Drives
    // MSSQL-MODULE-SIGNATURE-ADDED / MSSQL-SIGNATURE-INLINE-PASSWORD.
    if let ast::AstStmt::MssqlAddSignature(s) = stmt {
        let plan = ir::lower_add_signature_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_add_signature_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL Service Master Key rotation (ALTER SERVICE MASTER KEY). Top-level
    // `StatementFacts.mssql_service_master_key`. Operation + force +
    // inline-password presence are the recognition primitives; the re-key /
    // data-loss / credential verdicts are YAML rules. Drives
    // MSSQL-SERVICE-MASTER-KEY-REGENERATE / -FORCE-REGENERATE /
    // -INLINE-PASSWORD / INFO-MSSQL-SERVICE-MASTER-KEY.
    if let ast::AstStmt::MssqlAlterServiceMasterKey(s) = stmt {
        let plan = ir::lower_service_master_key_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_service_master_key_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // PostgreSQL ALTER DEFAULT PRIVILEGES (default-grant policy on future
    // objects). Top-level `StatementFacts.pg_default_privileges`. Action +
    // object class + privileges + grantees + role/schema scope are the
    // recognition primitives; the default-to-PUBLIC / global-scope verdicts
    // are YAML rules. Drives PG-DEFAULT-PRIV-* / INFO-PG-DEFAULT-PRIVILEGES.
    if let ast::AstStmt::PgAlterDefaultPrivileges(s) = stmt {
        let plan = ir::lower_pg_default_privileges_to_plan(s);
        let facts = facts::extract::derive_facts_from_pg_default_privileges_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // T-SQL RESTORE (data-protection utility — target Database/Log +
    // source Disk/Url/Tape). Top-level `StatementFacts.mssql_restore`
    // (parallel to `mssql_backup`) since RESTORE is not DDL. Drives
    // MSSQL-RESTORE-FROM-URL / MSSQL-RESTORE-REPLACE / INFO-MSSQL-RESTORE.
    if let ast::AstStmt::MssqlRestore(s) = stmt {
        let plan = ir::lower_restore_db_to_plan(s, sql);
        let facts = facts::extract::derive_facts_from_restore_plan(&plan, sql);
        out.push(facts);
        return;
    }

    // PG COPY (data-movement utility — direction FROM/TO + target
    // File/Program/Stdin/Stdout). Sits at the top level of
    // `StatementFacts` (parallel to `use_stmt`) since COPY is not
    // DDL. Drives PG-COPY-FROM / PG-COPY-TO / PG-COPY-PROGRAM.
    if let ast::AstStmt::PgCopy(s) = stmt {
        let plan = ir::lower_pg_copy_to_pg_copy_plan(s, sql);
        let facts = facts::extract::derive_facts_from_pg_copy_plan(&plan, sql);
        out.push(facts);
        return;
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
        ast::AstStmt::BqDropSnapshotTable(_) => Some(facts::extract::BqDdlKind::DropSnapshotTable),
        ast::AstStmt::BqCreateSearchIndex(_) => Some(facts::extract::BqDdlKind::CreateSearchIndex),
        ast::AstStmt::BqDropSearchIndex(_) => Some(facts::extract::BqDdlKind::DropSearchIndex),
        ast::AstStmt::BqCreateVectorIndex(_) => Some(facts::extract::BqDdlKind::CreateVectorIndex),
        ast::AstStmt::BqAlterVectorIndex(_) => Some(facts::extract::BqDdlKind::AlterVectorIndex),
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
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            let facts = facts::extract::derive_facts_from_bq_ddl_plan(&plan, kind, sql);
            out.push(facts);
        }
        return;
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
                ast::types::PrincipalKind::Login => Some(facts::extract::MssqlDdlKind::CreateLogin),
                ast::types::PrincipalKind::User => Some(facts::extract::MssqlDdlKind::CreateUser),
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
        ast::AstStmt::AlterPrincipal(p) if p.principal_kind == ast::types::PrincipalKind::Login => {
            Some(facts::extract::MssqlDdlKind::AlterLogin)
        }
        ast::AstStmt::DropPrincipal(p) if p.principal_kind == ast::types::PrincipalKind::Login => {
            Some(facts::extract::MssqlDdlKind::DropLogin)
        }
        ast::AstStmt::MssqlSetOption(_) => Some(facts::extract::MssqlDdlKind::SetOption),
        ast::AstStmt::DropMssqlTrigger(_) => Some(facts::extract::MssqlDdlKind::DropTrigger),
        ast::AstStmt::MssqlTriggerState(_) => Some(facts::extract::MssqlDdlKind::TriggerState),
        _ => None,
    };
    if let Some(kind) = mssql_kind {
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            let facts = facts::extract::derive_facts_from_mssql_ddl_plan(&plan, kind, sql);
            out.push(facts);
        }
        return;
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
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            let facts = facts::extract::derive_facts_from_principal_plan(&plan, sql);
            out.push(facts);
        }
        return;
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
        out.push(facts);
        return;
    }

    // SHOW <objects> — metadata introspection. Lowers to a generic
    // DDL plan carrying the typed `show` recognition sibling; the
    // facts projection exposes it under `ddl.show.*`.
    if let ast::AstStmt::Show(_) = stmt {
        let session = ir::types::SessionContext::default();
        let inputs = ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: function_catalog,
            session: &session,
            meaning: query.meaning,
            catalog: None,
            model_catalog: None,
            reasoning,
            flatten_body_into: None,
        };
        if let Some(plan) = ir::lower_ddl_stmt(stmt, &inputs) {
            if let Some(facts) = facts::extract::derive_facts_from_show_plan(&plan) {
                out.push(facts);
            }
        }
        return;
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
    // The dynamic-SQL calls the statement makes ([`statement_calls`]): a
    // bare variable argument resolves through the script's classifier,
    // so via-variable laundering (`v := '…' || x; EXECUTE v;`) reports
    // the built shape. One in a procedure, function or trigger body reads
    // its variables as that body assigns them ([`DdlReading::routine_calls`]).
    let calls = {
        let span = stmt.span();
        match routine_calls.get(&(span.start, span.end)) {
            Some(calls) => Some(std::borrow::Cow::Borrowed(calls)),
            None => statement_calls(stmt, sql, dynamic_sql, fold.parameters_at(span))
                .map(std::borrow::Cow::Owned),
        }
    };
    let (run_call, reached_calls) = match calls.as_deref() {
        Some(StatementCalls::Runs(call)) => (Some(call), &[][..]),
        Some(StatementCalls::Reaches(reached)) => (None, reached.as_slice()),
        None => (None, &[][..]),
    };
    if let (ast::AstStmt::ExecuteImmediate { span, .. }, Some(call_ir)) = (stmt, run_call) {
        let call = facts::extract::project_dynamic_sql_call(call_ir);
        let facts = facts::extract::derive_facts_dynamic_sql_stmt(
            facts::StatementKind::ExecuteImmediate,
            *span,
            call,
        );
        out.push(facts);
        return;
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
        out.push(facts);
        return;
    }
    if let ast::AstStmt::PgPrepare(p) = stmt {
        // Top-level `PREPARE`. PG form (`PREPARE … AS <stmt>`)
        // carries a parsed body and is not itself a dynamic-SQL
        // surface (the AS branch executes a known statement). MySQL
        // form (`PREPARE … FROM <expr>`) IS a dynamic-SQL surface
        // — classify the FROM expression's shape and attach.
        let facts = match run_call {
            Some(c) => facts::extract::derive_facts_dynamic_sql_stmt(
                facts::StatementKind::PgPrepare,
                p.span,
                facts::extract::project_dynamic_sql_call(c),
            ),
            None => {
                facts::extract::derive_facts_stmt_kind_only(facts::StatementKind::PgPrepare, p.span)
            }
        };
        out.push(facts);
        return;
    }
    // T-SQL impersonation statements — `EXECUTE AS LOGIN/USER = …`
    // and `REVERT`. Typed facts drive the MSSQL-EXECAS-* rules.
    if let ast::AstStmt::MssqlExecuteAs(e) = stmt {
        let raw = sql
            .get(e.principal_span.start as usize..e.principal_span.end as usize)
            .unwrap_or("");
        // A string literal's value; a bare @variable as written.
        let inner = ir::span_extract::literal_value_or_text(raw);
        let impersonation = facts::ddl::ImpersonationFacts {
            principal_kind: match e.principal_kind {
                ast::types::AstImpersonationPrincipalKind::Login => {
                    facts::ddl::ImpersonationPrincipalKind::Login
                }
                ast::types::AstImpersonationPrincipalKind::User => {
                    facts::ddl::ImpersonationPrincipalKind::User
                }
            },
            principal: facts::identity::IdentName::new(inner).written_at(e.principal_span),
            no_revert: e.no_revert,
        };
        let facts = facts::extract::derive_facts_mssql_impersonation(
            facts::StatementKind::MssqlExecuteAs,
            e.span,
            Some(impersonation),
        );
        out.push(facts);
        return;
    }
    if let ast::AstStmt::MssqlRevert { span, .. } = stmt {
        let facts = facts::extract::derive_facts_mssql_impersonation(
            facts::StatementKind::MssqlRevert,
            *span,
            None,
        );
        out.push(facts);
        return;
    }
    // T-SQL `SETUSER ['username']` — the legacy, database-scoped equivalent
    // of `EXECUTE AS USER`. Reuses the shared `ImpersonationFacts` carrier
    // (principal kind is always User); a bare `SETUSER` is the revert form
    // (no principal). Drives MSSQL-SETUSER-IMPERSONATION / INFO-MSSQL-SETUSER.
    if let ast::AstStmt::MssqlSetuser(s) = stmt {
        let impersonation = s.principal_span.map(|p| {
            let raw = sql.get(p.start as usize..p.end as usize).unwrap_or("");
            let inner = ir::span_extract::literal_value_or_text(raw);
            facts::ddl::ImpersonationFacts {
                principal_kind: facts::ddl::ImpersonationPrincipalKind::User,
                principal: facts::identity::IdentName::new(inner).written_at(p),
                no_revert: false,
            }
        });
        let facts = facts::extract::derive_facts_mssql_impersonation(
            facts::StatementKind::MssqlSetuser,
            s.span,
            impersonation,
        );
        out.push(facts);
        return;
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
                ast::types::AstMssqlAuditScope::ServerAudit => facts::ddl::AuditScope::ServerAudit,
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
        out.push(facts);
        return;
    }
    if let ast::AstStmt::MssqlSecurityObjectDdl(s) = stmt {
        let kind = match s.action {
            ast::types::AstMssqlAuditAction::Create => {
                facts::StatementKind::MssqlCreateSecurityObject
            }
            ast::types::AstMssqlAuditAction::Alter => {
                facts::StatementKind::MssqlAlterSecurityObject
            }
            ast::types::AstMssqlAuditAction::Drop => facts::StatementKind::MssqlDropSecurityObject,
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
                ast::types::AstMssqlSecurityObjectKind::DatabaseEncryptionKey => {
                    facts::ddl::SecurityObjectKind::DatabaseEncryptionKey
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
        out.push(facts);
        return;
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
            crate::dialect::normalize_identifier(
                sql.get(s.start as usize..s.end as usize).unwrap_or(""),
            )
            .to_ascii_lowercase()
        });
        let args_text_lower = e.args_span.map(|s| {
            facts::identity::WrittenText::at(
                sql.get(s.start as usize..s.end as usize)
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                s,
            )
        });
        let mssql_exec_facts = Some(facts::ddl::MssqlExecFacts {
            procedure_name: procedure_name_lower.clone(),
            args_text: args_text_lower,
            args: facts::extract::project_mssql_exec_args(&e.args, sql),
        });

        // `EXEC (…)` and `EXEC sp_executesql …` run SQL text; any other
        // `EXEC` calls a procedure.
        if let Some(call_ir) = run_call {
            let call = facts::extract::project_dynamic_sql_call(call_ir);
            let mut facts = facts::extract::derive_facts_dynamic_sql_stmt(
                facts::StatementKind::MssqlExec,
                e.span,
                call,
            );
            facts.mssql_exec = mssql_exec_facts;
            out.push(facts);
        } else {
            // Ordinary EXEC <proc_name> — no dynamic SQL at the
            // call itself, but the callee's body may pass an
            // argument on to a sink. Emit one row per sink it
            // reaches, each carrying its provenance chain. Always
            // also surface `mssql_exec` facts so procedure-name-keyed
            // rules (xp_cmdshell, …) fire.
            for call_ir in reached_calls {
                let call = facts::extract::project_dynamic_sql_call(call_ir);
                let mut facts = facts::extract::derive_facts_dynamic_sql_stmt(
                    facts::StatementKind::MssqlExec,
                    e.span,
                    call,
                );
                facts.mssql_exec = mssql_exec_facts.clone();
                out.push(facts);
            }
            let mut facts = facts::extract::derive_facts_stmt_kind_only(
                facts::StatementKind::MssqlExec,
                e.span,
            );
            facts.mssql_exec = mssql_exec_facts;
            out.push(facts);
        }
        return;
    }
    if let ast::AstStmt::Call { span, .. } = stmt {
        for call_ir in reached_calls {
            let call = facts::extract::project_dynamic_sql_call(call_ir);
            let facts = facts::extract::derive_facts_dynamic_sql_stmt(
                facts::StatementKind::Call,
                *span,
                call,
            );
            out.push(facts);
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
        ast::AstStmt::PgCreateOperator(s) => Some((facts::StatementKind::PgCreateOperator, s.span)),
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
        // PostgreSQL prepared-statement lifecycle: `EXECUTE` and
        // `DEALLOCATE` hold no statement and reach the ledger via this
        // kind-only stub (`PREPARE` is read above).
        ast::AstStmt::PgExecute(s) => Some((facts::StatementKind::PgExecute, s.span)),
        ast::AstStmt::PgDeallocate(s) => Some((facts::StatementKind::PgDeallocate, s.span)),
        // A call is one whether or not the reasoning provider reports a
        // sink its callee reaches.
        ast::AstStmt::Call { span, .. } => Some((facts::StatementKind::Call, *span)),
        ast::AstStmt::Reconfigure { span, .. } => Some((facts::StatementKind::Reconfigure, *span)),
        ast::AstStmt::MssqlServerCommand { span, .. } => {
            Some((facts::StatementKind::MssqlServerCommand, *span))
        }
        ast::AstStmt::MysqlAdmin(admin) => {
            use ast::{AstMysqlAdminKind as A, AstMysqlTableOperation as Op};
            let kind = match &admin.kind {
                A::TableMaintenance { operation, .. } => match operation {
                    Op::Analyze => facts::StatementKind::AnalyzeStmt,
                    Op::Optimize => facts::StatementKind::OptimizeTable,
                    Op::Check => facts::StatementKind::CheckTable,
                    Op::Checksum => facts::StatementKind::ChecksumTable,
                    Op::Repair => facts::StatementKind::RepairTable,
                },
                A::Flush { .. } => facts::StatementKind::Flush,
                A::Kill { .. } => facts::StatementKind::Kill,
                A::AlterInstance => facts::StatementKind::AlterInstance,
                A::Xa => facts::StatementKind::XaTransaction,
                A::RenameUser { .. } => facts::StatementKind::RenameUser,
            };
            Some((kind, admin.span))
        }
        _ => None,
    };
    if let Some((kind, span)) = kind_only {
        let facts = facts::extract::derive_facts_stmt_kind_only(kind, span);
        out.push(facts);
    }
}

/// What the DDL families read the statements of a script with.
struct DdlReading<'a> {
    sql: &'a str,
    /// The placeholder spans `sql` was parsed with.
    placeholders: &'a [lexer::token::Span],
    fold: &'a ScriptContextFold,
    /// The script's function catalogs, in the dialect it was parsed in.
    functions: &'a ir::ScriptFunctions,
    reasoning: &'a dyn facts::reasoning::Reasoning,
    /// What reads the query a statement holds, as the query family reads
    /// a statement where the query starts.
    query: &'a QueryReading<'a>,
    /// The `DECLARE … HANDLER` statements read as handlers: every one but
    /// those in an exception handler, a loop's query or an `INSERT … EXEC`.
    handlers: std::collections::HashSet<ast::NodeId>,
    /// The dynamic-SQL calls each statement in a procedure, function or
    /// trigger body makes, by the statement's span: its arguments read as
    /// that body assigns its variables, as the routine's own facts read them.
    routine_calls: std::collections::HashMap<(u32, u32), StatementCalls>,
}

impl<'a> DdlReading<'a> {
    fn new(
        script: &ast::AstScript,
        sql: &'a str,
        placeholders: &'a [lexer::token::Span],
        fold: &'a ScriptContextFold,
        functions: &'a ir::ScriptFunctions,
        reasoning: &'a dyn facts::reasoning::Reasoning,
        query: &'a QueryReading<'a>,
        script_reasoning: &dyn facts::reasoning::ScriptReasoning,
    ) -> Self {
        let mut handlers = Vec::new();
        for stmt in &script.stmts {
            collect_declare_handlers(stmt, &mut handlers);
        }
        DdlReading {
            sql,
            placeholders,
            fold,
            functions,
            reasoning,
            query,
            handlers: handlers.into_iter().map(|h| h.node_id).collect(),
            routine_calls: routine_calls(script, sql, fold, script_reasoning),
        }
    }
}

/// The dynamic-SQL calls a statement makes ([`statement_calls`]).
#[derive(Debug, Clone)]
enum StatementCalls {
    /// It runs SQL text: the call it makes.
    Runs(ir::dynamic_sql::DynamicSqlCallIr),
    /// It calls a routine: one call per sink an argument reaches in it.
    Reaches(Vec<ir::dynamic_sql::DynamicSqlCallIr>),
}

/// The dynamic-SQL calls `stmt` makes, its arguments read by `classifier`
/// as the statement holding them reads its variables; `parameters` are those
/// of the routine whose body holds `stmt`. `None` for a statement that
/// neither runs SQL text nor calls a routine.
fn statement_calls(
    stmt: &ast::AstStmt,
    sql: &str,
    classifier: &dyn facts::reasoning::DynamicSqlClassifier,
    parameters: &[IdentKey],
) -> Option<StatementCalls> {
    if let Some(run) = ir::dynamic_sql::sql_run(stmt, sql) {
        return Some(StatementCalls::Runs(ir::dynamic_sql::dynamic_sql_call(
            &run, classifier, sql, parameters,
        )));
    }
    procedure_call_site(stmt, sql, parameters)
        .map(|site| StatementCalls::Reaches(classifier.call_site_calls(&site)))
}

/// [`DdlReading::routine_calls`]: each routine's body read once for all the
/// calls it makes.
fn routine_calls(
    script: &ast::AstScript,
    sql: &str,
    fold: &ScriptContextFold,
    script_reasoning: &dyn facts::reasoning::ScriptReasoning,
) -> std::collections::HashMap<(u32, u32), StatementCalls> {
    use crate::error::ExpectInvariant;
    let statements = flat_stmts_for_rules(script);
    let mut by_routine: std::collections::BTreeMap<usize, Vec<&ast::AstStmt>> =
        std::collections::BTreeMap::new();
    for &stmt in &statements {
        let makes_calls = ir::dynamic_sql::sql_run(stmt, sql).is_some()
            || procedure_call_site(stmt, sql, &[]).is_some();
        if makes_calls {
            if let Some(place) = fold.routine_holding(stmt.span()) {
                by_routine.entry(place).or_default().push(stmt);
            }
        }
    }
    let mut out = std::collections::HashMap::new();
    for (place, stmts) in by_routine {
        let routine = statements
            .get(place)
            .expect_invariant("the fold lists the script's statements in flattened order");
        let classifier = script_reasoning.dynamic_sql_for_body(routine);
        for stmt in stmts {
            let span = stmt.span();
            if let Some(calls) =
                statement_calls(stmt, sql, classifier.as_ref(), fold.parameters_at(span))
            {
                out.insert((span.start, span.end), calls);
            }
        }
    }
    out
}

/// The facts the DDL families derive for `stmt` ([`ddl_statement_facts`]),
/// and its handler facts where it is a handler `ddl` reads, onto `out`.
fn ddl_facts(
    stmt: &ast::AstStmt,
    ddl: &DdlReading<'_>,
    script_reasoning: &dyn facts::reasoning::ScriptReasoning,
    facts_out: Option<&mut StatementFactsSink<'_>>,
    out: &mut Vec<facts::StatementFacts>,
) {
    ddl_statement_facts(stmt, ddl, script_reasoning, facts_out, out);
    if let ast::AstStmt::DeclareHandler(h) = stmt {
        if ddl.handlers.contains(&h.node_id) {
            let plan = ir::lower_declare_handler_to_handler_plan(h, ddl.sql);
            out.push(facts::extract::derive_facts_from_handler_plan(
                &plan, ddl.sql,
            ));
        }
    }
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

/// The call `stmt` makes of a named routine, for the script's reasoning to
/// say which of its arguments the callee runs as SQL; `None` for a statement
/// that calls none, or that runs SQL text itself (`EXEC (…)`,
/// `EXEC sp_executesql …`). `parameters` are those of the routine whose
/// body holds `stmt`.
fn procedure_call_site<'s>(
    stmt: &'s ast::AstStmt,
    source: &str,
    parameters: &'s [IdentKey],
) -> Option<facts::reasoning::CallSite<'s>> {
    if let ast::AstStmt::MssqlExec(e) = stmt {
        if ir::dynamic_sql::sql_run(stmt, source).is_some() {
            return None;
        }
        return Some(facts::reasoning::CallSite {
            span: e.span,
            callee_name_span: e.procedure_name_span,
            args_span: e.args_span,
            args: &e.args,
            node_id: e.node_id,
            kind: facts::reasoning::CallSiteKind::MssqlExec,
            parameters,
        });
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
        return Some(facts::reasoning::CallSite {
            span: *span,
            callee_name_span: Some(*procedure_name_span),
            args_span: *args_span,
            args,
            node_id: *node_id,
            kind: facts::reasoning::CallSiteKind::Call,
            parameters,
        });
    }
    None
}

/// The pieces of `stmt` not parsed, each counted as one statement skipped:
/// the statement itself where [`coverage_class`] says so, else each header
/// of it that did not parse (an `IF` / `ELSEIF`, `WHILE`, `WHEN` or
/// `UNTIL` condition, a simple `CASE`'s operand, a FOR loop's range, cursor
/// or query), whose body is read.
fn unparsed_spans(stmt: &ast::AstStmt) -> Vec<lexer::token::Span> {
    if coverage_class(stmt) == CoverageClass::Skipped {
        return vec![stmt.span()];
    }
    let unparsed = |e: &ast::AstExpr| matches!(e, ast::AstExpr::Error { .. }).then(|| e.span());
    if let ast::AstStmt::If(i) = stmt {
        i.branches
            .iter()
            .filter_map(|b| unparsed(&b.condition))
            .collect()
    } else if let ast::AstStmt::CaseStmt(c) = stmt {
        c.operand
            .iter()
            .filter_map(|o| unparsed(o))
            .chain(c.branches.iter().flat_map(|b| {
                std::iter::once(b.condition.as_ref())
                    .chain(&b.more_values)
                    .filter_map(unparsed)
            }))
            .collect()
    } else if let ast::AstStmt::While(w) = stmt {
        unparsed(&w.condition).into_iter().collect()
    } else if let ast::AstStmt::Repeat(r) = stmt {
        unparsed(&r.until_condition).into_iter().collect()
    } else if let ast::AstStmt::For(f) = stmt {
        match &f.iterates {
            ast::AstForIterable::Expr(e) => unparsed(e).into_iter().collect(),
            ast::AstForIterable::Range { .. } | ast::AstForIterable::Query(_) => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

/// What a sqlcmd command line runs that the analysis does not read; `None`
/// for a command that only sets or shows the client's state.
fn sqlcmd_unread(action: &ast::SqlcmdAction) -> Option<analyzer::SqlcmdUnread> {
    use analyzer::SqlcmdUnread;
    use ast::SqlcmdAction as A;
    match action {
        A::Client { .. } => None,
        A::Include { .. } => Some(SqlcmdUnread::IncludedFile),
        A::Connect { .. } => Some(SqlcmdUnread::OtherServer),
        A::OsCommand => Some(SqlcmdUnread::OsCommand),
        A::Edit => Some(SqlcmdUnread::EditedBatch),
        A::ExitQuery { .. } => Some(SqlcmdUnread::ExitQuery),
    }
}

/// The sqlcmd command lines of `stmts` that run what the analysis does not
/// read, by where each starts: what it runs, and the part of the line a
/// report may quote — the command and the file or server it names, never
/// the rest (`:connect srv -U u -P password`, an operating-system command).
fn unread_sqlcmd_lines(
    stmts: &[&ast::AstStmt],
) -> std::collections::BTreeMap<u32, (analyzer::SqlcmdUnread, lexer::token::Span)> {
    use ast::SqlcmdAction as A;
    stmts
        .iter()
        .filter_map(|stmt| {
            let ast::AstStmt::SqlcmdCommand {
                span,
                name_span,
                action,
                ..
            } = stmt
            else {
                return None;
            };
            let unread = sqlcmd_unread(action)?;
            let quoted_end = match action {
                A::Include { file_span: named } | A::Connect { server_span: named } => {
                    named.map_or(name_span.end, |named| named.end)
                }
                A::ExitQuery { .. } => span.end,
                A::Client { .. } | A::OsCommand | A::Edit => name_span.end,
            };
            let quoted = lexer::token::Span {
                start: span.start,
                end: quoted_end,
            };
            Some((span.start, (unread, quoted)))
        })
        .collect()
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

        // ── A sqlcmd command: the client's state passes; one that runs
        // what the analysis did not read counts as skipped ──
        S::SqlcmdCommand { action, .. } => match sqlcmd_unread(action) {
            Some(_) => CoverageClass::Skipped,
            None => CoverageClass::Excluded,
        },

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
        S::Grant(g)
            if matches!(
                g.shape,
                ast::AstGrantShape::Unparsed { .. } | ast::AstGrantShape::Membership { .. }
            ) =>
        {
            CoverageClass::Partial
        }
        S::Revoke(r)
            if matches!(
                r.shape,
                ast::AstRevokeShape::Unparsed { .. } | ast::AstRevokeShape::Membership { .. }
            ) =>
        {
            CoverageClass::Partial
        }

        // ── Everything else is an analyzed statement. Enumerated in full
        //    (no catch-all) so a new `AstStmt` variant must be classified
        //    here explicitly rather than silently defaulting to analyzed. ──
        S::Select(_)
        | S::Perform(_)
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
        | S::PsqlGexec(_)
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
        | S::MssqlCreateRule(_)
        | S::MysqlDo(_)
        | S::ExecuteTask(_)
        | S::MysqlCreateLoadableFunction(_)
        | S::MysqlAdmin(_)
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
        | S::MssqlServerCommand { .. }
        | S::MysqlSet(_)
        | S::MysqlUnlockTables(_)
        | S::MssqlWaitfor(_)
        | S::MssqlGoto(_)
        | S::MssqlLabel(_)
        | S::CreateMssqlTrigger(_)
        | S::DropMssqlTrigger(_)
        | S::MssqlTriggerState(_)
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
        | S::Savepoint(_)
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
/// body-bearing scripting / procedural arm, and the statements the value
/// of an assignment, a `DECLARE` default or a `RETURN` holds).
/// Mirrors the recursion pattern in `collect_declare_handlers` but pushes
/// every stmt rather than only `DeclareHandler` leaves.
///
/// The rule evaluators iterate the result so per-statement facts are
/// accumulated and rules are evaluated against inner-body statements.
/// Without this, e.g. `DECLARE c CURSOR FOR <SELECT>` inside a
/// `BEGIN ... END` block would silently fail to surface the cursor's
/// read set (the underlying SELECT only reaches the lowerer through the
/// wrapper's `decls` field, which the top-level `script.stmts`
/// iteration alone does not visit).
///
/// Every body a statement holds ([`ast::AstStmt::bodies`]) is descended;
/// what else holds statements is closed-enum exhaustive: adding a new
/// `AstStmt` variant breaks the compile.
pub fn flatten_stmts_for_rules<'a>(stmt: &'a ast::AstStmt, out: &mut Vec<&'a ast::AstStmt>) {
    let mut tree = Vec::new();
    flatten_statement_tree(stmt, None, &mut tree);
    out.extend(tree.into_iter().map(|(stmt, _)| stmt));
}

/// The writes a `WITH` clause runs: each CTE whose body is an `INSERT`,
/// `UPDATE`, `DELETE` or `MERGE`, flattened as a statement held by
/// `parent`. A CTE that queries is read as part of its statement's query.
fn flatten_writing_ctes<'a>(
    with: Option<&'a ast::AstWithClause>,
    parent: Option<usize>,
    out: &mut Vec<(&'a ast::AstStmt, Option<usize>)>,
) {
    for item in with.into_iter().flat_map(|with| &with.ctes) {
        match item {
            ast::CteItem::Cte(cte) => {
                if matches!(
                    cte.query.as_ref(),
                    ast::AstStmt::Insert(_)
                        | ast::AstStmt::Update(_)
                        | ast::AstStmt::Delete(_)
                        | ast::AstStmt::Merge(_)
                ) {
                    flatten_statement_tree(&cte.query, parent, out);
                }
            }
            // A template block's CTEs are read once it is rendered.
            ast::CteItem::JinjaBlock(_) => {}
        }
    }
}

/// The `WITH` clause a query or a write starts with.
fn with_clause_of(stmt: &ast::AstStmt) -> Option<&ast::AstWithClause> {
    if let ast::AstStmt::Select(s) = stmt {
        s.with_clause.as_deref()
    } else if let ast::AstStmt::Insert(s) = stmt {
        s.with_clause.as_ref()
    } else if let ast::AstStmt::Update(s) = stmt {
        s.with_clause.as_ref()
    } else if let ast::AstStmt::Delete(s) = stmt {
        s.with_clause.as_ref()
    } else if let ast::AstStmt::Merge(s) = stmt {
        s.with_clause.as_ref()
    } else {
        None
    }
}

/// The CTEs a write a CTE holds reads beside its own, and the `WITH` clause
/// of its holder.
struct CtesAround<'a> {
    clause: &'a ast::AstWithClause,
    ctes: Vec<&'a ast::CteItem>,
}

/// For each statement of `tree` ([`flatten_statement_tree`]), the CTEs a
/// write a CTE holds reads beside its own: those before it in its holder's
/// `WITH` clause (every other one of a `RECURSIVE` clause), after what its
/// holder reads. `None` for any other statement.
fn ctes_around<'a>(tree: &[(&'a ast::AstStmt, Option<usize>)]) -> Vec<Option<CtesAround<'a>>> {
    let mut around: Vec<Option<CtesAround<'a>>> = Vec::with_capacity(tree.len());
    for &(stmt, holder) in tree {
        let read = holder.and_then(|holder| {
            let clause = with_clause_of(tree.get(holder)?.0)?;
            let at = clause.ctes.iter().position(|item| match item {
                ast::CteItem::Cte(cte) => std::ptr::eq(cte.query.as_ref(), stmt),
                ast::CteItem::JinjaBlock(_) => false,
            })?;
            let recursive = clause.recursive_span.is_some();
            let mut ctes = around
                .get(holder)
                .and_then(Option::as_ref)
                .map(|outer| outer.ctes.clone())
                .unwrap_or_default();
            ctes.extend(
                clause
                    .ctes
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i < at || (recursive && i != at))
                    .map(|(_, item)| item),
            );
            Some(CtesAround { clause, ctes })
        });
        around.push(read);
    }
    around
}

/// `write` with the CTEs `around` it before its own `WITH` clause's, so a
/// CTE it reads resolves as it does where it runs; `None` where it reads
/// none.
fn with_ctes_around(write: &ast::AstStmt, around: &CtesAround<'_>) -> Option<ast::AstStmt> {
    if around.ctes.is_empty() {
        return None;
    }
    let mut write = write.clone();
    let with = if let ast::AstStmt::Insert(s) = &mut write {
        &mut s.with_clause
    } else if let ast::AstStmt::Update(s) = &mut write {
        &mut s.with_clause
    } else if let ast::AstStmt::Delete(s) = &mut write {
        &mut s.with_clause
    } else if let ast::AstStmt::Merge(s) = &mut write {
        &mut s.with_clause
    } else {
        return None;
    };
    let mut ctes: Vec<ast::CteItem> = around.ctes.iter().map(|&item| item.clone()).collect();
    *with = Some(match with.take() {
        // Its own CTEs come last: a name they define hides an outer one.
        Some(mut own) => {
            ctes.append(&mut own.ctes);
            own.ctes = ctes;
            own
        }
        None => ast::AstWithClause {
            node_id: around.clause.node_id,
            with_span: around.clause.with_span,
            recursive_span: around.clause.recursive_span,
            ctes,
            span: around.clause.span,
        },
    });
    Some(write)
}

/// [`flatten_stmts_for_rules`], each statement with the index in `out` of
/// the statement that holds it: in a body, or in a value it evaluates.
fn flatten_statement_tree<'a>(
    stmt: &'a ast::AstStmt,
    parent: Option<usize>,
    out: &mut Vec<(&'a ast::AstStmt, Option<usize>)>,
) {
    let me = Some(out.len());
    out.push((stmt, parent));
    // A body nested deeper than the stack lets the analyzer walk is not read.
    let Some(_frame) = ir::lower::enter_nested() else {
        return;
    };
    for body in stmt.bodies() {
        for s in body.stmts {
            flatten_statement_tree(s, me, out);
        }
    }
    match stmt {
        // T-SQL CETAS (`CREATE EXTERNAL TABLE … AS <query>`): recurse the egress
        // query so its reads/predicates are rule-evaluated — the query's results
        // are written out to external storage. Read-only external tables carry
        // no `AS` query (`None`) and are leaves.
        ast::AstStmt::CreateExternalTable(c) => {
            if let Some(Ok(q)) = c.as_query.as_ref() {
                flatten_statement_tree(q, me, out);
            }
        }
        // Redshift `UNLOAD ('<query>')`: the query its literal holds, where it
        // was read, is a statement of its own, as CETAS's is.
        ast::AstStmt::Unload { source, .. } => match source {
            Some(ast::AstUnloadSource::Subquery(q)) => flatten_statement_tree(q, me, out),
            Some(ast::AstUnloadSource::Table { .. }) | None => {}
        },
        // PostgreSQL `PREPARE name AS <stmt>`: the statement it holds is
        // a statement of its own. MySQL's `PREPARE name FROM <expr>` holds
        // SQL text, read as the SQL text a script runs.
        ast::AstStmt::PgPrepare(p) => {
            if p.from_expr.is_none() {
                flatten_statement_tree(&p.body, me, out);
            }
        }
        // The value an assignment or a DECLARE default takes runs the
        // statements it holds: a scalar query (`SET x = (SELECT …)`) or
        // dynamic SQL (Snowflake `res := (EXECUTE IMMEDIATE :q)`, `LET res
        // RESULTSET := (…)`).
        ast::AstStmt::Assign { expr, .. } | ast::AstStmt::Let { expr, .. } => {
            flatten_statements_held_in(expr, me, out);
        }
        ast::AstStmt::Declare { variables, .. } => {
            for expr in variables.iter().filter_map(|v| v.default_expr.as_deref()) {
                flatten_statements_held_in(expr, me, out);
            }
        }
        ast::AstStmt::SetVariable { values, .. } => {
            for expr in values {
                flatten_statements_held_in(expr, me, out);
            }
        }
        ast::AstStmt::MysqlSet(s) => match &s.kind {
            ast::AstMysqlSetKind::Assignments(assignments) => {
                for a in assignments {
                    flatten_statements_held_in(&a.value, me, out);
                }
            }
            ast::AstMysqlSetKind::Names(_)
            | ast::AstMysqlSetKind::CharacterSet(_)
            | ast::AstMysqlSetKind::Password(_)
            | ast::AstMysqlSetKind::Role(_)
            | ast::AstMysqlSetKind::DefaultRole(_)
            | ast::AstMysqlSetKind::Transaction(_) => {}
        },
        ast::AstStmt::Return { expr, .. } => {
            if let Some(expr) = expr.as_deref() {
                flatten_statements_held_in(expr, me, out);
            }
        }
        // A data-modifying CTE (PostgreSQL `WITH d AS (DELETE … RETURNING
        // *) SELECT …`) runs its write whatever the statement around it
        // reads: the write is a statement of its own.
        ast::AstStmt::Select(s) => flatten_writing_ctes(s.with_clause.as_deref(), me, out),
        ast::AstStmt::Insert(s) => flatten_writing_ctes(s.with_clause.as_ref(), me, out),
        ast::AstStmt::Update(s) => flatten_writing_ctes(s.with_clause.as_ref(), me, out),
        ast::AstStmt::Delete(s) => flatten_writing_ctes(s.with_clause.as_ref(), me, out),
        ast::AstStmt::Merge(s) => flatten_writing_ctes(s.with_clause.as_ref(), me, out),
        // No statement held beside the bodies read above.
        ast::AstStmt::Block(_)
        | ast::AstStmt::DeclareHandler(_)
        | ast::AstStmt::If(_)
        | ast::AstStmt::CaseStmt(_)
        | ast::AstStmt::While(_)
        | ast::AstStmt::For(_)
        | ast::AstStmt::ForEach(_)
        | ast::AstStmt::Loop(_)
        | ast::AstStmt::Repeat(_)
        | ast::AstStmt::MssqlTryCatch(_)
        | ast::AstStmt::MssqlIf(_)
        | ast::AstStmt::MssqlWhile(_)
        | ast::AstStmt::CreateProcedure(_)
        | ast::AstStmt::CreateFunction(_)
        | ast::AstStmt::DoBlock(_)
        | ast::AstStmt::CreateEvent(_)
        | ast::AstStmt::AlterEvent(_)
        | ast::AstStmt::CreateMysqlTrigger(_)
        | ast::AstStmt::CreateTask(_)
        | ast::AstStmt::CreateMssqlTrigger(_)
        | ast::AstStmt::Perform(_)
        | ast::AstStmt::SetSelect(_)
        | ast::AstStmt::ValuesQuery(_)
        | ast::AstStmt::ReplaceInto(_)
        | ast::AstStmt::MultiInsert(_)
        | ast::AstStmt::Explain(_)
        | ast::AstStmt::PsqlGexec(_)
        | ast::AstStmt::ExecuteImmediate { .. }
        | ast::AstStmt::ExecuteImmediateFrom(_)
        | ast::AstStmt::OpaqueContent { .. }
        | ast::AstStmt::ClauseFragment { .. }
        | ast::AstStmt::JinjaPlaceholder { .. }
        | ast::AstStmt::JinjaConditionalStmt(_)
        | ast::AstStmt::Error { .. }
        | ast::AstStmt::GoBatchSeparator { .. }
        | ast::AstStmt::SqlcmdCommand { .. }
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
        | ast::AstStmt::MssqlTriggerState(_)
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
        | ast::AstStmt::MssqlServerCommand { .. }
        | ast::AstStmt::MysqlUnlockTables(_)
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
        | ast::AstStmt::MssqlCreateRule(_)
        | ast::AstStmt::MysqlDo(_)
        | ast::AstStmt::ExecuteTask(_)
        | ast::AstStmt::MysqlCreateLoadableFunction(_)
        | ast::AstStmt::MysqlAdmin(_)
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
        | ast::AstStmt::Revoke(_)
        | ast::AstStmt::Rollback { .. }
        | ast::AstStmt::Savepoint(_)
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

/// Push every statement `expr` holds: a query (scalar, `EXISTS`, `IN`) and
/// dynamic SQL (`EXECUTE IMMEDIATE …`).
fn flatten_statements_held_in<'a>(
    expr: &'a ast::AstExpr,
    parent: Option<usize>,
    out: &mut Vec<(&'a ast::AstStmt, Option<usize>)>,
) {
    for inner in ir::dynamic_sql::collect_inner_stmts_from_expr(expr) {
        flatten_statement_tree(inner, parent, out);
    }
}

/// Recursively walk an [`ast::AstStmt`] subtree, collecting every
/// [`ast::AstDeclareHandlerStmt`] reachable through the bodies of
/// scripting / procedural statements ([`ast::AstStmt::bodies`]) other than
/// a block's exception handlers, a `FOR` loop's query and an `INSERT …
/// EXEC`'s `EXEC`.
fn collect_declare_handlers<'a>(
    stmt: &'a ast::AstStmt,
    out: &mut Vec<&'a ast::AstDeclareHandlerStmt>,
) {
    // A body nested deeper than the stack lets the analyzer walk is not read.
    let Some(_frame) = ir::lower::enter_nested() else {
        return;
    };
    if let ast::AstStmt::DeclareHandler(h) = stmt {
        out.push(h.as_ref());
    }
    for body in stmt.bodies() {
        match body.role {
            ast::BodyRole::ExceptionHandler
            | ast::BodyRole::LoopQuery
            | ast::BodyRole::InsertExec => continue,
            ast::BodyRole::Declarations
            | ast::BodyRole::Block
            | ast::BodyRole::Branch
            | ast::BodyRole::Else
            | ast::BodyRole::Loop
            | ast::BodyRole::Catch
            | ast::BodyRole::HandlerAction
            | ast::BodyRole::Routine => {}
        }
        for s in body.stmts {
            collect_declare_handlers(s, out);
        }
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

/// What the query family reads the statements of a script with.
struct QueryReading<'a> {
    sql: &'a str,
    /// The placeholder spans `sql` was parsed with.
    placeholders: &'a [lexer::token::Span],
    fold: &'a ScriptContextFold,
    /// The script's function catalogs, in the dialect it was parsed in.
    functions: &'a ir::ScriptFunctions,
    /// What that dialect states its syntax means.
    meaning: dialect::SyntaxMeaning,
    catalog: Option<&'a crate::catalog::CatalogIndex>,
    /// The relations the script's statements make, which a name `catalog`
    /// does not have may name, and the statements reading them lowered,
    /// each taken in place of lowering it again ([`script_relations`]).
    relations: &'a ReadRelations,
    model_catalog: Option<&'a ir::model_catalog::ModelCatalog>,
    reasoning: &'a dyn facts::reasoning::Reasoning,
    /// Whether each statement's facts state the columns of the relation it
    /// returns or makes, which a comparison reads.
    output_columns: bool,
    /// The script's last statement and what reads it as it is lowered here.
    last: Option<&'a dyn ReadsLastStatement>,
    /// The catalog tags the organization lists as marking a column that
    /// holds no secret.
    shown_tags: &'a [rules::ShownColumnTag],
}

/// What [`QueryReading`] reads a statement at one position with: the
/// function catalog and namespace in force there, the values its variables
/// hold (while this lives) and the names the scopes around it declare.
struct QueryPosition<'q> {
    function_catalog: &'q ir::FunctionCatalog,
    session: ir::SessionContext,
    declared: ir::lower::DeclaredNames,
    relations: catalog::RelationsAt<'q>,
    meaning: dialect::SyntaxMeaning,
    _values: ir::statement_values::StatementValues,
}

impl QueryPosition<'_> {
    /// What the script and the dialect around the statement tell its
    /// lowering.
    fn around(&self) -> ir::lower::AroundStatement<'_> {
        ir::lower::AroundStatement {
            declared: &self.declared,
            meaning: self.meaning,
            relations: self.relations,
        }
    }
}

impl QueryReading<'_> {
    /// What a statement starting at `position` is read with.
    fn at(&self, position: u32) -> QueryPosition<'_> {
        // Qualify bare table references under the namespace
        // (USE DATABASE/SCHEMA) active at the position, and name what
        // `IDENTIFIER($v)` names by the text its variable holds.
        let session = self.fold.session_context_at(position);
        let values = self.fold.enter_statement(position);
        QueryPosition {
            function_catalog: self.functions.at(position),
            session,
            declared: self.fold.declared_at(position),
            relations: self.relations.relations.at(position),
            meaning: self.meaning,
            _values: values,
        }
    }

    /// `stmt` lowered as the query family lowers it at `at`: as reading the
    /// script's relations lowered it, where that lowering is `taken`, else
    /// lowered here.
    fn lower(
        &self,
        stmt: &ast::AstStmt,
        at: &QueryPosition<'_>,
        taken: Option<LoweredQuery>,
    ) -> Result<LoweredQuery, ir::LowerError> {
        match taken {
            Some(lowered) => Ok(lowered),
            None => ir::lower::lower_query_with_declared_names(
                stmt,
                self.sql,
                ir::StrictMode::Permissive,
                at.function_catalog,
                &at.session,
                self.catalog,
                self.model_catalog,
                at.around(),
            ),
        }
    }

    /// The facts of `plan` and `held_plans`, the statement at `span`
    /// lowered at `at` with `bindings` and `catalog_ctx`, with what they
    /// are derived from of `plan` and the scan index of `plan`; with
    /// `output_columns`, the columns of the relation it returns or makes.
    #[allow(clippy::too_many_arguments)] // one lowered statement, and where it was read
    fn plan_facts(
        &self,
        span: lexer::token::Span,
        at: &QueryPosition<'_>,
        plan: &ir::RelPlan,
        held_plans: &[&ir::RelPlan],
        bindings: &ir::BindingTable,
        catalog_ctx: &ir::IndexedCatalogContext,
        output_columns: bool,
    ) -> (
        facts::StatementFacts,
        ir::derived_facts::DerivedFacts,
        ir::expression_fact::ScanIndex,
    ) {
        // The scan index of the plan alone, and of the plan with the plans
        // its expressions hold, where it holds any.
        let own_index = ir::expression_fact::build_scan_index(plan);
        let held_index = (!held_plans.is_empty()).then(|| {
            let plans: Vec<&ir::RelPlan> = std::iter::once(plan)
                .chain(held_plans.iter().copied())
                .collect();
            ir::expression_fact::build_scan_index_over(&plans)
        });
        let derived_facts = ir::derived_facts::derive_facts_from_indexed_plan(
            self.sql,
            plan,
            bindings,
            at.function_catalog,
            &own_index,
        );
        let catalog_for_facts = self.catalog.map(|_| catalog_ctx);
        // Pass the AST statement's outer span so root `RelPlan::Limit`
        // (top-level SELECT with TOP / LIMIT / OFFSET / FETCH) records
        // its `source_span` over the full statement bytes — not just the
        // limit-clause bytes. The analyzer ledger keys on
        // `source_span.start`; without the override, top-level row-cap
        // SELECTs end up mis-indexed and flagged as
        // `UnimplementedStatementType`.
        let facts = facts::extract::derive_facts_from_query_plan_and_held_plans(
            plan,
            held_index.as_ref().unwrap_or(&own_index),
            bindings,
            &derived_facts,
            self.sql,
            at.function_catalog,
            catalog_for_facts,
            Some(catalog_ctx),
            Some(span),
            self.reasoning,
            self.placeholders,
            output_columns,
        );
        (facts, derived_facts, own_index)
    }
}

/// A script read as its analysis reads it, for lowering its statements
/// where they start ([`Self::lower`]).
pub struct ScriptReading<'a> {
    sql: &'a str,
    /// The placeholder spans `sql` was parsed with.
    placeholders: &'a [lexer::token::Span],
    fold: &'a ScriptContextFold,
    functions: &'a ir::ScriptFunctions,
    meaning: dialect::SyntaxMeaning,
    catalog: Option<&'a crate::catalog::CatalogIndex>,
    model_catalog: Option<&'a ir::model_catalog::ModelCatalog>,
    /// The relations the script's statements make, alter and drop.
    relations: ReadRelations,
}

impl<'a> ScriptReading<'a> {
    /// `script`, parsed from `sql` with `placeholders` and folded into
    /// `fold`, with its function catalogs `functions`, read in `dialect`
    /// against `catalog` and `model_catalog`: the relations its statements
    /// make, alter and drop are read as the analysis reads them, `reasoning`
    /// giving what is found of the values a statement makes a relation with.
    #[allow(clippy::too_many_arguments)] // the script as read, and what it is read against
    pub fn new(
        script: &ast::AstScript,
        sql: &'a str,
        placeholders: &'a [lexer::token::Span],
        fold: &'a ScriptContextFold,
        functions: &'a ir::ScriptFunctions,
        dialect: &dyn dialect::Dialect,
        catalog: Option<&'a crate::catalog::CatalogIndex>,
        model_catalog: Option<&'a ir::model_catalog::ModelCatalog>,
        reasoning: &dyn facts::reasoning::Reasoning,
    ) -> Self {
        let (relations, _) = script_relations(
            script,
            sql,
            placeholders,
            fold,
            functions,
            dialect,
            catalog,
            reasoning,
            model_catalog,
            None,
            &[],
            RunTexts::Parsed,
        );
        Self {
            sql,
            placeholders,
            fold,
            functions,
            meaning: dialect.syntax_meaning(),
            catalog,
            model_catalog,
            relations,
        }
    }

    /// `stmt`, a statement of the script, lowered as the analysis lowers a
    /// statement where it starts: under the namespace in force there, with
    /// the values its variables hold, the names the scopes around it
    /// declare, the function catalog and the relations the statements
    /// before it make there, against the catalog and the model catalog.
    pub fn lower(
        &self,
        stmt: &ast::AstStmt,
    ) -> Result<
        (
            ir::RelPlan,
            ir::IndexedCatalogContext,
            ir::BindingTable,
            ir::statement_facts::StatementFacts,
        ),
        ir::LowerError,
    > {
        let query = QueryReading {
            sql: self.sql,
            placeholders: self.placeholders,
            fold: self.fold,
            functions: self.functions,
            meaning: self.meaning,
            catalog: self.catalog,
            relations: &self.relations,
            model_catalog: self.model_catalog,
            reasoning: &facts::reasoning::RecognitionOnly,
            output_columns: false,
            last: None,
            shown_tags: &[],
        };
        let at = query.at(stmt.span().start);
        query
            .lower(stmt, &at, self.relations.take_lowered(stmt.span()))
            .map(|(plan, catalog_ctx, bindings, facts, _)| (plan, catalog_ctx, bindings, facts))
    }
}

/// The facts of the query an unload reads, the table form's
/// `SELECT * FROM <table>` among them, read as the query family reads a
/// statement where the query starts; `None` where it does not lower.
fn unload_query_facts(
    source: &ast::AstUnloadSource,
    query: &QueryReading<'_>,
) -> Option<facts::StatementFacts> {
    let stmt = match source {
        ast::AstUnloadSource::Subquery(stmt) => stmt,
        ast::AstUnloadSource::Table { query, .. } => query,
    };
    let at = query.at(stmt.span().start);
    let (plan, catalog_ctx, bindings, _, policy_facts) = query.lower(stmt, &at, None).ok()?;
    let held_plans = policy_facts
        .as_ref()
        .map(|policy| policy.held_plans())
        .unwrap_or_default();
    let (facts, ..) = query.plan_facts(
        stmt.span(),
        &at,
        &plan,
        &held_plans,
        &bindings,
        &catalog_ctx,
        false,
    );
    Some(facts)
}

/// The query facts of `stmt`, the statement at `position` of the
/// script's flattened statements (the position stale references are read
/// at), read with `query`: its plan's, what earlier statements made stale,
/// and the dynamic SQL its expressions run; `None` where it does not lower.
/// `facts_out` is told when the lowering lost the statement's analysis;
/// `shown_out` takes its string literals a walk shows safe.
fn query_facts(
    position: usize,
    stmt: &ast::AstStmt,
    query: &QueryReading<'_>,
    script_reasoning: &mut dyn facts::reasoning::ScriptReasoning,
    facts_out: Option<&mut StatementFactsSink<'_>>,
    mut shown_out: Option<(&dyn dialect::Dialect, &mut facts::secrets::ShownLiterals)>,
) -> Option<facts::StatementFacts> {
    let sql = query.sql;
    let at = query.at(stmt.span().start);
    let function_catalog = at.function_catalog;
    let lowered = query.lower(stmt, &at, query.relations.take_lowered(stmt.span()));
    let (rel_plan, catalog_ctx, bindings, stmt_facts, policy_facts) = match lowered {
        Ok(t) => t,
        Err(_) => return None,
    };
    // The plans a policy statement's body holds: lowering returns
    // no plan for the statement, and their sources name the tables
    // of the columns read of them.
    let held_plans = policy_facts
        .as_ref()
        .map(|policy| policy.held_plans())
        .unwrap_or_default();
    if let Some((dialect, shown)) = shown_out.as_mut() {
        let plans: Vec<&ir::RelPlan> = std::iter::once(&rel_plan)
            .chain(held_plans.iter().copied())
            .collect();
        // A view's column names what its query selects afresh: what a
        // catalog records of a column of that name tells nothing of it.
        let mut writes = Vec::new();
        plan_writes(&rel_plan, &mut writes);
        let into_view = writes.iter().any(|write| match write {
            PlanWrite::Insert { target, .. }
            | PlanWrite::Update { target, .. }
            | PlanWrite::Merge { target, .. }
            | PlanWrite::Rows { target } => {
                at.relations.is_view(query.catalog, target, &at.session)
            }
            // A delete stores no value.
            PlanWrite::Removes { .. } => false,
        });
        let bodies = policy_facts
            .as_ref()
            .map(|policy| policy.bodies())
            .unwrap_or_default();
        let stated = query.fold.stated_session_at(stmt.span().start);
        let found = shown_literal_spans(
            stmt,
            &plans,
            &bodies,
            &bindings,
            &at.session,
            at.around(),
            facts::secrets::Reading {
                source: sql,
                dialect: *dialect,
                functions: function_catalog,
                tables: query.catalog.filter(|_| !into_view).map(|catalog| {
                    facts::secrets::CatalogTables {
                        catalog,
                        relations: at.relations,
                        session: &at.session,
                    }
                }),
                written: query.relations.relations.written(),
                places: facts::secrets::Places {
                    relations: at.relations,
                    catalog: query.catalog,
                    session: &at.session,
                    stated: &stated,
                },
                shown_tags: query.shown_tags,
            },
        );
        shown.spans.extend(found.spans);
        shown.vetoed.extend(found.vetoed);
    }
    // When lowering bottoms out in an opaque terminal whose reason
    // means findings were *lost* — not merely a non-query statement
    // the query path correctly declined — hand the statement span
    // to the sink, the only channel from here to the report. Drives
    // confidence; the coverage counts stay parse-defined.
    if let ir::RelPlan::Opaque { reason, .. } = &rel_plan {
        if reason.indicates_lost_analysis() {
            if let Some(sink) = facts_out {
                sink.record_lost_analysis(stmt.span());
            }
        }
    }
    let catalog_for_facts = query.catalog.map(|_| &catalog_ctx);
    let (mut facts, derived, tables) = query.plan_facts(
        stmt.span(),
        &at,
        &rel_plan,
        &held_plans,
        &bindings,
        &catalog_ctx,
        query.output_columns,
    );
    // The tables the session holds: named as one, or a table it writes that
    // an earlier statement of the script made temporary.
    let mut held_by_session = stmt_facts.session_tables.clone();
    let mut writes = Vec::new();
    plan_writes(&rel_plan, &mut writes);
    held_by_session.extend(writes.iter().filter_map(|write| {
        let (PlanWrite::Insert { target, .. }
        | PlanWrite::Update { target, .. }
        | PlanWrite::Merge { target, .. }
        | PlanWrite::Rows { target }
        | PlanWrite::Removes { target }) = write;
        target
            .span
            .filter(|_| at.relations.temporary(target, &at.session))
    }));
    if let Some(query_facts) = facts.query.as_mut() {
        let held = |event: &facts::query::TableEvent| {
            event
                .source_span
                .is_some_and(|span| held_by_session.contains(&span))
        };
        for event in query_facts
            .reads_table
            .iter_mut()
            .chain(query_facts.writes_table.iter_mut())
            .chain(
                query_facts
                    .scopes
                    .iter_mut()
                    .flat_map(|scope| scope.tables.iter_mut()),
            )
        {
            event.temporary = held(event);
        }
    }
    if let Some(last) = query.last {
        last.offer(
            stmt,
            LastStatement {
                plan: &rel_plan,
                bindings: &bindings,
                catalog: &catalog_ctx,
                functions: function_catalog,
                derived: &derived,
                tables: &tables,
            },
        );
    }

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
    // The values a query psql's `\gexec` sends returns run as SQL.
    if let ast::AstStmt::PsqlGexec(_) = stmt {
        if let Some(run) = ir::dynamic_sql::sql_run(stmt, sql) {
            // `\gexec` runs no argument a parameter could be.
            let call_ir =
                ir::dynamic_sql::dynamic_sql_call(&run, script_reasoning.dynamic_sql(), sql, &[]);
            facts
                .dynamic_sql_calls
                .push(facts::extract::project_dynamic_sql_call(&call_ir));
        }
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
    let places = StatementPlaces {
        relations: at.relations,
        catalog: query.catalog,
        session: &at.session,
    };
    script_reasoning.attach_stale_references(
        &mut facts,
        position,
        &rel_plan,
        &bindings,
        catalog_for_facts,
        &places,
    );
    Some(facts)
}

/// Where the tables a statement names are: as the relations the
/// statements before it made and the catalog resolve a name under the
/// statement's session ([`catalog::RelationsAt::resolved`]).
struct StatementPlaces<'a> {
    relations: catalog::RelationsAt<'a>,
    catalog: Option<&'a catalog::CatalogIndex>,
    session: &'a ir::SessionContext,
}

impl facts::reasoning::TablePlaces for StatementPlaces<'_> {
    fn place_of(&self, table: &facts::identity::TableRef) -> facts::reasoning::TableIdentity {
        let normalized =
            |part: &facts::IdentName| IdentKey::from_normalized(part.normalized.clone());
        let written = crate::context::node_metadata::TableRef {
            server: table.server.as_ref().map(|part| part.raw.clone()),
            db: table.database.as_ref().map(|part| part.raw.clone()),
            schema: table.schema.as_ref().map(|part| part.raw.clone()),
            name: table.name.raw.clone(),
            span: None,
        };
        let resolved = self
            .relations
            .resolved(self.catalog, &written, self.session);
        facts::reasoning::TableIdentity {
            database: table.database.as_ref().map(normalized),
            schema: match (&table.schema, resolved.schema) {
                (Some(schema), _) => Some(normalized(schema)),
                (None, placed) => placed.as_deref().map(IdentKey::new),
            },
            name: normalized(&table.name),
        }
    }
}

/// The string literals of `stmt`, lowered to `plans` and the policy
/// `bodies` with `bindings`, and of the values it holds outside any query,
/// that a walk shows safe, and the literals it finds to be a secret's value
/// ([`facts::secrets::plan_literals`], [`facts::secrets::script_literals`]).
fn shown_literal_spans(
    stmt: &ast::AstStmt,
    plans: &[&ir::RelPlan],
    bodies: &[&ir::ScalarExpr],
    bindings: &ir::column::BindingTable,
    session: &ir::SessionContext,
    around: ir::lower::AroundStatement<'_>,
    reading: facts::secrets::Reading<'_>,
) -> facts::secrets::ShownLiterals {
    let mut shown = facts::secrets::plan_literals(plans, bodies, bindings, reading);
    let held = facts::secrets::script_literals(stmt, session, around, reading);
    shown.spans.extend(held.spans);
    shown.vetoed.extend(held.vetoed);
    shown
}

/// The policy-attachment or account-parameter facts of `stmt`: an `ALTER
/// USER`, or an `ALTER ACCOUNT` that attaches a policy or sets or unsets a
/// parameter.
fn policy_attachment_facts(stmt: &ast::AstStmt, sql: &str) -> Option<facts::StatementFacts> {
    match stmt {
        ast::AstStmt::AlterUser(u) => {
            Some(facts::extract::derive_facts_from_policy_attachment_plan(
                &ir::PolicyAttachmentPlan::from_alter_user(u),
                sql,
            ))
        }
        ast::AstStmt::AlterAccount(a) => match ir::PolicyAttachmentPlan::from_alter_account(a) {
            Some(plan) => Some(facts::extract::derive_facts_from_policy_attachment_plan(
                &plan, sql,
            )),
            // Generic `ALTER ACCOUNT SET/UNSET <param>`: account-level
            // parameter governance.
            None => ir::lower_alter_account_params_to_plan(a, sql)
                .map(|plan| facts::extract::derive_facts_from_account_plan(&plan, sql)),
        },
        _ => None,
    }
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
/// substitution, Jinja render, unresolved-variable confidence folding and
/// dialect-aware parse — in that order, the same at every entry point.
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
    Ok(PreparedScript { artifacts, script })
}

/// Fold the top-level statement sequence into the script-level session
/// context — the active-role transitions established by `USE ROLE` — and
/// the statements at every depth into the string literals the script runs
/// as dynamic SQL.
///
/// Reuses the typed `USE` recognition (`lower_use_to_use_plan`) and the
/// standard identifier normalization, so the role name matches the
/// `use_stmt` facts exactly. A role takes effect for statements after
/// its `USE ROLE`; a nested `USE ROLE` inside a body is session-scoped
/// and intentionally not tracked here.
pub fn build_script_context_fold(script: &ast::AstScript, sql: &str) -> ScriptContextFold {
    script_context_fold(script, sql, ir::normalize::dialect_in_force().as_ref())
}

/// [`build_script_context_fold`], the text the script builds read as
/// `dialect` reads its calls.
fn script_context_fold(
    script: &ast::AstScript,
    sql: &str,
    dialect: &dyn dialect::Dialect,
) -> ScriptContextFold {
    script_context_fold_reading(script, sql, dialect, &facts::reasoning::RecognitionOnly)
}

/// [`script_context_fold`], the routines another script of the run defines
/// told by `elsewhere` ([`facts::reasoning::Reasoning::routines_elsewhere`]):
/// the arguments of a call into one are read as those of a call into a
/// routine the script defines.
fn script_context_fold_reading(
    script: &ast::AstScript,
    sql: &str,
    dialect: &dyn dialect::Dialect,
    elsewhere: &dyn facts::reasoning::Reasoning,
) -> ScriptContextFold {
    let mut role_changes: Vec<(u32, facts::IdentName)> = Vec::new();
    let mut db_changes: Vec<(u32, facts::IdentName)> = Vec::new();
    let mut schema_changes: Vec<(u32, Option<facts::IdentName>)> = Vec::new();
    let mut search_path_changes: Vec<(u32, Vec<facts::IdentName>)> = Vec::new();
    // Whether each path set names the session's user, whose schema the
    // run does not know.
    let mut user_path_changes: Vec<(u32, bool)> = Vec::new();
    let mut routine_search_paths: Vec<(std::ops::Range<u32>, Vec<facts::IdentName>)> = Vec::new();
    // Literals executed as written, (scope, variable name, literal)
    // assignments, and the variables executed, each with its scope.
    let mut dynamic_sql_literals: Vec<ir::dynamic_sql::ExecutedLiteral> = Vec::new();
    let mut assigned: Vec<(
        VariableScope,
        lexer::token::Span,
        ir::dynamic_sql::ExecutedLiteral,
    )> = Vec::new();
    let mut executed: Vec<(VariableScope, ir::dynamic_sql::ExecutedVariable)> = Vec::new();
    // The texts assigned and executed, by where their statement starts.
    let mut text_events: Vec<(u32, VariableScope, TextEvent)> = Vec::new();
    // The routines the script creates and calls, and how each variable's
    // text reaches the text a statement runs.
    let mut flows = TextFlows::default();
    let names = VariableNames {
        sql,
        session_variables: ir::dynamic_sql::SessionVariables::of(dialect),
    };
    // The routines whose bodies hold the statement read, innermost last.
    let mut open: Vec<usize> = Vec::new();
    let mut nested: Vec<(&ast::AstStmt, Option<usize>)> = Vec::new();
    let mut batch = 0usize;
    let cut_ids: std::collections::BTreeSet<ast::NodeId> =
        script.cut_statements.iter().map(|cut| cut.stmt).collect();
    let mut cut_statements = std::collections::BTreeSet::new();
    // The names declared over stretches of the script, and those declared
    // at the top level of the batch read, each from where it is declared.
    let mut declared: Vec<DeclaredScope> = Vec::new();
    let mut batch_declared: Vec<(u32, Vec<IdentKey>)> = Vec::new();
    // The functions the script's top-level statements define.
    let mut declared_functions: Vec<(u32, String, ast::AstFunctionReturns)> = Vec::new();
    // What each assignment makes its variable hold, the statements whose
    // bodies may not run, or may run again, where they are written, where
    // each batch starts and where each call ends.
    let mut assignments: Vec<VariableAssignment> = Vec::new();
    let mut unsettled: Vec<UnsettledBody> = Vec::new();
    let mut batch_starts: Vec<u32> = Vec::new();
    let mut calls_end: Vec<u32> = Vec::new();
    // Every statement at every depth, and the index of each by its span.
    let mut statements: Vec<FoldStatement> = Vec::new();
    let mut statement_at: std::collections::BTreeMap<(u32, u32), usize> =
        std::collections::BTreeMap::new();
    for stmt in &script.stmts {
        // T-SQL's `GO` ends a batch: the next one's variables are its own.
        if let ast::AstStmt::GoBatchSeparator { .. } = stmt {
            batch += 1;
            batch_starts.push(stmt.span().start);
            let to = stmt.span().start;
            declared.extend(batch_declared.drain(..).map(|(from, names)| DeclaredScope {
                from,
                to,
                names,
            }));
        }
        let declares = declared_variables(stmt, sql);
        if !declares.is_empty() {
            batch_declared.push((stmt.span().start, declares));
        }
        nested.clear();
        flatten_statement_tree(stmt, None, &mut nested);
        let first = statements.len();
        for &(inner, parent) in &nested {
            let span = inner.span();
            statement_at
                .entry((span.start, span.end))
                .or_insert(statements.len());
            statements.push(FoldStatement {
                parent: parent.map(|p| first + p),
                body: holding_body(inner, sql),
                parameters: ir::dynamic_sql::created_routine(inner)
                    .map(|(_, params)| ir::dynamic_sql::parameter_keys(params, sql))
                    .unwrap_or_default(),
            });
            if !cut_ids.is_empty() && cut_ids.contains(&inner.node_id()) {
                let span = inner.span();
                cut_statements.insert((span.start, span.end));
            }
            declared.extend(declared_in(inner, sql));
            // A routine's own `SET search_path` is its body's path.
            let routine_path = if let ast::AstStmt::CreateFunction(function) = inner {
                function
                    .search_path
                    .as_ref()
                    .map(|entries| (entries, function.body_span.start..function.span.end))
            } else if let ast::AstStmt::CreateProcedure(procedure) = inner {
                procedure
                    .search_path
                    .as_ref()
                    .map(|entries| (entries, procedure.body_span.start..procedure.span.end))
            } else {
                None
            };
            if let Some((entries, body)) = routine_path {
                let listed = entries
                    .iter()
                    .filter_map(|span| search_path_schema(sql, *span))
                    .filter(|schema| schema.normalized != "$user")
                    .collect();
                routine_search_paths.push((body, listed));
            }
            let at = inner.span().start;
            let scope = flows.scope_at(&mut open, at, batch);
            let texts = ir::dynamic_sql::assigned_texts(inner, sql, dialect);
            assigned.extend(
                ir::dynamic_sql::assigned_string_literals(&texts)
                    .into_iter()
                    .map(|(text, literal)| {
                        (
                            names.scope(scope, &text.name, text.session),
                            text.name,
                            literal,
                        )
                    }),
            );
            for text in &texts {
                flows.assigned(names, scope, text, at);
                if let Some(variable) = names.variable(scope, &text.name, text.session) {
                    // A value that is one of several texts holds none known.
                    assignments.push(VariableAssignment {
                        variable,
                        span: inner.span(),
                        text: match text.choice {
                            true => None,
                            false => whole_literal_text(&text.pieces, sql),
                        },
                    });
                }
            }
            unsettled.extend(inner.bodies().iter().filter_map(|body| {
                Some(UnsettledBody {
                    owner: inner.span(),
                    routine: unsettled_body(body.role)?,
                })
            }));
            if !ir::dynamic_sql::routine_calls(inner, sql).is_empty() {
                calls_end.push(inner.span().end);
            }
            text_events.extend(
                texts
                    .into_iter()
                    .map(|text| (at, scope, TextEvent::Assigned(text))),
            );
            let pieces = ir::dynamic_sql::executed_pieces(inner, sql, dialect);
            if !pieces.is_empty() {
                flows.executed(names, scope, &pieces, at);
                dynamic_sql_literals.extend(ir::dynamic_sql::executed_literals(&pieces));
                executed.extend(
                    ir::dynamic_sql::executed_variables(&pieces)
                        .into_iter()
                        .map(|variable| names.executed(scope, variable)),
                );
                text_events.push((at, scope, TextEvent::Executed(pieces)));
            }
            flows.called(inner, at, scope, sql);
            if let Some(routine) = flows.created(inner, sql) {
                open.push(routine);
            }
        }
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
                // `USE DATABASE`, `USE CATALOG` (the first of three name
                // levels, as in `catalog.schema.table`), `USE SCHEMA`, bare
                // `USE <db>`, and the qualified `USE <db>.<schema>` forms set
                // the default namespace that later bare table refs resolve
                // under.
                ir::UseKind::Database | ir::UseKind::Catalog | ir::UseKind::Schema => {
                    let comps = use_target_components(sql, u.object_span);
                    match (plan.kind, comps.as_slice()) {
                        // `db.schema` (qualified USE / USE SCHEMA db.schema): set both.
                        (_, [db, schema]) => {
                            db_changes.push((pos, db.clone()));
                            schema_changes.push((pos, Some(schema.clone())));
                        }
                        // A database is the schema where the dialect says so.
                        (ir::UseKind::Database, [db]) => {
                            match dialect.syntax_meaning().database_level {
                                dialect::DatabaseLevel::Schema => {
                                    schema_changes.push((pos, Some(db.clone())))
                                }
                                dialect::DatabaseLevel::AboveSchema
                                | dialect::DatabaseLevel::NotStated => {
                                    db_changes.push((pos, db.clone()))
                                }
                            }
                        }
                        (ir::UseKind::Catalog, [db]) => db_changes.push((pos, db.clone())),
                        (ir::UseKind::Schema, [schema]) => {
                            schema_changes.push((pos, Some(schema.clone())))
                        }
                        // Empty, or more than two components: nothing usable.
                        _ => {}
                    }
                }
                ir::UseKind::Warehouse | ir::UseKind::SecondaryRoles => {}
            }
        }
        // `SET search_path` lists, past the user's own schema, where a name
        // written without a schema after it is looked for, in order: one
        // schema places such a name; more are searched, the first taking
        // what a statement makes. A reset leaves the dialect's own path.
        let set_config = set_config_where_written(stmt, sql);
        if let Some(listed) = set_config {
            let pos = stmt.span().end;
            let names_user = listed.iter().any(|schema| schema.normalized == "$user");
            user_path_changes.push((pos, names_user));
            let mut listed: Vec<facts::IdentName> = listed
                .into_iter()
                .filter(|schema| schema.normalized != "$user")
                .collect();
            // A path naming the user's schema places a bare name in none
            // the run states.
            if listed.len() == 1 && !names_user {
                schema_changes.push((pos, listed.pop()));
                search_path_changes.push((pos, Vec::new()));
            } else {
                schema_changes.push((pos, None));
                search_path_changes.push((pos, listed));
            }
        }
        if let ast::AstStmt::PgSet(set) = stmt {
            let pos = stmt.span().end;
            match set.kind {
                ast::PgSetKind::SetSearchPath => {
                    let written: Vec<facts::IdentName> = set
                        .search_path
                        .iter()
                        .filter_map(|span| search_path_schema(sql, *span))
                        .collect();
                    // A schema not read as a name is one the run does not
                    // know, as the user's is.
                    let names_user = written.len() != set.search_path.len()
                        || written.iter().any(|schema| schema.normalized == "$user");
                    user_path_changes.push((pos, names_user));
                    let mut listed: Vec<facts::IdentName> = written
                        .into_iter()
                        .filter(|schema| schema.normalized != "$user")
                        .collect();
                    if listed.len() == 1 && !names_user {
                        schema_changes.push((pos, listed.pop()));
                        search_path_changes.push((pos, Vec::new()));
                    } else {
                        schema_changes.push((pos, None));
                        search_path_changes.push((pos, listed));
                    }
                }
                ast::PgSetKind::ResetSearchPath | ast::PgSetKind::ResetAll => {
                    schema_changes.push((pos, None));
                    search_path_changes.push((pos, Vec::new()));
                    user_path_changes.push((pos, false));
                }
                ast::PgSetKind::SetRole
                | ast::PgSetKind::SetSessionAuthorization
                | ast::PgSetKind::SetParameter
                | ast::PgSetKind::ResetRole
                | ast::PgSetKind::ResetSessionAuthorization
                | ast::PgSetKind::ResetParameter => {}
            }
        }
        declared_functions.extend(declared_function(stmt, sql));
    }
    declared.extend(
        batch_declared
            .into_iter()
            .map(|(from, names)| DeclaredScope {
                from,
                to: u32::MAX,
                names,
            }),
    );
    let variable_texts = variable_timelines(assignments, &unsettled, &flows.routines);
    let routine_spans: Vec<lexer::token::Span> =
        flows.routines.iter().map(|routine| routine.span).collect();
    // A call's argument that the routine called runs as SQL is text the
    // call runs.
    let (arguments_run, routine_runs) = flows.arguments_run(names, dialect, elsewhere);
    let arguments_run: Vec<ArgumentText> = arguments_run
        .into_iter()
        .filter(|(_, _, pieces)| !pieces.is_empty())
        .collect();
    for (at, scope, pieces) in arguments_run {
        dynamic_sql_literals.extend(ir::dynamic_sql::executed_literals(&pieces));
        executed.extend(
            ir::dynamic_sql::executed_variables(&pieces)
                .into_iter()
                .map(|variable| names.executed(scope, variable)),
        );
        text_events.push((at, scope, TextEvent::Executed(pieces)));
    }
    // The literals a statement runs as written, or through a variable
    // whose whole text one is.
    let mut run_as_written: std::collections::BTreeSet<(u32, u32)> = dynamic_sql_literals
        .iter()
        .filter_map(|literal| match literal {
            ir::dynamic_sql::ExecutedLiteral::Whole(span) => Some((span.start, span.end)),
            ir::dynamic_sql::ExecutedLiteral::Run(_) => None,
        })
        .collect();
    let reached = variables_written_into_executed(&executed, &text_events, names);
    executed.extend(reached);
    dynamic_sql_literals.extend(executed_variable_literals(&assigned, &executed, sql));
    let through_variables = literals_run_through_variables(text_events, names);
    dynamic_sql_literals.extend(through_variables.spliced);
    run_as_written.extend(
        through_variables
            .as_written
            .iter()
            .map(|span| (span.start, span.end)),
    );
    calls_end.sort_unstable();
    ScriptContextFold {
        role_changes,
        db_changes,
        schema_changes,
        search_path_changes,
        user_path_changes,
        routine_search_paths,
        default_search_path: match dialect.syntax_meaning().default_search_path {
            dialect::DefaultSearchPath::Schemas(schemas) => schemas,
            dialect::DefaultSearchPath::SessionSchema | dialect::DefaultSearchPath::NotStated => {
                &[]
            }
        },
        dynamic_sql_literals,
        run_as_written,
        routine_runs,
        cut_statements,
        declared,
        declared_functions,
        variable_texts,
        routine_spans,
        statements,
        statement_at,
        batch_starts,
        calls_end,
    }
}

/// The last statement of a script as its analysis lowered it to read it as
/// a query ([`Engine::analyze_script_reading_last`]): for a caller that
/// reads more of the statement than the report states.
pub struct LastStatement<'a> {
    pub plan: &'a ir::RelPlan,
    pub bindings: &'a ir::BindingTable,
    /// The catalog context the lowering built.
    pub catalog: &'a ir::IndexedCatalogContext,
    /// The function catalog in force at the statement.
    pub functions: &'a ir::FunctionCatalog,
    /// What the analysis derived of `plan`.
    pub derived: &'a ir::derived_facts::DerivedFacts,
    /// The table each scan of `plan` reads, by the scan's node.
    pub tables: &'a ir::expression_fact::ScanIndex,
}

/// What reads a script's last statement as its analysis lowers it.
type ReadsLast<'a> = dyn FnMut(LastStatement<'_>) + 'a;

/// A script's last statement and what reads it ([`LastStatement`]).
struct ReadLast<'a> {
    stmt: &'a ast::AstStmt,
    read: std::cell::Cell<Option<&'a mut ReadsLast<'a>>>,
}

/// Hands a statement of a script, as the analysis lowered it, to what
/// reads the script's last statement, where it is that statement.
trait ReadsLastStatement {
    fn offer(&self, stmt: &ast::AstStmt, lowered: LastStatement<'_>);
}

impl ReadsLastStatement for ReadLast<'_> {
    fn offer(&self, stmt: &ast::AstStmt, lowered: LastStatement<'_>) {
        if !std::ptr::eq(self.stmt, stmt) {
            return;
        }
        if let Some(read) = self.read.take() {
            read(lowered);
            self.read.set(Some(read));
        }
    }
}

/// What the scripts run so far leave for the script run next
/// ([`Engine::analyze_script_carrying`]): each table their statements
/// outside a routine's body create, rename, alter or drop, as the catalog
/// they were analysed with is read beside them, none a temporary table, a
/// session's own, holds; and the tables and columns they left removed
/// ([`facts::reasoning::EarlierRemovals`]).
#[derive(Debug, Clone, Default)]
pub struct CarriedRelations {
    relations: catalog::ScriptRelations,
}

impl CarriedRelations {
    /// Whether no script run so far left a relation it changed.
    pub fn is_empty(&self) -> bool {
        self.relations.is_empty()
    }
}

/// A statement as the query evaluator lowers it.
type LoweredQuery = (
    ir::RelPlan,
    ir::IndexedCatalogContext,
    ir::BindingTable,
    ir::statement_facts::StatementFacts,
    Option<ir::policy_facts::PolicyStatementFacts>,
);

/// A script's relations as [`script_relations`] reads them, and the
/// statements it lowered to read them, each lowered as the query evaluator
/// lowers it, which the evaluator takes in place of lowering it again.
#[derive(Default)]
pub(crate) struct ReadRelations {
    pub(crate) relations: catalog::ScriptRelations,
    /// By the statement's span.
    lowered: std::cell::RefCell<std::collections::BTreeMap<(u32, u32), LoweredQuery>>,
}

impl ReadRelations {
    /// The statement at `span` as reading the relations lowered it, once.
    fn take_lowered(&self, span: lexer::token::Span) -> Option<LoweredQuery> {
        self.lowered.borrow_mut().remove(&(span.start, span.end))
    }
}

/// The relations `script`'s statements create, rename, alter and drop
/// ([`catalog::ScriptRelations`]), each from the end of its statement; one
/// in a routine's body to the end of the routine only. Without a catalog
/// what is known of a relation's columns is what its statements say, and
/// a lowering asks only which names the script's statements change
/// ([`catalog::RelationsAt::names`]). `placeholders` are the placeholder
/// spans `sql`, written in `dialect`, was parsed with. The relations the
/// scripts run before left, taken from `carried`, hold from the start; a
/// statement is lowered over `models` as the analysis lowers it. What the
/// SQL text a statement runs whole writes is read as `runs` says; with the
/// reading of the script's run texts where that is made here.
#[allow(clippy::too_many_arguments)] // the script as read, and what it is read against
fn script_relations(
    script: &ast::AstScript,
    sql: &str,
    placeholders: &[lexer::token::Span],
    fold: &ScriptContextFold,
    functions: &ir::ScriptFunctions,
    dialect: &dyn dialect::Dialect,
    catalog: Option<&catalog::CatalogIndex>,
    reasoning: &dyn facts::reasoning::Reasoning,
    models: Option<&ir::model_catalog::ModelCatalog>,
    carried: Option<&mut catalog::ScriptRelations>,
    session_sql: &[template::artifacts::SessionSql],
    runs: RunTexts<'_>,
) -> (ReadRelations, Option<DynamicBodies>) {
    let mut read = ReadRelations::default();
    if let Some(carried) = carried {
        read.relations = std::mem::take(carried);
    }
    let meaning = dialect.syntax_meaning();
    read.relations =
        std::mem::take(&mut read.relations).placing_temporary_tables(meaning.temporary_tables);
    let mut reading = RelationReading {
        sql,
        placeholders,
        fold,
        functions,
        dialect,
        meaning,
        catalog,
        models,
        reasoning,
        relations: &mut read.relations,
        lowered: &read.lowered,
        shared_sql: std::cell::OnceCell::new(),
        firing: Vec::new(),
        runs,
        met: Vec::new(),
    };
    reading.define_routines(&script.stmts, u32::MAX);
    reading.note_session_sql(session_sql);
    walk_statement_runs(
        &script.stmts,
        sql,
        &mut |stmt, run, reached| match reached {
            Reached::Statement => {
                reading.record(stmt, run);
                if let Some(insert) = run.inserted_by {
                    reading.record_insert_exec(insert, stmt, run);
                }
            }
            // What a statement holding bodies evaluates itself (a condition)
            // runs where it is written.
            Reached::Holder => reading.record_holder(stmt, run),
        },
    );
    // Each run met is decided where it runs, from the reading's parse of
    // its text: what a run writes holds at every statement of the script.
    let bodies = match runs {
        RunTexts::Read { dialect, analysed } => {
            let met = std::mem::take(&mut reading.met);
            Some(DynamicBodies::read(
                sql,
                fold,
                dialect,
                analysed,
                Some((&mut reading, &met)),
            ))
        }
        RunTexts::Recorded(_) | RunTexts::Parsed => None,
    };
    (read, bodies)
}

/// What a statement assigns of the row a trigger is given (`NEW`)
/// ([`statement_assigns`]).
enum Assigns {
    /// It assigns variables and changes no relation: an assignment (`x :=
    /// v`), MySQL `SET x = v`.
    Only(catalog::RowAssigned),
    /// It may assign variables beside what else it does.
    Beside(catalog::RowAssigned),
}

/// What of the row a trigger is given a target names.
enum RowTarget {
    /// `NEW` itself: every column.
    Row,
    /// `NEW.col`, an element of it, `"NEW".col`.
    Column(IdentKey),
}

/// What of the row a trigger is given the target written at `span` names,
/// `sql` the script's text; `None` for any other target.
fn row_target(span: lexer::token::Span, sql: &str) -> Option<RowTarget> {
    let written = sql.get(span.start as usize..span.end as usize)?;
    let is_new = |part: &str| {
        IdentKey::new_as(part, ir::normalize::NameKind::Column)
            .as_str()
            .eq_ignore_ascii_case("new")
    };
    let parts = ir::lower_ddl::split_qualified(written.trim_start_matches(':'));
    match parts.as_slice() {
        [record] if is_new(record) => Some(RowTarget::Row),
        [record, column] if is_new(record) => Some(RowTarget::Column(IdentKey::new_as(
            column,
            ir::normalize::NameKind::Column,
        ))),
        [] | [_] | [_, _] | [_, _, _, ..] => None,
    }
}

/// What `stmt` assigns of the row a trigger is given: each column of
/// `NEW` a target names (`NEW.col`, an element of it, `"NEW".col`), and
/// the row where a target is `NEW` itself; `sql` the script's text. The
/// statements that assign are an assignment, MySQL's and the other
/// dialects' `SET`, Snowflake's `LET`, `SELECT … INTO`, `FETCH … INTO`,
/// `EXECUTE … INTO` and `GET DIAGNOSTICS`, and a `CALL` passing a column
/// of the row to a parameter `passes_back` says the routine called may
/// assign, by its position or the name written.
fn statement_assigns(
    stmt: &ast::AstStmt,
    sql: &str,
    passes_back: &dyn Fn(usize, Option<lexer::token::Span>) -> bool,
) -> Assigns {
    let mut row = catalog::RowAssigned::default();
    let mut target = |span: lexer::token::Span| match row_target(span, sql) {
        Some(RowTarget::Row) => row.whole = true,
        Some(RowTarget::Column(column)) if !row.columns.contains(&column) => {
            row.columns.push(column)
        }
        Some(RowTarget::Column(_)) | None => {}
    };
    match stmt {
        ast::AstStmt::Assign {
            name_span,
            assign_op_span,
            ..
        } => match assign_op_span {
            Some(_) => {
                target(*name_span);
                Assigns::Only(row)
            }
            None => Assigns::Beside(row),
        },
        ast::AstStmt::MysqlSet(set) => {
            match &set.kind {
                ast::AstMysqlSetKind::Assignments(assignments) => {
                    for assignment in assignments {
                        match &assignment.target {
                            ast::AstMysqlSetTarget::System {
                                scope_span: None,
                                name_span,
                            } => target(*name_span),
                            ast::AstMysqlSetTarget::System {
                                scope_span: Some(_),
                                ..
                            }
                            | ast::AstMysqlSetTarget::UserVar { .. }
                            | ast::AstMysqlSetTarget::SystemAtAt { .. } => {}
                        }
                    }
                }
                ast::AstMysqlSetKind::Names(_)
                | ast::AstMysqlSetKind::CharacterSet(_)
                | ast::AstMysqlSetKind::Password(_)
                | ast::AstMysqlSetKind::Role(_)
                | ast::AstMysqlSetKind::DefaultRole(_)
                | ast::AstMysqlSetKind::Transaction(_) => {}
            }
            Assigns::Only(row)
        }
        ast::AstStmt::Select(select) => {
            match select.into_target.as_deref() {
                Some(ast::AstSelectIntoTarget::ScriptingVars { vars, .. }) => {
                    for var in vars {
                        target(*var);
                    }
                }
                Some(
                    ast::AstSelectIntoTarget::NewTable(_) | ast::AstSelectIntoTarget::OutFile(_),
                )
                | None => {}
            }
            Assigns::Beside(row)
        }
        ast::AstStmt::FetchCursor { into_targets, .. } => {
            for into in into_targets {
                target(into.span);
            }
            Assigns::Beside(row)
        }
        ast::AstStmt::ExecuteImmediate { into_vars, .. } => {
            for into in into_vars {
                target(*into);
            }
            Assigns::Beside(row)
        }
        ast::AstStmt::GetDiagnostics { targets, .. } => {
            for into in targets {
                target(*into);
            }
            Assigns::Beside(row)
        }
        ast::AstStmt::SetVariable { variable_names, .. } => {
            for name in variable_names {
                target(name.span);
            }
            Assigns::Beside(row)
        }
        ast::AstStmt::Let { name, .. } => {
            target(name.span);
            Assigns::Beside(row)
        }
        // A routine called assigns an argument passed to an `OUT` or
        // `INOUT` parameter.
        ast::AstStmt::Call { args, .. } => {
            for (position, arg) in args.iter().enumerate() {
                if let ast::AstExpr::Ident { column_ref, .. } = &arg.value {
                    let span = lexer::token::Span {
                        start: column_ref
                            .qualifier
                            .as_ref()
                            .map_or(column_ref.name.span.start, |record| record.span.start),
                        end: column_ref.name.span.end,
                    };
                    if row_target(span, sql).is_some()
                        && passes_back(position, arg.name.as_ref().map(|name| name.span))
                    {
                        target(span);
                    }
                }
            }
            Assigns::Beside(row)
        }
        // Assign no variable.
        ast::AstStmt::SetSelect(_)
        | ast::AstStmt::ValuesQuery(_)
        | ast::AstStmt::OpaqueContent { .. }
        | ast::AstStmt::GoBatchSeparator { .. }
        | ast::AstStmt::SqlcmdCommand { .. }
        | ast::AstStmt::Reconfigure { .. }
        | ast::AstStmt::MssqlServerCommand { .. }
        | ast::AstStmt::MssqlExec(_)
        | ast::AstStmt::MssqlExecuteAs(_)
        | ast::AstStmt::MssqlRevert { .. }
        | ast::AstStmt::MssqlAuditDdl(_)
        | ast::AstStmt::MssqlSecurityObjectDdl(_)
        | ast::AstStmt::MssqlTryCatch(_)
        | ast::AstStmt::MssqlIf(_)
        | ast::AstStmt::MssqlWhile(_)
        | ast::AstStmt::MssqlPrint(_)
        | ast::AstStmt::MssqlThrow(_)
        | ast::AstStmt::MssqlRaiserror(_)
        | ast::AstStmt::MssqlSetOption(_)
        | ast::AstStmt::MysqlUnlockTables(_)
        | ast::AstStmt::MssqlWaitfor(_)
        | ast::AstStmt::MssqlGoto(_)
        | ast::AstStmt::MssqlLabel(_)
        | ast::AstStmt::CreateMssqlTrigger(_)
        | ast::AstStmt::DropMssqlTrigger(_)
        | ast::AstStmt::MssqlTriggerState(_)
        | ast::AstStmt::Savepoint(_)
        | ast::AstStmt::MssqlBulkInsert(_)
        | ast::AstStmt::MssqlCreateExternalModel(_)
        | ast::AstStmt::MssqlCreateExternalDataSource(_)
        | ast::AstStmt::MssqlAlterExternalDataSource(_)
        | ast::AstStmt::CreateForeignServer(_)
        | ast::AstStmt::AlterForeignServer(_)
        | ast::AstStmt::MssqlAlterServerConfiguration(_)
        | ast::AstStmt::CreateUserMapping(_)
        | ast::AstStmt::AlterUserMapping(_)
        | ast::AstStmt::DropUserMapping(_)
        | ast::AstStmt::CreateForeignTable(_)
        | ast::AstStmt::ImportForeignSchema(_)
        | ast::AstStmt::MssqlAlterExternalModel(_)
        | ast::AstStmt::MssqlDropExternalModel(_)
        | ast::AstStmt::MssqlCreateVectorIndex(_)
        | ast::AstStmt::ClauseFragment { .. }
        | ast::AstStmt::CreateTable(_)
        | ast::AstStmt::CreateView(_)
        | ast::AstStmt::CreateDynamicTable(_)
        | ast::AstStmt::CreateTask(_)
        | ast::AstStmt::CreateStage(_)
        | ast::AstStmt::CreateRowAccessPolicy(_)
        | ast::AstStmt::CreateMaskingPolicy(_)
        | ast::AstStmt::CreateNetworkPolicy(_)
        | ast::AstStmt::CreateSessionPolicy(_)
        | ast::AstStmt::CreateAuthenticationPolicy(_)
        | ast::AstStmt::CreateApiIntegration(_)
        | ast::AstStmt::CreateNotificationIntegration(_)
        | ast::AstStmt::CreatePasswordPolicy(_)
        | ast::AstStmt::CreateAggregationPolicy(_)
        | ast::AstStmt::CreateProjectionPolicy(_)
        | ast::AstStmt::CreateStorageIntegration(_)
        | ast::AstStmt::AlterRowAccessPolicy(_)
        | ast::AstStmt::AlterMaskingPolicy(_)
        | ast::AstStmt::AlterNetworkPolicy(_)
        | ast::AstStmt::AlterSessionPolicy(_)
        | ast::AstStmt::AlterSession(_)
        | ast::AstStmt::AlterAuthenticationPolicy(_)
        | ast::AstStmt::AlterUser(_)
        | ast::AstStmt::AlterAccount(_)
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
        | ast::AstStmt::AlterPasswordPolicy(_)
        | ast::AstStmt::AlterAggregationPolicy(_)
        | ast::AstStmt::AlterProjectionPolicy(_)
        | ast::AstStmt::AlterStorageIntegration(_)
        | ast::AstStmt::AlterTable(_)
        | ast::AstStmt::AlterView(_)
        | ast::AstStmt::AlterMaterializedView(_)
        | ast::AstStmt::AlterDynamicTable(_)
        | ast::AstStmt::AlterFunction(_)
        | ast::AstStmt::AlterProcedure(_)
        | ast::AstStmt::AlterStage(_)
        | ast::AstStmt::AlterTask(_)
        | ast::AstStmt::Show(_)
        | ast::AstStmt::Describe(_)
        | ast::AstStmt::Use(_)
        | ast::AstStmt::Truncate(_)
        | ast::AstStmt::Drop(_)
        | ast::AstStmt::DropRowAccessPolicy(_)
        | ast::AstStmt::DropAllRowAccessPolicies(_)
        | ast::AstStmt::DropMaskingPolicy(_)
        | ast::AstStmt::DropNetworkPolicy(_)
        | ast::AstStmt::DropSessionPolicy(_)
        | ast::AstStmt::DropAuthenticationPolicy(_)
        | ast::AstStmt::DropApiIntegration(_)
        | ast::AstStmt::DropNotificationIntegration(_)
        | ast::AstStmt::DropPasswordPolicy(_)
        | ast::AstStmt::DropAggregationPolicy(_)
        | ast::AstStmt::DropProjectionPolicy(_)
        | ast::AstStmt::DropStorageIntegration(_)
        | ast::AstStmt::DropTask(_)
        | ast::AstStmt::CreateWarehouse(_)
        | ast::AstStmt::AlterWarehouse(_)
        | ast::AstStmt::DropWarehouse(_)
        | ast::AstStmt::CreatePipe(_)
        | ast::AstStmt::AlterPipe(_)
        | ast::AstStmt::DropPipe(_)
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
        | ast::AstStmt::AlterAlert(_)
        | ast::AstStmt::CreateJoinPolicy(_)
        | ast::AstStmt::AlterJoinPolicy(_)
        | ast::AstStmt::DropJoinPolicy(_)
        | ast::AstStmt::CreateDataMetricFunction(_)
        | ast::AstStmt::CreateReplicationFailoverGroup(_)
        | ast::AstStmt::CreateExternalAccessIntegration(_)
        | ast::AstStmt::AlterExternalAccessIntegration(_)
        | ast::AstStmt::DropExternalAccessIntegration(_)
        | ast::AstStmt::CreateStream(_)
        | ast::AstStmt::AlterStream(_)
        | ast::AstStmt::DropStream(_)
        | ast::AstStmt::CreateDatabase(_)
        | ast::AstStmt::AlterDatabase(_)
        | ast::AstStmt::DropDatabase(_)
        | ast::AstStmt::UndropDatabase(_)
        | ast::AstStmt::CreateSchema(_)
        | ast::AstStmt::AlterSchema(_)
        | ast::AstStmt::DropSchema(_)
        | ast::AstStmt::UndropSchema(_)
        | ast::AstStmt::UndropTable(_)
        | ast::AstStmt::UndropType(_)
        | ast::AstStmt::Insert(_)
        | ast::AstStmt::ReplaceInto(_)
        | ast::AstStmt::MultiInsert(_)
        | ast::AstStmt::Update(_)
        | ast::AstStmt::Delete(_)
        | ast::AstStmt::Merge(_)
        | ast::AstStmt::Explain(_)
        | ast::AstStmt::PsqlGexec(_)
        | ast::AstStmt::MysqlDo(_)
        | ast::AstStmt::ExecuteTask(_)
        | ast::AstStmt::MysqlCreateLoadableFunction(_)
        | ast::AstStmt::MysqlAdmin(_)
        | ast::AstStmt::CreateIndex(_)
        | ast::AstStmt::CreateSynonym(_)
        | ast::AstStmt::CommentOn(_)
        | ast::AstStmt::DoBlock(_)
        | ast::AstStmt::Perform(_)
        | ast::AstStmt::Vacuum(_)
        | ast::AstStmt::AnalyzeStmt(_)
        | ast::AstStmt::CreateType(_)
        | ast::AstStmt::AlterType(_)
        | ast::AstStmt::CreateExtension(_)
        | ast::AstStmt::CreateSequence(_)
        | ast::AstStmt::AlterSequence(_)
        | ast::AstStmt::CreatePgTrigger(_)
        | ast::AstStmt::AlterPgTrigger(_)
        | ast::AstStmt::DropPgTrigger(_)
        | ast::AstStmt::CreateDomain(_)
        | ast::AstStmt::AlterDomain(_)
        | ast::AstStmt::DropDomain(_)
        | ast::AstStmt::CreatePgPolicy(_)
        | ast::AstStmt::AlterPgPolicy(_)
        | ast::AstStmt::DropPgPolicy(_)
        | ast::AstStmt::AlterIndex(_)
        | ast::AstStmt::Reindex(_)
        | ast::AstStmt::PgPrepare(_)
        | ast::AstStmt::PgExecute(_)
        | ast::AstStmt::PgDeallocate(_)
        | ast::AstStmt::PgCopy(_)
        | ast::AstStmt::PgRefreshMatview(_)
        | ast::AstStmt::PgListen(_)
        | ast::AstStmt::PgNotify(_)
        | ast::AstStmt::PgUnlisten(_)
        | ast::AstStmt::PgLockTable(_)
        | ast::AstStmt::PgCreateRule(_)
        | ast::AstStmt::MssqlCreateRule(_)
        | ast::AstStmt::PgCreateAggregate(_)
        | ast::AstStmt::PgCreateOperator(_)
        | ast::AstStmt::PgAlterSystem(_)
        | ast::AstStmt::PgAlterTablespace(_)
        | ast::AstStmt::PgDropOwned(_)
        | ast::AstStmt::PgReassignOwned(_)
        | ast::AstStmt::PgDiscard(_)
        | ast::AstStmt::PgCluster(_)
        | ast::AstStmt::PgPublication(_)
        | ast::AstStmt::PgSubscription(_)
        | ast::AstStmt::CreatePrincipal(_)
        | ast::AstStmt::AlterPrincipal(_)
        | ast::AstStmt::DropPrincipal(_)
        | ast::AstStmt::PgDropExtension(_)
        | ast::AstStmt::PgAlterRule(_)
        | ast::AstStmt::PgDropRule(_)
        | ast::AstStmt::PgAlterTableTriggerState(_)
        | ast::AstStmt::PgSet(_)
        | ast::AstStmt::PgDropSequence(_)
        | ast::AstStmt::PgDropType(_)
        | ast::AstStmt::PgDropIndex(_)
        | ast::AstStmt::PgCreateTablespace(_)
        | ast::AstStmt::PgDropTablespace(_)
        | ast::AstStmt::BqExportData(_)
        | ast::AstStmt::BqLoadData(_)
        | ast::AstStmt::MysqlLoadData(_)
        | ast::AstStmt::MysqlRenameTable(_)
        | ast::AstStmt::CreateEvent(_)
        | ast::AstStmt::AlterEvent(_)
        | ast::AstStmt::CreateMysqlTrigger(_)
        | ast::AstStmt::BqAssert(_)
        | ast::AstStmt::BqCreateSnapshotTable(_)
        | ast::AstStmt::BqDropSnapshotTable(_)
        | ast::AstStmt::BqCreateSearchIndex(_)
        | ast::AstStmt::BqDropSearchIndex(_)
        | ast::AstStmt::BqCreateVectorIndex(_)
        | ast::AstStmt::BqDropVectorIndex(_)
        | ast::AstStmt::BqAlterVectorIndex(_)
        | ast::AstStmt::BqCreateModel(_)
        | ast::AstStmt::BqAlterModel(_)
        | ast::AstStmt::BqExportModel(_)
        | ast::AstStmt::BqDropModel(_)
        | ast::AstStmt::Optimize(_)
        | ast::AstStmt::DescribeHistory(_)
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
        | ast::AstStmt::CacheTable(_)
        | ast::AstStmt::UncacheTable(_)
        | ast::AstStmt::RepairTable(_)
        | ast::AstStmt::CreateCatalog(_)
        | ast::AstStmt::AlterCatalog(_)
        | ast::AstStmt::DropCatalog(_)
        | ast::AstStmt::CreateVolume(_)
        | ast::AstStmt::AlterVolume(_)
        | ast::AstStmt::DropVolume(_)
        | ast::AstStmt::CreateExternalLocation(_)
        | ast::AstStmt::AlterExternalLocation(_)
        | ast::AstStmt::DropExternalLocation(_)
        | ast::AstStmt::CreateStorageCredential(_)
        | ast::AstStmt::AlterStorageCredential(_)
        | ast::AstStmt::DropStorageCredential(_)
        | ast::AstStmt::CreateConnection(_)
        | ast::AstStmt::AlterConnection(_)
        | ast::AstStmt::DropConnection(_)
        | ast::AstStmt::CreateFlow(_)
        | ast::AstStmt::CreateExternalTable(_)
        | ast::AstStmt::CreateExternalSchema(_)
        | ast::AstStmt::PipeChain { .. }
        | ast::AstStmt::Block(_)
        | ast::AstStmt::If(_)
        | ast::AstStmt::CaseStmt(_)
        | ast::AstStmt::Declare { .. }
        | ast::AstStmt::DeclareTable { .. }
        | ast::AstStmt::DeclareCursor { .. }
        | ast::AstStmt::LetCursor { .. }
        | ast::AstStmt::Return { .. }
        | ast::AstStmt::Raise { .. }
        | ast::AstStmt::Signal { .. }
        | ast::AstStmt::Resignal { .. }
        | ast::AstStmt::DeclareCondition { .. }
        | ast::AstStmt::DeclareHandler(_)
        | ast::AstStmt::For(_)
        | ast::AstStmt::ForEach(_)
        | ast::AstStmt::While(_)
        | ast::AstStmt::Repeat(_)
        | ast::AstStmt::Loop(_)
        | ast::AstStmt::Await { .. }
        | ast::AstStmt::Cancel { .. }
        | ast::AstStmt::Break { .. }
        | ast::AstStmt::Continue { .. }
        | ast::AstStmt::Null { .. }
        | ast::AstStmt::OpenCursor { .. }
        | ast::AstStmt::CloseCursor { .. }
        | ast::AstStmt::CreateProcedure(_)
        | ast::AstStmt::CreateFunction(_)
        | ast::AstStmt::CreateTableFunction(_)
        | ast::AstStmt::ExecuteImmediateFrom(_)
        | ast::AstStmt::CreateExternalFunction(_)
        | ast::AstStmt::BeginTransaction { .. }
        | ast::AstStmt::Commit { .. }
        | ast::AstStmt::Rollback { .. }
        | ast::AstStmt::CopyIntoTable { .. }
        | ast::AstStmt::CopyIntoLocation { .. }
        | ast::AstStmt::Unload { .. }
        | ast::AstStmt::RedshiftCopy { .. }
        | ast::AstStmt::JinjaPlaceholder { .. }
        | ast::AstStmt::JinjaConditionalStmt(_)
        | ast::AstStmt::Grant(_)
        | ast::AstStmt::Revoke(_)
        | ast::AstStmt::Deny(_)
        | ast::AstStmt::AlterAuthorization(_)
        | ast::AstStmt::Error { .. } => Assigns::Beside(row),
    }
}

/// What a statement sets to run at a write into a table, or changes of
/// what is set ([`RelationReading::write_hooks`]).
enum WriteHook {
    /// A write into `table` (any table where `None`) runs what
    /// `definition` says; `name` names a trigger or a rule, which replaces
    /// one of its name on its table where `replaces`.
    Defines {
        name: Option<IdentKey>,
        table: Option<crate::context::node_metadata::TableRef>,
        definition: catalog::TriggerDefinition,
        replaces: bool,
    },
    /// A trigger or a rule in force is changed.
    Changes(catalog::TriggerOp),
}

/// What [`script_relations`] reads the statements with.
struct RelationReading<'a> {
    sql: &'a str,
    placeholders: &'a [lexer::token::Span],
    fold: &'a ScriptContextFold,
    functions: &'a ir::ScriptFunctions,
    dialect: &'a dyn dialect::Dialect,
    meaning: dialect::SyntaxMeaning,
    catalog: Option<&'a catalog::CatalogIndex>,
    models: Option<&'a ir::model_catalog::ModelCatalog>,
    reasoning: &'a dyn facts::reasoning::Reasoning,
    relations: &'a mut catalog::ScriptRelations,
    /// The statements lowered to read them ([`ReadRelations`]).
    lowered: &'a std::cell::RefCell<std::collections::BTreeMap<(u32, u32), LoweredQuery>>,
    /// `sql`, shared by the queries of the relations its statements make.
    shared_sql: std::cell::OnceCell<std::sync::Arc<str>>,
    /// The triggers running, outermost first, each with what set it
    /// running ([`Self::fire_triggers`]).
    firing: Vec<(usize, catalog::Hook)>,
    /// Where what the SQL text a statement runs whole writes is taken from.
    runs: RunTexts<'a>,
    /// The runs met, where `runs` says they are read with the script.
    met: Vec<MetRun>,
}

/// A statement running SQL text written whole as one literal, as a
/// relation reading met it: the literal, where the statement starts, and
/// the session it runs under ([`RelationReading::note_run_writes`]).
struct MetRun {
    literal: lexer::token::Span,
    at: u32,
    session: ir::SessionContext,
}

/// How [`script_relations`] reads what the SQL text a statement runs whole
/// writes.
#[derive(Clone, Copy)]
enum RunTexts<'r> {
    /// With the script, as [`DynamicBodies::read`] reads it under
    /// `dialect`, its texts kept for analysis where `analysed`, once the
    /// statements are read: each run is met ([`MetRun`]) and decided from
    /// that reading's parse of its text ([`RelationReading::decide_read`]).
    Read {
        dialect: &'r dialect::DialectRef,
        analysed: bool,
    },
    /// Read with the text that runs this script, which recorded what each
    /// writes ([`DynamicBodies::run_writes`]).
    Recorded(&'r DynamicBodies),
    /// Read by no reading: each text parsed where it is met.
    Parsed,
}

/// A write, as the triggers it runs see it ([`RelationReading::fire_triggers`]).
#[derive(Clone, Copy)]
struct Triggering<'r> {
    /// The events it raises.
    events: catalog::WriteEvents,
    /// The rows it writes; `None` where it only removes rows.
    rows: Option<&'r catalog::WrittenRows>,
    /// It writes the table alone, none of its children (`ONLY`).
    only: bool,
    /// The columns its update assigns.
    updated: &'r catalog::UpdatedColumns,
    /// Its rows are those a child's triggers assigned, written into the
    /// parents whose write ran them: they run only each parent's own
    /// child hook, on up to its parents.
    returns: bool,
}

/// How a hook runs at a write ([`RelationReading::fire_triggers`]).
#[derive(Clone, Copy)]
enum HookRun {
    /// Where the write runs it.
    Now,
    /// A child's hook run by its parent's: after the child's triggers,
    /// carrying back to the parent what they assign of each row.
    Returns,
    /// Not run.
    Skipped,
}

impl HookRun {
    /// How `hook` runs at a write: one of rows returning from a child
    /// where `returns`, the write of the hook `by` where one is.
    fn of(returns: bool, by: Option<catalog::Hook>, hook: catalog::Hook) -> HookRun {
        match (returns, by, hook) {
            (true, _, catalog::Hook::Child | catalog::Hook::Partition) => HookRun::Now,
            (true, _, catalog::Hook::Trigger | catalog::Hook::Rule | catalog::Hook::Parent) => {
                HookRun::Skipped
            }
            (
                false,
                Some(catalog::Hook::Child | catalog::Hook::Partition),
                catalog::Hook::Parent,
            ) => HookRun::Skipped,
            (
                false,
                Some(catalog::Hook::Parent),
                catalog::Hook::Child | catalog::Hook::Partition,
            ) => HookRun::Returns,
            (
                false,
                None | Some(catalog::Hook::Trigger | catalog::Hook::Rule),
                catalog::Hook::Trigger
                | catalog::Hook::Rule
                | catalog::Hook::Child
                | catalog::Hook::Partition
                | catalog::Hook::Parent,
            )
            | (
                false,
                Some(catalog::Hook::Child | catalog::Hook::Partition | catalog::Hook::Parent),
                catalog::Hook::Trigger | catalog::Hook::Rule,
            )
            | (
                false,
                Some(catalog::Hook::Child | catalog::Hook::Partition),
                catalog::Hook::Child | catalog::Hook::Partition,
            )
            | (false, Some(catalog::Hook::Parent), catalog::Hook::Parent) => HookRun::Now,
        }
    }
}

/// Where a statement [`for_each_statement_run`] hands over runs.
#[derive(Debug, Clone, Copy)]
pub struct StatementRun<'a> {
    /// The 0-indexed position, among the script's top-level statements,
    /// of the statement or of the one holding it.
    pub holder: u32,
    /// The end of the routine whose body holds it: `u32::MAX` for a
    /// statement that runs where it is written, outside any routine's,
    /// trigger's, event's or task's body (a DO block's body runs where it
    /// is written).
    pub until: u32,
    /// The bodies holding it, outermost first, that may not run, or may run
    /// again, where they are written (a branch, an `ELSE`, a loop, a
    /// handler).
    pub unsettled: &'a [UnsettledRange],
    /// The `INSERT` whose rows its result gives (T-SQL `INSERT … EXEC`).
    pub inserted_by: Option<&'a ast::AstStmt>,
}

/// A body that may not run, or may run again, where it is written
/// ([`StatementRun::unsettled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsettledRange {
    /// From its first statement's start to its last's end.
    pub range: std::ops::Range<u32>,
    /// The statement holding it.
    pub owner: lexer::token::Span,
    /// Where the statement holding it runs exactly one of its bodies (the
    /// branches of an `IF` or a `CASE` and its `ELSE`, written or not):
    /// how many it has.
    pub alternatives: Option<usize>,
    /// The table it runs only where that table is absent
    /// ([`absence_guard`]): a statement in it that makes the table makes
    /// it on every path.
    pub absent: Option<facts::reasoning::TableIdentity>,
}

/// Hands `visit` each statement of `stmts`, and of the bodies they hold at
/// every depth, that holds no body, in source order, with where it runs
/// ([`StatementRun`]), `sql` the script's text. A body nested deeper than
/// the analyzer's walk allows is not read.
pub fn for_each_statement_run<'s>(
    stmts: &'s [ast::AstStmt],
    sql: &str,
    visit: &mut dyn FnMut(&'s ast::AstStmt, StatementRun<'_>),
) {
    walk_statement_runs(stmts, sql, &mut |stmt, run, reached| match reached {
        Reached::Statement => visit(stmt, run),
        Reached::Holder => {}
    });
}

/// What [`walk_statement_runs`] hands over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// A statement that holds no body.
    Statement,
    /// A statement that holds bodies, before them: what it evaluates
    /// itself (a condition, an operand) runs where it is written.
    Holder,
}

/// [`for_each_statement_run`], handing `visit` each statement holding
/// bodies too, before its bodies, where it runs.
fn walk_statement_runs<'s>(
    stmts: &'s [ast::AstStmt],
    sql: &str,
    visit: &mut dyn FnMut(&'s ast::AstStmt, StatementRun<'_>, Reached),
) {
    let mut unsettled = Vec::new();
    for (holder, stmt) in stmts.iter().enumerate() {
        let holder = u32::try_from(holder).unwrap_or(u32::MAX);
        visit_statement_run(stmt, sql, holder, u32::MAX, &mut unsettled, None, visit);
    }
}

/// [`walk_statement_runs`] of `stmt`, held by the top-level statement
/// `holder`, `until` the end of the routine whose body holds it, inside
/// the `unsettled` bodies, its result the rows of `inserted_by`.
fn visit_statement_run<'s>(
    stmt: &'s ast::AstStmt,
    sql: &str,
    holder: u32,
    until: u32,
    unsettled: &mut Vec<UnsettledRange>,
    inserted_by: Option<&'s ast::AstStmt>,
    visit: &mut dyn FnMut(&'s ast::AstStmt, StatementRun<'_>, Reached),
) {
    let bodies = stmt.bodies();
    let run = StatementRun {
        holder,
        until,
        unsettled,
        inserted_by,
    };
    if bodies.is_empty() {
        visit(stmt, run, Reached::Statement);
        return;
    }
    visit(stmt, run, Reached::Holder);
    let Some(_frame) = ir::lower::enter_nested() else {
        return;
    };
    // A conditional with an `ELSE` body, written or not, runs exactly one.
    let alternative =
        |role: ast::BodyRole| matches!(role, ast::BodyRole::Branch | ast::BodyRole::Else);
    let alternatives = (bodies.iter().all(|body| alternative(body.role))
        && bodies
            .iter()
            .any(|body| matches!(body.role, ast::BodyRole::Else)))
    .then_some(bodies.len());
    let absent = absence_guard(stmt, sql);
    for body in &bodies {
        // A routine's body runs when the routine is called; a DO block
        // runs where it is written.
        let until = if is_routine_body(body.role) && !matches!(stmt, ast::AstStmt::DoBlock(_)) {
            until.min(stmt.span().end)
        } else {
            until
        };
        let range = match (body.stmts.first(), body.stmts.last()) {
            (Some(first), Some(last)) => Some(first.span().start..last.span().end),
            (None, _) | (_, None) => None,
        };
        let held = match (unsettled_body(body.role), range) {
            (Some(false), Some(range)) => {
                unsettled.push(UnsettledRange {
                    range,
                    owner: stmt.span(),
                    alternatives,
                    absent: absent
                        .clone()
                        .filter(|_| matches!(body.role, ast::BodyRole::Branch)),
                });
                true
            }
            (Some(_) | None, _) => false,
        };
        let inserted_by = match body.role {
            ast::BodyRole::InsertExec => Some(stmt),
            ast::BodyRole::Routine
            | ast::BodyRole::Declarations
            | ast::BodyRole::Block
            | ast::BodyRole::Branch
            | ast::BodyRole::Else
            | ast::BodyRole::Loop
            | ast::BodyRole::LoopQuery
            | ast::BodyRole::Catch
            | ast::BodyRole::ExceptionHandler
            | ast::BodyRole::HandlerAction => None,
        };
        for inner in body.stmts {
            visit_statement_run(inner, sql, holder, until, unsettled, inserted_by, visit);
        }
        if held {
            unsettled.pop();
        }
    }
}

impl RelationReading<'_> {
    /// Record each routine `stmts`, and the bodies they hold at every
    /// depth, define, `until` the end of the routine whose body holds them
    /// ([`StatementRun::until`]): its name, and whether its body was read.
    fn define_routines(&mut self, stmts: &[ast::AstStmt], until: u32) {
        for stmt in stmts {
            // What a statement changes of the triggers in force is read
            // where it runs ([`Self::change_triggers`]).
            let session = self.fold.session_context_at(stmt.span().start);
            let _values = self.fold.enter_statement(stmt.span().start);
            for hook in self.write_hooks(stmt) {
                match hook {
                    WriteHook::Defines {
                        name,
                        table,
                        definition,
                        replaces: _,
                    } => self.relations.define_trigger(
                        name,
                        table.as_ref(),
                        &session,
                        stmt.span(),
                        until,
                        definition,
                    ),
                    WriteHook::Changes(_) => {}
                }
            }
            let bodies = stmt.bodies();
            let runs_where_written = matches!(stmt, ast::AstStmt::DoBlock(_));
            let routine: Vec<&ast::StatementBody<'_>> = bodies
                .iter()
                .filter(|body| is_routine_body(body.role))
                .collect();
            if !routine.is_empty() && !runs_where_written {
                if let Some(name) = self.routine_name(stmt) {
                    let read = routine.iter().any(|body| !body.stmts.is_empty());
                    let (signature, replaces) = routine_signature(stmt, self.sql, self.dialect);
                    self.relations.define_routine(
                        name,
                        signature,
                        routine_params(stmt, self.sql),
                        replaces,
                        stmt.span(),
                        until,
                        read,
                    );
                }
            }
            for body in &bodies {
                let inner = if is_routine_body(body.role) && !runs_where_written {
                    until.min(stmt.span().end)
                } else {
                    until
                };
                self.define_routines(body.stmts, inner);
            }
        }
    }

    /// What `stmt` sets to run at a write into a table, or changes of what
    /// is set: a trigger or a rule, which runs its body or its function; a
    /// table that is a child or a partition of others, a write into which
    /// writes rows into them, and the parent an update of which updates the
    /// child's rows; a trigger or a rule dropped, renamed, enabled or
    /// disabled. A table not read is any table, and a function not read
    /// runs what is not read.
    fn write_hooks(&self, stmt: &ast::AstStmt) -> Vec<WriteHook> {
        use catalog::WriteEvents;
        let table = |span| {
            ir::lower_ddl::target_from(span, self.sql).map(|target| ddl_target_table(&target))
        };
        let name = |span: lexer::token::Span| {
            let written = self.sql.get(span.start as usize..span.end as usize)?;
            ir::lower::routine_name(written).pop()
        };
        let body = || catalog::TriggerRuns::Body {
            end: stmt.span().end,
        };
        let defines = |name, table, hook, runs, events, sets_row, replaces| {
            vec![WriteHook::Defines {
                name,
                table,
                definition: catalog::TriggerDefinition {
                    hook,
                    runs,
                    events,
                    update_of: Vec::new(),
                    sets_row,
                },
                replaces,
            }]
        };
        // Rows written into a child are rows of each parent. An update or a
        // truncate of a parent changes the child's rows too; every row a
        // partitioned table is written goes into its partitions.
        let parents_of = |child: Option<crate::context::node_metadata::TableRef>,
                          parents: &[lexer::token::Span],
                          partition: bool,
                          at: u32| {
            let session = self.fold.session_context_at(at);
            let change = |target, change| catalog::RoutineChange {
                target,
                session: session.clone(),
                change,
                updated: catalog::UpdatedColumns::Unknown,
            };
            let read: Vec<crate::context::node_metadata::TableRef> =
                parents.iter().filter_map(|parent| table(*parent)).collect();
            // A parent not read is a write not read.
            let runs = (read.len() == parents.len()).then(|| {
                catalog::BodyChanges::of(
                    read.iter()
                        .map(|parent| {
                            change(
                                parent.clone(),
                                catalog::RoutineChangeKind::Rows(WriteEvents::ANY),
                            )
                        })
                        .collect(),
                )
            });
            let (child_hook, rows) = if partition {
                (
                    catalog::Hook::Partition,
                    WriteEvents::INSERT.union(WriteEvents::UPDATE),
                )
            } else {
                (catalog::Hook::Child, WriteEvents::UPDATE)
            };
            let mut hooks = defines(
                None,
                child.clone(),
                child_hook,
                catalog::TriggerRuns::Changes(runs),
                WriteEvents::ANY,
                false,
                false,
            );
            if let Some(child) = child {
                for parent in read {
                    let writes = vec![
                        change(child.clone(), catalog::RoutineChangeKind::Rows(rows)),
                        change(
                            child.clone(),
                            catalog::RoutineChangeKind::Removes(WriteEvents::TRUNCATE),
                        ),
                    ];
                    hooks.extend(defines(
                        None,
                        Some(parent),
                        catalog::Hook::Parent,
                        catalog::TriggerRuns::Changes(Some(catalog::BodyChanges::of(writes))),
                        rows.union(WriteEvents::TRUNCATE),
                        false,
                        false,
                    ));
                }
            }
            hooks
        };
        let drops = |name: Option<IdentKey>, table| {
            name.map(|name| WriteHook::Changes(catalog::TriggerOp::Drop { name, table }))
                .into_iter()
                .collect()
        };
        match stmt {
            ast::AstStmt::CreatePgTrigger(trigger) => {
                let runs = match table(trigger.function_name) {
                    Some(function) => catalog::TriggerRuns::Calls(routine_identity(&function)),
                    None => catalog::TriggerRuns::Changes(None),
                };
                let events = trigger
                    .events
                    .iter()
                    .fold(WriteEvents::NONE, |events, event| {
                        events.union(match event.kind {
                            ast::PgTriggerEventKind::Insert => WriteEvents::INSERT,
                            ast::PgTriggerEventKind::Update { .. } => WriteEvents::UPDATE,
                            ast::PgTriggerEventKind::Delete => WriteEvents::DELETE,
                            ast::PgTriggerEventKind::Truncate => WriteEvents::TRUNCATE,
                        })
                    });
                let sets_row = match (trigger.timing, trigger.for_each) {
                    (ast::PgTriggerTiming::Before, Some(ast::PgForEachMode::Row)) => true,
                    (
                        ast::PgTriggerTiming::Before
                        | ast::PgTriggerTiming::After
                        | ast::PgTriggerTiming::InsteadOf,
                        Some(ast::PgForEachMode::Row | ast::PgForEachMode::Statement) | None,
                    ) => false,
                };
                // `UPDATE OF a, b`: an update runs it where it assigns one.
                let update_of = trigger
                    .events
                    .iter()
                    .flat_map(|event| match &event.kind {
                        ast::PgTriggerEventKind::Update { columns } => columns.as_slice(),
                        ast::PgTriggerEventKind::Insert
                        | ast::PgTriggerEventKind::Delete
                        | ast::PgTriggerEventKind::Truncate => &[],
                    })
                    .filter_map(|span| ir::utils::slice_span(self.sql, *span))
                    .map(|column| IdentKey::new_as(column, ir::normalize::NameKind::Column))
                    .collect();
                vec![WriteHook::Defines {
                    name: name(trigger.trigger_name),
                    table: table(trigger.table_name),
                    definition: catalog::TriggerDefinition {
                        hook: catalog::Hook::Trigger,
                        runs,
                        events,
                        update_of,
                        sets_row,
                    },
                    replaces: trigger.or_replace,
                }]
            }
            // A MySQL trigger of a name in use is not made.
            ast::AstStmt::CreateMysqlTrigger(trigger) => defines(
                name(trigger.name_span),
                table(trigger.target_table_span),
                catalog::Hook::Trigger,
                body(),
                match trigger.event {
                    ast::TriggerEvent::Insert => WriteEvents::INSERT,
                    ast::TriggerEvent::Update => WriteEvents::UPDATE,
                    ast::TriggerEvent::Delete => WriteEvents::DELETE,
                },
                match trigger.timing {
                    ast::TriggerTiming::Before => true,
                    ast::TriggerTiming::After => false,
                },
                false,
            ),
            ast::AstStmt::CreateMssqlTrigger(trigger) => defines(
                name(trigger.name_span),
                table(trigger.target_span),
                catalog::Hook::Trigger,
                body(),
                trigger
                    .events
                    .iter()
                    .fold(WriteEvents::NONE, |events, event| {
                        events.union(match event {
                            ast::MssqlTriggerEvent::Insert => WriteEvents::INSERT,
                            ast::MssqlTriggerEvent::Update => WriteEvents::UPDATE,
                            ast::MssqlTriggerEvent::Delete => WriteEvents::DELETE,
                            ast::MssqlTriggerEvent::Named => WriteEvents::NONE,
                        })
                    }),
                false,
                match trigger.verb {
                    ast::AstDefinitionVerb::Create => false,
                    ast::AstDefinitionVerb::Alter | ast::AstDefinitionVerb::CreateOrAlter => true,
                },
            ),
            ast::AstStmt::PgCreateRule(rule) => defines(
                name(rule.rule_name),
                table(rule.table_name),
                catalog::Hook::Rule,
                body(),
                WriteEvents::ANY,
                false,
                rule.or_replace,
            ),
            ast::AstStmt::CreateTable(create) => {
                let mut hooks = Vec::new();
                for (parents, partition) in [
                    (create.partition_of.as_slice(), true),
                    (create.inherits.as_slice(), false),
                ] {
                    let parents: Vec<lexer::token::Span> =
                        parents.iter().map(|parent| parent.span).collect();
                    if !parents.is_empty() {
                        hooks.extend(parents_of(
                            table(create.name.span),
                            &parents,
                            partition,
                            create.span.start,
                        ));
                    }
                }
                hooks
            }
            // `[NO] INHERIT parent`, `ATTACH` / `DETACH PARTITION child`:
            // the child's rows become, or stop being, rows of the parent.
            ast::AstStmt::AlterTable(alter) => {
                let child = table(alter.name.span);
                let mut hooks = Vec::new();
                for action in &alter.actions {
                    let (kind, parent) = match &action.kind {
                        // `ATTACH PARTITION p`: `p`'s rows become rows of
                        // the altered table, here the parent; `DETACH`
                        // ends that.
                        ast::AstAlterTableActionKind::AttachPartition { partition, .. } => {
                            hooks.extend(parents_of(
                                table(partition.span),
                                &[alter.name.span],
                                true,
                                alter.span.start,
                            ));
                            continue;
                        }
                        ast::AstAlterTableActionKind::DetachPartition { partition, .. } => {
                            if let (Some(child), Some(parent)) =
                                (table(partition.span), child.clone())
                            {
                                hooks.push(WriteHook::Changes(catalog::TriggerOp::Uninherit {
                                    child,
                                    parent,
                                }));
                            }
                            continue;
                        }
                        ast::AstAlterTableActionKind::NamedAction {
                            kind,
                            name_span: Some(parent),
                            ..
                        } => (kind, *parent),
                        ast::AstAlterTableActionKind::NamedAction {
                            name_span: None, ..
                        }
                        | ast::AstAlterTableActionKind::RenameTo { .. }
                        | ast::AstAlterTableActionKind::RenameColumn { .. }
                        | ast::AstAlterTableActionKind::ChangeColumn { .. }
                        | ast::AstAlterTableActionKind::SwapWith { .. }
                        | ast::AstAlterTableActionKind::AddColumn { .. }
                        | ast::AstAlterTableActionKind::DropColumn { .. }
                        | ast::AstAlterTableActionKind::AlterColumn { .. }
                        | ast::AstAlterTableActionKind::AlterColumnList { .. }
                        | ast::AstAlterTableActionKind::AddConstraint { .. }
                        | ast::AstAlterTableActionKind::DropConstraint { .. }
                        | ast::AstAlterTableActionKind::ClusterBy { .. }
                        | ast::AstAlterTableActionKind::DropClusteringKey { .. }
                        | ast::AstAlterTableActionKind::SuspendRecluster { .. }
                        | ast::AstAlterTableActionKind::ResumeRecluster { .. }
                        | ast::AstAlterTableActionKind::Set { .. }
                        | ast::AstAlterTableActionKind::Unset { .. }
                        | ast::AstAlterTableActionKind::AddRowAccessPolicy(_)
                        | ast::AstAlterTableActionKind::DropRowAccessPolicy { .. }
                        | ast::AstAlterTableActionKind::DropAllRowAccessPolicies { .. }
                        | ast::AstAlterTableActionKind::SetRowFilter { .. }
                        | ast::AstAlterTableActionKind::DropRowFilter { .. }
                        | ast::AstAlterTableActionKind::SetAggregationPolicy { .. }
                        | ast::AstAlterTableActionKind::UnsetAggregationPolicy { .. }
                        | ast::AstAlterTableActionKind::SetJoinPolicy { .. }
                        | ast::AstAlterTableActionKind::UnsetJoinPolicy { .. }
                        | ast::AstAlterTableActionKind::SetColumnMaskingPolicy { .. }
                        | ast::AstAlterTableActionKind::UnsetColumnMaskingPolicy { .. }
                        | ast::AstAlterTableActionKind::SetColumnMask { .. }
                        | ast::AstAlterTableActionKind::DropColumnMask { .. }
                        | ast::AstAlterTableActionKind::SetColumnProjectionPolicy { .. }
                        | ast::AstAlterTableActionKind::UnsetColumnProjectionPolicy { .. }
                        | ast::AstAlterTableActionKind::SetTag { .. }
                        | ast::AstAlterTableActionKind::UnsetTag { .. }
                        | ast::AstAlterTableActionKind::SetColumnTag { .. }
                        | ast::AstAlterTableActionKind::UnsetColumnTag { .. }
                        | ast::AstAlterTableActionKind::AddSearchOptimization { .. }
                        | ast::AstAlterTableActionKind::DropSearchOptimization { .. }
                        | ast::AstAlterTableActionKind::SetDataMetricSchedule { .. }
                        | ast::AstAlterTableActionKind::UnsetDataMetricSchedule { .. }
                        | ast::AstAlterTableActionKind::AddDataMetricFunction { .. }
                        | ast::AstAlterTableActionKind::DropDataMetricFunction { .. }
                        | ast::AstAlterTableActionKind::AddStorageLifecyclePolicy { .. }
                        | ast::AstAlterTableActionKind::DropStorageLifecyclePolicy { .. }
                        | ast::AstAlterTableActionKind::SetOptions { .. }
                        | ast::AstAlterTableActionKind::SetDefaultCollate { .. }
                        | ast::AstAlterTableActionKind::DropPrimaryKey { .. }
                        | ast::AstAlterTableActionKind::AlterColumnSetOptions { .. }
                        | ast::AstAlterTableActionKind::AlterColumnDropNotNull { .. }
                        | ast::AstAlterTableActionKind::AlterColumnSetDataType { .. }
                        | ast::AstAlterTableActionKind::AlterColumnSetDefault { .. }
                        | ast::AstAlterTableActionKind::AlterColumnDropDefault { .. }
                        | ast::AstAlterTableActionKind::SetTblProperties { .. }
                        | ast::AstAlterTableActionKind::UnsetTblProperties { .. }
                        | ast::AstAlterTableActionKind::RowLevelSecurity { .. }
                        | ast::AstAlterTableActionKind::OwnerTo { .. }
                        | ast::AstAlterTableActionKind::SetSchema { .. }
                        | ast::AstAlterTableActionKind::SwitchTo { .. }
                        | ast::AstAlterTableActionKind::GovernanceSpan { .. }
                        | ast::AstAlterTableActionKind::Unknown { .. } => continue,
                    };
                    match kind {
                        ast::AstNamedTableAction::Inherit => {
                            hooks.extend(parents_of(
                                child.clone(),
                                &[parent],
                                false,
                                alter.span.start,
                            ));
                        }
                        ast::AstNamedTableAction::NoInherit => {
                            if let (Some(child), Some(parent)) = (child.clone(), table(parent)) {
                                hooks.push(WriteHook::Changes(catalog::TriggerOp::Uninherit {
                                    child,
                                    parent,
                                }));
                            }
                        }
                        ast::AstNamedTableAction::DropConstraint
                        | ast::AstNamedTableAction::DropIndex
                        | ast::AstNamedTableAction::DropForeignKey
                        | ast::AstNamedTableAction::DropCheck
                        | ast::AstNamedTableAction::DropPartition
                        | ast::AstNamedTableAction::DropPeriod
                        | ast::AstNamedTableAction::AddPrimaryKey
                        | ast::AstNamedTableAction::AddUnique
                        | ast::AstNamedTableAction::AddCheck
                        | ast::AstNamedTableAction::AddIndex
                        | ast::AstNamedTableAction::AddPartition
                        | ast::AstNamedTableAction::AddPeriod
                        | ast::AstNamedTableAction::AddDefault
                        | ast::AstNamedTableAction::CheckConstraint
                        | ast::AstNamedTableAction::NocheckConstraint
                        | ast::AstNamedTableAction::EnableTrigger
                        | ast::AstNamedTableAction::DisableTrigger
                        | ast::AstNamedTableAction::ChangeTracking
                        | ast::AstNamedTableAction::FiletableNamespace
                        | ast::AstNamedTableAction::Rebuild
                        | ast::AstNamedTableAction::RenameIndex
                        | ast::AstNamedTableAction::RenameConstraint
                        | ast::AstNamedTableAction::AlterIndex
                        | ast::AstNamedTableAction::AlterConstraint
                        | ast::AstNamedTableAction::ValidateConstraint
                        | ast::AstNamedTableAction::TableOption
                        | ast::AstNamedTableAction::ReplicaIdentity
                        | ast::AstNamedTableAction::Distribution
                        | ast::AstNamedTableAction::PartitionMaintenance
                        | ast::AstNamedTableAction::RuleState
                        | ast::AstNamedTableAction::SearchOptimization
                        | ast::AstNamedTableAction::DropUnique
                        | ast::AstNamedTableAction::ResetOptions
                        | ast::AstNamedTableAction::RowLevelSecurity
                        | ast::AstNamedTableAction::KeysState
                        | ast::AstNamedTableAction::DropFeature
                        | ast::AstNamedTableAction::PredictiveOptimization => {}
                    }
                }
                hooks
            }
            ast::AstStmt::PgAlterTableTriggerState(state) => {
                vec![WriteHook::Changes(catalog::TriggerOp::State {
                    name: match state.target {
                        ast::PgAlterTableTriggerStateTarget::Named(span) => match name(span) {
                            Some(name) => Some(name),
                            None => return Vec::new(),
                        },
                        ast::PgAlterTableTriggerStateTarget::All
                        | ast::PgAlterTableTriggerStateTarget::User => None,
                    },
                    table: table(state.table_name),
                    // A trigger enabled for replication only may run.
                    enabled: match state.action {
                        ast::PgAlterTableTriggerStateAction::Disable => false,
                        ast::PgAlterTableTriggerStateAction::Enable
                        | ast::PgAlterTableTriggerStateAction::EnableAlways
                        | ast::PgAlterTableTriggerStateAction::EnableReplica => true,
                    },
                })]
            }
            ast::AstStmt::MssqlTriggerState(state) => {
                let on = match &state.scope {
                    ast::MssqlTriggerScope::Object(on) => table(on.span),
                    // A database or server trigger runs at no write.
                    ast::MssqlTriggerScope::Database | ast::MssqlTriggerScope::AllServer => {
                        return Vec::new()
                    }
                };
                let enabled = match state.action {
                    ast::MssqlTriggerStateAction::Enable => true,
                    ast::MssqlTriggerStateAction::Disable => false,
                };
                match &state.triggers {
                    ast::MssqlTriggerList::All => {
                        vec![WriteHook::Changes(catalog::TriggerOp::State {
                            name: None,
                            table: on,
                            enabled,
                        })]
                    }
                    ast::MssqlTriggerList::Named(triggers) => triggers
                        .iter()
                        .filter_map(|trigger| name(trigger.span))
                        .map(|name| {
                            WriteHook::Changes(catalog::TriggerOp::State {
                                name: Some(name),
                                table: on.clone(),
                                enabled,
                            })
                        })
                        .collect(),
                }
            }
            ast::AstStmt::AlterPgTrigger(alter) => match &alter.action {
                ast::PgAlterTriggerAction::RenameTo { new_name, .. } => {
                    match (name(alter.trigger_name), name(*new_name)) {
                        (Some(old), Some(to)) => {
                            vec![WriteHook::Changes(catalog::TriggerOp::Rename {
                                name: old,
                                table: table(alter.table_name),
                                to,
                            })]
                        }
                        (None, _) | (_, None) => Vec::new(),
                    }
                }
                ast::PgAlterTriggerAction::DependsOnExtension { .. } => Vec::new(),
            },
            ast::AstStmt::DropPgTrigger(drop) => {
                drops(name(drop.trigger_name), table(drop.table_name))
            }
            ast::AstStmt::PgDropRule(drop) => drops(name(drop.rule_name), table(drop.table_name)),
            ast::AstStmt::DropMssqlTrigger(drop) => drop
                .trigger_names
                .iter()
                .filter_map(|span| name(*span))
                .map(|name| WriteHook::Changes(catalog::TriggerOp::Drop { name, table: None }))
                .collect(),
            // MySQL's `DROP TRIGGER [schema.]name`.
            ast::AstStmt::Drop(drop) => {
                let session = self.fold.session_context_at(drop.span.start);
                let trigger = ir::lower_ddl_stmt(stmt, &self.ddl_inputs(drop.span.start, &session))
                    .is_some_and(|plan| {
                        matches!(plan.object_kind, facts::identity::ObjectKind::Trigger)
                    });
                drops(
                    drop.target_name
                        .as_ref()
                        .filter(|_| trigger)
                        .and_then(|target| name(target.span)),
                    None,
                )
            }
            ast::AstStmt::Select(_)
            | ast::AstStmt::SetSelect(_)
            | ast::AstStmt::ValuesQuery(_)
            | ast::AstStmt::OpaqueContent { .. }
            | ast::AstStmt::GoBatchSeparator { .. }
            | ast::AstStmt::SqlcmdCommand { .. }
            | ast::AstStmt::Reconfigure { .. }
            | ast::AstStmt::MssqlServerCommand { .. }
            | ast::AstStmt::MssqlExec(_)
            | ast::AstStmt::MssqlExecuteAs(_)
            | ast::AstStmt::MssqlRevert { .. }
            | ast::AstStmt::MssqlAuditDdl(_)
            | ast::AstStmt::MssqlSecurityObjectDdl(_)
            | ast::AstStmt::MssqlTryCatch(_)
            | ast::AstStmt::MssqlIf(_)
            | ast::AstStmt::MssqlWhile(_)
            | ast::AstStmt::MssqlPrint(_)
            | ast::AstStmt::MssqlThrow(_)
            | ast::AstStmt::MssqlRaiserror(_)
            | ast::AstStmt::MssqlSetOption(_)
            | ast::AstStmt::MysqlSet(_)
            | ast::AstStmt::MysqlUnlockTables(_)
            | ast::AstStmt::MssqlWaitfor(_)
            | ast::AstStmt::MssqlGoto(_)
            | ast::AstStmt::MssqlLabel(_)
            | ast::AstStmt::Savepoint(_)
            | ast::AstStmt::MssqlBulkInsert(_)
            | ast::AstStmt::MssqlCreateExternalModel(_)
            | ast::AstStmt::MssqlCreateExternalDataSource(_)
            | ast::AstStmt::MssqlAlterExternalDataSource(_)
            | ast::AstStmt::CreateForeignServer(_)
            | ast::AstStmt::AlterForeignServer(_)
            | ast::AstStmt::MssqlAlterServerConfiguration(_)
            | ast::AstStmt::CreateUserMapping(_)
            | ast::AstStmt::AlterUserMapping(_)
            | ast::AstStmt::DropUserMapping(_)
            | ast::AstStmt::CreateForeignTable(_)
            | ast::AstStmt::ImportForeignSchema(_)
            | ast::AstStmt::MssqlAlterExternalModel(_)
            | ast::AstStmt::MssqlDropExternalModel(_)
            | ast::AstStmt::MssqlCreateVectorIndex(_)
            | ast::AstStmt::ClauseFragment { .. }
            | ast::AstStmt::CreateView(_)
            | ast::AstStmt::CreateDynamicTable(_)
            | ast::AstStmt::CreateTask(_)
            | ast::AstStmt::CreateStage(_)
            | ast::AstStmt::CreateRowAccessPolicy(_)
            | ast::AstStmt::CreateMaskingPolicy(_)
            | ast::AstStmt::CreateNetworkPolicy(_)
            | ast::AstStmt::CreateSessionPolicy(_)
            | ast::AstStmt::CreateAuthenticationPolicy(_)
            | ast::AstStmt::CreateApiIntegration(_)
            | ast::AstStmt::CreateNotificationIntegration(_)
            | ast::AstStmt::CreatePasswordPolicy(_)
            | ast::AstStmt::CreateAggregationPolicy(_)
            | ast::AstStmt::CreateProjectionPolicy(_)
            | ast::AstStmt::CreateStorageIntegration(_)
            | ast::AstStmt::AlterRowAccessPolicy(_)
            | ast::AstStmt::AlterMaskingPolicy(_)
            | ast::AstStmt::AlterNetworkPolicy(_)
            | ast::AstStmt::AlterSessionPolicy(_)
            | ast::AstStmt::AlterSession(_)
            | ast::AstStmt::AlterAuthenticationPolicy(_)
            | ast::AstStmt::AlterUser(_)
            | ast::AstStmt::AlterAccount(_)
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
            | ast::AstStmt::AlterPasswordPolicy(_)
            | ast::AstStmt::AlterAggregationPolicy(_)
            | ast::AstStmt::AlterProjectionPolicy(_)
            | ast::AstStmt::AlterStorageIntegration(_)
            | ast::AstStmt::AlterView(_)
            | ast::AstStmt::AlterMaterializedView(_)
            | ast::AstStmt::AlterDynamicTable(_)
            | ast::AstStmt::AlterFunction(_)
            | ast::AstStmt::AlterProcedure(_)
            | ast::AstStmt::AlterStage(_)
            | ast::AstStmt::AlterTask(_)
            | ast::AstStmt::Show(_)
            | ast::AstStmt::Describe(_)
            | ast::AstStmt::Use(_)
            | ast::AstStmt::Truncate(_)
            | ast::AstStmt::DropRowAccessPolicy(_)
            | ast::AstStmt::DropAllRowAccessPolicies(_)
            | ast::AstStmt::DropMaskingPolicy(_)
            | ast::AstStmt::DropNetworkPolicy(_)
            | ast::AstStmt::DropSessionPolicy(_)
            | ast::AstStmt::DropAuthenticationPolicy(_)
            | ast::AstStmt::DropApiIntegration(_)
            | ast::AstStmt::DropNotificationIntegration(_)
            | ast::AstStmt::DropPasswordPolicy(_)
            | ast::AstStmt::DropAggregationPolicy(_)
            | ast::AstStmt::DropProjectionPolicy(_)
            | ast::AstStmt::DropStorageIntegration(_)
            | ast::AstStmt::DropTask(_)
            | ast::AstStmt::CreateWarehouse(_)
            | ast::AstStmt::AlterWarehouse(_)
            | ast::AstStmt::DropWarehouse(_)
            | ast::AstStmt::CreatePipe(_)
            | ast::AstStmt::AlterPipe(_)
            | ast::AstStmt::DropPipe(_)
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
            | ast::AstStmt::AlterAlert(_)
            | ast::AstStmt::CreateJoinPolicy(_)
            | ast::AstStmt::AlterJoinPolicy(_)
            | ast::AstStmt::DropJoinPolicy(_)
            | ast::AstStmt::CreateDataMetricFunction(_)
            | ast::AstStmt::CreateReplicationFailoverGroup(_)
            | ast::AstStmt::CreateExternalAccessIntegration(_)
            | ast::AstStmt::AlterExternalAccessIntegration(_)
            | ast::AstStmt::DropExternalAccessIntegration(_)
            | ast::AstStmt::CreateStream(_)
            | ast::AstStmt::AlterStream(_)
            | ast::AstStmt::DropStream(_)
            | ast::AstStmt::CreateDatabase(_)
            | ast::AstStmt::AlterDatabase(_)
            | ast::AstStmt::DropDatabase(_)
            | ast::AstStmt::UndropDatabase(_)
            | ast::AstStmt::CreateSchema(_)
            | ast::AstStmt::AlterSchema(_)
            | ast::AstStmt::DropSchema(_)
            | ast::AstStmt::UndropSchema(_)
            | ast::AstStmt::UndropTable(_)
            | ast::AstStmt::UndropType(_)
            | ast::AstStmt::Insert(_)
            | ast::AstStmt::ReplaceInto(_)
            | ast::AstStmt::MultiInsert(_)
            | ast::AstStmt::Update(_)
            | ast::AstStmt::Delete(_)
            | ast::AstStmt::Merge(_)
            | ast::AstStmt::Explain(_)
            | ast::AstStmt::PsqlGexec(_)
            | ast::AstStmt::MysqlDo(_)
            | ast::AstStmt::ExecuteTask(_)
            | ast::AstStmt::MysqlCreateLoadableFunction(_)
            | ast::AstStmt::MysqlAdmin(_)
            | ast::AstStmt::CreateIndex(_)
            | ast::AstStmt::CreateSynonym(_)
            | ast::AstStmt::CommentOn(_)
            | ast::AstStmt::DoBlock(_)
            | ast::AstStmt::Perform(_)
            | ast::AstStmt::Vacuum(_)
            | ast::AstStmt::AnalyzeStmt(_)
            | ast::AstStmt::CreateType(_)
            | ast::AstStmt::AlterType(_)
            | ast::AstStmt::CreateExtension(_)
            | ast::AstStmt::CreateSequence(_)
            | ast::AstStmt::AlterSequence(_)
            | ast::AstStmt::CreateDomain(_)
            | ast::AstStmt::AlterDomain(_)
            | ast::AstStmt::DropDomain(_)
            | ast::AstStmt::CreatePgPolicy(_)
            | ast::AstStmt::AlterPgPolicy(_)
            | ast::AstStmt::DropPgPolicy(_)
            | ast::AstStmt::AlterIndex(_)
            | ast::AstStmt::Reindex(_)
            | ast::AstStmt::PgPrepare(_)
            | ast::AstStmt::PgExecute(_)
            | ast::AstStmt::PgDeallocate(_)
            | ast::AstStmt::PgCopy(_)
            | ast::AstStmt::PgRefreshMatview(_)
            | ast::AstStmt::PgListen(_)
            | ast::AstStmt::PgNotify(_)
            | ast::AstStmt::PgUnlisten(_)
            | ast::AstStmt::PgLockTable(_)
            | ast::AstStmt::MssqlCreateRule(_)
            | ast::AstStmt::PgCreateAggregate(_)
            | ast::AstStmt::PgCreateOperator(_)
            | ast::AstStmt::PgAlterSystem(_)
            | ast::AstStmt::PgAlterTablespace(_)
            | ast::AstStmt::PgDropOwned(_)
            | ast::AstStmt::PgReassignOwned(_)
            | ast::AstStmt::PgDiscard(_)
            | ast::AstStmt::PgCluster(_)
            | ast::AstStmt::PgPublication(_)
            | ast::AstStmt::PgSubscription(_)
            | ast::AstStmt::CreatePrincipal(_)
            | ast::AstStmt::AlterPrincipal(_)
            | ast::AstStmt::DropPrincipal(_)
            | ast::AstStmt::PgDropExtension(_)
            | ast::AstStmt::PgAlterRule(_)
            | ast::AstStmt::PgSet(_)
            | ast::AstStmt::PgDropSequence(_)
            | ast::AstStmt::PgDropType(_)
            | ast::AstStmt::PgDropIndex(_)
            | ast::AstStmt::PgCreateTablespace(_)
            | ast::AstStmt::PgDropTablespace(_)
            | ast::AstStmt::BqExportData(_)
            | ast::AstStmt::BqLoadData(_)
            | ast::AstStmt::MysqlLoadData(_)
            | ast::AstStmt::MysqlRenameTable(_)
            | ast::AstStmt::CreateEvent(_)
            | ast::AstStmt::AlterEvent(_)
            | ast::AstStmt::BqAssert(_)
            | ast::AstStmt::BqCreateSnapshotTable(_)
            | ast::AstStmt::BqDropSnapshotTable(_)
            | ast::AstStmt::BqCreateSearchIndex(_)
            | ast::AstStmt::BqDropSearchIndex(_)
            | ast::AstStmt::BqCreateVectorIndex(_)
            | ast::AstStmt::BqDropVectorIndex(_)
            | ast::AstStmt::BqAlterVectorIndex(_)
            | ast::AstStmt::BqCreateModel(_)
            | ast::AstStmt::BqAlterModel(_)
            | ast::AstStmt::BqExportModel(_)
            | ast::AstStmt::BqDropModel(_)
            | ast::AstStmt::Optimize(_)
            | ast::AstStmt::DescribeHistory(_)
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
            | ast::AstStmt::CacheTable(_)
            | ast::AstStmt::UncacheTable(_)
            | ast::AstStmt::RepairTable(_)
            | ast::AstStmt::CreateCatalog(_)
            | ast::AstStmt::AlterCatalog(_)
            | ast::AstStmt::DropCatalog(_)
            | ast::AstStmt::CreateVolume(_)
            | ast::AstStmt::AlterVolume(_)
            | ast::AstStmt::DropVolume(_)
            | ast::AstStmt::CreateExternalLocation(_)
            | ast::AstStmt::AlterExternalLocation(_)
            | ast::AstStmt::DropExternalLocation(_)
            | ast::AstStmt::CreateStorageCredential(_)
            | ast::AstStmt::AlterStorageCredential(_)
            | ast::AstStmt::DropStorageCredential(_)
            | ast::AstStmt::CreateConnection(_)
            | ast::AstStmt::AlterConnection(_)
            | ast::AstStmt::DropConnection(_)
            | ast::AstStmt::CreateFlow(_)
            | ast::AstStmt::CreateExternalTable(_)
            | ast::AstStmt::CreateExternalSchema(_)
            | ast::AstStmt::SetVariable { .. }
            | ast::AstStmt::PipeChain { .. }
            | ast::AstStmt::Block(_)
            | ast::AstStmt::Assign { .. }
            | ast::AstStmt::If(_)
            | ast::AstStmt::CaseStmt(_)
            | ast::AstStmt::Declare { .. }
            | ast::AstStmt::DeclareTable { .. }
            | ast::AstStmt::DeclareCursor { .. }
            | ast::AstStmt::Let { .. }
            | ast::AstStmt::LetCursor { .. }
            | ast::AstStmt::Return { .. }
            | ast::AstStmt::Raise { .. }
            | ast::AstStmt::Signal { .. }
            | ast::AstStmt::Resignal { .. }
            | ast::AstStmt::GetDiagnostics { .. }
            | ast::AstStmt::DeclareCondition { .. }
            | ast::AstStmt::DeclareHandler(_)
            | ast::AstStmt::For(_)
            | ast::AstStmt::ForEach(_)
            | ast::AstStmt::While(_)
            | ast::AstStmt::Repeat(_)
            | ast::AstStmt::Loop(_)
            | ast::AstStmt::Await { .. }
            | ast::AstStmt::Cancel { .. }
            | ast::AstStmt::Break { .. }
            | ast::AstStmt::Continue { .. }
            | ast::AstStmt::Null { .. }
            | ast::AstStmt::OpenCursor { .. }
            | ast::AstStmt::FetchCursor { .. }
            | ast::AstStmt::CloseCursor { .. }
            | ast::AstStmt::CreateProcedure(_)
            | ast::AstStmt::CreateFunction(_)
            | ast::AstStmt::CreateTableFunction(_)
            | ast::AstStmt::ExecuteImmediate { .. }
            | ast::AstStmt::ExecuteImmediateFrom(_)
            | ast::AstStmt::CreateExternalFunction(_)
            | ast::AstStmt::BeginTransaction { .. }
            | ast::AstStmt::Commit { .. }
            | ast::AstStmt::Rollback { .. }
            | ast::AstStmt::Call { .. }
            | ast::AstStmt::CopyIntoTable { .. }
            | ast::AstStmt::CopyIntoLocation { .. }
            | ast::AstStmt::Unload { .. }
            | ast::AstStmt::RedshiftCopy { .. }
            | ast::AstStmt::JinjaPlaceholder { .. }
            | ast::AstStmt::JinjaConditionalStmt(_)
            | ast::AstStmt::Grant(_)
            | ast::AstStmt::Revoke(_)
            | ast::AstStmt::Deny(_)
            | ast::AstStmt::AlterAuthorization(_)
            | ast::AstStmt::Error { .. } => Vec::new(),
        }
    }

    /// The name of the routine `stmt` defines, each part as written,
    /// normalized.
    fn routine_name(&self, stmt: &ast::AstStmt) -> Option<facts::reasoning::TableIdentity> {
        let session = self.fold.session_context_at(stmt.span().start);
        let _values = self.fold.enter_statement(stmt.span().start);
        let plan = ir::lower_ddl_stmt(stmt, &self.ddl_inputs(stmt.span().start, &session))?;
        plan.target
            .as_ref()
            .map(|target| routine_identity(&ddl_target_table(target)))
    }

    /// What the DDL lowering of a statement starting at `at` reads, under
    /// `session`.
    fn ddl_inputs<'i>(&'i self, at: u32, session: &'i ir::SessionContext) -> ir::IrLowerInputs<'i> {
        self.ddl_inputs_in(self.sql, self.placeholders, at, session)
    }

    /// [`Self::ddl_inputs`] for a statement of the text `sql`, whose
    /// placeholders are at `placeholders`.
    fn ddl_inputs_in<'i>(
        &'i self,
        sql: &'i str,
        placeholders: &'i [lexer::token::Span],
        at: u32,
        session: &'i ir::SessionContext,
    ) -> ir::IrLowerInputs<'i> {
        ir::IrLowerInputs {
            source: sql,
            placeholder_spans: placeholders,
            strict: ir::StrictMode::Permissive,
            func_catalog: self.functions.at(at),
            session,
            meaning: self.meaning,
            catalog: None,
            model_catalog: None,
            reasoning: self.reasoning,
            flatten_body_into: None,
        }
    }

    /// Record `edit` of the relation `target` names by the statement at
    /// `site`; one in a routine's body is a change a call of the routine
    /// makes. A relation that runs its query over a relation changed is
    /// read again.
    fn edit(
        &mut self,
        target: &crate::context::node_metadata::TableRef,
        edit: catalog::RelationEdit<'_>,
        site: catalog::RelationSite<'_>,
    ) {
        if site.until != u32::MAX {
            self.relations.routine_changes(
                site.until,
                target,
                site.session,
                catalog::RoutineChangeKind::Relation,
                &catalog::UpdatedColumns::NONE,
            );
        }
        let changed = self.relations.record(target, edit, site, self.catalog);
        self.read_again(changed, site);
    }

    /// Record what `stmt`, at `site`, changes of the triggers and rules in
    /// force, where it runs: a trigger made under a name in use that
    /// replaces the one of its name; a trigger dropped, renamed, enabled or
    /// disabled; a child no longer a parent's. One in a routine's body is
    /// changed where the routine is called ([`Self::run_changes`]); an
    /// enable there may run, so it is also read where it is written.
    fn change_triggers(&mut self, stmt: &ast::AstStmt, site: catalog::RelationSite<'_>) {
        let at = site.statement.start;
        for hook in self.write_hooks(stmt) {
            let op = match hook {
                WriteHook::Defines {
                    name: Some(name),
                    table,
                    replaces: true,
                    ..
                } if site.until == u32::MAX => catalog::TriggerOp::Replace { name, table },
                // Made where the routine whose body holds it is called.
                WriteHook::Defines {
                    name,
                    table,
                    definition,
                    replaces,
                } if site.until != u32::MAX => catalog::TriggerOp::Create {
                    name,
                    table,
                    definition,
                    replaces,
                },
                WriteHook::Defines { .. } => continue,
                WriteHook::Changes(op) => op,
            };
            let enables = match &op {
                catalog::TriggerOp::State { enabled, .. } => *enabled,
                catalog::TriggerOp::Drop { .. }
                | catalog::TriggerOp::Rename { .. }
                | catalog::TriggerOp::Uninherit { .. }
                | catalog::TriggerOp::Replace { .. }
                | catalog::TriggerOp::Create { .. } => false,
            };
            let change = catalog::TriggerChange {
                op,
                session: site.session.clone(),
            };
            if site.until != u32::MAX {
                self.relations.routine_changes_trigger(site.until, &change);
            }
            if site.until == u32::MAX || enables {
                self.relations.change_trigger(&change, at);
            }
        }
    }

    /// Record the routines `stmt`, at `site`, drops: a `DROP PROCEDURE` or
    /// `DROP FUNCTION` ends each routine of a name it lists, of the
    /// parameter types written where they are. One in a routine's body is
    /// not read: the routines it drops stand.
    fn drop_routines(&mut self, stmt: &ast::AstStmt, site: catalog::RelationSite<'_>) {
        if site.until != u32::MAX {
            return;
        }
        if let ast::AstStmt::Drop(drop) = stmt {
            if drop.targets.is_empty() {
                return;
            }
            let routine = ir::lower_ddl_stmt(stmt, &self.ddl_inputs(drop.span.start, site.session))
                .is_some_and(|plan| {
                    matches!(plan.action, ir::ddl_plan::DdlAction::Drop)
                        && matches!(
                            plan.object_kind,
                            facts::identity::ObjectKind::Procedure
                                | facts::identity::ObjectKind::Function
                        )
                });
            if !routine {
                return;
            }
            for target in &drop.targets {
                let Some(name) = ir::lower_ddl::target_from_name(&target.name, self.sql) else {
                    continue;
                };
                let signature = target
                    .signature
                    .and_then(|_| param_types(&target.params, self.sql, self.dialect));
                self.relations.drop_routine(
                    &routine_identity(&ddl_target_table(&name)),
                    signature.as_deref(),
                    site.statement.start,
                );
            }
        }
    }

    /// Record that the statement at `site` writes rows into `target` as
    /// `rows` says, by a write that raises `events`, its update assigning
    /// `updated`, into the table alone where `only`; one in a routine's
    /// body is a change a call of the routine makes. A relation that runs
    /// its query over a relation written is read again, and each trigger
    /// on a relation written runs.
    fn write(
        &mut self,
        target: &crate::context::node_metadata::TableRef,
        rows: &catalog::WrittenRows,
        events: catalog::WriteEvents,
        updated: &catalog::UpdatedColumns,
        only: bool,
        site: catalog::RelationSite<'_>,
    ) {
        if site.until != u32::MAX {
            self.relations.routine_changes(
                site.until,
                target,
                site.session,
                catalog::RoutineChangeKind::Rows(events),
                updated,
            );
        }
        let written = self
            .relations
            .write(target, rows, self.reasoning, site, self.catalog);
        self.read_again(written.clone(), site);
        let triggering = Triggering {
            events,
            rows: Some(rows),
            only,
            updated,
            returns: false,
        };
        self.fire_triggers(target, &written, triggering, site);
    }

    /// Record that the statement at `site` removes rows from `target`, by
    /// a write that raises `events`, from the table alone where `only`,
    /// writing none: what held of every row holds, and each trigger on it
    /// runs. One in a routine's body is a change a call of the routine
    /// makes.
    fn remove_rows(
        &mut self,
        target: &crate::context::node_metadata::TableRef,
        events: catalog::WriteEvents,
        only: bool,
        site: catalog::RelationSite<'_>,
    ) {
        if site.until != u32::MAX {
            self.relations.routine_changes(
                site.until,
                target,
                site.session,
                catalog::RoutineChangeKind::Removes(events),
                &catalog::UpdatedColumns::NONE,
            );
        }
        let triggering = Triggering {
            events,
            rows: None,
            only,
            updated: &catalog::UpdatedColumns::NONE,
            returns: false,
        };
        self.fire_triggers(target, &[], triggering, site);
    }

    /// Run, at the statement at `site`, each trigger the scripts define on
    /// the table `target` names, or on one of `written`, that the write
    /// `triggering` runs there: what it changes, read as a call, and, of one
    /// run before each row, the columns of the row it is given that it
    /// assigns, written in place into the table it is on. A parent's hook
    /// writes the rows of the write into each child, at the events it runs
    /// at that the write raises, except under `ONLY`; a hook's writes
    /// assign the columns the write's update assigns.
    /// In a routine's body nothing runs: the triggers in force where the
    /// routine is called run there. A trigger already running is not run
    /// again, and rows a child's hook writes into its parent do not go
    /// down to its children. Rows a parent's hook writes into a child do
    /// not come back, but what the child's triggers assign of them does:
    /// it is written into each parent, running none of the parent's own
    /// hooks but the one carrying it on up.
    fn fire_triggers(
        &mut self,
        target: &crate::context::node_metadata::TableRef,
        written: &[catalog::RelationKey],
        triggering: Triggering<'_>,
        site: catalog::RelationSite<'_>,
    ) {
        if !self.reasoning.provides_analysis() || site.until != u32::MAX {
            return;
        }
        let at = site.statement.start;
        let events = triggering.events;
        let updated = triggering.updated;
        // The hook whose write this is, where one is.
        let by = self.firing.last().map(|(_, hook)| *hook);
        // The hooks the write may run, each found by the table it is on.
        let hooks: Vec<catalog::Hook> = catalog::Hook::ALL
            .into_iter()
            .filter(|hook| match HookRun::of(triggering.returns, by, *hook) {
                HookRun::Now | HookRun::Returns => true,
                HookRun::Skipped => false,
            })
            .collect();
        let write = catalog::HookedWrite {
            at,
            events,
            updated,
            hooks: &hooks,
        };
        // Each trigger, with the relation it is on: `None` for `target`.
        let mut triggers: Vec<(catalog::Fired, Option<&catalog::RelationKey>)> = self
            .relations
            .triggers_on(target, site.session, self.catalog, write)
            .into_iter()
            .map(|fired| (fired, None))
            .collect();
        for key in written {
            triggers.extend(
                self.relations
                    .triggers_on_key(key, write)
                    .into_iter()
                    .map(|fired| (fired, Some(key))),
            );
        }
        triggers.sort_by_key(|(fired, _)| fired.index);
        triggers.dedup_by_key(|(fired, _)| fired.index);
        // What a trigger runs is a routine of the dialect: one MySQL lets
        // run no DDL changes no declaration.
        let reach = self.routine_reach();
        // What the triggers run before each row assign of it, by the
        // relation they are on, and the child hooks that carry it back.
        let mut assigned: Vec<(Option<&catalog::RelationKey>, catalog::RowAssigned)> = Vec::new();
        let mut returning: Vec<(catalog::Fired, Option<&catalog::RelationKey>)> = Vec::new();
        for (fired, on) in triggers {
            let trigger = fired.index;
            if self.firing.iter().any(|(running, _)| *running == trigger) {
                continue;
            }
            let run = HookRun::of(triggering.returns, by, fired.hook);
            match run {
                HookRun::Now => {}
                HookRun::Returns => {
                    returning.push((fired, on));
                    continue;
                }
                HookRun::Skipped => continue,
            }
            // Rows returning to a parent go on up through its own child
            // hook.
            if triggering.returns {
                if let Some(rows) = triggering.rows {
                    self.firing.push((trigger, fired.hook));
                    self.return_through(fired.runs, rows, updated, site);
                    self.firing.pop();
                }
                continue;
            }
            // The rows the hook writes: those of the write into a parent,
            // rows not known for what any other runs. A hook's writes
            // assign what the write assigns, a routine's what it assigns.
            let (rows, through) = match fired.hook {
                catalog::Hook::Parent if triggering.only => continue,
                catalog::Hook::Parent => (triggering.rows, Some(updated)),
                catalog::Hook::Child | catalog::Hook::Partition => (None, Some(updated)),
                catalog::Hook::Trigger | catalog::Hook::Rule => (None, None),
            };
            let changes = match fired.runs {
                catalog::TriggerRuns::Body { end } => self.relations.changes_of_body(end),
                catalog::TriggerRuns::Calls(name) => match self.relations.called(&name, at) {
                    catalog::Called::Changes(changes) => Some(changes),
                    catalog::Called::NotDefined | catalog::Called::Unread => None,
                },
                catalog::TriggerRuns::Changes(changes) => changes,
            };
            let changes = match fired.hook {
                catalog::Hook::Parent => changes.map(|changes| changes.raised_by(events)),
                catalog::Hook::Trigger
                | catalog::Hook::Rule
                | catalog::Hook::Child
                | catalog::Hook::Partition => changes,
            };
            if let Some(row) = changes
                .as_ref()
                .filter(|changes| fired.sets_row && !changes.row.is_empty())
                .map(|changes| changes.row.written())
            {
                let changed = match on {
                    Some(key) => self.relations.write_key(key, &row, self.reasoning, site),
                    None => self
                        .relations
                        .write(target, &row, self.reasoning, site, self.catalog),
                };
                self.read_again(changed, site);
                if let Some(changes) = &changes {
                    match assigned.iter_mut().find(|(held, _)| *held == on) {
                        Some((_, held)) => held.join(&changes.row),
                        None => assigned.push((on, changes.row.clone())),
                    }
                }
            }
            self.firing.push((trigger, fired.hook));
            self.run_changes(changes, site, reach, rows, through);
            self.firing.pop();
        }
        for (fired, on) in returning {
            let Some((_, row)) = assigned.iter().find(|(held, _)| *held == on) else {
                continue;
            };
            let rows = row.written();
            self.firing.push((fired.index, fired.hook));
            self.return_through(fired.runs, &rows, updated, site);
            self.firing.pop();
        }
    }

    /// Record that the statement at `site` writes `rows`, what a child's
    /// triggers assigned of its rows, into each parent the child's hook,
    /// which runs `runs`, writes; each parent runs only its own child hook
    /// ([`Triggering::returns`]), the write's update assigning `updated`.
    /// A parent not read is a run not read.
    fn return_through(
        &mut self,
        runs: catalog::TriggerRuns,
        rows: &catalog::WrittenRows,
        updated: &catalog::UpdatedColumns,
        site: catalog::RelationSite<'_>,
    ) {
        let changes = match runs {
            catalog::TriggerRuns::Changes(Some(changes)) => changes,
            catalog::TriggerRuns::Changes(None) => {
                self.unread_reaching(site, catalog::UnreadReach::Rows);
                return;
            }
            // A child's hook runs the rows it writes into its parents.
            catalog::TriggerRuns::Body { .. } | catalog::TriggerRuns::Calls(_) => return,
        };
        for change in &changes.changes {
            let site = catalog::RelationSite {
                session: &change.session,
                ..site
            };
            match change.change {
                catalog::RoutineChangeKind::Rows(events) => {
                    let written = self.relations.write(
                        &change.target,
                        rows,
                        self.reasoning,
                        site,
                        self.catalog,
                    );
                    self.read_again(written.clone(), site);
                    let triggering = Triggering {
                        events,
                        rows: Some(rows),
                        only: false,
                        updated,
                        returns: true,
                    };
                    self.fire_triggers(&change.target, &written, triggering, site);
                }
                // A child's hook writes rows into its parents, nothing else.
                catalog::RoutineChangeKind::Removes(_) | catalog::RoutineChangeKind::Relation => {}
            }
        }
    }

    /// Record that the statement at `site` runs what changes `changes`, a
    /// routine's: each relation it writes, rows written into it as `rows`
    /// says (rows not known where `None`), each it removes rows from, and
    /// each it makes, alters or drops, changed in a way not read; each
    /// trigger on a relation it writes or removes rows from runs; then each
    /// trigger it changes is changed. With `None`, a run not read, which
    /// changes what `reach` says ([`Self::unread_reaching`]). Each write's
    /// update assigns what `updated` says, else what the change says. In a
    /// routine's body, it is what a call of that routine runs.
    fn run_changes(
        &mut self,
        changes: Option<catalog::BodyChanges>,
        site: catalog::RelationSite<'_>,
        reach: catalog::UnreadReach,
        rows: Option<&catalog::WrittenRows>,
        updated: Option<&catalog::UpdatedColumns>,
    ) {
        let Some(changes) = changes else {
            self.unread_reaching(site, reach);
            return;
        };
        if site.until != u32::MAX {
            for change in &changes.changes {
                self.relations.routine_changes(
                    site.until,
                    &change.target,
                    &change.session,
                    change.change,
                    updated.unwrap_or(&change.updated),
                );
            }
            for change in &changes.triggers {
                self.relations.routine_changes_trigger(site.until, change);
            }
        }
        // A trigger the run makes runs at its own writes.
        if site.until == u32::MAX {
            for change in &changes.triggers {
                self.relations.create_for_call(change, site.statement);
            }
        }
        let rows = rows.unwrap_or(&catalog::WrittenRows::Unknown);
        let mut changed = Vec::new();
        let mut fired = Vec::new();
        for change in &changes.changes {
            let site = catalog::RelationSite {
                session: &change.session,
                ..site
            };
            match change.change {
                catalog::RoutineChangeKind::Rows(events) => {
                    let written = self.relations.write(
                        &change.target,
                        rows,
                        self.reasoning,
                        site,
                        self.catalog,
                    );
                    changed.extend(written.iter().cloned());
                    fired.push((change, written, Some(rows), events));
                }
                catalog::RoutineChangeKind::Removes(events) => {
                    fired.push((change, Vec::new(), None, events))
                }
                catalog::RoutineChangeKind::Relation => {
                    changed.extend(self.relations.unread_relation(
                        &change.target,
                        self.reasoning,
                        site,
                        self.catalog,
                    ))
                }
            }
        }
        self.read_again(changed, site);
        for (change, written, rows, events) in fired {
            let site = catalog::RelationSite {
                session: &change.session,
                ..site
            };
            let triggering = Triggering {
                events,
                rows,
                only: false,
                updated: updated.unwrap_or(&change.updated),
                returns: false,
            };
            self.fire_triggers(&change.target, &written, triggering, site);
        }
        // A trigger the run changes is changed after what it writes: one it
        // disables, drops or renames still runs at its writes.
        if site.until == u32::MAX {
            for change in &changes.triggers {
                self.relations.change_trigger(change, site.statement.start);
            }
        }
    }

    /// Record that the statement at `site` is not read: it may change any
    /// relation ([`catalog::ScriptRelations::unread`]). In a routine's body,
    /// a call of that routine runs what the run does not read.
    fn unread(&mut self, site: catalog::RelationSite<'_>) {
        self.unread_reaching(site, catalog::UnreadReach::Anything);
    }

    /// [`Self::unread`], of a statement that changes what `reach` says.
    fn unread_reaching(&mut self, site: catalog::RelationSite<'_>, reach: catalog::UnreadReach) {
        if !self.reasoning.provides_analysis() {
            return;
        }
        if site.until != u32::MAX {
            self.relations.routine_runs_unread(site.until);
        }
        let changed = self.relations.unread(self.reasoning, site, reach);
        self.read_again(changed, site);
    }

    /// What a function or trigger not read may change: rows, and, where
    /// the dialect lets one run DDL, what a relation declares.
    fn routine_reach(&self) -> catalog::UnreadReach {
        if self.dialect.user_functions_run_ddl() {
            catalog::UnreadReach::Anything
        } else {
            catalog::UnreadReach::Rows
        }
    }

    /// Read again, after the statement at `site`, the query of each
    /// relation that runs it over one of `written`, at any depth; one
    /// whose query is not kept takes rows not known.
    fn read_again(&mut self, written: Vec<catalog::RelationKey>, site: catalog::RelationSite<'_>) {
        if written.is_empty() {
            return;
        }
        let at = site.statement.end;
        for (key, query) in self.relations.reruns_over(&written, at) {
            match query {
                Some(query) => {
                    let declared = self.query_relation_columns(&query, at);
                    let every = declared.as_ref().is_none_or(|declared| declared.every);
                    self.relations.requery(
                        &key,
                        declared.map(|declared| declared.columns),
                        every,
                        site,
                    );
                }
                None => self.relations.write_unknown(&key, self.reasoning, site),
            }
        }
    }

    /// The columns the relation `query` makes gives from its query read at
    /// `at`, over the relations as they stand there.
    fn query_relation_columns(
        &self,
        query: &catalog::RelationQuery,
        at: u32,
    ) -> Option<DeclaredColumns> {
        let stmt = &query.stmt;
        let sql: &str = &query.sql;
        let session = &query.session;
        let query_columns =
            |body: &ast::AstStmt| self.query_columns(stmt, body, sql, session, at, None).0;
        let like_columns = |source: &ast::AstObjectRef| self.like_columns(source, sql, session, at);
        declared_columns(
            stmt,
            sql,
            self.meaning,
            session,
            &query_columns,
            &like_columns,
        )
    }

    /// Record what `stmt`, a statement holding no body, does to the
    /// relation it names.
    fn record(&mut self, stmt: &ast::AstStmt, run: StatementRun<'_>) {
        use catalog::RelationEdit;
        let span = stmt.span();
        let session = self.fold.session_context_at(span.start);
        let site = catalog::RelationSite {
            statement: span,
            holder: run.holder,
            until: run.until,
            unsettled: run.unsettled,
            session: &session,
        };
        // A trigger ended before here is in force at no later statement.
        self.relations.forget_ended_triggers(span.start);
        self.change_triggers(stmt, site);
        self.drop_routines(stmt, site);
        // What it writes and names; a statement writing rows that the
        // relational lowering reads, where it is lowered below.
        let deferred = match (
            statement_effect(stmt, self.sql),
            ir::lower_dispatch::route(stmt),
        ) {
            (StatementEffect::Rows, ir::lower_dispatch::StatementRoute::Relational) => true,
            (
                StatementEffect::Rows,
                ir::lower_dispatch::StatementRoute::Ddl
                | ir::lower_dispatch::StatementRoute::Opaque
                | ir::lower_dispatch::StatementRoute::Separator,
            )
            | (
                StatementEffect::Nothing
                | StatementEffect::Defines(_)
                | StatementEffect::Alters
                | StatementEffect::Loads
                | StatementEffect::RunsText
                | StatementEffect::Calls
                | StatementEffect::Runs(_)
                | StatementEffect::Holds(_)
                | StatementEffect::DefinesPipe(_)
                | StatementEffect::RefreshesPipe(_)
                | StatementEffect::Anything,
                ir::lower_dispatch::StatementRoute::Relational
                | ir::lower_dispatch::StatementRoute::Ddl
                | ir::lower_dispatch::StatementRoute::Opaque
                | ir::lower_dispatch::StatementRoute::Separator,
            ) => false,
        };
        if deferred {
            self.note_function_calls(stmt, self.sql, span.start);
        } else {
            self.note_effect(
                stmt,
                self.sql,
                self.placeholders,
                span.start,
                &session,
                None,
            );
        }
        match change_beside_plan(stmt, self.sql) {
            Some(ChangeBesidePlan::Makes { target, temporary }) => {
                let edit = RelationEdit::Create {
                    columns: None,
                    every_column: true,
                    temporary,
                    session_temporary: false,
                    if_not_exists: false,
                    clone_of: None,
                    fails_where_it_exists: false,
                    reruns: &[],
                    query: None,
                    keys: Vec::new(),
                    view: false,
                };
                let made = ddl_target_table(&target);
                // The table holds the values its statement writes.
                let place = self.stated_place(&made, span.start);
                self.relations.written_mut().record(&place, None);
                self.edit(&made, edit, site);
                return;
            }
            Some(ChangeBesidePlan::Renames(rename)) => {
                self.record_procedure_rename(rename, site);
                return;
            }
            None => {}
        }
        // An assignment to a column of the row a trigger is given, in a
        // routine's body, writes it where a write runs the trigger. One
        // that assigns variables alone changes no relation.
        // A routine a `CALL` runs, by the parameters the scripts declare.
        let passes_back = |position: usize, named: Option<lexer::token::Span>| {
            let Some(called) = self.routine_name(stmt) else {
                return true;
            };
            let named = named
                .and_then(|span| ir::utils::slice_span(self.sql, span))
                .map(|name| IdentKey::new_as(name, ir::normalize::NameKind::Column));
            self.relations
                .call_assigns(&called, span.start, position, named.as_ref())
        };
        let (row, only) = match statement_assigns(stmt, self.sql, &passes_back) {
            Assigns::Only(row) => (row, true),
            Assigns::Beside(row) => (row, false),
        };
        if site.until != u32::MAX && !row.is_empty() {
            self.relations.routine_assigns_row(site.until, &row);
        }
        if only {
            if self.reasoning.provides_analysis() {
                self.read_calls(stmt, site);
            }
            return;
        }
        let _values = self.fold.enter_statement(span.start);
        // What the evaluator takes in place of lowering the statement again.
        let kept = self.lowered;
        let keep = |lowered: Option<LoweredQuery>| {
            if let Some(lowered) = lowered {
                kept.borrow_mut().insert((span.start, span.end), lowered);
            }
        };
        // A statement the relational lowering reads, lowered once: as
        // reading the relations needs it, and for the evaluator.
        let route = ir::lower_dispatch::route(stmt);
        let lowered = match route {
            ir::lower_dispatch::StatementRoute::Relational
                if self.reasoning.provides_analysis() =>
            {
                let lowered = self.lower_relational(stmt, &session, span.start);
                if deferred {
                    self.note_effect(
                        stmt,
                        self.sql,
                        self.placeholders,
                        span.start,
                        &session,
                        lowered.as_ref(),
                    );
                }
                // A plan read only in part, or not lowered, is not read;
                // else what it calls is read.
                let read = lowered
                    .as_ref()
                    .is_some_and(|lowered| self.plan_read(&lowered.0));
                if read {
                    self.read_calls(stmt, site);
                } else {
                    self.unread(site);
                }
                lowered
            }
            // A statement writing rows is lowered for the columns it
            // writes, and released: kept until the evaluator's turn, the
            // plans of a long script's writes would all be held at once.
            ir::lower_dispatch::StatementRoute::Relational if deferred => {
                let lowered = self.lower_relational(stmt, &session, span.start);
                self.note_effect(
                    stmt,
                    self.sql,
                    self.placeholders,
                    span.start,
                    &session,
                    lowered.as_ref(),
                );
                return;
            }
            ir::lower_dispatch::StatementRoute::Relational => None,
            ir::lower_dispatch::StatementRoute::Ddl => {
                if self.reasoning.provides_analysis() {
                    self.read_calls(stmt, site);
                }
                None
            }
            // Text not parsed as a statement may change any relation.
            ir::lower_dispatch::StatementRoute::Opaque => {
                self.unread(site);
                return;
            }
            ir::lower_dispatch::StatementRoute::Separator => return,
        };
        let writes = lowered
            .as_ref()
            .map(|lowered| self.written_rows(lowered, &session, span.start))
            .unwrap_or_default();
        // A query in a routine's body that returns rows gives them to the
        // routine's caller.
        if let (Some(lowered), ast::AstStmt::Select(_)) = (&lowered, stmt) {
            if run.until != u32::MAX && writes.is_empty() && lowered.3.into_vars.is_empty() {
                let values = self.result_values(lowered, span.start);
                self.relations.routine_result(run.until, values);
            }
        }
        if !writes.is_empty() {
            keep(lowered);
            for write in &writes {
                match &write.rows {
                    Some(rows) => self.write(
                        &write.target,
                        rows,
                        write.events,
                        &write.updated,
                        write.only,
                        site,
                    ),
                    None => self.remove_rows(&write.target, write.events, write.only, site),
                }
            }
            return;
        }
        // Lowered as the DDL rules lower it.
        let Some(plan) = ir::lower_ddl_stmt(stmt, &self.ddl_inputs(span.start, &session)) else {
            // A query that writes nothing is lowered again by the evaluator
            // at its turn: kept until then, each would hold memory for the
            // rest of the script.
            drop(lowered);
            // A statement of the DDL lowering it does not read is not read.
            match route {
                ir::lower_dispatch::StatementRoute::Ddl => self.unread(site),
                ir::lower_dispatch::StatementRoute::Relational
                | ir::lower_dispatch::StatementRoute::Opaque
                | ir::lower_dispatch::StatementRoute::Separator => {}
            }
            return;
        };
        // A schema or database dropped, replaced or renamed takes the
        // relations in it.
        if ir::lower_ddl::changes_a_namespace(&plan) {
            keep(lowered);
            self.unread(site);
            return;
        }
        let names_a_relation = ir::lower_ddl::target_names_a_relation(stmt, &plan);
        let target = plan.target.as_ref().map(ddl_target_table);
        // A change of a relation whose name is not read is not read.
        if target.is_none() && names_a_relation && plan.truncated.is_empty() {
            match plan.action {
                ir::ddl_plan::DdlAction::Create
                | ir::ddl_plan::DdlAction::Drop
                | ir::ddl_plan::DdlAction::Alter
                | ir::ddl_plan::DdlAction::Rename
                | ir::ddl_plan::DdlAction::BulkLoad
                | ir::ddl_plan::DdlAction::Truncate => {
                    keep(lowered);
                    self.unread(site);
                    return;
                }
                ir::ddl_plan::DdlAction::Comment
                | ir::ddl_plan::DdlAction::Refresh
                | ir::ddl_plan::DdlAction::Grant
                | ir::ddl_plan::DdlAction::Revoke
                | ir::ddl_plan::DdlAction::Execute
                | ir::ddl_plan::DdlAction::Configure
                | ir::ddl_plan::DdlAction::ControlFlow
                | ir::ddl_plan::DdlAction::Transaction
                | ir::ddl_plan::DdlAction::Backup
                | ir::ddl_plan::DdlAction::Restore => {}
            }
        }
        match plan.action {
            ir::ddl_plan::DdlAction::Create => {
                let Some(target) = target.filter(|_| names_a_relation) else {
                    keep(lowered);
                    return;
                };
                let lowered = std::cell::Cell::new(lowered);
                let clone_of = cloned_table(stmt, self.sql);
                // The tables the query reads, for a relation that runs it on
                // each read.
                let read = std::cell::RefCell::new(Vec::new());
                let from_query = std::cell::Cell::new(false);
                let query_columns = |query: &ast::AstStmt| {
                    from_query.set(true);
                    let (columns, tables, kept) = self.query_columns(
                        stmt,
                        query,
                        self.sql,
                        &session,
                        span.start,
                        lowered.take(),
                    );
                    read.borrow_mut().extend(tables);
                    keep(kept);
                    columns
                };
                let like_columns = |source: &ast::AstObjectRef| {
                    self.like_columns(source, self.sql, &session, span.start)
                };
                let declared = declared_columns(
                    stmt,
                    self.sql,
                    self.meaning,
                    &session,
                    &query_columns,
                    &like_columns,
                );
                keep(lowered.take());
                let reruns_query = matches!(
                    plan.object_kind,
                    facts::identity::ObjectKind::View
                        | facts::identity::ObjectKind::MaterializedView
                );
                let reruns = if reruns_query {
                    read.into_inner()
                } else {
                    Vec::new()
                };
                // A table made from a query holds the values it writes.
                if from_query.get() && !reruns_query {
                    let place = self.stated_place(&target, span.start);
                    let written = self.relations.written_mut();
                    match &declared {
                        Some(declared) if declared.every => {
                            for made in &declared.columns {
                                written.record(&place, Some(&made.column.name.name));
                            }
                        }
                        Some(_) | None => written.record(&place, None),
                    }
                }
                // The query a view runs on each read, read again at a
                // write into a relation it reads.
                let query = (reruns_query && !reruns.is_empty()).then(|| {
                    std::sync::Arc::new(catalog::RelationQuery {
                        stmt: stmt.clone(),
                        sql: self.shared_sql(),
                        session: session.clone(),
                    })
                });
                let mut keys = if let ast::AstStmt::CreateTable(table) = stmt {
                    declared_keys(table, self.sql)
                } else {
                    Vec::new()
                };
                if self.dialect.unnamed_index_takes_column_name() {
                    catalog::name_unnamed_keys(&mut keys, &[]);
                }
                let every_column = declared.as_ref().is_none_or(|declared| declared.every);
                let temporary = plan.options.temporary
                    || matches!(stmt, ast::AstStmt::CreateTable(table) if ir::table_plan::names_a_temporary_table(&table.name));
                let names_its_columns = matches!(
                    stmt,
                    ast::AstStmt::CreateTable(table)
                        if table.ctas_query.is_none() && table.columns_span.is_some()
                );
                let fails_where_it_exists = names_its_columns
                    && clone_of.is_none()
                    && !plan.options.or_replace
                    && !plan.options.if_not_exists;
                let edit = RelationEdit::Create {
                    columns: declared.map(|declared| declared.columns),
                    every_column,
                    temporary,
                    session_temporary: plan.options.temporary
                        && matches!(
                            self.meaning.temporary_tables,
                            dialect::TemporaryTables::SessionSchema { .. }
                        ),
                    if_not_exists: plan.options.if_not_exists,
                    clone_of: clone_of.as_ref(),
                    fails_where_it_exists,
                    reruns: &reruns,
                    query,
                    keys,
                    view: reruns_query,
                };
                self.edit(&target, edit, site);
            }
            ir::ddl_plan::DdlAction::Drop => {
                keep(lowered);
                let Some(target) = target else {
                    return;
                };
                if names_a_relation {
                    let kind = if matches!(
                        plan.object_kind,
                        facts::identity::ObjectKind::View
                            | facts::identity::ObjectKind::MaterializedView
                    ) {
                        facts::query::DroppedObjectKind::View
                    } else {
                        facts::query::DroppedObjectKind::Table
                    };
                    let temporary = matches!(
                        stmt,
                        ast::AstStmt::Drop(drop)
                            if drop.target_name.as_ref().is_some_and(ir::table_plan::names_a_temporary_table)
                    );
                    let edit = RelationEdit::Drop { kind, temporary };
                    self.edit(&target, edit, site);
                }
            }
            ir::ddl_plan::DdlAction::Alter | ir::ddl_plan::DdlAction::Rename => {
                keep(lowered);
                let Some(target) = target else {
                    return;
                };
                if !matches!(plan.object_kind, facts::identity::ObjectKind::Table) {
                    // Another relation altered is changed in a way not read.
                    if names_a_relation && self.reasoning.provides_analysis() {
                        let changed = self.relations.unread_relation(
                            &target,
                            self.reasoning,
                            site,
                            self.catalog,
                        );
                        self.read_again(changed.into_iter().collect(), site);
                    }
                    return;
                }
                let mutations = plan.schema_mutations.as_slice();
                let mut renamed = false;
                for mutation in mutations {
                    if let ir::ddl_plan::DdlSchemaMutation::RenameTo { new_target, source } =
                        mutation
                    {
                        let from = source
                            .as_ref()
                            .map_or_else(|| target.clone(), ddl_target_table);
                        let to = ddl_target_table(new_target);
                        let edit = RelationEdit::RenameTo { to: &to, mutations };
                        self.edit(&from, edit, site);
                        renamed = true;
                    }
                }
                // A swap exchanges the two tables; the target's other
                // changes come first.
                let (swaps, changes): (Vec<_>, Vec<_>) =
                    mutations.iter().cloned().partition(|mutation| {
                        matches!(mutation, ir::ddl_plan::DdlSchemaMutation::SwapWith { .. })
                    });
                if !renamed {
                    let (dropped, added) = if let ast::AstStmt::AlterTable(alter) = stmt {
                        (
                            ir::lower_ddl::dropped_declarations(alter, self.sql),
                            added_keys(alter, self.sql),
                        )
                    } else {
                        (Vec::new(), Vec::new())
                    };
                    let edit = RelationEdit::Alter {
                        mutations: &changes,
                        dropped: &dropped,
                        added: &added,
                        column_names: self.dialect.unnamed_index_takes_column_name(),
                    };
                    self.edit(&target, edit, site);
                }
                for mutation in &swaps {
                    if let ir::ddl_plan::DdlSchemaMutation::SwapWith { other } = mutation {
                        let other = ddl_target_table(other);
                        let edit = RelationEdit::SwapWith { other: &other };
                        self.edit(&target, edit, site);
                    }
                }
            }
            // A load adds rows whose values are not known.
            ir::ddl_plan::DdlAction::BulkLoad => {
                keep(lowered);
                // It writes every column of its table: an export does not.
                let exports = matches!(
                    stmt,
                    ast::AstStmt::PgCopy(copy) if matches!(copy.direction, ast::PgCopyDirection::To)
                );
                if let Some(target) = target.as_ref().filter(|_| !exports) {
                    let place = self.stated_place(target, span.start);
                    self.relations.written_mut().record(&place, None);
                }
                if let Some(target) = target.filter(|_| self.reasoning.provides_analysis()) {
                    let kind = if plan.options.replaces_duplicates {
                        catalog::WriteKind::Replace
                    } else {
                        catalog::WriteKind::Insert
                    };
                    self.write(
                        &target,
                        &catalog::WrittenRows::Unknown,
                        kind.events(),
                        &catalog::UpdatedColumns::NONE,
                        false,
                        site,
                    );
                }
            }
            // A routine, prepared statement, task or SQL text run.
            ir::ddl_plan::DdlAction::Execute => {
                keep(lowered);
                self.record_run(&plan, site);
            }
            ir::ddl_plan::DdlAction::Truncate => {
                keep(lowered);
                let events = catalog::WriteKind::Truncate.events();
                if plan.truncated.is_empty() {
                    if let Some(target) = target {
                        self.remove_rows(&target, events, false, site);
                    }
                }
                for table in &plan.truncated {
                    self.remove_rows(&ddl_target_table(&table.target), events, table.only, site);
                }
            }
            ir::ddl_plan::DdlAction::Comment
            | ir::ddl_plan::DdlAction::Refresh
            | ir::ddl_plan::DdlAction::Grant
            | ir::ddl_plan::DdlAction::Revoke
            | ir::ddl_plan::DdlAction::Configure
            | ir::ddl_plan::DdlAction::ControlFlow
            | ir::ddl_plan::DdlAction::Transaction
            | ir::ddl_plan::DdlAction::Backup
            | ir::ddl_plan::DdlAction::Restore => keep(lowered),
        }
    }

    /// What reasoning finds of each column, by position, of the rows the
    /// query `lowered`, the statement starting at `at`, returns; nothing
    /// with recognition alone.
    fn result_values(&self, lowered: &LoweredQuery, at: u32) -> Vec<catalog::MadeValue> {
        let (plan, known, bindings, ..) = lowered;
        if matches!(plan, ir::RelPlan::CreateAsQuery { .. }) {
            return Vec::new();
        }
        let reasoning = self.reasoning.for_query(facts::reasoning::QueryInputs {
            plan,
            bindings,
            catalog: Some(known),
            function_catalog: self.functions.at(at),
            source: self.sql,
        });
        plan.positional_columns()
            .known
            .iter()
            .map(|output| made_value(&*reasoning, plan, *output))
            .collect()
    }

    /// Record the rows the statement `exec`, at `run`, gives the `INSERT`
    /// `insert` holding it (T-SQL `INSERT … EXEC`): written into its target,
    /// by column what the routine called returns where its body is read,
    /// else rows not known.
    fn record_insert_exec(
        &mut self,
        insert: &ast::AstStmt,
        exec: &ast::AstStmt,
        run: StatementRun<'_>,
    ) {
        if !self.reasoning.provides_analysis() {
            return;
        }
        let span = insert.span();
        let session = self.fold.session_context_at(span.start);
        let site = catalog::RelationSite {
            statement: span,
            holder: run.holder,
            until: run.until,
            unsettled: run.unsettled,
            session: &session,
        };
        let _values = self.fold.enter_statement(span.start);
        let Some(lowered) = self.lower_relational(insert, &session, span.start) else {
            self.unread(site);
            return;
        };
        let mut writes = Vec::new();
        plan_writes(&lowered.0, &mut writes);
        let called = ir::lower_ddl_stmt(exec, &self.ddl_inputs(exec.span().start, &session))
            .and_then(|plan| {
                plan.target
                    .as_ref()
                    .map(|t| routine_identity(&ddl_target_table(t)))
            });
        let results = called.and_then(|name| self.relations.results_of_called(&name, span.start));
        let bindings = &lowered.2;
        for write in writes {
            let PlanWrite::Insert {
                target,
                target_columns,
                kind,
                ..
            } = write
            else {
                continue;
            };
            // The columns written, as the list names them; without a list,
            // the target's, by position, where its columns are known.
            let named: Option<Vec<IdentKey>> = if target_columns.is_empty() {
                self.relations
                    .at(span.start)
                    .catalogued_table(self.catalog, target, &session)
                    .filter(|table| !table.columns.is_empty())
                    .map(|table| {
                        table
                            .columns
                            .iter()
                            .map(|column| {
                                IdentKey::new_as(&column.name.name, ir::normalize::NameKind::Column)
                            })
                            .collect()
                    })
            } else {
                target_columns
                    .iter()
                    .map(|column| {
                        let binding = bindings.get(*column)?;
                        Some(IdentKey::new_as(
                            &binding.display_name,
                            ir::normalize::NameKind::Column,
                        ))
                    })
                    .collect()
            };
            let rows = match (&results, named) {
                (Some(results), Some(named)) => catalog::WrittenRows::Known {
                    columns: named.into_iter().zip(results.iter().cloned()).collect(),
                    replaces: false,
                },
                (Some(_), None) | (None, _) => catalog::WrittenRows::Unknown,
            };
            self.write(
                target,
                &rows,
                kind.events(),
                &catalog::UpdatedColumns::Unknown,
                false,
                site,
            );
        }
    }

    /// The script's text, shared by the queries of the relations its
    /// statements make.
    fn shared_sql(&self) -> std::sync::Arc<str> {
        self.shared_sql
            .get_or_init(|| std::sync::Arc::from(self.sql))
            .clone()
    }

    /// Record what the statement at `site`, which `plan` runs a routine,
    /// prepared statement, task or SQL text by, changes: a call of a
    /// routine the scripts define changes what its body changes, each
    /// relation written with rows not known; any other run, rows not known
    /// in every relation. In a routine's body, it is what a call of that
    /// routine runs.
    fn record_run(&mut self, plan: &ir::ddl_plan::DdlPlan, site: catalog::RelationSite<'_>) {
        if !self.reasoning.provides_analysis() {
            return;
        }
        let called = match (&plan.target, plan.options.dynamic_sql) {
            (Some(target), false) => Some(routine_identity(&ddl_target_table(target))),
            (Some(_), true) | (None, _) => None,
        };
        let changes =
            called.and_then(
                |name| match self.relations.called(&name, site.statement.start) {
                    catalog::Called::Changes(changes) => Some(changes),
                    catalog::Called::NotDefined | catalog::Called::Unread => None,
                },
            );
        self.run_changes(changes, site, catalog::UnreadReach::Anything, None, None);
    }

    /// Whether `plan`, a statement's plan, is read whole: no part of it
    /// is one the parser recovered past or could not structure, and, where
    /// a function the dialect lets a user define may write, no value of it
    /// is one not read, which may call one.
    fn plan_read(&self, plan: &ir::RelPlan) -> bool {
        let runs = plan_runs(plan);
        !(runs.partial || (runs.unread_value && self.dialect.user_functions_write()))
    }

    /// Record what the statement `stmt`, at `site`, runs by the functions
    /// it calls in the expressions it evaluates: a function a user may
    /// define that may write is a call of it, read through what the
    /// routines the scripts define change; a built-in the function catalog
    /// holds writes nothing; any other is not read, and changes what a
    /// function of the dialect may ([`Self::routine_reach`]). A routine the
    /// statement itself runs (`CALL`, `EXEC`) is read as the run it is.
    fn read_calls(&mut self, stmt: &ast::AstStmt, site: catalog::RelationSite<'_>) {
        let functions_write = self.dialect.user_functions_write();
        let tables_run = self.dialect.table_calls_may_run_procedures();
        if !functions_write && !tables_run {
            return;
        }
        let at = site.statement.start;
        let reach = self.routine_reach();
        for call in ir::dynamic_sql::routine_calls(stmt, self.sql) {
            if call.node == stmt.node_id() || !(functions_write || (call.table && tables_run)) {
                continue;
            }
            let Some(written) = self
                .sql
                .get(call.name.start as usize..call.name.end as usize)
            else {
                self.unread(site);
                return;
            };
            match self.relations.called(&called_identity(written), at) {
                catalog::Called::Changes(changes) => {
                    self.run_changes(Some(changes), site, reach, None, None)
                }
                catalog::Called::Unread => {
                    self.unread_reaching(site, reach);
                    return;
                }
                catalog::Called::NotDefined => {
                    let parts = ir::lower::routine_name(written);
                    if !names_builtin_function_in(&parts, self.dialect, self.functions.at(at)) {
                        self.unread_reaching(site, reach);
                        return;
                    }
                }
            }
        }
    }

    /// Record what `stmt`, a statement holding bodies, at `run`, writes
    /// itself (an `INSERT … EXEC`'s rows) as its effect states, and runs by
    /// the functions it calls in what it evaluates itself (a condition, an
    /// operand), before its bodies ([`Self::read_calls`]).
    fn record_holder(&mut self, stmt: &ast::AstStmt, run: StatementRun<'_>) {
        let _values = self.fold.enter_statement(stmt.span().start);
        {
            let session = self.fold.session_context_at(stmt.span().start);
            let site = catalog::RelationSite {
                statement: stmt.span(),
                holder: run.holder,
                until: run.until,
                unsettled: run.unsettled,
                session: &session,
            };
            self.change_triggers(stmt, site);
            self.note_effect(
                stmt,
                self.sql,
                self.placeholders,
                stmt.span().start,
                &session,
                None,
            );
        }
        if !self.reasoning.provides_analysis() {
            return;
        }
        // It runs before its bodies: up to the first statement they hold.
        let whole = stmt.span();
        let end = stmt
            .bodies()
            .iter()
            .filter_map(|body| body.stmts.first())
            .map(|first| first.span().start)
            .min()
            .unwrap_or(whole.end);
        let span = lexer::token::Span {
            start: whole.start,
            end: end.max(whole.start),
        };
        let session = self.fold.session_context_at(span.start);
        let site = catalog::RelationSite {
            statement: span,
            holder: run.holder,
            until: run.until,
            unsettled: run.unsettled,
            session: &session,
        };
        self.read_calls(stmt, site);
    }

    /// The tables `table` may name at `at` under the session the run
    /// states ([`ScriptContextFold::stated_session_at`]).
    fn stated_place(
        &self,
        table: &crate::context::node_metadata::TableRef,
        at: u32,
    ) -> catalog::Resolution {
        self.relations
            .at(at)
            .resolution(self.catalog, table, &self.fold.stated_session_at(at))
    }

    /// Record what `stmt`, a statement of `sql` (whose placeholders are at
    /// `placeholders`) starting at `at` under `session`, writes and the
    /// names it gives a table or a column, as its effect states
    /// ([`statement_effect`]); `lowered`, its plan where it is lowered
    /// already. What the run cannot read of it writes any column under any
    /// name.
    fn note_effect(
        &mut self,
        stmt: &ast::AstStmt,
        sql: &str,
        placeholders: &[lexer::token::Span],
        at: u32,
        session: &ir::SessionContext,
        lowered: Option<&LoweredQuery>,
    ) {
        self.note_function_calls(stmt, sql, at);
        match statement_effect(stmt, sql) {
            StatementEffect::Nothing => {}
            StatementEffect::Rows => match lowered {
                Some(lowered) => self.note_written_columns(lowered, session, at),
                None => match self.lower_in(stmt, sql, at, session) {
                    Some(lowered) => self.note_written_columns(&lowered, session, at),
                    None => self.relations.written_mut().record_anything(),
                },
            },
            StatementEffect::Defines(made) => {
                self.note_made(stmt, made, sql, placeholders, at, session)
            }
            StatementEffect::Alters | StatementEffect::Loads => {
                self.note_changed(stmt, sql, placeholders, at, session)
            }
            StatementEffect::RunsText => self.note_run_writes(stmt, sql, session, at),
            StatementEffect::Calls => self.note_call(stmt, sql, placeholders, at, session),
            // A statement it holds, each statement of its bodies included.
            StatementEffect::Runs(held) => {
                let mut inner = Vec::new();
                flatten_stmts_for_rules(held, &mut inner);
                for inner in inner {
                    self.note_effect(inner, sql, placeholders, at, session, None);
                }
            }
            // Each statement a value holds: `(EXECUTE IMMEDIATE …)`, a
            // subquery, a call.
            StatementEffect::Holds(held) => {
                let values: Vec<&ast::AstExpr> = match held {
                    Held::Value(value) => value.into_iter().collect(),
                    Held::Declared(variables) => variables
                        .iter()
                        .filter_map(|variable| variable.default_expr.as_deref())
                        .collect(),
                    Held::Values(values) => values.iter().collect(),
                };
                for value in values {
                    for inner in ir::dynamic_sql::collect_inner_stmts_from_expr(value) {
                        self.note_effect(inner, sql, placeholders, at, session, None);
                    }
                }
            }
            StatementEffect::DefinesPipe(pipe) => self.note_pipe(pipe, sql, at, session),
            StatementEffect::RefreshesPipe(pipe) => {
                let defined = ir::utils::slice_span(sql, pipe.name_span)
                    .and_then(written_table_name)
                    .is_some_and(|name| self.relations.defines_pipe(&routine_identity(&name), at));
                if !defined {
                    self.relations.written_mut().record_anything();
                }
            }
            StatementEffect::Anything => self.relations.written_mut().record_anything(),
        }
    }

    /// Record that `pipe`, a statement of `sql` starting at `at` under
    /// `session`, defines a pipe, and what the statement it loads with
    /// writes and names, read from its text through its own effect
    /// ([`Self::note_effect`]); any column under any name where that
    /// statement is not read.
    fn note_pipe(
        &mut self,
        pipe: &ast::AstCreatePipe,
        sql: &str,
        at: u32,
        session: &ir::SessionContext,
    ) {
        if let Some(name) = ir::utils::slice_span(sql, pipe.name_span).and_then(written_table_name)
        {
            self.relations.define_pipe(routine_identity(&name), at);
        }
        let Some(body) = pipe
            .copy_body_span
            .and_then(|span| ir::utils::slice_span(sql, span))
        else {
            self.relations.written_mut().record_anything();
            return;
        };
        let tokens = lex_body(body, self.dialect);
        let Some(script) = parse_body(body, &tokens, self.dialect) else {
            self.relations.written_mut().record_anything();
            return;
        };
        self.parsing_runs(|reading| reading.note_text_writes(&script, body, at, session));
    }

    /// Record what the run does in the session beside the script writes
    /// and names: each statement of a text read, through its own effect
    /// ([`Self::note_effect`]); every column of a table a seed loads, in
    /// any schema; any column under any name for text not read or not
    /// parsed.
    fn note_session_sql(&mut self, texts: &[template::artifacts::SessionSql]) {
        let session = self.fold.session_context_at(0);
        for text in texts {
            let text = match text {
                template::artifacts::SessionSql::Read(text) => text,
                template::artifacts::SessionSql::Unread => {
                    self.relations.written_mut().record_anything();
                    continue;
                }
                template::artifacts::SessionSql::Seed(table) => {
                    let table = catalog::Resolution::Any(
                        crate::context::node_metadata::TableRef::new(table.clone()),
                    );
                    self.relations.written_mut().record(&table, None);
                    continue;
                }
            };
            let tokens = lex_body(text, self.dialect);
            let Some(script) = parse_body(text, &tokens, self.dialect) else {
                self.relations.written_mut().record_anything();
                continue;
            };
            self.parsing_runs(|reading| reading.note_text_writes(&script, text, 0, &session));
        }
    }

    /// `stmt`, a statement of `sql` starting at `at`, lowered as the query
    /// evaluator lowers it, under `session`.
    fn lower_in(
        &self,
        stmt: &ast::AstStmt,
        sql: &str,
        at: u32,
        session: &ir::SessionContext,
    ) -> Option<LoweredQuery> {
        let relations = self.relations.at(at);
        let declared = self.fold.declared_at(at);
        let around = ir::lower::AroundStatement {
            declared: &declared,
            meaning: self.meaning,
            relations,
        };
        ir::lower::lower_query_with_declared_names(
            stmt,
            sql,
            ir::StrictMode::Permissive,
            self.functions.at(at),
            session,
            self.catalog,
            self.models,
            around,
        )
        .ok()
    }

    /// The DDL plan of `stmt`, a statement of `sql` starting at `at`.
    fn ddl_plan_in(
        &self,
        stmt: &ast::AstStmt,
        sql: &str,
        placeholders: &[lexer::token::Span],
        at: u32,
        session: &ir::SessionContext,
    ) -> Option<ir::ddl_plan::DdlPlan> {
        let _values = self.fold.enter_statement(at);
        ir::lower_ddl_stmt(stmt, &self.ddl_inputs_in(sql, placeholders, at, session))
    }

    /// Record what the relation `stmt` makes ([`Made`]) holds and names: a
    /// table the values its query writes and the names of the table it
    /// clones; a view each column's names for the table columns its query
    /// shows; a synonym or a stream the names of the relation it stands
    /// for. A relation whose name is not read may be any.
    fn note_made(
        &mut self,
        stmt: &ast::AstStmt,
        made: Made<'_>,
        sql: &str,
        placeholders: &[lexer::token::Span],
        at: u32,
        session: &ir::SessionContext,
    ) {
        let target = self
            .ddl_plan_in(stmt, sql, placeholders, at, session)
            .and_then(|plan| plan.target.as_ref().map(ddl_target_table));
        let Some(target) = target else {
            self.relations.written_mut().record_anything();
            return;
        };
        let place = self.stated_place(&target, at);
        match made {
            Made::Table(made) => {
                match made_rows(made, sql) {
                    MadeRows::Own => {}
                    MadeRows::Clone(source) => {
                        let source = self.stated_place(&source, at);
                        self.relations.written_mut().same_table(&place, &source);
                    }
                    MadeRows::Unstated => self.relations.written_mut().record_anything(),
                }
                let (declared, from_query) = self.made_columns(stmt, sql, at, session);
                if from_query {
                    let written = self.relations.written_mut();
                    match declared {
                        Some(declared) if declared.every => {
                            for made in &declared.columns {
                                written.record(&place, Some(&made.column.name.name));
                            }
                        }
                        Some(_) | None => written.record(&place, None),
                    }
                }
            }
            Made::View => self.note_view(stmt, sql, &target, at, session),
            Made::Synonym(synonym) => {
                let referent =
                    ir::utils::slice_span(sql, synonym.target_span).and_then(written_table_name);
                self.same_as(&place, referent, at);
            }
            Made::Stream(stream) => self.same_as(&place, streamed_table(stream, sql), at),
        }
    }

    /// Record that `place` and the relation `referent` names are one
    /// table; that any may be written where `referent` is not read.
    fn same_as(
        &mut self,
        place: &catalog::Resolution,
        referent: Option<crate::context::node_metadata::TableRef>,
        at: u32,
    ) {
        match referent {
            Some(referent) => {
                let referent = self.stated_place(&referent, at);
                self.relations.written_mut().same_table(place, &referent);
            }
            None => self.relations.written_mut().record_anything(),
        }
    }

    /// The columns of the relation `stmt` makes, a statement of `sql`
    /// starting at `at` under `session`, and whether a query gives them.
    fn made_columns(
        &self,
        stmt: &ast::AstStmt,
        sql: &str,
        at: u32,
        session: &ir::SessionContext,
    ) -> (Option<DeclaredColumns>, bool) {
        let from_query = std::cell::Cell::new(false);
        let query_columns = |query: &ast::AstStmt| {
            from_query.set(true);
            self.query_columns(stmt, query, sql, session, at, None).0
        };
        let like_columns = |source: &ast::AstObjectRef| self.like_columns(source, sql, session, at);
        let declared = declared_columns(
            stmt,
            sql,
            self.meaning,
            session,
            &query_columns,
            &like_columns,
        );
        (declared, from_query.get())
    }

    /// Record what `stmt`, a change of a relation's schema or a load,
    /// writes and names: each column of the table a load writes; the
    /// renames and swaps of a change, a namespace's changing the name of
    /// every table in it. One whose plan or target is not read may write
    /// or rename any.
    fn note_changed(
        &mut self,
        stmt: &ast::AstStmt,
        sql: &str,
        placeholders: &[lexer::token::Span],
        at: u32,
        session: &ir::SessionContext,
    ) {
        let Some(plan) = self.ddl_plan_in(stmt, sql, placeholders, at, session) else {
            self.relations.written_mut().record_anything();
            return;
        };
        let Some(target) = plan.target.as_ref().map(ddl_target_table) else {
            self.relations.written_mut().record_anything();
            return;
        };
        let place = self.stated_place(&target, at);
        if ir::lower_ddl::changes_a_namespace(&plan) {
            self.relations.written_mut().record_anything();
            return;
        }
        match plan.action {
            ir::ddl_plan::DdlAction::BulkLoad => {
                self.relations.written_mut().record(&place, None);
            }
            ir::ddl_plan::DdlAction::Alter | ir::ddl_plan::DdlAction::Rename => {
                for mutation in &plan.schema_mutations {
                    match mutation {
                        ir::ddl_plan::DdlSchemaMutation::RenameColumn { from, to } => self
                            .relations
                            .written_mut()
                            .same_column(&place, from, &place, to),
                        ir::ddl_plan::DdlSchemaMutation::RenameTo { new_target, source } => {
                            let from = match source {
                                Some(source) => self.stated_place(&ddl_target_table(source), at),
                                None => place.clone(),
                            };
                            let to = self.stated_place(&ddl_target_table(new_target), at);
                            self.relations.written_mut().same_table(&from, &to);
                        }
                        ir::ddl_plan::DdlSchemaMutation::SwapWith { other } => {
                            let other = self.stated_place(&ddl_target_table(other), at);
                            self.relations.written_mut().same_table(&place, &other);
                        }
                        // A link the plan does not state may join any
                        // name to any column.
                        ir::ddl_plan::DdlSchemaMutation::NamesUnread => {
                            self.relations.written_mut().record_anything()
                        }
                        ir::ddl_plan::DdlSchemaMutation::AddColumn { .. }
                        | ir::ddl_plan::DdlSchemaMutation::DropColumn { .. }
                        | ir::ddl_plan::DdlSchemaMutation::SetColumnTags { .. }
                        | ir::ddl_plan::DdlSchemaMutation::UnsetColumnTags { .. }
                        | ir::ddl_plan::DdlSchemaMutation::SetColumnType { .. }
                        | ir::ddl_plan::DdlSchemaMutation::ColumnsUnread => {}
                    }
                }
            }
            // A restore puts back values the run does not read.
            ir::ddl_plan::DdlAction::Restore => {
                self.relations.written_mut().record(&place, None);
            }
            ir::ddl_plan::DdlAction::Create
            | ir::ddl_plan::DdlAction::Drop
            | ir::ddl_plan::DdlAction::Truncate
            | ir::ddl_plan::DdlAction::Comment
            | ir::ddl_plan::DdlAction::Refresh
            | ir::ddl_plan::DdlAction::Grant
            | ir::ddl_plan::DdlAction::Revoke
            | ir::ddl_plan::DdlAction::Execute
            | ir::ddl_plan::DdlAction::Configure
            | ir::ddl_plan::DdlAction::ControlFlow
            | ir::ddl_plan::DdlAction::Transaction
            | ir::ddl_plan::DdlAction::Backup => {}
        }
    }

    /// Record what a call `stmt` makes, a statement of `sql` starting at
    /// `at`, writes and names: the rename a routine of the dialect's that
    /// renames makes ([`dialect::Dialect::rename_routine`]); nothing for
    /// another routine of the dialect that runs no text or command, nor
    /// for one the run defines with a body it reads, which is read where
    /// it is defined; any column under any name for every other routine.
    fn note_call(
        &mut self,
        stmt: &ast::AstStmt,
        sql: &str,
        placeholders: &[lexer::token::Span],
        at: u32,
        session: &ir::SessionContext,
    ) {
        let called = self
            .ddl_plan_in(stmt, sql, placeholders, at, session)
            .and_then(|plan| plan.target.as_ref().map(ddl_target_table));
        let Some(called) = called else {
            self.relations.written_mut().record_anything();
            return;
        };
        if self.note_rename_calls(stmt, sql, at) {
            return;
        }
        let mut parts: Vec<String> = [&called.db, &called.schema]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        parts.push(called.name.clone());
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        let documented = self.dialect.system_routine(&parts).map(|routine| {
            routine.forms.iter().all(|form| {
                form.parameters
                    .iter()
                    .map(|parameter| parameter.reads)
                    .chain(form.rest)
                    .all(|reads| match reads {
                        dialect::ArgumentUse::Value
                        | dialect::ArgumentUse::Name
                        | dialect::ArgumentUse::Flag
                        | dialect::ArgumentUse::Credential
                        | dialect::ArgumentUse::ConnectionString => true,
                        dialect::ArgumentUse::RunsSql
                        | dialect::ArgumentUse::RunsSqlRemotely
                        | dialect::ArgumentUse::Command => false,
                    })
            })
        });
        let read = match documented {
            Some(runs_nothing) => runs_nothing,
            None => self
                .relations
                .runs_read_routine(&routine_identity(&called), at),
        };
        if !read {
            self.relations.written_mut().record_anything();
        }
    }

    /// Record that each function `stmt`, a statement of `sql` starting at
    /// `at`, calls may write any column under any name where a function the
    /// dialect lets a user define may write ([`may_write_rows`]): one it
    /// does not build in, that the run does not define with a body it reads.
    fn note_function_calls(&mut self, stmt: &ast::AstStmt, sql: &str, at: u32) {
        for call in ir::dynamic_sql::routine_calls(stmt, sql) {
            let statement = call.node == stmt.node_id();
            if statement || !may_write_rows(self.dialect, call.table) {
                continue;
            }
            let Some(name) = ir::utils::slice_span(sql, call.name) else {
                self.relations.written_mut().record_anything();
                continue;
            };
            let parts = ir::lower::routine_name(name);
            if names_builtin_function(&parts, self.dialect) {
                continue;
            }
            let read = written_table_name(name).is_some_and(|called| {
                self.relations
                    .runs_read_routine(&routine_identity(&called), at)
            });
            if !read {
                self.relations.written_mut().record_anything();
            }
        }
    }

    /// Record the rename each call `stmt`, a statement of `sql` starting at
    /// `at`, makes of the dialect's rename routine
    /// ([`dialect::Dialect::rename_routine`]): a column's, where the kind
    /// it gives is a column's, else a table's, its new name in the same
    /// schema. A name not written as one string renames any. Whether
    /// `stmt` calls the routine.
    fn note_rename_calls(&mut self, stmt: &ast::AstStmt, sql: &str, at: u32) -> bool {
        let Some(rename) = self.dialect.rename_routine() else {
            return false;
        };
        let mut renames_any = false;
        for call in ir::dynamic_sql::routine_calls(stmt, sql) {
            let Some(name) = ir::utils::slice_span(sql, call.name) else {
                // A call whose name is not read may be the rename routine's.
                self.relations.written_mut().record_anything();
                continue;
            };
            let parts = ir::lower::routine_name(name);
            let parts: Vec<&str> = parts.iter().map(IdentKey::as_str).collect();
            let renames = self
                .dialect
                .system_routine(&parts)
                .is_some_and(|routine| routine.name == rename.name);
            if !renames {
                continue;
            }
            renames_any = true;
            // Each argument by the parameter it is written to: by name,
            // else by its place.
            let parameters = [rename.object, rename.new_name, rename.kind];
            let mut given: [Option<String>; 3] = [None, None, None];
            for (place, (named, value)) in call.arguments.iter().enumerate() {
                let parameter = match named {
                    Some(named) => ir::utils::slice_span(sql, *named).and_then(|named| {
                        let named = named.trim_start_matches('@');
                        parameters
                            .iter()
                            .position(|parameter| parameter.eq_ignore_ascii_case(named))
                    }),
                    None => (place < parameters.len()).then_some(place),
                };
                let text = value
                    .and_then(|value| ir::utils::slice_span(sql, value.span()))
                    .and_then(|raw| {
                        ir::span_extract::decode_string_literal_text_with_map_in(raw, self.dialect)
                    })
                    .map(|(text, _)| text);
                if let (Some(parameter), Some(text)) = (parameter, text) {
                    given[parameter] = Some(text);
                }
            }
            let [Some(object), Some(new_name), kind] = given else {
                self.relations.written_mut().record_anything();
                continue;
            };
            let column = kind
                .as_deref()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(rename.column_kind));
            if column {
                let mut parts = ir::lower_ddl::split_qualified(object.trim());
                let Some(column_name) = parts.pop() else {
                    self.relations.written_mut().record_anything();
                    continue;
                };
                let Some(table) = written_table_name(&parts.join(".")) else {
                    self.relations.written_mut().record_anything();
                    continue;
                };
                let table = self.stated_place(&table, at);
                self.relations.written_mut().same_column(
                    &table,
                    &column_name,
                    &table,
                    new_name.trim(),
                );
            } else {
                let Some(table) = written_table_name(&object) else {
                    self.relations.written_mut().record_anything();
                    continue;
                };
                let renamed = crate::context::node_metadata::TableRef {
                    name: new_name.trim().to_string(),
                    ..table.clone()
                };
                let (table, renamed) = (
                    self.stated_place(&table, at),
                    self.stated_place(&renamed, at),
                );
                self.relations.written_mut().same_table(&table, &renamed);
            }
        }
        renames_any
    }

    /// Record the names the columns of `view`, a view, a materialized view
    /// or a dynamic table `stmt` makes, a statement of `sql` starting at
    /// `at` under `session`, are for the table columns its query shows
    /// ([`Self::note_view_names`]).
    fn note_view(
        &mut self,
        stmt: &ast::AstStmt,
        sql: &str,
        view: &crate::context::node_metadata::TableRef,
        at: u32,
        session: &ir::SessionContext,
    ) {
        let sources = std::cell::RefCell::new(None);
        let scanned = std::cell::RefCell::new((Vec::new(), false));
        let declared = {
            let query_columns = |query: &ast::AstStmt| {
                let (columns, _, kept) = self.query_columns(stmt, query, sql, session, at, None);
                if let Some((
                    ir::RelPlan::CreateAsQuery {
                        body: Some(body), ..
                    },
                    _,
                    bindings,
                    ..,
                )) = &kept
                {
                    *sources.borrow_mut() = facts::secrets::column_sources(body, bindings);
                    *scanned.borrow_mut() = facts::secrets::tables_scanned(body);
                }
                columns
            };
            let like_columns =
                |source: &ast::AstObjectRef| self.like_columns(source, sql, session, at);
            declared_columns(
                stmt,
                sql,
                self.meaning,
                session,
                &query_columns,
                &like_columns,
            )
        };
        let (mut sources, (mut scanned, mut renames)) =
            (sources.into_inner(), scanned.into_inner());
        // A query the statement's columns are not read from is lowered
        // with the statement.
        if scanned.is_empty() {
            if let Some((
                ir::RelPlan::CreateAsQuery {
                    body: Some(body), ..
                },
                _,
                bindings,
                ..,
            )) = self.lower_in(stmt, sql, at, session)
            {
                sources = facts::secrets::column_sources(&body, &bindings);
                (scanned, renames) = facts::secrets::tables_scanned(&body);
            }
        }
        if scanned.is_empty() && sources.is_none() {
            self.relations.written_mut().record_anything();
            return;
        }
        self.note_view_names(view, declared.as_ref(), sources, (&scanned, renames), at);
    }

    /// Record that each column of the view `view`, which the statement
    /// starting at `at` makes, is a name for the table columns its query
    /// shows (`sources`, by position, of the columns `declared` names),
    /// where its columns and their sources are known; else that it names
    /// each table its query reads (`read`), whose columns it shows under
    /// their names, where the query gives no value a name of its own (an
    /// `UNPIVOT`'s value columns), and any name where it does.
    fn note_view_names(
        &mut self,
        view: &crate::context::node_metadata::TableRef,
        declared: Option<&DeclaredColumns>,
        sources: Option<Vec<Vec<(crate::context::node_metadata::TableRef, String)>>>,
        (read, renames): (&[crate::context::node_metadata::TableRef], bool),
        at: u32,
    ) {
        let place = self.stated_place(view, at);
        let named = declared
            .zip(sources)
            .filter(|(declared, sources)| declared.columns.len() == sources.len());
        match named {
            Some((declared, sources)) => {
                for (column, sources) in declared.columns.iter().zip(sources) {
                    for (table, name) in sources {
                        let table = self.stated_place(&table, at);
                        self.relations.written_mut().same_column(
                            &place,
                            &column.column.name.name,
                            &table,
                            &name,
                        );
                    }
                }
            }
            None if renames => self.relations.written_mut().record_anything(),
            None => {
                for table in read {
                    let table = self.stated_place(table, at);
                    self.relations.written_mut().same_table(&place, &table);
                }
            }
        }
    }

    /// Record what the SQL text `stmt`, a statement of `sql` starting at
    /// `at` under `session`, runs writes and names: the statement a
    /// PostgreSQL `PREPARE … AS` prepares, through its own effect
    /// ([`Self::note_effect`]); a text written whole as one literal as
    /// [`Self::runs`] says it is read; any column under any name where the
    /// text is built.
    fn note_run_writes(
        &mut self,
        stmt: &ast::AstStmt,
        sql: &str,
        session: &ir::SessionContext,
        at: u32,
    ) {
        if let ast::AstStmt::PgPrepare(prepare) = stmt {
            if prepare.from_expr.is_none() {
                self.note_effect(&prepare.body, sql, &[], at, session, None);
                return;
            }
        }
        let Some(run) = ir::dynamic_sql::sql_run(stmt, sql) else {
            self.relations.written_mut().record_anything();
            return;
        };
        let pieces = ir::dynamic_sql::executed_pieces(stmt, sql, self.dialect);
        let literal = match (run.sql, pieces.as_slice()) {
            (Some(_), [ir::dynamic_sql::TextPiece::Literal(literal)]) => *literal,
            (Some(_) | None, _) => {
                self.relations.written_mut().record_anything();
                return;
            }
        };
        match self.runs {
            RunTexts::Read { .. } => self.met.push(MetRun {
                literal,
                at,
                session: session.clone(),
            }),
            RunTexts::Recorded(bodies) => match bodies.run_writes(literal) {
                Some(writes) => self.relations.written_mut().merge(writes),
                None => self.relations.written_mut().record_anything(),
            },
            RunTexts::Parsed => self.parse_run_text(literal, sql, at, session),
        }
    }

    /// Record what the text of the literal at `literal` in `sql`, run by a
    /// statement starting at `at` under `session`, writes and names, its
    /// text parsed here ([`Self::note_text_writes`]); any column under any
    /// name where it does not decode or parse.
    fn parse_run_text(
        &mut self,
        literal: lexer::token::Span,
        sql: &str,
        at: u32,
        session: &ir::SessionContext,
    ) {
        let text = ir::utils::slice_span(sql, literal)
            .and_then(|raw| {
                ir::span_extract::decode_string_literal_text_with_map_in(raw, self.dialect)
            })
            .map(|(text, _)| text);
        let Some(text) = text else {
            self.relations.written_mut().record_anything();
            return;
        };
        let tokens = lex_body(&text, self.dialect);
        let Some(script) = parse_body(&text, &tokens, self.dialect) else {
            self.relations.written_mut().record_anything();
            return;
        };
        drop(tokens);
        self.note_text_writes(&script, &text, at, session);
    }

    /// Record what `script`, the parse of SQL text `text` a statement
    /// starting at `at` under `session` runs, writes and names: each of its
    /// statements through its own effect ([`Self::note_effect`]). The one
    /// place a run text's writes are decided, from whichever parse of it
    /// is made first.
    fn note_text_writes(
        &mut self,
        script: &ast::AstScript,
        text: &str,
        at: u32,
        session: &ir::SessionContext,
    ) {
        for inner in flat_stmts_for_rules(script) {
            self.note_effect(inner, text, &[], at, session, None);
        }
    }

    /// Decide what a text the reading of the script's run texts parsed to
    /// `script` writes, for each of `runs`, the runs of it met; any column
    /// under any name where it does not parse. What the text writes itself,
    /// recorded here too, and the runs of text it holds in turn, met to be
    /// decided as the reading reads them.
    fn decide_read(
        &mut self,
        runs: &[&MetRun],
        text: &str,
        script: Option<&ast::AstScript>,
    ) -> (facts::secrets::WrittenColumns, Vec<MetRun>) {
        let outer = std::mem::take(&mut self.met);
        let writes = self.recording(|reading| {
            for run in runs {
                match script {
                    Some(script) => reading.note_text_writes(script, text, run.at, &run.session),
                    None => reading.relations.written_mut().record_anything(),
                }
            }
        });
        (writes, std::mem::replace(&mut self.met, outer))
    }

    /// Decide what the text of each of `runs`, runs met of one literal of
    /// `src` the reading did not parse, writes, from a parse made here.
    fn decide_unread(&mut self, runs: &[&MetRun], src: &str) -> facts::secrets::WrittenColumns {
        self.parsing_runs(|reading| {
            reading.recording(|reading| {
                for run in runs {
                    reading.parse_run_text(run.literal, src, run.at, &run.session);
                }
            })
        })
    }

    /// What `note` records as written and named, recorded beside what was
    /// before.
    fn recording(&mut self, note: impl FnOnce(&mut Self)) -> facts::secrets::WrittenColumns {
        let before = std::mem::take(self.relations.written_mut());
        note(self);
        let noted = std::mem::replace(self.relations.written_mut(), before);
        self.relations.written_mut().merge(&noted);
        noted
    }

    /// `note`, each text a statement runs whole parsed where it is met: for
    /// text no reading of run texts reads, whose literals are not the
    /// script's.
    fn parsing_runs<T>(&mut self, note: impl FnOnce(&mut Self) -> T) -> T {
        let outer = std::mem::replace(&mut self.runs, RunTexts::Parsed);
        let noted = note(self);
        self.runs = outer;
        noted
    }

    /// `stmt`, the statement starting at `at`, lowered as the query
    /// evaluator lowers it, under `session`, over the relations the
    /// statements before it made.
    /// Record the columns `lowered`, a statement, writes values into
    /// ([`catalog::ScriptRelations::written`]): those an `INSERT`, an
    /// `UPDATE` or a `MERGE` names, and every column of a table written by
    /// position.
    fn note_written_columns(
        &mut self,
        lowered: &LoweredQuery,
        session: &ir::SessionContext,
        at: u32,
    ) {
        let (plan, _, bindings, ..) = lowered;
        let mut writes = Vec::new();
        plan_writes(plan, &mut writes);
        let relations = self.relations.at(at);
        let catalog = self.catalog;
        let stated = self.fold.stated_session_at(at);
        let mut noted: Vec<(catalog::Resolution, Option<String>)> = Vec::new();
        // Each table by the name it resolves to under the session the run
        // states; one written by position, each column it is known to have,
        // where every one is known.
        let mut columns = |target: &crate::context::node_metadata::TableRef,
                           columns: &[ir::ColumnId]| {
            let place = relations.resolution(catalog, target, &stated);
            if columns.is_empty() {
                let known = relations
                    .catalogued_table(catalog, target, session)
                    .filter(|table| {
                        !table.columns.is_empty()
                            && relations.lists_every_column(table)
                            && catalog.is_none_or(|catalog| catalog.listed_columns(table).is_some())
                    });
                match known {
                    Some(table) => noted.extend(
                        table
                            .columns
                            .iter()
                            .map(|column| (place.clone(), Some(column.name.name.clone()))),
                    ),
                    None => noted.push((place.clone(), None)),
                }
            }
            for column in columns {
                noted.push((
                    place.clone(),
                    bindings
                        .get(*column)
                        .map(|binding| binding.display_name.clone()),
                ));
            }
        };
        for write in writes {
            match write {
                PlanWrite::Insert {
                    target,
                    target_columns,
                    ..
                } => columns(target, target_columns),
                PlanWrite::Update {
                    target,
                    assignments,
                    ..
                } => {
                    for assignment in assignments {
                        columns(target, &assignment.columns);
                    }
                }
                PlanWrite::Merge {
                    target, branches, ..
                } => {
                    for branch in branches {
                        match &branch.action {
                            ir::MergeAction::Insert { target_columns, .. } => {
                                columns(target, target_columns)
                            }
                            ir::MergeAction::Update { assignments } => {
                                for assignment in assignments {
                                    columns(target, &assignment.columns);
                                }
                            }
                            ir::MergeAction::InsertStar { .. }
                            | ir::MergeAction::InsertAllByName { .. }
                            | ir::MergeAction::UpdateSetStar { .. }
                            | ir::MergeAction::UpdateAllByName { .. } => columns(target, &[]),
                            ir::MergeAction::Delete | ir::MergeAction::DoNothing => {}
                        }
                    }
                }
                PlanWrite::Rows { target } => columns(target, &[]),
                // A delete stores no value.
                PlanWrite::Removes { .. } => {}
            }
        }
        let written = self.relations.written_mut();
        for (table, column) in noted {
            written.record(&table, column.as_deref());
        }
    }

    fn lower_relational(
        &self,
        stmt: &ast::AstStmt,
        session: &ir::SessionContext,
        at: u32,
    ) -> Option<LoweredQuery> {
        let relations = self.relations.at(at);
        let declared = self.fold.declared_at(at);
        let around = ir::lower::AroundStatement {
            declared: &declared,
            meaning: self.meaning,
            relations,
        };
        ir::lower::lower_query_with_declared_names(
            stmt,
            self.sql,
            ir::StrictMode::Permissive,
            self.functions.at(at),
            session,
            self.catalog,
            self.models,
            around,
        )
        .ok()
    }

    /// The columns `query` gives the relation `stmt`, the statement
    /// starting at `at` of the script `sql`, makes from it
    /// ([`query_output_columns`]), with `stmt` lowered as the query
    /// evaluator lowers it, under `session`, over the relations as they
    /// stand at `at`, where `lowered` does not already hold it; and the
    /// tables its query reads, and the statement as lowered. With
    /// reasoning, each column carries the tags its value carries; with
    /// recognition alone, the tags of the column it copies.
    #[allow(clippy::type_complexity)] // the columns, the tables read, and the lowering kept
    fn query_columns(
        &self,
        stmt: &ast::AstStmt,
        query: &ast::AstStmt,
        sql: &str,
        session: &ir::SessionContext,
        at: u32,
        lowered: Option<LoweredQuery>,
    ) -> (
        Option<QueryColumns>,
        Vec<crate::context::node_metadata::TableRef>,
        Option<LoweredQuery>,
    ) {
        let relations = self.relations.at(at);
        let functions = self.functions.at(at);
        let lowered = lowered.or_else(|| {
            let declared = self.fold.declared_at(at);
            let around = ir::lower::AroundStatement {
                declared: &declared,
                meaning: self.meaning,
                relations,
            };
            ir::lower::lower_query_with_declared_names(
                stmt,
                sql,
                ir::StrictMode::Permissive,
                functions,
                session,
                self.catalog,
                self.models,
                around,
            )
            .ok()
        });
        let source = |table: &crate::context::node_metadata::TableRef| {
            relations.catalogued_table(self.catalog, table, session)
        };
        let columns = match &lowered {
            Some((plan, known, bindings, ..)) => {
                let body = if let ir::RelPlan::CreateAsQuery {
                    body: Some(body), ..
                } = plan
                {
                    Some(body.as_ref())
                } else {
                    None
                };
                let reasoned = self.reasoning.provides_analysis().then(|| {
                    self.reasoning.for_query(facts::reasoning::QueryInputs {
                        plan,
                        bindings,
                        catalog: Some(known),
                        function_catalog: functions,
                        source: sql,
                    })
                });
                let lowered = body.map(|body| LoweredBody {
                    body,
                    known,
                    bindings,
                    reasoning: reasoned.as_deref(),
                });
                query_output_columns(query, sql, lowered, &source)
            }
            None => query_output_columns(query, sql, None, &source),
        };
        let read = lowered
            .as_ref()
            .map(|lowered| lowered.1.tables_read().cloned().collect())
            .unwrap_or_default();
        (columns, read, lowered)
    }

    /// The columns of the table `source` names, which the relation the
    /// statement starting at `at` of the script `sql` makes `LIKE` it
    /// copies: names, types, NULL-ability and tags, nothing of any value;
    /// and whether they are every column it has.
    fn like_columns(
        &self,
        source: &ast::AstObjectRef,
        sql: &str,
        session: &ir::SessionContext,
        at: u32,
    ) -> Option<LikeColumns> {
        let source = ddl_target_table(&ir::lower_ddl::target_from_name(source, sql)?);
        let relations = self.relations.at(at);
        let table = relations.catalogued_table(self.catalog, &source, session)?;
        let every = relations.lists_every_column(table)
            && self
                .catalog
                .is_none_or(|catalog| catalog.listed_columns(table).is_some());
        (!table.columns.is_empty()).then(|| (table.columns.clone(), every))
    }

    /// What the statement `lowered` holds, the statement starting at `at`,
    /// writes into each relation it writes rows into, the relation named
    /// as written: rows an `INSERT` adds, or puts in place of every row
    /// where it overwrites, by column where reasoning knows their values
    /// and the relation is one the script holds; the columns an `UPDATE`
    /// or a `MERGE` changes, a `MERGE` that inserts adding rows not known;
    /// rows not known a multi-table `INSERT` adds to each of its targets;
    /// `None` for a relation it only removes rows from.
    fn written_rows(
        &self,
        lowered: &LoweredQuery,
        session: &ir::SessionContext,
        at: u32,
    ) -> Vec<StatementWrite> {
        let (plan, known, bindings, ..) = lowered;
        let mut writes = Vec::new();
        plan_writes(plan, &mut writes);
        if writes.is_empty() {
            return Vec::new();
        }
        let relations = self.relations.at(at);
        let functions = self.functions.at(at);
        // A column a write names is named as written.
        let name = |column: &ir::ColumnId| {
            bindings.get(*column).map(|binding| {
                IdentKey::new_as(&binding.display_name, ir::normalize::NameKind::Column)
            })
        };
        // Reasoning reads the rows only once, for a relation the script holds.
        let reasoning = std::cell::OnceCell::new();
        writes
            .into_iter()
            .map(|write| match write {
                PlanWrite::Insert {
                    target,
                    target_columns,
                    source,
                    overwrite,
                    on_conflict,
                    kind,
                } => {
                    let held = relations.holds(self.catalog, target, session);
                    let rows = match source {
                        ir::InsertSource::Query(body) | ir::InsertSource::Values(body)
                            if held && !target_columns.is_empty() && on_conflict.is_none() =>
                        {
                            let reasoning: &dyn facts::reasoning::QueryReasoning = &**reasoning
                                .get_or_init(|| {
                                    self.reasoning.for_query(facts::reasoning::QueryInputs {
                                        plan,
                                        bindings,
                                        catalog: Some(known),
                                        function_catalog: functions,
                                        source: self.sql,
                                    })
                                });
                            let outputs = body.positional_columns();
                            let columns = target_columns
                                .iter()
                                .zip(&outputs.known)
                                .filter_map(|(column, output)| {
                                    Some((name(column)?, made_value(reasoning, body, *output)))
                                })
                                .collect();
                            catalog::WrittenRows::Known {
                                columns,
                                replaces: overwrite,
                            }
                        }
                        ir::InsertSource::Query(_)
                        | ir::InsertSource::Values(_)
                        | ir::InsertSource::DefaultValues => catalog::WrittenRows::Unknown,
                    };
                    StatementWrite {
                        target: target.clone(),
                        rows: Some(rows),
                        events: kind.events(),
                        updated: conflict_updated(on_conflict, &name),
                        only: false,
                    }
                }
                PlanWrite::Update {
                    target,
                    assignments,
                    only,
                } => {
                    let columns = assignments
                        .iter()
                        .flat_map(|assignment| &assignment.columns)
                        .filter_map(name)
                        .collect();
                    StatementWrite {
                        target: target.clone(),
                        rows: Some(catalog::WrittenRows::Assigned(columns)),
                        events: catalog::WriteKind::Update.events(),
                        updated: assigned_columns(assignments, &name),
                        only,
                    }
                }
                PlanWrite::Merge {
                    target,
                    branches,
                    only,
                } => StatementWrite {
                    target: target.clone(),
                    rows: Some(merge_written(branches, &name)),
                    events: merge_events(branches),
                    updated: merge_updated(branches, &name),
                    only,
                },
                PlanWrite::Rows { target } => StatementWrite {
                    target: target.clone(),
                    rows: Some(catalog::WrittenRows::Unknown),
                    events: catalog::WriteKind::Insert.events(),
                    updated: catalog::UpdatedColumns::NONE,
                    only: false,
                },
                PlanWrite::Removes { target } => StatementWrite {
                    target: target.clone(),
                    rows: None,
                    events: catalog::WriteKind::Delete.events(),
                    updated: catalog::UpdatedColumns::NONE,
                    only: false,
                },
            })
            .collect()
    }

    /// Record what an `EXEC sp_rename` renames ([`ProcedureRename`]); a
    /// table it may rename in a way not read has columns not read.
    fn record_procedure_rename(
        &mut self,
        rename: ProcedureRename,
        site: catalog::RelationSite<'_>,
    ) {
        use catalog::RelationEdit;
        use ir::ddl_plan::DdlSchemaMutation;
        let unread = [DdlSchemaMutation::ColumnsUnread];
        match rename {
            ProcedureRename::Table { from, to } => {
                let to = ddl_target_table(&to);
                let edit = RelationEdit::RenameTo {
                    to: &to,
                    mutations: &[],
                };
                self.edit(&ddl_target_table(&from), edit, site);
            }
            ProcedureRename::Column { table, from, to } => {
                let renamed = [DdlSchemaMutation::RenameColumn { from, to }];
                let edit = RelationEdit::Alter {
                    mutations: &renamed,
                    dropped: &[],
                    added: &[],
                    column_names: false,
                };
                self.edit(&ddl_target_table(&table), edit, site);
            }
            ProcedureRename::Unread(tables) => {
                for table in tables {
                    let edit = RelationEdit::Alter {
                        mutations: &unread,
                        dropped: &[],
                        added: &[],
                        column_names: false,
                    };
                    self.edit(&ddl_target_table(&table), edit, site);
                }
            }
        }
    }
}

/// A write a statement's plan makes into a relation ([`plan_writes`]).
enum PlanWrite<'p> {
    /// The rows an `INSERT` adds, or puts in place of every row where it
    /// overwrites; values not known where it acts on a conflict.
    Insert {
        target: &'p crate::context::node_metadata::TableRef,
        target_columns: &'p [ir::ColumnId],
        source: &'p ir::InsertSource,
        overwrite: bool,
        on_conflict: Option<&'p ir::OnConflict>,
        kind: catalog::WriteKind,
    },
    /// The columns an `UPDATE` assigns, of the table alone where `only`.
    Update {
        target: &'p crate::context::node_metadata::TableRef,
        assignments: &'p [ir::Assignment],
        only: bool,
    },
    /// What the branches of a `MERGE` write, into the table alone where
    /// `only`.
    Merge {
        target: &'p crate::context::node_metadata::TableRef,
        branches: &'p [ir::MergeBranch],
        only: bool,
    },
    /// Rows whose values are not read: those a multi-table `INSERT` adds
    /// to each of its targets.
    Rows {
        target: &'p crate::context::node_metadata::TableRef,
    },
    /// Rows a `DELETE` removes: no row is written, and what held of every
    /// row holds of those left.
    Removes {
        target: &'p crate::context::node_metadata::TableRef,
    },
}

/// What a statement does to the columns a run writes and the names it
/// gives them ([`statement_effect`]). Each statement says its effect: one
/// the run cannot read writes any column under any name.
#[derive(Debug, Clone, Copy)]
enum StatementEffect<'s> {
    /// Writes no column and names none.
    Nothing,
    /// Writes the rows its plan writes ([`plan_writes`]).
    Rows,
    /// Makes a relation ([`Made`]).
    Defines(Made<'s>),
    /// Changes a relation's or a namespace's schema: the renames and swaps
    /// it makes.
    Alters,
    /// Loads rows into its table: every column of it.
    Loads,
    /// Runs SQL text: each statement of a text read whole.
    RunsText,
    /// Calls a routine: what the dialect documents its own routine does, or
    /// what the body the run defines it with does.
    Calls,
    /// Has a task run the statement it holds: that statement's effect.
    Runs(&'s ast::AstStmt),
    /// Evaluates values ([`Held`]): the effect of each statement they hold.
    Holds(Held<'s>),
    /// Defines a pipe: the effect of the statement it loads with, read
    /// from its text; any where that is not read.
    DefinesPipe(&'s ast::AstCreatePipe),
    /// Has a pipe load again: the effect of the pipe the run defines, else
    /// any.
    RefreshesPipe(&'s ast::AstAlterPipe),
    /// May write any column under any name.
    Anything,
}

/// The values a statement evaluates, which may hold statements
/// (`LET rs RESULTSET := (EXECUTE IMMEDIATE :q)`): every statement written
/// in them, whether or not a variable keeps the value.
#[derive(Debug, Clone, Copy)]
enum Held<'s> {
    /// One value: `LET v := …`, `v := …`, `RETURN …`.
    Value(Option<&'s ast::AstExpr>),
    /// The default of each variable a `DECLARE` declares.
    Declared(&'s [ast::AstDeclaredVariable]),
    /// Each value `SET` gives.
    Values(&'s [ast::AstExpr]),
}

/// The relation a statement makes ([`StatementEffect::Defines`]).
#[derive(Debug, Clone, Copy)]
enum Made<'s> {
    /// A table: the values its query writes, the rows it takes from
    /// another relation ([`made_rows`]).
    Table(MadeTable<'s>),
    /// A relation showing its query's columns: a view, a materialized view,
    /// a dynamic table.
    View,
    /// A synonym for another relation.
    Synonym(&'s ast::AstCreateSynonym),
    /// A stream on a table or a view, which shows its columns.
    Stream(&'s ast::AstCreateStream),
}

/// The statement making a table ([`Made::Table`]).
#[derive(Debug, Clone, Copy)]
enum MadeTable<'s> {
    /// `CREATE TABLE`.
    Create(&'s ast::AstCreateTable),
    /// `CACHE TABLE`.
    Cache(&'s ast::AstCacheTable),
    /// BigQuery `CREATE SNAPSHOT TABLE`.
    Snapshot,
}

/// The effect of `stmt`, a statement of `sql`, beside the bodies it holds
/// ([`ast::AstStmt::bodies`]), whose statements each state their own.
/// Every statement is listed, so a new one fails the build until its effect
/// is stated.
fn statement_effect<'s>(stmt: &'s ast::AstStmt, sql: &str) -> StatementEffect<'s> {
    use ast::AstStmt as S;
    match stmt {
        S::Select { .. }
        | S::SetSelect { .. }
        | S::ValuesQuery { .. }
        | S::Insert { .. }
        | S::ReplaceInto { .. }
        | S::MultiInsert { .. }
        | S::Update { .. }
        | S::Delete { .. }
        | S::Merge { .. }
        | S::Explain { .. }
        | S::Perform { .. }
        | S::MysqlDo { .. }
        | S::PipeChain { .. } => StatementEffect::Rows,
        S::CreateTable(table) => StatementEffect::Defines(Made::Table(MadeTable::Create(table))),
        S::CacheTable(cache) => StatementEffect::Defines(Made::Table(MadeTable::Cache(cache))),
        S::BqCreateSnapshotTable { .. } => {
            StatementEffect::Defines(Made::Table(MadeTable::Snapshot))
        }
        S::CreateView { .. } | S::CreateDynamicTable { .. } => StatementEffect::Defines(Made::View),
        S::CreateStream(stream) => StatementEffect::Defines(Made::Stream(stream)),
        S::CreateSynonym(synonym) => StatementEffect::Defines(Made::Synonym(synonym)),
        S::AlterTable { .. }
        | S::AlterView { .. }
        | S::AlterMaterializedView { .. }
        | S::AlterDynamicTable { .. }
        | S::MysqlRenameTable { .. }
        | S::AlterSchema { .. }
        | S::AlterDatabase { .. } => StatementEffect::Alters,
        S::MssqlBulkInsert { .. }
        | S::CopyIntoTable { .. }
        | S::RedshiftCopy { .. }
        | S::BqLoadData { .. }
        | S::MysqlLoadData { .. }
        | S::Restore { .. } => StatementEffect::Loads,
        S::ExecuteImmediate { .. } | S::PgPrepare { .. } => StatementEffect::RunsText,
        S::Call { .. } | S::ExecuteTask { .. } => StatementEffect::Calls,
        // Text not read as a statement, or read only in part, and a script
        // run from a file the run does not read.
        S::OpaqueContent { .. }
        | S::Error { .. }
        | S::ClauseFragment { .. }
        | S::JinjaPlaceholder { .. }
        | S::JinjaConditionalStmt { .. }
        | S::ExecuteImmediateFrom { .. }
        | S::PsqlGexec { .. }
        | S::PgExecute { .. }
        | S::MssqlRestore { .. }
        | S::CreateFlow { .. } => StatementEffect::Anything,
        // A routine, trigger, event, task or block holding no body the run
        // read ([`ast::AstStmt::bodies`]): what it runs is not read. One
        // holding a body writes what the body's statements do, each read on
        // its own.
        S::CreateProcedure { .. }
        | S::CreateFunction { .. }
        | S::CreateTableFunction { .. }
        | S::DoBlock { .. }
        | S::CreateMssqlTrigger { .. }
        | S::CreatePgTrigger { .. }
        | S::CreateMysqlTrigger { .. }
        | S::CreateEvent { .. }
        | S::CreateTask { .. }
        | S::CreateAlert { .. } => match stmt.bodies().is_empty() {
            true => StatementEffect::Anything,
            false => StatementEffect::Nothing,
        },
        // A body a new `DO` gives that did not parse runs what the run does
        // not read; one parsed is a body, read statement by statement.
        S::AlterEvent(event) => match (event.do_span, stmt.bodies().is_empty()) {
            (Some(_), true) => StatementEffect::Anything,
            (Some(_), false) | (None, _) => StatementEffect::Nothing,
        },
        // A subscription copies and replicates another server's tables into
        // tables of its own: the statement does not say which.
        S::PgSubscription { .. } => StatementEffect::Anything,
        S::CreatePipe(pipe) => StatementEffect::DefinesPipe(pipe),
        S::AlterPipe(pipe) => match &pipe.action.kind {
            ast::AstAlterPipeActionKind::Refresh { .. } => StatementEffect::RefreshesPipe(pipe),
            ast::AstAlterPipeActionKind::Set { .. }
            | ast::AstAlterPipeActionKind::SetTag { .. }
            | ast::AstAlterPipeActionKind::UnsetTag { .. } => StatementEffect::Nothing,
        },
        S::Let { expr, .. } | S::Assign { expr, .. } => {
            StatementEffect::Holds(Held::Value(Some(expr)))
        }
        S::Return { expr, .. } => StatementEffect::Holds(Held::Value(expr.as_deref())),
        S::Declare { variables, .. } => StatementEffect::Holds(Held::Declared(variables)),
        S::SetVariable { values, .. } => StatementEffect::Holds(Held::Values(values)),
        // An export reads its table; a load writes every column of it.
        S::PgCopy(copy) => match copy.direction {
            ast::PgCopyDirection::From => StatementEffect::Loads,
            ast::PgCopyDirection::To => StatementEffect::Nothing,
        },
        // `ALTER TASK … MODIFY AS` gives the task the statement it holds,
        // which the task runs; a statement not parsed may write anything.
        // Its other actions run nothing beyond the body already read.
        S::AlterTask(task) => match &task.action.kind {
            ast::AstAlterTaskActionKind::ModifyAs { body: Ok(body), .. } => {
                StatementEffect::Runs(body)
            }
            ast::AstAlterTaskActionKind::ModifyAs { body: Err(_), .. } => StatementEffect::Anything,
            ast::AstAlterTaskActionKind::Resume { .. }
            | ast::AstAlterTaskActionKind::Suspend { .. }
            | ast::AstAlterTaskActionKind::AddAfter { .. }
            | ast::AstAlterTaskActionKind::RemoveAfter { .. }
            | ast::AstAlterTaskActionKind::Set { .. }
            | ast::AstAlterTaskActionKind::SetTag { .. }
            | ast::AstAlterTaskActionKind::SetFinalize { .. }
            | ast::AstAlterTaskActionKind::Unset { .. }
            | ast::AstAlterTaskActionKind::UnsetTag { .. }
            | ast::AstAlterTaskActionKind::UnsetFinalize { .. }
            | ast::AstAlterTaskActionKind::ModifyWhen { .. }
            | ast::AstAlterTaskActionKind::RemoveWhen { .. } => StatementEffect::Nothing,
        },
        // `EXEC (…)` and `sp_executesql` run text; any other `EXEC` calls.
        S::MssqlExec { .. } => match ir::dynamic_sql::sql_run(stmt, sql) {
            Some(_) => StatementEffect::RunsText,
            None => StatementEffect::Calls,
        },
        // A sqlcmd command that sets the client's state sends nothing; one
        // that reads a file, connects, runs a command or an editor, or
        // sends a query runs what the run does not read.
        S::SqlcmdCommand { action, .. } => match action {
            ast::SqlcmdAction::Client { .. } => StatementEffect::Nothing,
            ast::SqlcmdAction::Include { .. }
            | ast::SqlcmdAction::Connect { .. }
            | ast::SqlcmdAction::OsCommand
            | ast::SqlcmdAction::Edit
            | ast::SqlcmdAction::ExitQuery { .. } => StatementEffect::Anything,
        },
        // Writes no column and names none.
        S::GoBatchSeparator { .. }
        | S::Reconfigure { .. }
        | S::MssqlServerCommand { .. }
        | S::MssqlExecuteAs { .. }
        | S::MssqlRevert { .. }
        | S::MssqlAuditDdl { .. }
        | S::MssqlSecurityObjectDdl { .. }
        | S::MssqlTryCatch { .. }
        | S::MssqlIf { .. }
        | S::MssqlWhile { .. }
        | S::MssqlPrint { .. }
        | S::MssqlThrow { .. }
        | S::MssqlRaiserror { .. }
        | S::MssqlSetOption { .. }
        | S::MysqlSet { .. }
        | S::MysqlUnlockTables { .. }
        | S::MssqlWaitfor { .. }
        | S::MssqlGoto { .. }
        | S::MssqlLabel { .. }
        | S::DropMssqlTrigger { .. }
        | S::MssqlTriggerState { .. }
        | S::Savepoint { .. }
        | S::MssqlCreateExternalModel { .. }
        | S::MssqlCreateExternalDataSource { .. }
        | S::MssqlAlterExternalDataSource { .. }
        | S::CreateForeignServer { .. }
        | S::AlterForeignServer { .. }
        | S::MssqlAlterServerConfiguration { .. }
        | S::CreateUserMapping { .. }
        | S::AlterUserMapping { .. }
        | S::DropUserMapping { .. }
        | S::CreateForeignTable { .. }
        | S::ImportForeignSchema { .. }
        | S::MssqlAlterExternalModel { .. }
        | S::MssqlDropExternalModel { .. }
        | S::MssqlCreateVectorIndex { .. }
        | S::CreateStage { .. }
        | S::CreateRowAccessPolicy { .. }
        | S::CreateMaskingPolicy { .. }
        | S::CreateNetworkPolicy { .. }
        | S::CreateSessionPolicy { .. }
        | S::CreateAuthenticationPolicy { .. }
        | S::CreateApiIntegration { .. }
        | S::CreateNotificationIntegration { .. }
        | S::CreatePasswordPolicy { .. }
        | S::CreateAggregationPolicy { .. }
        | S::CreateProjectionPolicy { .. }
        | S::CreateStorageIntegration { .. }
        | S::AlterRowAccessPolicy { .. }
        | S::AlterMaskingPolicy { .. }
        | S::AlterNetworkPolicy { .. }
        | S::AlterSessionPolicy { .. }
        | S::AlterSession { .. }
        | S::AlterAuthenticationPolicy { .. }
        | S::AlterUser { .. }
        | S::AlterAccount { .. }
        | S::AlterApiIntegration { .. }
        | S::AlterNotificationIntegration { .. }
        | S::CreateShare { .. }
        | S::AlterShare { .. }
        | S::CreateDatashare { .. }
        | S::AlterDatashare { .. }
        | S::CreateSecurityIntegration { .. }
        | S::AlterSecurityIntegration { .. }
        | S::AlterReplicationGroup { .. }
        | S::AlterFailoverGroup { .. }
        | S::AlterPasswordPolicy { .. }
        | S::AlterAggregationPolicy { .. }
        | S::AlterProjectionPolicy { .. }
        | S::AlterStorageIntegration { .. }
        | S::AlterFunction { .. }
        | S::AlterProcedure { .. }
        | S::AlterStage { .. }
        | S::Show { .. }
        | S::Describe { .. }
        | S::Use { .. }
        | S::Truncate { .. }
        | S::Drop { .. }
        | S::DropRowAccessPolicy { .. }
        | S::DropAllRowAccessPolicies { .. }
        | S::DropMaskingPolicy { .. }
        | S::DropNetworkPolicy { .. }
        | S::DropSessionPolicy { .. }
        | S::DropAuthenticationPolicy { .. }
        | S::DropApiIntegration { .. }
        | S::DropNotificationIntegration { .. }
        | S::DropPasswordPolicy { .. }
        | S::DropAggregationPolicy { .. }
        | S::DropProjectionPolicy { .. }
        | S::DropStorageIntegration { .. }
        | S::DropTask { .. }
        | S::CreateWarehouse { .. }
        | S::AlterWarehouse { .. }
        | S::DropWarehouse { .. }
        | S::DropPipe { .. }
        | S::CreateTag { .. }
        | S::AlterTag { .. }
        | S::UndropTag { .. }
        | S::CreateFileFormat { .. }
        | S::AlterFileFormat { .. }
        | S::CreateSecret { .. }
        | S::AlterSecret { .. }
        | S::CreateNetworkRule { .. }
        | S::AlterNetworkRule { .. }
        | S::CreateResourceMonitor { .. }
        | S::AlterResourceMonitor { .. }
        | S::CreateComputePool { .. }
        | S::AlterComputePool { .. }
        | S::CreateGitRepository { .. }
        | S::AlterGitRepository { .. }
        | S::CreateImageRepository { .. }
        | S::AlterImageRepository { .. }
        | S::CreateStreamlit { .. }
        | S::AlterStreamlit { .. }
        | S::CreateService { .. }
        | S::AlterService { .. }
        | S::CreateNotebook { .. }
        | S::AlterNotebook { .. }
        | S::CreateSemanticView { .. }
        | S::AlterSemanticView { .. }
        | S::CreateCortexSearchService { .. }
        | S::AlterCortexSearchService { .. }
        | S::CreateApplication { .. }
        | S::AlterApplication { .. }
        | S::CreateApplicationPackage { .. }
        | S::AlterApplicationPackage { .. }
        | S::CreateListing { .. }
        | S::AlterListing { .. }
        | S::CreateManagedAccount { .. }
        | S::CreateAccount { .. }
        | S::StageFileCommand { .. }
        | S::AlterAlert { .. }
        | S::CreateJoinPolicy { .. }
        | S::AlterJoinPolicy { .. }
        | S::DropJoinPolicy { .. }
        | S::CreateDataMetricFunction { .. }
        | S::CreateReplicationFailoverGroup { .. }
        | S::CreateExternalAccessIntegration { .. }
        | S::AlterExternalAccessIntegration { .. }
        | S::DropExternalAccessIntegration { .. }
        | S::AlterStream { .. }
        | S::DropStream { .. }
        | S::CreateDatabase { .. }
        | S::DropDatabase { .. }
        | S::UndropDatabase { .. }
        | S::CreateSchema { .. }
        | S::DropSchema { .. }
        | S::UndropSchema { .. }
        | S::UndropTable { .. }
        | S::UndropType { .. }
        | S::MysqlCreateLoadableFunction { .. }
        | S::MysqlAdmin { .. }
        | S::CreateIndex { .. }
        | S::CommentOn { .. }
        | S::Vacuum { .. }
        | S::AnalyzeStmt { .. }
        | S::CreateType { .. }
        | S::AlterType { .. }
        | S::CreateExtension { .. }
        | S::CreateSequence { .. }
        | S::AlterSequence { .. }
        | S::AlterPgTrigger { .. }
        | S::DropPgTrigger { .. }
        | S::CreateDomain { .. }
        | S::AlterDomain { .. }
        | S::DropDomain { .. }
        | S::CreatePgPolicy { .. }
        | S::AlterPgPolicy { .. }
        | S::DropPgPolicy { .. }
        | S::AlterIndex { .. }
        | S::Reindex { .. }
        | S::PgDeallocate { .. }
        | S::PgRefreshMatview { .. }
        | S::PgListen { .. }
        | S::PgNotify { .. }
        | S::PgUnlisten { .. }
        | S::PgLockTable { .. }
        | S::PgCreateRule { .. }
        | S::MssqlCreateRule { .. }
        | S::PgCreateAggregate { .. }
        | S::PgCreateOperator { .. }
        | S::PgAlterSystem { .. }
        | S::PgAlterTablespace { .. }
        | S::PgDropOwned { .. }
        | S::PgReassignOwned { .. }
        | S::PgDiscard { .. }
        | S::PgCluster { .. }
        | S::PgPublication { .. }
        | S::CreatePrincipal { .. }
        | S::AlterPrincipal { .. }
        | S::DropPrincipal { .. }
        | S::PgDropExtension { .. }
        | S::PgAlterRule { .. }
        | S::PgDropRule { .. }
        | S::PgAlterTableTriggerState { .. }
        | S::PgSet { .. }
        | S::PgDropSequence { .. }
        | S::PgDropType { .. }
        | S::PgDropIndex { .. }
        | S::PgCreateTablespace { .. }
        | S::PgDropTablespace { .. }
        | S::BqExportData { .. }
        | S::BqAssert { .. }
        | S::BqDropSnapshotTable { .. }
        | S::BqCreateSearchIndex { .. }
        | S::BqDropSearchIndex { .. }
        | S::BqCreateVectorIndex { .. }
        | S::BqDropVectorIndex { .. }
        | S::BqAlterVectorIndex { .. }
        | S::BqCreateModel { .. }
        | S::BqAlterModel { .. }
        | S::BqExportModel { .. }
        | S::BqDropModel { .. }
        | S::Optimize { .. }
        | S::DescribeHistory { .. }
        | S::MssqlBackup { .. }
        | S::MssqlDbcc { .. }
        | S::MssqlKeyManagement { .. }
        | S::MssqlSecurityPolicy { .. }
        | S::MssqlKeyBackup { .. }
        | S::MssqlAssembly { .. }
        | S::MssqlAddSignature { .. }
        | S::MssqlSetuser { .. }
        | S::MssqlAlterServiceMasterKey { .. }
        | S::PgAlterDefaultPrivileges { .. }
        | S::UncacheTable { .. }
        | S::RepairTable { .. }
        | S::CreateCatalog { .. }
        | S::AlterCatalog { .. }
        | S::DropCatalog { .. }
        | S::CreateVolume { .. }
        | S::AlterVolume { .. }
        | S::DropVolume { .. }
        | S::CreateExternalLocation { .. }
        | S::AlterExternalLocation { .. }
        | S::DropExternalLocation { .. }
        | S::CreateStorageCredential { .. }
        | S::AlterStorageCredential { .. }
        | S::DropStorageCredential { .. }
        | S::CreateConnection { .. }
        | S::AlterConnection { .. }
        | S::DropConnection { .. }
        | S::CreateExternalTable { .. }
        | S::CreateExternalSchema { .. }
        | S::Block { .. }
        | S::If { .. }
        | S::CaseStmt { .. }
        | S::DeclareTable { .. }
        | S::DeclareCursor { .. }
        | S::LetCursor { .. }
        | S::Raise { .. }
        | S::Signal { .. }
        | S::Resignal { .. }
        | S::GetDiagnostics { .. }
        | S::DeclareCondition { .. }
        | S::DeclareHandler { .. }
        | S::For { .. }
        | S::ForEach { .. }
        | S::While { .. }
        | S::Repeat { .. }
        | S::Loop { .. }
        | S::Await { .. }
        | S::Cancel { .. }
        | S::Break { .. }
        | S::Continue { .. }
        | S::Null { .. }
        | S::OpenCursor { .. }
        | S::FetchCursor { .. }
        | S::CloseCursor { .. }
        | S::CreateExternalFunction { .. }
        | S::BeginTransaction { .. }
        | S::Commit { .. }
        | S::Rollback { .. }
        | S::CopyIntoLocation { .. }
        | S::Unload { .. }
        | S::Grant { .. }
        | S::Revoke { .. }
        | S::Deny { .. }
        | S::AlterAuthorization { .. } => StatementEffect::Nothing,
    }
}

/// Each write `plan`, a statement's plan, makes into a relation: its own,
/// each data-modifying CTE's, and that of the statement an `EXPLAIN
/// ANALYZE` runs. Every variant is listed, so a new one that writes breaks
/// the build.
fn plan_writes<'p>(plan: &'p ir::RelPlan, writes: &mut Vec<PlanWrite<'p>>) {
    use ir::RelPlan;
    match plan {
        RelPlan::Insert {
            target,
            target_columns,
            source,
            on_conflict,
            overwrite,
            replace_into,
            ..
        } => writes.push(PlanWrite::Insert {
            target,
            target_columns,
            source,
            overwrite: *overwrite == Some(ir::OverwriteScope::Table),
            on_conflict: on_conflict.as_ref(),
            kind: insert_kind(*replace_into, overwrite.is_some(), on_conflict.as_ref()),
        }),
        RelPlan::Update {
            target,
            assignments,
            only,
            ..
        } => writes.push(PlanWrite::Update {
            target,
            assignments,
            only: only.is_some(),
        }),
        RelPlan::Merge {
            target,
            branches,
            only,
            ..
        } => writes.push(PlanWrite::Merge {
            target,
            branches,
            only: only.is_some(),
        }),
        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            ..
        } => {
            let targets = unconditional_clauses
                .iter()
                .chain(when_clauses.iter().flat_map(|when| &when.targets))
                .chain(else_clauses);
            for into in targets {
                writes.push(PlanWrite::Rows {
                    target: &into.target,
                });
            }
        }
        RelPlan::Delete { target, .. } => writes.push(PlanWrite::Removes { target }),
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                match &cte.body {
                    ir::CteBody::NonRecursive(body) => plan_writes(body, writes),
                    ir::CteBody::Recursive { anchor, step, .. } => {
                        plan_writes(anchor, writes);
                        plan_writes(step, writes);
                    }
                }
            }
            plan_writes(body, writes);
        }
        RelPlan::Explain { body, options, .. } => {
            if options.analyze {
                plan_writes(body, writes);
            }
        }
        // A query, or a relation made from one: no row is written.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

/// What reading a statement's plan finds of the parts not read
/// ([`plan_runs`]).
#[derive(Default)]
struct PlanRuns {
    /// Part of it was not read: the parser recovered past it, or could not
    /// structure it.
    partial: bool,
    /// A value of it was not read, which may call a function.
    unread_value: bool,
}

/// What `plan`, a statement's plan, holds that is not read, at every depth
/// it runs; the statement an `EXPLAIN` without `ANALYZE` shows is not run.
fn plan_runs(plan: &ir::RelPlan) -> PlanRuns {
    use ir::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};

    struct Runs(PlanRuns);

    impl<'p> RelPlanVisitor<'p> for Runs {
        fn visit_rel_plan(&mut self, plan: &'p ir::RelPlan) {
            match plan_node_run(plan) {
                PlanNodeRun::Runs => walk_rel_plan(self, plan),
                PlanNodeRun::Partial => self.0.partial = true,
                PlanNodeRun::Shown => {}
            }
        }

        fn visit_scalar_expr(&mut self, expr: &'p ir::ScalarExpr) {
            match expr {
                ir::ScalarExpr::Opaque { .. } => self.0.unread_value = true,
                ir::ScalarExpr::FuncCall { .. }
                | ir::ScalarExpr::Column { .. }
                | ir::ScalarExpr::OuterRef { .. }
                | ir::ScalarExpr::Lit { .. }
                | ir::ScalarExpr::BinOp { .. }
                | ir::ScalarExpr::LogicalChain { .. }
                | ir::ScalarExpr::OperatorChain { .. }
                | ir::ScalarExpr::UnaryOp { .. }
                | ir::ScalarExpr::Case { .. }
                | ir::ScalarExpr::Cast { .. }
                | ir::ScalarExpr::InList { .. }
                | ir::ScalarExpr::Between { .. }
                | ir::ScalarExpr::Like { .. }
                | ir::ScalarExpr::Exists { .. }
                | ir::ScalarExpr::ScalarSubquery { .. }
                | ir::ScalarExpr::QuantifiedCmp { .. }
                | ir::ScalarExpr::RowCmp { .. }
                | ir::ScalarExpr::WindowFn { .. }
                | ir::ScalarExpr::FieldAccess { .. }
                | ir::ScalarExpr::Lambda { .. }
                | ir::ScalarExpr::PatternVarRef { .. } => {}
            }
            walk_scalar_expr(self, expr);
        }
    }

    let mut runs = Runs(PlanRuns::default());
    runs.visit_rel_plan(plan);
    runs.0
}

/// Whether a plan node runs what it holds ([`plan_node_run`]).
enum PlanNodeRun {
    Runs,
    /// The parser recovered past it, or could not structure it.
    Partial,
    /// It shows a statement without running it.
    Shown,
}

/// Whether `plan`, a node of a statement's plan, runs what it holds. Every
/// variant is listed, so a new one breaks the build.
fn plan_node_run(plan: &ir::RelPlan) -> PlanNodeRun {
    use ir::RelPlan;
    match plan {
        RelPlan::ParseRecovery { .. } | RelPlan::Opaque { .. } => PlanNodeRun::Partial,
        RelPlan::Explain { options, .. } if !options.analyze => PlanNodeRun::Shown,
        RelPlan::Explain { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Delete { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. } => PlanNodeRun::Runs,
    }
}

/// The routine a call naming `written` calls, each part normalized as a
/// routine's name a statement defines is ([`routine_identity`]).
fn called_identity(written: &str) -> facts::reasoning::TableIdentity {
    let mut parts = ir::lower_ddl::split_qualified(written);
    let name = parts.pop().unwrap_or_else(|| written.to_string());
    facts::reasoning::TableIdentity {
        name: IdentKey::new(&name),
        schema: parts.pop().as_deref().map(IdentKey::new),
        database: parts.pop().as_deref().map(IdentKey::new),
    }
}

/// A routine's name as `name` writes it, each part normalized.
fn routine_identity(
    name: &crate::context::node_metadata::TableRef,
) -> facts::reasoning::TableIdentity {
    facts::reasoning::TableIdentity {
        database: name.db.as_deref().map(IdentKey::new),
        schema: name.schema.as_deref().map(IdentKey::new),
        name: IdentKey::new(&name.name),
    }
}

/// The types of the parameters of the routine `stmt` defines that tell it
/// from another of its name: each but an `OUT` one's, as written, its
/// letters folded and its spaces gone; `None` where the statement defines
/// no routine so read, or a type is not written. With whether the
/// statement replaces the routine of its name and those types.
fn routine_signature(
    stmt: &ast::AstStmt,
    sql: &str,
    dialect: &dyn dialect::Dialect,
) -> (Option<Vec<String>>, bool) {
    let Some(created) = ir::dynamic_sql::created_routine_parts(stmt) else {
        return (None, false);
    };
    (param_types(created.params, sql, dialect), created.replaces)
}

/// The types of `params`, a routine's parameters or the arguments a `DROP`
/// of one lists, that tell it from another of its name: each but an `OUT`
/// one's, as [`type_key`] reads it; `None` where a type is not written.
fn param_types(
    params: &[ast::AstProcedureParam],
    sql: &str,
    dialect: &dyn dialect::Dialect,
) -> Option<Vec<String>> {
    params
        .iter()
        .filter(|param| match param.mode {
            ast::ProcedureParamMode::In
            | ast::ProcedureParamMode::InOut
            | ast::ProcedureParamMode::Variadic => true,
            ast::ProcedureParamMode::Out => false,
        })
        .map(|param| {
            let written = ir::utils::slice_span(sql, param.type_span?)?;
            Some(type_key(written, dialect))
        })
        .collect()
}

/// The type `written` names, as a routine's signature or a comparison of
/// two versions of a statement compares it: as written, its letters
/// folded and its spaces gone; of a type the dialect gives other names,
/// its name, then its length or precision as written (a precision written
/// alone with the scale the name implies for it), else the one the name
/// implies, and its array bounds as written
/// ([`dialect::Dialect::type_synonyms`]).
pub fn type_key(written: &str, dialect: &dyn dialect::Dialect) -> String {
    let folded = written.to_ascii_lowercase();
    // The words of the name, apart from what `(…)` and `[…]` hold.
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let (mut modifier, mut bounds) = (String::new(), String::new());
    let (mut parens, mut brackets) = (0usize, 0usize);
    for c in folded.chars() {
        if parens > 0 || c == '(' {
            parens = match c {
                '(' => parens + 1,
                ')' => parens.saturating_sub(1),
                _ => parens,
            };
            if !c.is_whitespace() {
                modifier.push(c);
            }
        } else if brackets > 0 || c == '[' {
            brackets = match c {
                '[' => brackets + 1,
                ']' => brackets.saturating_sub(1),
                _ => brackets,
            };
            if !c.is_whitespace() {
                bounds.push(c);
            }
        } else if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    match dialect.type_synonym(&words.join(" ")) {
        Some(synonyms) => {
            let name: String = synonyms
                .name
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            // A precision written alone, of a type that takes a scale.
            let precision_alone = modifier
                .strip_prefix('(')
                .and_then(|inner| inner.strip_suffix(')'))
                .filter(|inner| !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()));
            let modifier = match (modifier.is_empty(), precision_alone) {
                (true, _) => synonyms.implied.to_string(),
                (false, Some(precision)) if !synonyms.scale.is_empty() => {
                    format!("({precision},{})", synonyms.scale)
                }
                (false, Some(_) | None) => modifier,
            };
            name + &modifier + &bounds
        }
        None => folded.chars().filter(|c| !c.is_whitespace()).collect(),
    }
}

/// The parameters of the routine `stmt` defines, in order, `sql` the
/// script's text; `None` for a statement that defines none.
fn routine_params(stmt: &ast::AstStmt, sql: &str) -> Option<Vec<catalog::RoutineParam>> {
    let created = ir::dynamic_sql::created_routine_parts(stmt)?;
    Some(
        created
            .params
            .iter()
            .map(|param| catalog::RoutineParam {
                name: param
                    .name_span
                    .and_then(|span| ir::utils::slice_span(sql, span))
                    .map(|name| IdentKey::new_as(name, ir::normalize::NameKind::Column)),
                assigns: match param.mode {
                    ast::ProcedureParamMode::Out | ast::ProcedureParamMode::InOut => true,
                    ast::ProcedureParamMode::In | ast::ProcedureParamMode::Variadic => false,
                },
            })
            .collect(),
    )
}

/// The kind of write an `INSERT` makes: one that replaces each row a
/// row it adds meets on a key (`replace_into`), one that puts its rows in
/// place of every row (`overwrite`), or one that acts on a conflict as
/// `on_conflict` says.
fn insert_kind(
    replace_into: bool,
    overwrite: bool,
    on_conflict: Option<&ir::OnConflict>,
) -> catalog::WriteKind {
    if replace_into {
        return catalog::WriteKind::Replace;
    }
    if overwrite {
        return catalog::WriteKind::Overwrite;
    }
    match on_conflict.map(|conflict| &conflict.action) {
        Some(
            ir::ConflictAction::DoUpdate { .. }
            | ir::ConflictAction::MySqlDuplicateKeyUpdate { .. },
        ) => catalog::WriteKind::InsertOrUpdate,
        Some(ir::ConflictAction::DoNothing) | None => catalog::WriteKind::Insert,
    }
}

/// The events the branches of a `MERGE` raise: each branch's.
fn merge_events(branches: &[ir::MergeBranch]) -> catalog::WriteEvents {
    branches
        .iter()
        .fold(catalog::WriteEvents::NONE, |events, branch| {
            let kind = match &branch.action {
                ir::MergeAction::Insert { .. }
                | ir::MergeAction::InsertStar { .. }
                | ir::MergeAction::InsertAllByName { .. } => catalog::WriteKind::Insert,
                ir::MergeAction::Update { .. }
                | ir::MergeAction::UpdateSetStar { .. }
                | ir::MergeAction::UpdateAllByName { .. } => catalog::WriteKind::Update,
                ir::MergeAction::Delete => catalog::WriteKind::Delete,
                ir::MergeAction::DoNothing => return events,
            };
            events.union(kind.events())
        })
}

/// A write a statement makes into a relation ([`RelationReading::written_rows`]).
struct StatementWrite {
    /// The relation, named as written.
    target: crate::context::node_metadata::TableRef,
    /// The rows written; `None` where rows are only removed.
    rows: Option<catalog::WrittenRows>,
    /// The events the write raises.
    events: catalog::WriteEvents,
    /// The columns its update assigns.
    updated: catalog::UpdatedColumns,
    /// It writes the table alone, none of its children (`ONLY`).
    only: bool,
}

/// The columns `assignments` assign, `name` naming each; not read where a
/// column has no name.
fn assigned_columns(
    assignments: &[ir::Assignment],
    name: &dyn Fn(&ir::ColumnId) -> Option<IdentKey>,
) -> catalog::UpdatedColumns {
    let mut columns = Vec::new();
    for column in assignments
        .iter()
        .flat_map(|assignment| &assignment.columns)
    {
        match name(column) {
            Some(column) => columns.push(column),
            None => return catalog::UpdatedColumns::Unknown,
        }
    }
    catalog::UpdatedColumns::Named(columns)
}

/// The columns an `INSERT`'s update on a conflict assigns (`ON CONFLICT
/// … DO UPDATE`, `ON DUPLICATE KEY UPDATE`): none without one.
fn conflict_updated(
    on_conflict: Option<&ir::OnConflict>,
    name: &dyn Fn(&ir::ColumnId) -> Option<IdentKey>,
) -> catalog::UpdatedColumns {
    match on_conflict.map(|conflict| &conflict.action) {
        Some(
            ir::ConflictAction::DoUpdate { assignments, .. }
            | ir::ConflictAction::MySqlDuplicateKeyUpdate { assignments },
        ) => assigned_columns(assignments, name),
        Some(ir::ConflictAction::DoNothing) | None => catalog::UpdatedColumns::NONE,
    }
}

/// The columns the branches of a `MERGE` that update assign; not read
/// where one sets every column.
fn merge_updated(
    branches: &[ir::MergeBranch],
    name: &dyn Fn(&ir::ColumnId) -> Option<IdentKey>,
) -> catalog::UpdatedColumns {
    let mut columns = Vec::new();
    for branch in branches {
        match &branch.action {
            ir::MergeAction::Update { assignments } => match assigned_columns(assignments, name) {
                catalog::UpdatedColumns::Named(named) => columns.extend(named),
                catalog::UpdatedColumns::Unknown => return catalog::UpdatedColumns::Unknown,
            },
            ir::MergeAction::UpdateSetStar { .. } | ir::MergeAction::UpdateAllByName { .. } => {
                return catalog::UpdatedColumns::Unknown
            }
            ir::MergeAction::Insert { .. }
            | ir::MergeAction::InsertStar { .. }
            | ir::MergeAction::InsertAllByName { .. }
            | ir::MergeAction::Delete
            | ir::MergeAction::DoNothing => {}
        }
    }
    catalog::UpdatedColumns::Named(columns)
}

/// What the branches of a `MERGE` write into its target, `name` naming
/// each column it writes: rows not known where a branch inserts, or sets
/// every column by name the catalog does not list; else the columns the
/// branches set.
fn merge_written(
    branches: &[ir::MergeBranch],
    name: &dyn Fn(&ir::ColumnId) -> Option<IdentKey>,
) -> catalog::WrittenRows {
    let mut assigned = Vec::new();
    for branch in branches {
        match &branch.action {
            ir::MergeAction::Insert { .. }
            | ir::MergeAction::InsertStar { .. }
            | ir::MergeAction::InsertAllByName { .. } => return catalog::WrittenRows::Unknown,
            ir::MergeAction::Update { assignments } => assigned.extend(
                assignments
                    .iter()
                    .flat_map(|assignment| &assignment.columns)
                    .filter_map(name),
            ),
            ir::MergeAction::UpdateSetStar { columns }
            | ir::MergeAction::UpdateAllByName { columns } => {
                if columns.is_empty() {
                    return catalog::WrittenRows::Unknown;
                }
                assigned.extend(columns.iter().filter_map(|column| name(&column.written)));
            }
            ir::MergeAction::Delete | ir::MergeAction::DoNothing => {}
        }
    }
    catalog::WrittenRows::Assigned(assigned)
}

/// The table the first branch of `stmt` runs only where it is absent, its
/// parts as written, each normalized: a T-SQL `IF OBJECT_ID('t'[, type]) IS
/// NULL`, or an `IF NOT EXISTS (SELECT … FROM sys.tables | sys.objects |
/// INFORMATION_SCHEMA.TABLES WHERE …)` naming the table by its name, and
/// its schema where one is written, or by `object_id = OBJECT_ID('t')`.
/// `None` for any other statement.
pub fn absence_guard(stmt: &ast::AstStmt, sql: &str) -> Option<facts::reasoning::TableIdentity> {
    let ast::AstStmt::MssqlIf(branch) = stmt else {
        return None;
    };
    absent_table(&branch.condition, sql)
}

/// The table `condition` holds only where it is absent ([`absence_guard`]).
fn absent_table(condition: &ast::AstExpr, sql: &str) -> Option<facts::reasoning::TableIdentity> {
    if let ast::AstExpr::Parenthesized { expr, .. } = condition {
        return absent_table(expr, sql);
    }
    if let ast::AstExpr::IsNull {
        expr,
        not_span: None,
        ..
    } = condition
    {
        return object_id_of(expr, sql);
    }
    if let ast::AstExpr::ExistsSubquery {
        subquery,
        negated: true,
        ..
    } = condition
    {
        return listed_table(subquery, sql);
    }
    None
}

/// The table `expr`, an `OBJECT_ID('t'[, type])`, names.
fn object_id_of(expr: &ast::AstExpr, sql: &str) -> Option<facts::reasoning::TableIdentity> {
    let ast::AstExpr::FunctionCall {
        func_name, args, ..
    } = expr
    else {
        return None;
    };
    let function = ir::utils::slice_span(sql, func_name.span)?;
    if !crate::dialect::normalize_identifier(function).eq_ignore_ascii_case("object_id") {
        return None;
    }
    let ast::AstFunctionArg::Positional(name) = &**args.first()? else {
        return None;
    };
    table_written_in(name, sql)
}

/// The table the string literal `expr` writes the name of, its empty
/// parts not written (`tempdb..#t`).
fn table_written_in(expr: &ast::AstExpr, sql: &str) -> Option<facts::reasoning::TableIdentity> {
    let ast::AstExpr::Literal {
        literal: ast::AstLiteral::String { span },
        ..
    } = expr
    else {
        return None;
    };
    let text = ir::span_extract::string_literal_value(ir::utils::slice_span(sql, *span)?)?;
    let parts = ir::lower::split_dotted_name(&text);
    let (name, qualifiers) = parts.split_last()?;
    let mut qualifiers = qualifiers
        .iter()
        .rev()
        .map(|part| Some(part.as_str()).filter(|part| !part.is_empty()));
    let schema = qualifiers.next().flatten();
    let database = qualifiers.next().flatten();
    Some(facts::reasoning::TableIdentity::from_components(
        database, schema, name,
    ))
}

/// The table `query`, a query of one catalog view of tables (`sys.tables`,
/// `sys.objects`, `INFORMATION_SCHEMA.TABLES`), lists where its filter
/// names it: by the view's name column and schema column equal to string
/// literals, or by `object_id = OBJECT_ID('t')`.
fn listed_table(query: &ast::AstStmt, sql: &str) -> Option<facts::reasoning::TableIdentity> {
    let ast::AstStmt::Select(select) = query else {
        return None;
    };
    let [from] = select.from.as_slice() else {
        return None;
    };
    let view = ir::lower_ddl::target_from_name(&from.as_table_ref()?.name, sql)?;
    let is = |part: Option<&str>, name: &str| {
        part.is_some_and(|part| IdentKey::new(part) == IdentKey::new(name))
    };
    let (name_column, schema_column) = if is(view.schema.as_deref(), "sys")
        && (is(Some(&view.name), "tables") || is(Some(&view.name), "objects"))
    {
        ("name", None)
    } else if is(view.schema.as_deref(), "information_schema") && is(Some(&view.name), "tables") {
        ("table_name", Some("table_schema"))
    } else {
        return None;
    };
    let condition = &select.where_clause.as_ref()?.expr;
    let conjuncts: Vec<&ast::AstExpr> = if let ast::AstExpr::LogicalChain {
        operator: ast::LogicalChainOperator::And,
        operands,
        ..
    } = condition
    {
        operands.iter().map(|operand| &**operand).collect()
    } else if let ast::AstExpr::BinaryOp {
        operator: ast::BinaryOperator::And,
        left,
        right,
        ..
    } = condition
    {
        vec![&**left, &**right]
    } else {
        vec![condition]
    };
    let mut name = None;
    let mut schema = None;
    for conjunct in conjuncts {
        let ast::AstExpr::BinaryOp {
            operator: ast::BinaryOperator::Equal,
            left,
            right,
            ..
        } = conjunct
        else {
            continue;
        };
        let ast::AstExpr::Ident { column_ref, .. } = &**left else {
            continue;
        };
        let column = ir::utils::slice_span(sql, column_ref.name.span)?;
        if is(Some(column), "object_id") {
            if let Some(table) = object_id_of(right, sql) {
                return Some(table);
            }
        } else if is(Some(column), name_column) {
            name = table_written_in(right, sql).map(|table| table.name);
        } else if schema_column.is_some_and(|schema_column| is(Some(column), schema_column)) {
            schema = table_written_in(right, sql).map(|table| table.name);
        }
    }
    Some(facts::reasoning::TableIdentity {
        database: None,
        schema,
        name: name?,
    })
}

/// What a statement does to a relation that its DDL plan does not say
/// ([`change_beside_plan`]).
#[derive(Debug, Clone)]
pub enum ChangeBesidePlan {
    /// It makes the table `target` names: a T-SQL or PostgreSQL
    /// `SELECT … INTO t`, a PostgreSQL foreign table; `temporary` where the
    /// name is a T-SQL temporary table's.
    Makes {
        target: ir::ddl_plan::DdlTarget,
        temporary: bool,
    },
    /// A T-SQL `EXEC sp_rename`.
    Renames(ProcedureRename),
}

/// What T-SQL's `EXEC sp_rename objname, newname [, objtype]` renames, by
/// position or by name: a `COLUMN` renames the column `objname` ends in,
/// no type or `OBJECT` renames the table `objname` names, and any other
/// type renames no table or column.
#[derive(Debug, Clone)]
pub enum ProcedureRename {
    /// The table `from`, renamed `to`.
    Table {
        from: ir::ddl_plan::DdlTarget,
        to: ir::ddl_plan::DdlTarget,
    },
    /// The column `from` of `table`, renamed `to`.
    Column {
        table: ir::ddl_plan::DdlTarget,
        from: String,
        to: String,
    },
    /// A table or a column of one, each table it may be, renamed where an
    /// argument is not a literal.
    Unread(Vec<ir::ddl_plan::DdlTarget>),
}

/// What `stmt` does to a relation that its DDL plan does not say
/// ([`ChangeBesidePlan`]); `None` where it does nothing more.
pub fn change_beside_plan(stmt: &ast::AstStmt, sql: &str) -> Option<ChangeBesidePlan> {
    if let ast::AstStmt::MssqlExec(exec) = stmt {
        return procedure_rename(exec, sql).map(ChangeBesidePlan::Renames);
    }
    let (name, target) = created_beside_ddl_plan(stmt, sql)?;
    Some(ChangeBesidePlan::Makes {
        target,
        temporary: ir::table_plan::names_a_temporary_table(name),
    })
}

/// What `exec` renames, where it is an `EXEC sp_rename` that renames a
/// table or a column ([`ProcedureRename`]).
fn procedure_rename(exec: &ast::AstMssqlExec, sql: &str) -> Option<ProcedureRename> {
    use facts::ddl::{MssqlExecArgFacts, MssqlExecArgValueKind};
    let procedure = exec
        .procedure_base_name_span
        .and_then(|span| ir::utils::slice_span(sql, span))?;
    if !crate::dialect::normalize_identifier(procedure).eq_ignore_ascii_case("sp_rename") {
        return None;
    }
    let args = facts::extract::project_mssql_exec_args(&exec.args, sql);
    let arg = |name: &str, position: u32| {
        args.iter()
            .find(|arg| arg.name.as_deref() == Some(name))
            .or_else(|| {
                args.iter()
                    .find(|arg| arg.name.is_none() && arg.position == position)
            })
    };
    let literal = |arg: &MssqlExecArgFacts| match arg.value_kind {
        MssqlExecArgValueKind::StringLiteral => {
            arg.value_literal.as_ref().map(|value| value.text.clone())
        }
        MssqlExecArgValueKind::Number
        | MssqlExecArgValueKind::Null
        | MssqlExecArgValueKind::Variable
        | MssqlExecArgValueKind::Other => None,
    };
    let object = arg("objname", 0).and_then(literal)?;
    let parts = ir::lower::split_dotted_name(&object);
    let new_name = arg("newname", 1).and_then(literal);
    // No type renames an object; a type not written as a literal is not
    // known. SQL Server compares the type without trailing spaces.
    let kind = match arg("objtype", 2) {
        None => Some(String::new()),
        Some(kind) => literal(kind).map(|kind| kind.trim_end_matches(' ').to_string()),
    };
    let table_of = |parts: &[String]| -> Option<ir::ddl_plan::DdlTarget> {
        let (name, qualifiers) = parts.split_last()?;
        let mut qualifiers = qualifiers.iter().rev();
        let schema = qualifiers.next().cloned();
        let db = qualifiers.next().cloned();
        Some(ir::ddl_plan::DdlTarget {
            name: name.clone(),
            schema,
            db,
            span: exec.span,
        })
    };
    let column_table = parts
        .split_last()
        .and_then(|(column, table)| Some((column.clone(), table_of(table)?)));
    match kind.as_deref() {
        Some("column") => {
            let (column, table) = column_table?;
            Some(match new_name {
                Some(to) => ProcedureRename::Column {
                    table,
                    from: column,
                    to,
                },
                None => ProcedureRename::Unread(vec![table]),
            })
        }
        Some("" | "object") => {
            let table = table_of(&parts)?;
            Some(match new_name {
                Some(to) => ProcedureRename::Table {
                    to: ir::ddl_plan::DdlTarget {
                        name: to,
                        ..table.clone()
                    },
                    from: table,
                },
                None => ProcedureRename::Unread(vec![table]),
            })
        }
        Some(_) => None,
        // Either the table `objname` names or the one its column is of.
        None => {
            let tables: Vec<_> = table_of(&parts)
                .into_iter()
                .chain(column_table.map(|(_, table)| table))
                .collect();
            (!tables.is_empty()).then_some(ProcedureRename::Unread(tables))
        }
    }
}

/// The relation `stmt` creates that its DDL plan does not name as one, by
/// the name written and its target: the table a T-SQL or PostgreSQL
/// `SELECT … INTO t` creates, and a PostgreSQL foreign table.
fn created_beside_ddl_plan<'s>(
    stmt: &'s ast::AstStmt,
    sql: &str,
) -> Option<(&'s ast::AstObjectRef, ir::ddl_plan::DdlTarget)> {
    let name = if let ast::AstStmt::Select(select) = stmt {
        let ast::AstSelectIntoTarget::NewTable(into) = select.into_target.as_deref()? else {
            return None;
        };
        &*into.name
    } else if let ast::AstStmt::CreateForeignTable(foreign) = stmt {
        &foreign.name
    } else {
        return None;
    };
    let target = ir::lower_ddl::target_from_name(name, sql)?;
    Some((name, target))
}

/// The table the name `written` writes, `server.database.schema.name`
/// read from the right; `None` for a name of no part.
fn written_table_name(written: &str) -> Option<crate::context::node_metadata::TableRef> {
    let parts = ir::lower_ddl::split_qualified(written.trim());
    let mut parts = parts.into_iter().rev();
    let name = parts.next().filter(|name| !name.is_empty())?;
    let mut table = crate::context::node_metadata::TableRef::new(name);
    table.schema = parts.next();
    table.db = parts.next();
    table.server = parts.next();
    Some(table)
}

/// The table reference a DDL target names, its parts as written.
fn ddl_target_table(target: &ir::ddl_plan::DdlTarget) -> crate::context::node_metadata::TableRef {
    crate::context::node_metadata::TableRef {
        server: None,
        db: target.db.clone(),
        schema: target.schema.clone(),
        name: target.name.clone(),
        span: None,
    }
}

/// The table or view `stream` is on, as written.
fn streamed_table(
    stream: &ast::AstCreateStream,
    sql: &str,
) -> Option<crate::context::node_metadata::TableRef> {
    let target = ir::lower_ddl::target_from(stream.source_name_span?, sql)?;
    Some(ddl_target_table(&target))
}

/// The table `stmt`, a `CREATE TABLE … CLONE`, copies.
fn cloned_table(stmt: &ast::AstStmt, sql: &str) -> Option<crate::context::node_metadata::TableRef> {
    let ast::AstStmt::CreateTable(table) = stmt else {
        return None;
    };
    let target = ir::lower_ddl::target_from_name(table.clone_source.as_ref()?, sql)?;
    Some(ddl_target_table(&target))
}

/// Where the rows of a table a statement makes come from, beside the query
/// it writes ([`made_rows`]).
enum MadeRows {
    /// Its own: none of another relation's, or a query's it writes.
    Own,
    /// A clone of this table: its rows under the made table's name.
    Clone(crate::context::node_metadata::TableRef),
    /// Another relation's, by a link the statement does not state: a
    /// clone whose source is not read, a copy, a partition of or a child
    /// of another table, an archive or a snapshot restored, a cached query,
    /// a query not parsed, a column computed from others.
    Unstated,
}

/// Where the rows of the table `made`, made by a statement of `sql`, come
/// from.
fn made_rows(made: MadeTable<'_>, sql: &str) -> MadeRows {
    match made {
        MadeTable::Create(table) => {
            // A query written but not parsed gives rows the run cannot read.
            let query_unread = match &table.ctas_query {
                Some(Err(_)) => true,
                Some(Ok(_)) | None => false,
            };
            let linked = query_unread
                || table.partition_of.is_some()
                || !table.inherits.is_empty()
                || table
                    .columns
                    .iter()
                    .any(|column| column.virtual_expr_span.is_some());
            match table.variant {
                ast::AstCreateTableVariant::Clone => {
                    let source = table
                        .clone_source
                        .as_ref()
                        .and_then(|source| ir::lower_ddl::target_from_name(source, sql));
                    match (source, linked) {
                        (Some(source), false) => MadeRows::Clone(ddl_target_table(&source)),
                        (Some(_), true) | (None, _) => MadeRows::Unstated,
                    }
                }
                ast::AstCreateTableVariant::Copy
                | ast::AstCreateTableVariant::FromArchive
                | ast::AstCreateTableVariant::FromSnapshotSet => MadeRows::Unstated,
                ast::AstCreateTableVariant::Plain
                | ast::AstCreateTableVariant::Like
                | ast::AstCreateTableVariant::Ctas
                | ast::AstCreateTableVariant::UsingTemplate => match linked {
                    true => MadeRows::Unstated,
                    false => MadeRows::Own,
                },
            }
        }
        MadeTable::Cache(cache) => match cache.query {
            Some(_) => MadeRows::Unstated,
            None => MadeRows::Own,
        },
        // A snapshot holds its source's rows; the plan does not state the
        // source.
        MadeTable::Snapshot => MadeRows::Unstated,
    }
}

/// What a select item writes of its column's name
/// ([`query_output_columns`]).
enum ItemName {
    /// The name, as written: the item's alias, or the column it reads bare.
    Written(String),
    /// A star: each column it gives is named as the column it reads.
    Star,
    /// No name: an alias written as a string, or any other item.
    Unwritten,
}

/// The span of `item`, a select item, and what it writes of its column's
/// name. `None` for an item a template writes.
fn item_name(
    item: &ast::ProjectionItem,
    sql: &str,
    dialect: &dyn dialect::Dialect,
) -> Option<(lexer::token::Span, ItemName)> {
    let ast::ProjectionItemKind::SelectItem(item) = &item.kind else {
        return None;
    };
    let star = matches!(
        item.expr,
        ast::AstExpr::UnqualifiedStar { .. }
            | ast::AstExpr::QualifiedStar { .. }
            | ast::AstExpr::QualifiedStarFromExpr { .. }
    );
    if star {
        return Some((item.span, ItemName::Star));
    }
    let written = || {
        if item.assign_target.is_some() {
            return None;
        }
        let name = match (&item.alias, &item.expr) {
            (Some(alias), _) => &alias.ident,
            (None, ast::AstExpr::Ident { column_ref, .. }) => &column_ref.name,
            (None, _) => return None,
        };
        if name.templated.is_some() || name.kind != ast::AstIdentifierKind::Name {
            return None;
        }
        let written = ir::utils::slice_span(sql, name.span)?;
        // An alias written as a string (`AS 'x'`) names the column by its
        // value, not as a name is written.
        let as_string = ir::normalize::normalize_string_name(written, dialect)
            != dialect::normalize_identifier_as(written, dialect::NameKind::Column);
        (!as_string).then(|| written.to_string())
    };
    let name = written().map_or(ItemName::Unwritten, ItemName::Written);
    Some((item.span, name))
}

/// A relation's query as the statement holding it lowers, with what
/// lowering learned of the catalog, and the reasoning over the statement
/// where a provider gives it.
struct LoweredBody<'p> {
    body: &'p ir::RelPlan,
    known: &'p ir::IndexedCatalogContext,
    bindings: &'p ir::BindingTable,
    reasoning: Option<&'p dyn facts::reasoning::QueryReasoning>,
}

/// A column a relation's query gives: its name, the tags of the
/// catalogued column an item reads bare, and what reasoning found of its
/// value. A column the select list names no way is named by its item's
/// text, which no name a reader writes matches.
struct QueryColumn {
    name: Option<catalog::CatalogIdent>,
    tags: Vec<catalog::CatalogTag>,
    value: catalog::MadeValue,
}

/// The columns a relation's query gives, by position.
struct QueryColumns {
    columns: Vec<QueryColumn>,
    /// Whether columns the query does not place may follow.
    open: bool,
}

/// The columns a statement gives the relation it creates
/// ([`declared_columns`]).
struct DeclaredColumns {
    columns: Vec<catalog::MadeColumn>,
    /// Whether they are every column a reader can name.
    every: bool,
}

/// The name, as written, a star of `items` gives by `RENAME` to the column
/// it renames to `alias`.
fn renamed_as(
    items: &[ir::ProjectItem],
    alias: &IdentKey,
    sql: &str,
) -> Option<catalog::CatalogIdent> {
    items.iter().find_map(|item| {
        let ir::ProjectItem::Star(star) = item else {
            return None;
        };
        let rename = star.rename.iter().find(|rename| rename.to == *alias)?;
        let written = ir::utils::slice_span(sql, rename.to_span)?;
        Some(catalog::CatalogIdent::from_name(written))
    })
}

/// The column a star of `items` replaces by the item with output `output`,
/// where its `REPLACE` gives that item: the entry lowering left reading
/// the item's output.
fn replaced(items: &[ir::ProjectItem], output: ir::ColumnId) -> Option<&IdentKey> {
    items.iter().find_map(|item| {
        let ir::ProjectItem::Star(star) = item else {
            return None;
        };
        star.replace.iter().find_map(|entry| {
            let ir::ScalarExpr::Column { column, .. } = &entry.expr else {
                return None;
            };
            (*column == output).then_some(&entry.column)
        })
    })
}

/// `tag`, a column tag as a catalog context names it (one qualified name
/// and a value), as a catalog tag: the qualified name split back into its
/// database, schema and name at its last two dots.
fn catalog_tag(tag: &ir::TagRef) -> catalog::CatalogTag {
    let mut parts = tag.qualified_name.rsplitn(3, '.');
    let tag_name = parts.next().unwrap_or_default().to_string();
    let tag_schema = parts.next().map(str::to_string);
    let tag_database = parts.next().map(str::to_string);
    catalog::CatalogTag {
        tag_database,
        tag_schema,
        tag_name,
        tag_value: tag.value.clone(),
    }
}

/// The columns `query` returns, by position, named as the select list
/// names them (of a set operation, its first branch's): an item's alias or
/// the column an item that is a bare column reads, as written; each column
/// a star gives, named as its source names it or as the star's `RENAME`
/// names it; any other item by its text. `lowered` places them and gives
/// each its tags; where it is missing, the names the items write, carrying
/// no tag, and no name for any other item. `None` where a select list does
/// not name them by position, and without `lowered` for a star.
fn query_output_columns<'c>(
    query: &ast::AstStmt,
    sql: &str,
    lowered: Option<LoweredBody<'_>>,
    source: &dyn Fn(&crate::context::node_metadata::TableRef) -> Option<&'c catalog::CatalogTable>,
) -> Option<QueryColumns> {
    let mut first = query;
    while let ast::AstStmt::SetSelect(set) = first {
        first = &set.left;
    }
    let ast::AstStmt::Select(select) = first else {
        return None;
    };
    if select.projection.exclude.is_some() {
        return None;
    }
    let dialect = ir::normalize::dialect_in_force();
    let written: Vec<(lexer::token::Span, ItemName)> = match &select.projection.kind {
        ast::AstProjectionKind::Star(_) => vec![(select.projection.span, ItemName::Star)],
        ast::AstProjectionKind::Columns(items) => items
            .iter()
            .map(|item| item_name(item, sql, dialect.as_ref()))
            .collect::<Option<_>>()?,
    };
    let Some(lowered) = lowered else {
        let columns = written
            .into_iter()
            .map(|(_, name)| match name {
                ItemName::Written(name) => Some(QueryColumn {
                    name: Some(catalog::CatalogIdent::from_name(name)),
                    tags: Vec::new(),
                    value: catalog::MadeValue::default(),
                }),
                ItemName::Unwritten => Some(QueryColumn {
                    name: None,
                    tags: Vec::new(),
                    value: catalog::MadeValue::default(),
                }),
                ItemName::Star => None,
            })
            .collect::<Option<_>>()?;
        return Some(QueryColumns {
            columns,
            open: false,
        });
    };
    let (input, items) = lowered.body.naming_select_at_root()?;
    let (placed, _) = ir::schema::positioned_items(items);
    let outputs = lowered.body.positional_columns();
    // A first branch that places fewer columns than its set operation has
    // names those it places.
    let open = outputs.open || placed.len() < outputs.known.len();
    // The column of a table `source` finds that `item` reads bare.
    let read = |item: &ir::ProjectExpr| -> Option<&'c catalog::CatalogColumn> {
        let ir::ScalarExpr::Column { column, .. } = item.as_written(input) else {
            return None;
        };
        let (table, name) = lowered.known.column_origin(*column)?;
        source(table)?
            .columns
            .iter()
            .find(|held| IdentKey::new_as(&held.name.name, dialect::NameKind::Column) == *name)
    };
    let columns = outputs
        .known
        .iter()
        .zip(&placed)
        .map(|(output, index)| {
            let ir::ProjectItem::Expr(item) = items.get(*index)? else {
                return None;
            };
            // The text lowering names the item's column by: its expression's,
            // or the name a star gives it.
            let text = || {
                lowered
                    .bindings
                    .get(item.output)
                    .map(|binding| catalog::CatalogIdent::from_name(binding.display_name.clone()))
            };
            let name = match written.iter().find(|(span, _)| *span == item.span) {
                Some((_, ItemName::Written(name))) => Some(catalog::CatalogIdent::from_name(name)),
                // A column a star renames is named as its `RENAME` writes it,
                // one it replaces as the column its `REPLACE` entry replaces
                // (spelled as lowering names the item where the two agree),
                // whatever the replacement reads; one of a source not read
                // has no name known.
                Some((_, ItemName::Star)) => match &item.alias {
                    Some(alias) => renamed_as(items, alias, sql).or_else(text),
                    None => match replaced(items, item.output) {
                        Some(column) => text()
                            .filter(|name| {
                                IdentKey::new_as(&name.name, dialect::NameKind::Column) == *column
                            })
                            .or_else(|| Some(catalog::CatalogIdent::from_name(column.as_str()))),
                        None => read(item).map(|held| held.name.clone()),
                    },
                },
                Some((_, ItemName::Unwritten)) | None => text(),
            };
            let tags = read(item).map(|held| held.tags.clone()).unwrap_or_default();
            let value = lowered
                .reasoning
                .map(|reasoning| made_value(reasoning, lowered.body, *output))
                .unwrap_or_default();
            Some(QueryColumn { name, tags, value })
        })
        .collect::<Option<_>>()?;
    Some(QueryColumns { columns, open })
}

/// The columns of a table another is made `LIKE`, and whether they are
/// every column it has.
type LikeColumns = (Vec<catalog::CatalogColumn>, bool);

/// The columns of the primary key the table constraints of `table` declare,
/// each normalized.
fn declared_primary_key(table: &ast::AstCreateTable, sql: &str) -> Vec<IdentKey> {
    declared_keys(table, sql)
        .into_iter()
        .filter(|key| matches!(key.kind, catalog::CatalogConstraintKind::PrimaryKey))
        .flat_map(|key| key.columns)
        .map(|column| IdentKey::new_as(&column.name, ir::normalize::NameKind::Column))
        .collect()
}

/// The keys `table` declares: each column's own `PRIMARY KEY` or `UNIQUE`,
/// and each `PRIMARY KEY (…)` or `UNIQUE (…)` of its table constraints;
/// each column named as written.
fn declared_keys(table: &ast::AstCreateTable, sql: &str) -> Vec<catalog::CatalogConstraint> {
    let mut keys = Vec::new();
    for column in &table.columns {
        let (Some(kind), Some(name)) = (column.key, column.name_span) else {
            continue;
        };
        let Some(name) = ir::utils::slice_span(sql, name) else {
            continue;
        };
        let kind = match kind {
            ast::AstColumnKey::PrimaryKey => catalog::CatalogConstraintKind::PrimaryKey,
            ast::AstColumnKey::Unique => catalog::CatalogConstraintKind::Unique,
        };
        keys.push(catalog_key(kind, None, vec![name.to_string()]));
    }
    keys.extend(
        table
            .constraints
            .iter()
            .filter_map(|constraint| constraint.details.as_ref())
            .filter_map(|details| constraint_key(details, sql)),
    );
    keys
}

/// The keys `alter` adds: each `ADD [CONSTRAINT name] PRIMARY KEY (…)`,
/// `UNIQUE … (…)` or `FOREIGN KEY (…)`, each column named as written.
fn added_keys(alter: &ast::AstAlterTable, sql: &str) -> Vec<catalog::CatalogConstraint> {
    alter
        .actions
        .iter()
        .filter_map(|action| match &action.kind {
            ast::AstAlterTableActionKind::AddConstraint {
                details: Some(details),
                ..
            } => constraint_key(details, sql),
            ast::AstAlterTableActionKind::AddConstraint { details: None, .. }
            | ast::AstAlterTableActionKind::RenameTo { .. }
            | ast::AstAlterTableActionKind::RenameColumn { .. }
            | ast::AstAlterTableActionKind::ChangeColumn { .. }
            | ast::AstAlterTableActionKind::SwapWith { .. }
            | ast::AstAlterTableActionKind::AddColumn { .. }
            | ast::AstAlterTableActionKind::DropColumn { .. }
            | ast::AstAlterTableActionKind::AlterColumn { .. }
            | ast::AstAlterTableActionKind::AlterColumnList { .. }
            | ast::AstAlterTableActionKind::DropConstraint { .. }
            | ast::AstAlterTableActionKind::ClusterBy { .. }
            | ast::AstAlterTableActionKind::DropClusteringKey { .. }
            | ast::AstAlterTableActionKind::SuspendRecluster { .. }
            | ast::AstAlterTableActionKind::ResumeRecluster { .. }
            | ast::AstAlterTableActionKind::Set { .. }
            | ast::AstAlterTableActionKind::Unset { .. }
            | ast::AstAlterTableActionKind::AddRowAccessPolicy(_)
            | ast::AstAlterTableActionKind::DropRowAccessPolicy { .. }
            | ast::AstAlterTableActionKind::DropAllRowAccessPolicies { .. }
            | ast::AstAlterTableActionKind::SetRowFilter { .. }
            | ast::AstAlterTableActionKind::DropRowFilter { .. }
            | ast::AstAlterTableActionKind::SetAggregationPolicy { .. }
            | ast::AstAlterTableActionKind::UnsetAggregationPolicy { .. }
            | ast::AstAlterTableActionKind::SetJoinPolicy { .. }
            | ast::AstAlterTableActionKind::UnsetJoinPolicy { .. }
            | ast::AstAlterTableActionKind::SetColumnMaskingPolicy(_)
            | ast::AstAlterTableActionKind::UnsetColumnMaskingPolicy { .. }
            | ast::AstAlterTableActionKind::SetColumnMask { .. }
            | ast::AstAlterTableActionKind::DropColumnMask { .. }
            | ast::AstAlterTableActionKind::SetColumnProjectionPolicy(_)
            | ast::AstAlterTableActionKind::UnsetColumnProjectionPolicy { .. }
            | ast::AstAlterTableActionKind::SetTag { .. }
            | ast::AstAlterTableActionKind::UnsetTag { .. }
            | ast::AstAlterTableActionKind::SetColumnTag { .. }
            | ast::AstAlterTableActionKind::UnsetColumnTag { .. }
            | ast::AstAlterTableActionKind::AddSearchOptimization { .. }
            | ast::AstAlterTableActionKind::DropSearchOptimization { .. }
            | ast::AstAlterTableActionKind::SetDataMetricSchedule { .. }
            | ast::AstAlterTableActionKind::UnsetDataMetricSchedule { .. }
            | ast::AstAlterTableActionKind::AddDataMetricFunction { .. }
            | ast::AstAlterTableActionKind::DropDataMetricFunction { .. }
            | ast::AstAlterTableActionKind::AddStorageLifecyclePolicy { .. }
            | ast::AstAlterTableActionKind::DropStorageLifecyclePolicy { .. }
            | ast::AstAlterTableActionKind::SetOptions { .. }
            | ast::AstAlterTableActionKind::SetDefaultCollate { .. }
            | ast::AstAlterTableActionKind::DropPrimaryKey { .. }
            | ast::AstAlterTableActionKind::AlterColumnSetOptions { .. }
            | ast::AstAlterTableActionKind::AlterColumnDropNotNull { .. }
            | ast::AstAlterTableActionKind::AlterColumnSetDataType { .. }
            | ast::AstAlterTableActionKind::AlterColumnSetDefault { .. }
            | ast::AstAlterTableActionKind::AlterColumnDropDefault { .. }
            | ast::AstAlterTableActionKind::SetTblProperties { .. }
            | ast::AstAlterTableActionKind::UnsetTblProperties { .. }
            | ast::AstAlterTableActionKind::RowLevelSecurity { .. }
            | ast::AstAlterTableActionKind::OwnerTo { .. }
            | ast::AstAlterTableActionKind::SetSchema { .. }
            | ast::AstAlterTableActionKind::AttachPartition { .. }
            | ast::AstAlterTableActionKind::DetachPartition { .. }
            | ast::AstAlterTableActionKind::SwitchTo { .. }
            | ast::AstAlterTableActionKind::GovernanceSpan { .. }
            | ast::AstAlterTableActionKind::Unknown { .. }
            | ast::AstAlterTableActionKind::NamedAction { .. } => None,
        })
        .collect()
}

/// A key of `kind` named `name` on `columns`, each as written.
fn catalog_key(
    kind: catalog::CatalogConstraintKind,
    name: Option<String>,
    columns: Vec<String>,
) -> catalog::CatalogConstraint {
    catalog::CatalogConstraint {
        kind,
        name,
        columns: columns
            .into_iter()
            .map(catalog::CatalogIdent::from_name)
            .collect(),
        ref_table: None,
        ref_columns: Vec::new(),
        enforced: None,
        rely: None,
    }
}

/// The key a table constraint declares, its columns as written; `None`
/// where a column's name is not read.
fn constraint_key(
    details: &ast::AstConstraintDetails,
    sql: &str,
) -> Option<catalog::CatalogConstraint> {
    let (kind, columns) = match &details.kind {
        ast::AstConstraintKind::PrimaryKey { columns } => {
            (catalog::CatalogConstraintKind::PrimaryKey, columns)
        }
        ast::AstConstraintKind::Unique { columns } => {
            (catalog::CatalogConstraintKind::Unique, columns)
        }
        // Kept by its name, which a drop meets; it references no table
        // the catalog reads.
        ast::AstConstraintKind::ForeignKey { columns, .. } => {
            (catalog::CatalogConstraintKind::ForeignKey, columns)
        }
    };
    let named: Vec<String> = columns
        .iter()
        .map(|span| ir::utils::slice_span(sql, *span).map(str::to_string))
        .collect::<Option<_>>()?;
    let name = details
        .name
        .and_then(|name| ir::utils::slice_span(sql, name))
        .map(str::to_string);
    Some(catalog_key(kind, name, named))
}

/// What `reasoning` finds of the value of `output`, an output column of
/// `relation`, as a column of a relation made from it.
fn made_value(
    reasoning: &dyn facts::reasoning::QueryReasoning,
    relation: &ir::RelPlan,
    output: ir::ColumnId,
) -> catalog::MadeValue {
    use facts::catalog::Nullability;
    let site = facts::reasoning::ReadSite {
        node: relation,
        at: facts::reasoning::ReadAt::Output,
    };
    catalog::MadeValue {
        tags: reasoning
            .output_catalog_tags(output)
            .iter()
            .map(catalog_tag)
            .collect(),
        exposure: match reasoning.output_value_exposure(output) {
            facts::catalog::ValueExposure::Value => None,
            held @ (facts::catalog::ValueExposure::Digest
            | facts::catalog::ValueExposure::Cardinality
            | facts::catalog::ValueExposure::Derived) => Some(held),
        },
        constraints: reasoning.output_constraints(relation, output),
        nullable: match reasoning.nullability(site, output) {
            Nullability::CatalogNullable | Nullability::DerivedNullable { .. } => Some(true),
            Nullability::CatalogNonNullable
            | Nullability::DerivedNonNullable { .. }
            | Nullability::FilteredNonNullable => Some(false),
            Nullability::Unknown => None,
        },
        unique: reasoning.output_unique(relation, output),
    }
}

/// The columns the relation `stmt` creates has, in order, each named as
/// written: its column list, unless another table gives it columns too
/// or, under `meaning`, the list is added beside the query's columns,
/// each column carrying the tags its tag clause gives it and, over a
/// query, the tags of the query's column at its position, and, where
/// `meaning` reads a shorter list as naming the first columns, the
/// query's other columns after them; without a list, the columns its
/// query gives (`query_columns`, [`query_output_columns`]), every one a
/// reader can name where the query places all of them. A tag the statement writes is placed by `session`
/// ([`catalog::tag_in_session`]). A column declared `NOT NULL` or a
/// primary key holds no NULL. A table made `LIKE` another has the columns
/// `like_columns` gives of it, and every one of them where it says so,
/// before those it lists. `None` where the statement names none of them.
fn declared_columns(
    stmt: &ast::AstStmt,
    sql: &str,
    meaning: dialect::SyntaxMeaning,
    session: &ir::SessionContext,
    query_columns: &dyn Fn(&ast::AstStmt) -> Option<QueryColumns>,
    like_columns: &dyn Fn(&ast::AstObjectRef) -> Option<LikeColumns>,
) -> Option<DeclaredColumns> {
    // `column`, a column of a relation's query, as a column of the relation.
    fn made(column: QueryColumn) -> Option<catalog::MadeColumn> {
        Some(catalog::MadeColumn {
            column: catalog::CatalogColumn {
                name: column.name?,
                data_type: None,
                nullable: None,
                tags: column.tags,
            },
            written: Vec::new(),
            value: column.value,
        })
    }
    // The columns `listed` names, as written, where each is written, each
    // carrying its own tags and those of the query's column at its
    // position, where the query places as many as are listed; under
    // `shorter`, a list naming fewer columns names the query's first and
    // the others keep the query's names. A column its own tag clause tags
    // holds the value those tags label.
    fn listed<'n>(
        sql: &str,
        session: &ir::SessionContext,
        shorter: dialect::ShorterColumnList,
        listed: impl ExactSizeIterator<Item = (Option<lexer::token::Span>, &'n [ast::AstTagRef], bool)>,
        query: Option<QueryColumns>,
    ) -> Option<DeclaredColumns> {
        let count = listed.len();
        let names_the_first = match shorter {
            dialect::ShorterColumnList::NamesTheFirst => true,
            dialect::ShorterColumnList::NotStated => false,
        };
        let (by_position, rest, every) = match query {
            Some(query) if !query.open && query.columns.len() == count => {
                (query.columns, Vec::new(), true)
            }
            Some(query) if names_the_first && query.columns.len() >= count => {
                let mut by_position = query.columns;
                let rest = by_position.split_off(count);
                let every = !query.open && rest.iter().all(|column| column.name.is_some());
                (by_position, rest, every)
            }
            // Columns the query names may follow the listed ones: the
            // positions it places give their tags.
            Some(query) if names_the_first && query.open => (query.columns, Vec::new(), false),
            Some(_) | None => (Vec::new(), Vec::new(), true),
        };
        let mut by_position = by_position.into_iter();
        let mut columns: Vec<catalog::MadeColumn> = listed
            .map(|(name, tags, not_null)| {
                let column = by_position.next();
                let name = ir::utils::slice_span(sql, name?)?;
                let mut tags: Vec<catalog::CatalogTag> = ir::lower_ddl::written_tags(tags, sql)
                    .iter()
                    .map(|tag| catalog::tag_in_session(tag, session))
                    .collect();
                let written = tags.clone();
                let mut value = catalog::MadeValue::default();
                if let Some(column) = column {
                    tags.extend(column.tags);
                    value = column.value;
                    if !written.is_empty() {
                        value.exposure = None;
                    }
                }
                let mut column = catalog::made_column(name, tags);
                if not_null {
                    column.nullable = Some(false);
                }
                Some(catalog::MadeColumn {
                    column,
                    written,
                    value,
                })
            })
            .collect::<Option<_>>()?;
        columns.extend(rest.into_iter().filter_map(made));
        Some(DeclaredColumns { columns, every })
    }
    // The columns `listed` names beside those of `query`
    // ([`dialect::TypedCreateAs::AddsColumns`]): each listed name the
    // query has no column of is a column of its own, before the query's
    // columns, carrying its own tags; one the query has a column of is
    // that column, carrying its own tags too.
    fn beside<'n>(
        sql: &str,
        session: &ir::SessionContext,
        listed: impl Iterator<Item = (Option<lexer::token::Span>, &'n [ast::AstTagRef], bool)>,
        query: Option<QueryColumns>,
    ) -> Option<DeclaredColumns> {
        let key = |name: &str| IdentKey::new_as(name, ir::normalize::NameKind::Column);
        let mut query = query.map(named);
        let mut own = Vec::new();
        for (name, tags, not_null) in listed {
            let name = ir::utils::slice_span(sql, name?)?;
            let written: Vec<catalog::CatalogTag> = ir::lower_ddl::written_tags(tags, sql)
                .iter()
                .map(|tag| catalog::tag_in_session(tag, session))
                .collect();
            let of_query = query.as_mut().and_then(|query| {
                query
                    .columns
                    .iter_mut()
                    .find(|column| key(&column.column.name.name) == key(name))
            });
            match of_query {
                Some(column) => {
                    if !written.is_empty() {
                        column.value.exposure = None;
                    }
                    if not_null {
                        column.column.nullable = Some(false);
                    }
                    column.column.tags.extend(written.iter().cloned());
                    column.written.extend(written);
                }
                None => {
                    let mut column = catalog::made_column(name, written.clone());
                    if not_null {
                        column.nullable = Some(false);
                    }
                    own.push(catalog::MadeColumn {
                        column,
                        written,
                        value: catalog::MadeValue::default(),
                    });
                }
            }
        }
        let (columns, every) = match query {
            Some(query) => {
                own.extend(query.columns);
                (own, query.every)
            }
            None => (own, false),
        };
        Some(DeclaredColumns { columns, every })
    }
    // The columns of `query`: every column a reader can name, where the
    // query places and names all of them.
    fn named(query: QueryColumns) -> DeclaredColumns {
        let every = !query.open && query.columns.iter().all(|column| column.name.is_some());
        let columns = query.columns.into_iter().filter_map(made).collect();
        DeclaredColumns { columns, every }
    }
    if let ast::AstStmt::CreateTable(table) = stmt {
        let query = || match &table.ctas_query {
            Some(Ok(query)) => query_columns(query),
            Some(Err(_)) | None => None,
        };
        let given_elsewhere = table.clone_source.is_some()
            || table.copy_source.is_some()
            || table.partition_of.is_some()
            || !table.inherits.is_empty();
        if given_elsewhere {
            return None;
        }
        let primary = declared_primary_key(table, sql);
        let columns = table.columns.iter().map(|column| {
            let not_null = column.not_null
                || matches!(column.key, Some(ast::AstColumnKey::PrimaryKey))
                || column.name_span.is_some_and(|name| {
                    ir::utils::slice_span(sql, name).is_some_and(|name| {
                        primary.contains(&IdentKey::new_as(name, ir::normalize::NameKind::Column))
                    })
                });
            (column.name_span, column.tags.as_slice(), not_null)
        });
        // The columns of each table it is made like, then those it lists.
        let like: Vec<&ast::AstObjectRef> = table
            .like_source
            .iter()
            .chain(table.like_elements.iter().map(|item| &item.table))
            .collect();
        if !like.is_empty() {
            let mut made = Vec::new();
            let mut every = true;
            for source in like {
                let (columns, all) = like_columns(source)?;
                every &= all;
                made.extend(columns.into_iter().map(|column| catalog::MadeColumn {
                    column,
                    written: Vec::new(),
                    value: catalog::MadeValue::default(),
                }));
            }
            if table.columns_span.is_some() {
                let own = listed(
                    sql,
                    session,
                    dialect::ShorterColumnList::NotStated,
                    columns,
                    None,
                )?;
                made.extend(own.columns);
            }
            return Some(DeclaredColumns {
                columns: made,
                every,
            });
        }
        if table.columns_span.is_none() {
            return query().map(named);
        }
        if table.ctas_query.is_some()
            && meaning.typed_create_as == dialect::TypedCreateAs::AddsColumns
        {
            return beside(sql, session, columns, query());
        }
        return listed(sql, session, meaning.shorter_column_list, columns, query());
    }
    if let ast::AstStmt::CreateView(view) = stmt {
        let query = || match &view.query {
            Ok(query) => query_columns(query),
            Err(_) => None,
        };
        if view.columns_span.is_none() && view.column_list_id.is_none() {
            return query().map(named);
        }
        let columns = view
            .columns
            .iter()
            .map(|column| (Some(column.name_span), column.tags.as_slice(), false));
        return listed(sql, session, meaning.shorter_column_list, columns, query());
    }
    None
}

/// An assignment the script makes ([`script_context_fold`]): the variable,
/// the statement making it, and the text it then holds where that is one
/// string literal written whole.
struct VariableAssignment {
    variable: FlowVariable,
    span: lexer::token::Span,
    text: Option<String>,
}

/// A statement holding a body that may not run, or may run again, where the
/// statement is written: a branch, a loop, a handler, or (`routine`) the
/// body of a routine, which runs when it is called.
struct UnsettledBody {
    owner: lexer::token::Span,
    routine: bool,
}

/// Whether a body in this role may not run, or may run again, where it is
/// written: `Some(true)` for a routine's body, `Some(false)` for a branch,
/// a loop or a handler, `None` for a body that runs once in place.
fn unsettled_body(role: ast::BodyRole) -> Option<bool> {
    match role {
        ast::BodyRole::Routine => Some(true),
        ast::BodyRole::Branch
        | ast::BodyRole::Else
        | ast::BodyRole::Loop
        | ast::BodyRole::LoopQuery
        | ast::BodyRole::Catch
        | ast::BodyRole::ExceptionHandler
        | ast::BodyRole::HandlerAction => Some(false),
        ast::BodyRole::Declarations | ast::BodyRole::Block | ast::BodyRole::InsertExec => None,
    }
}

/// The text of `pieces` where they are one string literal written whole.
fn whole_literal_text(pieces: &[ir::dynamic_sql::TextPiece], sql: &str) -> Option<String> {
    let [ir::dynamic_sql::TextPiece::Literal(literal)] = pieces else {
        return None;
    };
    ir::span_extract::string_literal_value(ir::utils::slice_span(sql, *literal)?)
}

/// What each variable holds, from where, in order: the text an assignment
/// writes from the end of its statement, unknown (`None`) where it writes
/// any other value. An assignment in a body that may not run, or may run
/// again, leaves its variable unknown from the start of the outermost
/// statement holding that body, within the variable's own routine for a
/// routine's variable.
fn variable_timelines(
    assignments: Vec<VariableAssignment>,
    unsettled: &[UnsettledBody],
    routines: &[CreatedRoutine],
) -> std::collections::BTreeMap<FlowVariable, Vec<(u32, Option<String>)>> {
    let mut out: std::collections::BTreeMap<FlowVariable, Vec<(u32, Option<String>)>> =
        std::collections::BTreeMap::new();
    for assignment in assignments {
        let span = assignment.span;
        let own_routine = match assignment.variable.0 {
            VariableScope::Routine(id) => routines.get(id).map(|routine| routine.span),
            VariableScope::Session | VariableScope::Batch(_) => None,
        };
        let outermost = unsettled
            .iter()
            .filter(|body| {
                let holds = body.owner.start <= span.start
                    && span.end <= body.owner.end
                    && (body.owner.start, body.owner.end) != (span.start, span.end);
                let counted = match own_routine {
                    Some(routine) => {
                        !body.routine
                            && routine.start <= body.owner.start
                            && body.owner.end <= routine.end
                    }
                    None => true,
                };
                holds && counted
            })
            .map(|body| body.owner.start)
            .min();
        let entry = match outermost {
            Some(from) => (from, None),
            None => (span.end, assignment.text),
        };
        out.entry(assignment.variable).or_default().push(entry);
    }
    for timeline in out.values_mut() {
        timeline.sort_by_key(|(from, _)| *from);
    }
    out
}

/// The function the top-level statement `stmt` defines: where the statement
/// starts, the name as written and what one call returns. A function with
/// no `RETURNS` returns one value: its body's (BigQuery, Databricks) or its
/// `OUT` parameters' (PostgreSQL).
fn declared_function(
    stmt: &ast::AstStmt,
    sql: &str,
) -> Option<(u32, String, ast::AstFunctionReturns)> {
    let (name_span, returns) = if let ast::AstStmt::CreateFunction(s) = stmt {
        (
            s.name_span,
            s.returns
                .map_or(ast::AstFunctionReturns::Scalar, |clause| clause.kind),
        )
    } else if let ast::AstStmt::CreateTableFunction(s) = stmt {
        (s.name_span, ast::AstFunctionReturns::Table)
    } else {
        return None;
    };
    let name = sql.get(name_span.start as usize..name_span.end as usize)?;
    Some((stmt.span().start, name.trim().to_string(), returns))
}

/// The scopes `stmt` declares names in for the statements it holds: its
/// parameters, for a routine's body; a `FOR` loop's variable, for its
/// body; and what each `DECLARE` and `LET` of a body it holds declares,
/// for the statements after it to the end of `stmt`.
fn declared_in(stmt: &ast::AstStmt, sql: &str) -> Vec<DeclaredScope> {
    let span = stmt.span();
    let mut own: Vec<IdentKey> = routine_parameters(stmt)
        .iter()
        .filter_map(|param| declared_name(param.name_span?, sql))
        .collect();
    if let ast::AstStmt::For(f) = stmt {
        own.extend(declared_name(f.loop_var_span, sql));
    }
    let own = (!own.is_empty()).then_some(DeclaredScope {
        from: span.start,
        to: span.end,
        names: own,
    });
    let bodies = stmt.bodies();
    let in_bodies = bodies
        .iter()
        .flat_map(|body| body.stmts)
        .filter_map(|held| {
            let names = declared_variables(held, sql);
            (!names.is_empty()).then(|| DeclaredScope {
                from: held.span().start,
                to: span.end,
                names,
            })
        });
    own.into_iter().chain(in_bodies).collect()
}

/// The parameters a routine `stmt` declares for its body: a procedure's, a
/// function's, a table function's.
fn routine_parameters(stmt: &ast::AstStmt) -> &[ast::AstProcedureParam] {
    if let ast::AstStmt::CreateProcedure(p) = stmt {
        &p.params
    } else if let ast::AstStmt::CreateFunction(f) = stmt {
        &f.params
    } else if let ast::AstStmt::CreateTableFunction(f) = stmt {
        &f.params
    } else {
        &[]
    }
}

/// The names `stmt` declares as variables: each a `DECLARE` declares, a
/// `LET`'s.
fn declared_variables(stmt: &ast::AstStmt, sql: &str) -> Vec<IdentKey> {
    if let ast::AstStmt::Declare { variables, .. } = stmt {
        variables
            .iter()
            .filter_map(|variable| declared_name(variable.name.span, sql))
            .collect()
    } else if let ast::AstStmt::Let { name, .. } = stmt {
        declared_name(name.span, sql).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// The name written at `span`, keyed as a column's name is, as lowering
/// looks a bare name up.
fn declared_name(span: lexer::token::Span, sql: &str) -> Option<IdentKey> {
    sql.get(span.start as usize..span.end as usize)
        .map(|name| IdentKey::new_as(name, ir::normalize::NameKind::Column))
}

/// Names a script declares, for the statements that start in `from..to`.
#[derive(Debug, Clone)]
struct DeclaredScope {
    from: u32,
    to: u32,
    names: Vec<IdentKey>,
}

/// The literals of `assigned` whose variable is one `executed` names in the
/// same scope, compared as normalized identifiers: as assigned where the
/// variable is executed whole, and as a run of its own where it is an
/// operand of the concatenation executed, a whole literal written quoted
/// where the operand writes its value as a quoted literal.
fn executed_variable_literals(
    assigned: &[(
        VariableScope,
        lexer::token::Span,
        ir::dynamic_sql::ExecutedLiteral,
    )],
    executed: &[(VariableScope, ir::dynamic_sql::ExecutedVariable)],
    sql: &str,
) -> Vec<ir::dynamic_sql::ExecutedLiteral> {
    if assigned.is_empty() || executed.is_empty() {
        return Vec::new();
    }
    let name = |scope: &VariableScope, span: &lexer::token::Span| {
        variable_key(span, sql).map(|key| (*scope, key))
    };
    // Per variable: (executed whole, as an operand, as a quoted operand).
    let mut ways: std::collections::BTreeMap<FlowVariable, (bool, bool, bool)> =
        std::collections::BTreeMap::new();
    for (scope, variable) in executed {
        if let Some(key) = name(scope, &variable.name) {
            let way = ways.entry(key).or_default();
            if variable.whole {
                way.0 = true;
            } else if variable.quoted {
                way.2 = true;
            } else {
                way.1 = true;
            }
        }
    }
    let mut out = Vec::new();
    for (scope, variable, literal) in assigned {
        let Some(&(whole, operand, quoted_operand)) =
            name(scope, variable).and_then(|key| ways.get(&key))
        else {
            continue;
        };
        if whole {
            out.push(literal.clone());
        }
        for (quoted, written) in [(false, operand), (true, quoted_operand)] {
            if !written {
                continue;
            }
            out.push(match literal {
                ir::dynamic_sql::ExecutedLiteral::Whole(span) => {
                    ir::dynamic_sql::ExecutedLiteral::Run(vec![ir::dynamic_sql::RunPart {
                        literal: *span,
                        within: None,
                        quoted,
                    }])
                }
                ir::dynamic_sql::ExecutedLiteral::Run(parts) => {
                    ir::dynamic_sql::ExecutedLiteral::Run(parts.clone())
                }
            });
        }
    }
    out
}

/// The variables written as operands of a value assigned to a variable
/// `executed` names, or to one so found, at any depth: each operand as an
/// [`ir::dynamic_sql::ExecutedVariable`] of the concatenation executed, its
/// quoting kept (`q := format('… %L', p)` then `EXECUTE q`), in the scope
/// the statement assigning it gives the operand. Each variable's
/// assignments are read once; compared as normalized identifiers within a
/// scope.
fn variables_written_into_executed(
    executed: &[(VariableScope, ir::dynamic_sql::ExecutedVariable)],
    events: &[(u32, VariableScope, TextEvent)],
    names: VariableNames<'_>,
) -> Vec<(VariableScope, ir::dynamic_sql::ExecutedVariable)> {
    use ir::dynamic_sql::ExecutedVariable;
    // Per variable assigned: the variable operands of its values.
    let mut operands: std::collections::BTreeMap<
        FlowVariable,
        Vec<(VariableScope, ExecutedVariable)>,
    > = std::collections::BTreeMap::new();
    for (_, scope, event) in events {
        let TextEvent::Assigned(text) = event else {
            continue;
        };
        let Some(target) = names.variable(*scope, &text.name, text.session) else {
            continue;
        };
        let written = operands.entry(target).or_default();
        written.extend(
            ir::dynamic_sql::executed_variables(&text.pieces)
                .into_iter()
                .map(|variable| names.executed(*scope, variable)),
        );
    }
    let mut out = Vec::new();
    let mut seen: std::collections::BTreeSet<FlowVariable> = std::collections::BTreeSet::new();
    let mut pending: Vec<FlowVariable> = executed
        .iter()
        .filter_map(|(scope, variable)| Some((*scope, variable_key(&variable.name, names.sql)?)))
        .collect();
    while let Some(variable) = pending.pop() {
        if !seen.insert(variable.clone()) {
            continue;
        }
        for &(scope, operand) in operands.get(&variable).into_iter().flatten() {
            out.push((
                scope,
                ExecutedVariable {
                    whole: false,
                    ..operand
                },
            ));
            pending.extend(variable_key(&operand.name, names.sql).map(|key| (scope, key)));
        }
    }
    out
}

/// A statement's text a script assigns to a variable or runs as SQL
/// ([`literals_run_through_variables`]).
enum TextEvent {
    /// A variable is assigned a text.
    Assigned(ir::dynamic_sql::AssignedText),
    /// The text of these pieces is run as SQL.
    Executed(Vec<ir::dynamic_sql::TextPiece>),
}

/// What the statements of a script run through its variables
/// ([`literals_run_through_variables`]).
struct RunThroughVariables {
    /// The literals run as written through a variable run whole.
    as_written: Vec<lexer::token::Span>,
    /// The runs of the texts statements run with a variable's literals
    /// spliced in ([`push_spliced_runs`]).
    spliced: Vec<ir::dynamic_sql::ExecutedLiteral>,
}

/// The literals the statements of `events` run as written through a
/// variable run whole whose text, as of that statement, is one literal
/// written whole: held there, or through variables that each hold only
/// another's ([`held_literal`]); and the runs of every other text they
/// run, theirs or a variable's run whole (each text read once), with each
/// variable written in it whose text is literals spliced in at its place
/// ([`push_spliced_runs`]). Each variable's text is its
/// last assignment before the statement, a variable written in that value
/// spliced in by reference to its text then. Variables are compared as
/// normalized identifiers within their scope, in source order.
fn literals_run_through_variables(
    mut events: Vec<(u32, VariableScope, TextEvent)>,
    names: VariableNames<'_>,
) -> RunThroughVariables {
    use ir::dynamic_sql::{RunPart, TextPiece};
    let mut out = RunThroughVariables {
        as_written: Vec::new(),
        spliced: Vec::new(),
    };
    events.sort_by_key(|(at, _, _)| *at);
    // Every text assigned, in the order written; each variable's text as of
    // the statement read last. A text holds only texts written before it.
    let mut held: Vec<HeldText> = Vec::new();
    let mut texts: std::collections::BTreeMap<FlowVariable, HeldId> =
        std::collections::BTreeMap::new();
    // Texts run whole whose runs were read, and the long literals spliced.
    let mut read: std::collections::BTreeSet<HeldId> = std::collections::BTreeSet::new();
    let mut long_spliced: std::collections::BTreeSet<(u32, u32)> =
        std::collections::BTreeSet::new();
    for (_, scope, event) in events {
        match event {
            TextEvent::Assigned(assigned) => {
                let Some(variable) = names.variable(scope, &assigned.name, assigned.session) else {
                    continue;
                };
                let text = splice_variables(assigned.pieces, scope, &texts, &held, names);
                texts.insert(variable, HeldId(held.len()));
                held.push(text);
            }
            TextEvent::Executed(pieces) => {
                let [TextPiece::Variable {
                    name,
                    quoting: ir::dynamic_sql::HoleQuoting::Raw,
                    session,
                    ..
                }] = pieces.as_slice()
                else {
                    let text = splice_variables(pieces, scope, &texts, &held, names);
                    push_spliced_runs(&text.pieces, &held, &mut long_spliced, &mut out.spliced);
                    continue;
                };
                let Some(run_whole) = names
                    .variable(scope, name, *session)
                    .and_then(|variable| texts.get(&variable).copied())
                    .and_then(|id| held_text_followed(&held, id))
                else {
                    continue;
                };
                if let Some(RunPart { literal, .. }) = held_literal(&held, run_whole) {
                    out.as_written.push(literal);
                } else if read.insert(run_whole) {
                    if let Some(text) = held.get(run_whole.0) {
                        push_spliced_runs(&text.pieces, &held, &mut long_spliced, &mut out.spliced);
                    }
                }
            }
        }
    }
    out
}

/// A variable's literal at most this many bytes long, or text of several
/// pieces whose literals are, is spliced into every run that writes it
/// ([`push_spliced_runs`]); a longer literal into the first only, a longer
/// text into none, so the runs read stay linear in the source.
const SPLICED_LITERAL_BYTES: u32 = 1024;

/// Pieces a variable's text of several pieces spliced in place may hold at
/// most ([`held_parts`]), each text it holds counted.
const SPLICED_TEXT_PIECES: usize = 64;

/// The runs of `pieces` that hold a variable's literal spliced in at its
/// place ([`held_literal`], written quoted where the variable is), or the
/// literals of its text of several pieces ([`held_parts`]), each joining
/// them to the literals written beside them, so the string literals of the
/// text they make are read whole ([`push_run_comment_spans`]). A literal
/// longer than [`SPLICED_LITERAL_BYTES`] already in `long_spliced` is a
/// break.
fn push_spliced_runs(
    pieces: &[HeldPiece],
    held: &[HeldText],
    long_spliced: &mut std::collections::BTreeSet<(u32, u32)>,
    out: &mut Vec<ir::dynamic_sql::ExecutedLiteral>,
) {
    use ir::dynamic_sql::{ExecutedLiteral, RunPart};
    let mut run: Vec<RunPart> = Vec::new();
    let mut spliced = false;
    let mut end_run = |run: &mut Vec<RunPart>, spliced: &mut bool| {
        if *spliced && run.len() > 1 {
            out.push(ExecutedLiteral::Run(std::mem::take(run)));
        }
        run.clear();
        *spliced = false;
    };
    for piece in pieces {
        match *piece {
            HeldPiece::Literal(part) => run.push(part),
            HeldPiece::Break => end_run(&mut run, &mut spliced),
            HeldPiece::Held { id, quoted } => {
                let parts = match held_literal(held, id) {
                    Some(part) => (part.literal.end.saturating_sub(part.literal.start)
                        <= SPLICED_LITERAL_BYTES
                        || long_spliced.insert((part.literal.start, part.literal.end)))
                    .then(|| vec![RunPart { quoted, ..part }]),
                    None if !quoted => held_parts(held, id),
                    None => None,
                };
                match parts {
                    Some(parts) => {
                        run.extend(parts);
                        spliced = true;
                    }
                    None => end_run(&mut run, &mut spliced),
                }
            }
        }
    }
    end_run(&mut run, &mut spliced);
}

/// The literals the text `id` holds, in order, where each of its pieces is
/// a literal or a text that is so made, at any depth: at most
/// [`SPLICED_TEXT_PIECES`] pieces and [`SPLICED_LITERAL_BYTES`] bytes of
/// source; `None` past either bound or at a break.
fn held_parts(held: &[HeldText], id: HeldId) -> Option<Vec<ir::dynamic_sql::RunPart>> {
    let mut parts = Vec::new();
    let mut pieces = 0usize;
    let mut bytes = 0u32;
    let mut stack = vec![held.get(id.0)?.pieces.iter()];
    loop {
        let next = match stack.last_mut() {
            Some(top) => top.next(),
            None => return Some(parts),
        };
        let Some(piece) = next else {
            stack.pop();
            continue;
        };
        pieces += 1;
        if pieces > SPLICED_TEXT_PIECES {
            return None;
        }
        let part = match *piece {
            HeldPiece::Literal(part) => part,
            HeldPiece::Break => return None,
            HeldPiece::Held { id, quoted: true } => ir::dynamic_sql::RunPart {
                quoted: true,
                ..held_literal(held, id)?
            },
            // A text holds only texts written before it.
            HeldPiece::Held { id, quoted: false } => {
                stack.push(held.get(id.0)?.pieces.iter());
                continue;
            }
        };
        let source = part.within.unwrap_or(part.literal);
        bytes = bytes.saturating_add(source.end.saturating_sub(source.start));
        if bytes > SPLICED_LITERAL_BYTES {
            return None;
        }
        parts.push(part);
    }
}

/// A text of [`literals_run_through_variables`], by its place among the
/// texts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HeldId(usize);

/// A variable's text, built of pieces ([`literals_run_through_variables`]).
struct HeldText {
    pieces: Vec<HeldPiece>,
}

/// A piece of a [`HeldText`].
#[derive(Debug, Clone, Copy)]
enum HeldPiece {
    /// A literal operand's text.
    Literal(ir::dynamic_sql::RunPart),
    /// Text not known here: the pieces on its two sides do not join.
    Break,
    /// A variable's text, spliced in by reference; `quoted` where the
    /// variable is written as a quoted literal, its text then one literal
    /// written whole.
    Held { id: HeldId, quoted: bool },
}

/// Texts that each hold only another's that [`held_text_followed`] follows
/// at most.
const HELD_LITERAL_LINKS: usize = 16;

/// The variable named at `span`, by its key
/// ([`ir::dynamic_sql::variable_key`]).
fn variable_key(span: &lexer::token::Span, sql: &str) -> Option<IdentKey> {
    sql.get(span.start as usize..span.end as usize)
        .map(ir::dynamic_sql::variable_key)
}

/// `pieces`, written in `scope`, with each variable written in them spliced
/// in by reference to the text it holds in `texts` (of `held`), marked
/// quoted where it is written quoted. A variable with no text, or written
/// quoted where its text is not one literal written whole, is a break.
fn splice_variables(
    pieces: Vec<ir::dynamic_sql::TextPiece>,
    scope: VariableScope,
    texts: &std::collections::BTreeMap<FlowVariable, HeldId>,
    held: &[HeldText],
    names: VariableNames<'_>,
) -> HeldText {
    use ir::dynamic_sql::TextPiece;
    let mut out = HeldText {
        pieces: Vec::with_capacity(pieces.len()),
    };
    for piece in ir::dynamic_sql::flattened(&pieces) {
        let (name, session, quoted) = match piece {
            TextPiece::Variable {
                name,
                quoting,
                session,
                ..
            } => (
                name,
                *session,
                *quoting == ir::dynamic_sql::HoleQuoting::LitQuoter,
            ),
            TextPiece::Literal(_)
            | TextPiece::QuotedLiteral(_)
            | TextPiece::TemplateText { .. }
            | TextPiece::Verbatim(_)
            | TextPiece::Value { .. }
            | TextPiece::Rewritten { .. }
            | TextPiece::Choice { .. }
            | TextPiece::Break => {
                out.pieces.push(match ir::dynamic_sql::run_part(piece) {
                    Some(part) => HeldPiece::Literal(part),
                    None => HeldPiece::Break,
                });
                continue;
            }
        };
        let found = names
            .variable(scope, name, session)
            .and_then(|variable| texts.get(&variable).copied())
            .filter(|id| !quoted || held_literal(held, *id).is_some());
        out.pieces.push(match found {
            Some(id) => HeldPiece::Held { id, quoted },
            None => HeldPiece::Break,
        });
    }
    out
}

/// The literal the text `id` holds, where its text is one literal written
/// whole: held there, or through texts that each hold only another's
/// ([`held_text_followed`]).
fn held_literal(held: &[HeldText], id: HeldId) -> Option<ir::dynamic_sql::RunPart> {
    match held.get(held_text_followed(held, id)?.0)?.pieces.as_slice() {
        [HeldPiece::Literal(part)] if part.within.is_none() && !part.quoted => Some(*part),
        [..] => None,
    }
}

/// The text `id` holds, through texts that each hold only another's,
/// unquoted (at most [`HELD_LITERAL_LINKS`] of them).
fn held_text_followed(held: &[HeldText], mut id: HeldId) -> Option<HeldId> {
    for _ in 0..HELD_LITERAL_LINKS {
        match held.get(id.0)?.pieces.as_slice() {
            [HeldPiece::Held {
                id: inner,
                quoted: false,
            }] => id = *inner,
            [..] => return Some(id),
        }
    }
    None
}

/// Where the variables a statement names live: the body of the routine
/// (a procedure, function, trigger, event, task or `DO` block) that holds
/// the statement, innermost, by its place among the routines; else the
/// batch of the script it is in (T-SQL's `GO` ends one). A variable's text
/// reaches only the statements of its scope, but a session variable's
/// reaches every statement of the script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum VariableScope {
    Session,
    Batch(usize),
    Routine(usize),
}

/// A variable as the script's statements read it: its scope and its key.
type FlowVariable = (VariableScope, IdentKey);

/// The text of a call's argument a routine runs ([`TextFlows::arguments_run`]):
/// where the call's statement starts, the scope of its variables, the
/// pieces of the text run.
type ArgumentText = (u32, VariableScope, Vec<ir::dynamic_sql::TextPiece>);

/// The variables a script's statements name, read in its source as its
/// dialect scopes them.
#[derive(Clone, Copy)]
struct VariableNames<'s> {
    sql: &'s str,
    session_variables: ir::dynamic_sql::SessionVariables,
}

impl VariableNames<'_> {
    /// The scope of the variable written at `name` in a statement whose
    /// variables live in `statement`, `marked` where the syntax tree says
    /// it is a session variable.
    fn scope(
        self,
        statement: VariableScope,
        name: &lexer::token::Span,
        marked: bool,
    ) -> VariableScope {
        let written = self
            .sql
            .get(name.start as usize..name.end as usize)
            .unwrap_or_default();
        if self.session_variables.names_session(written, marked) {
            VariableScope::Session
        } else {
            statement
        }
    }

    /// A variable a statement runs, with its scope in a statement whose
    /// variables live in `statement`.
    fn executed(
        self,
        statement: VariableScope,
        variable: ir::dynamic_sql::ExecutedVariable,
    ) -> (VariableScope, ir::dynamic_sql::ExecutedVariable) {
        (
            self.scope(statement, &variable.name, variable.session),
            variable,
        )
    }

    /// The variable written at `name`, as above.
    fn variable(
        self,
        statement: VariableScope,
        name: &lexer::token::Span,
        marked: bool,
    ) -> Option<FlowVariable> {
        Some((
            self.scope(statement, name, marked),
            variable_key(name, self.sql)?,
        ))
    }
}

/// Whether a body in this role is the body of a routine: its variables are
/// its own ([`VariableScope`]).
fn is_routine_body(role: ast::BodyRole) -> bool {
    match role {
        ast::BodyRole::Routine => true,
        ast::BodyRole::Declarations
        | ast::BodyRole::Block
        | ast::BodyRole::Branch
        | ast::BodyRole::Else
        | ast::BodyRole::Loop
        | ast::BodyRole::LoopQuery
        | ast::BodyRole::Catch
        | ast::BodyRole::ExceptionHandler
        | ast::BodyRole::HandlerAction
        | ast::BodyRole::InsertExec => false,
    }
}

/// The ways a text is written into the SQL text a statement runs: as that
/// whole text, as an operand of the concatenation that builds it, and as a
/// quoted literal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RunWays {
    whole: bool,
    operand: bool,
    quoted: bool,
}

impl RunWays {
    /// How the text `variable` holds is run where it is written so.
    fn of(variable: &ir::dynamic_sql::ExecutedVariable) -> Self {
        Self {
            whole: variable.whole,
            operand: !variable.whole && !variable.quoted,
            quoted: !variable.whole && variable.quoted,
        }
    }

    fn is_empty(self) -> bool {
        !(self.whole || self.operand || self.quoted)
    }

    fn union(self, other: Self) -> Self {
        Self {
            whole: self.whole || other.whole,
            operand: self.operand || other.operand,
            quoted: self.quoted || other.quoted,
        }
    }

    /// These ways with a whole run read as an operand's: the text is
    /// masked where it is written, and is not read as the statements run.
    fn written_into(self) -> Self {
        Self {
            whole: false,
            operand: self.operand || self.whole,
            quoted: self.quoted,
        }
    }

    /// How the text of `variable`, written in a value run these ways, is
    /// run: as the value is, where it is the whole value; else as
    /// [`Self::of`] says.
    fn carried_to(self, variable: &ir::dynamic_sql::ExecutedVariable) -> Self {
        match (self.is_empty(), variable.whole) {
            (true, _) => Self::default(),
            (false, true) => self,
            (false, false) => Self::of(variable),
        }
    }
}

/// A routine the script creates ([`TextFlows`]): its name's parts, each
/// parameter's key in order (`None` for one with no name), and the span of
/// the statement creating it, which its body's statements fall in. A
/// trigger, an event, a task or a `DO` block is a routine no call names:
/// no name and no parameters.
struct CreatedRoutine {
    name: Vec<IdentKey>,
    params: Vec<Option<IdentKey>>,
    span: lexer::token::Span,
    /// Whether its body was not read: none was, or a statement of it does
    /// not parse. What it runs of an argument is not established.
    unread: bool,
}

/// A call of a named routine ([`TextFlows`]): whether it is a statement
/// (`EXEC p`, `CALL p`) rather than a function call, where its statement
/// starts, the scope of its variables, the name called, and each argument
/// in order, with the key of the parameter it is written to by name.
struct ScriptCall<'a> {
    statement: bool,
    /// Whether a `FROM` reads the call as a table.
    table: bool,
    /// The statement that makes the call.
    owner: lexer::token::Span,
    at: u32,
    scope: VariableScope,
    name: Vec<IdentKey>,
    arguments: Vec<(Option<IdentKey>, Option<&'a ast::AstExpr>)>,
}

impl ScriptCall<'_> {
    /// The argument written to the parameter at `position`, named `param`:
    /// the one written to it by name, else the one at its position written
    /// by none.
    fn bound_argument(&self, position: usize, param: Option<&IdentKey>) -> Option<usize> {
        param
            .and_then(|param| {
                self.arguments
                    .iter()
                    .position(|(name, _)| name.as_ref() == Some(param))
            })
            .or_else(|| {
                self.arguments
                    .get(position)
                    .is_some_and(|(name, _)| name.is_none())
                    .then_some(position)
            })
    }
}

/// What [`script_context_fold`] reads of the routines a script creates
/// and calls: which variable's text each variable's value writes, which
/// variables the statements that run SQL text run, and each call. A call
/// writes each argument to the parameter it is bound to, by name or by
/// position, as an assignment does; a routine runs a parameter where its
/// text reaches the text a statement of its body runs.
#[derive(Default)]
struct TextFlows<'a> {
    routines: Vec<CreatedRoutine>,
    /// The routines by the last part of their name.
    named: std::collections::BTreeMap<IdentKey, Vec<usize>>,
    /// Each variable a statement runs, with how and where the statement
    /// starts.
    runs: Vec<(FlowVariable, RunWays, u32)>,
    /// Where the first statement assigning each variable starts.
    first_assigned: std::collections::BTreeMap<FlowVariable, u32>,
    /// For each variable assigned, the variables written in its values,
    /// each with where the statement assigning it starts.
    written: std::collections::BTreeMap<
        FlowVariable,
        Vec<(FlowVariable, ir::dynamic_sql::ExecutedVariable, u32)>,
    >,
    calls: Vec<ScriptCall<'a>>,
    /// The nodes of the calls read.
    calls_read: std::collections::BTreeSet<ast::NodeId>,
}

impl<'a> TextFlows<'a> {
    /// The scope of the variables of a statement that starts at `at` in
    /// `batch`, the statements before it read: the routine whose body holds
    /// it, else the batch. `open` holds the routines whose bodies may hold
    /// it, innermost last, and loses those that end before `at`.
    fn scope_at(&self, open: &mut Vec<usize>, at: u32, batch: usize) -> VariableScope {
        while open
            .last()
            .and_then(|&id| self.routines.get(id))
            .is_some_and(|routine| routine.span.end <= at)
        {
            open.pop();
        }
        match open.last() {
            Some(&id) => VariableScope::Routine(id),
            None => VariableScope::Batch(batch),
        }
    }

    /// A statement in `scope` that starts at `at` assigns `text` to its
    /// variable.
    fn assigned(
        &mut self,
        names: VariableNames<'_>,
        scope: VariableScope,
        text: &ir::dynamic_sql::AssignedText,
        at: u32,
    ) {
        let Some(target) = names.variable(scope, &text.name, text.session) else {
            return;
        };
        self.first_assigned.entry(target.clone()).or_insert(at);
        let written: Vec<_> = ir::dynamic_sql::executed_variables(&text.pieces)
            .into_iter()
            .filter_map(|variable| {
                Some((
                    names.variable(scope, &variable.name, variable.session)?,
                    variable,
                    at,
                ))
            })
            .collect();
        if !written.is_empty() {
            self.written.entry(target).or_default().extend(written);
        }
    }

    /// A statement in `scope` that starts at `at` runs the text of `pieces`.
    fn executed(
        &mut self,
        names: VariableNames<'_>,
        scope: VariableScope,
        pieces: &[ir::dynamic_sql::TextPiece],
        at: u32,
    ) {
        for variable in ir::dynamic_sql::executed_variables(pieces) {
            if let Some(key) = names.variable(scope, &variable.name, variable.session) {
                self.runs.push((key, RunWays::of(&variable), at));
            }
        }
    }

    /// Whether `variable` is a parameter of the routine whose body runs it
    /// at `at`, assigned in that body before: the text run is then what the
    /// assignment wrote, not the call's.
    fn parameter_assigned_before(&self, variable: &FlowVariable, at: u32) -> bool {
        let (scope, key) = variable;
        let id = match scope {
            VariableScope::Routine(id) => id,
            VariableScope::Session | VariableScope::Batch(_) => return false,
        };
        self.routines
            .get(*id)
            .is_some_and(|routine| routine.params.iter().flatten().any(|param| param == key))
            && self
                .first_assigned
                .get(variable)
                .is_some_and(|&assigned| assigned < at)
    }

    /// The calls of a named routine `stmt`, at `at` in `scope`, makes.
    fn called(&mut self, stmt: &'a ast::AstStmt, at: u32, scope: VariableScope, sql: &str) {
        for call in ir::dynamic_sql::routine_calls(stmt, sql) {
            // A query an assignment holds is read again as a statement of
            // its own; each call is read once.
            if !self.calls_read.insert(call.node) {
                continue;
            }
            let name = routine_name(call.name, sql);
            if name.is_empty() {
                continue;
            }
            let arguments = call
                .arguments
                .into_iter()
                .map(|(name, value)| (name.and_then(|name| variable_key(&name, sql)), value))
                .collect();
            self.calls.push(ScriptCall {
                statement: call.node == stmt.node_id(),
                table: call.table,
                owner: stmt.span(),
                at,
                scope,
                name,
                arguments,
            });
        }
    }

    /// The routine `stmt` creates, by its place among the routines: a
    /// procedure or a function, or a statement holding a routine's body.
    fn created(&mut self, stmt: &ast::AstStmt, sql: &str) -> Option<usize> {
        let (name, params) = match ir::dynamic_sql::created_routine(stmt) {
            Some((name, params)) => (
                routine_name(name, sql),
                params
                    .into_iter()
                    .map(|param| param.and_then(|param| variable_key(&param, sql)))
                    .collect(),
            ),
            None if stmt.bodies().iter().any(|body| is_routine_body(body.role)) => {
                (Vec::new(), Vec::new())
            }
            None => return None,
        };
        let id = self.routines.len();
        if let Some(last) = name.last() {
            self.named.entry(last.clone()).or_default().push(id);
        }
        self.routines.push(CreatedRoutine {
            name,
            params,
            span: stmt.span(),
            unread: definition_unread(stmt),
        });
        Some(id)
    }

    /// The text of each call's argument that the routine called runs, as
    /// (where the call's statement starts, the scope of its variables, the
    /// pieces of the text run): the
    /// argument whole where the routine runs its parameter as the whole
    /// text, and each of its literals as written, quotes and all, where the
    /// routine writes it into the text run. A routine runs a parameter
    /// whose text reaches a variable a statement of its body runs, through
    /// the values of its variables and through the arguments of the calls
    /// its body makes, at any depth. A routine another script of the run
    /// defines, as `elsewhere` tells each of its definitions, runs an
    /// argument as that definition says; a call statement into a routine
    /// the run holds no definition of has every argument read as written
    /// into the text run. Each variable's ways grow at most three times,
    /// and each argument's text is read once. With them, the text of each
    /// argument a routine of the dialect runs as SQL, by the statement that
    /// calls it.
    fn arguments_run(
        self,
        names: VariableNames<'_>,
        dialect: &dyn dialect::Dialect,
        elsewhere: &dyn facts::reasoning::Reasoning,
    ) -> (Vec<ArgumentText>, Vec<RoutineRun>) {
        use ir::dynamic_sql::TextPiece;
        // Each argument a parameter is bound to, as (call, argument).
        let mut bound: std::collections::BTreeMap<FlowVariable, Vec<(usize, usize)>> =
            std::collections::BTreeMap::new();
        // The calls a name binds to more than one routine of (a bare name
        // over routines of several schemas, a routine several scripts
        // define): their arguments are masked as the routines run them, and
        // none is read as the statements run.
        let mut ambiguous: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        // How each argument is run by a routine the script does not define.
        let mut outside: std::collections::BTreeMap<(usize, usize), RunWays> =
            std::collections::BTreeMap::new();
        // The arguments a routine of the dialect runs as SQL.
        let mut system_runs: std::collections::BTreeSet<(usize, usize)> =
            std::collections::BTreeSet::new();
        // The dialect's functions, read once the first call needs them.
        for (c, call) in self.calls.iter().enumerate() {
            let Some(last) = call.name.last() else {
                continue;
            };
            let mut routines_bound = 0usize;
            for &id in self.named.get(last).into_iter().flatten() {
                let Some(routine) = self.routines.get(id) else {
                    continue;
                };
                if !ir::lower::routine_names_agree(&routine.name, &call.name) {
                    continue;
                }
                routines_bound += 1;
                // A routine whose body was not read may run any argument.
                if routine.unread {
                    for argument in 0..call.arguments.len() {
                        outside.entry((c, argument)).or_default().operand = true;
                    }
                }
                for (position, param) in routine.params.iter().enumerate() {
                    let Some(param) = param else {
                        continue;
                    };
                    if let Some(argument) = call.bound_argument(position, Some(param)) {
                        bound
                            .entry((VariableScope::Routine(id), param.clone()))
                            .or_default()
                            .push((c, argument));
                    }
                }
            }
            let definitions = elsewhere.routines_elsewhere(&call.name);
            routines_bound += definitions.len();
            if definitions.iter().any(|definition| definition.unread) {
                for argument in 0..call.arguments.len() {
                    outside.entry((c, argument)).or_default().operand = true;
                }
            }
            for definition in &definitions {
                for (position, param) in definition.parameters.iter().enumerate() {
                    let how = match param.run {
                        Some(facts::reasoning::ArgumentRun::Whole) => RunWays {
                            whole: true,
                            ..RunWays::default()
                        },
                        Some(facts::reasoning::ArgumentRun::WrittenInto) => RunWays {
                            operand: true,
                            ..RunWays::default()
                        },
                        None => continue,
                    };
                    if let Some(argument) = call.bound_argument(position, param.name.as_ref()) {
                        let now = outside.entry((c, argument)).or_default();
                        *now = now.union(how);
                    }
                }
            }
            // A routine the dialect defines does with each argument what it
            // states, an argument it runs as SQL text read as text the call
            // runs. What cannot be established is withheld: a routine the
            // run holds no definition of may run any argument it is called
            // with, and a function too where a function a user defines can
            // run SQL text and the dialect defines none of its name.
            if routines_bound == 0 {
                let uses = match system_routine_uses(call, dialect) {
                    Some(uses) => uses,
                    None if call.statement
                        || (may_run_sql_text(dialect, call.table)
                            && !names_builtin_function(&call.name, dialect)) =>
                    {
                        vec![(None, None); call.arguments.len()]
                    }
                    None => Vec::new(),
                };
                for (argument, (reads, masked)) in uses.into_iter().enumerate() {
                    let how = match (reads, masked) {
                        (
                            Some(
                                dialect::ArgumentUse::Value
                                | dialect::ArgumentUse::Name
                                | dialect::ArgumentUse::Flag
                                | dialect::ArgumentUse::ConnectionString,
                            ),
                            _,
                        ) => continue,
                        (
                            Some(
                                dialect::ArgumentUse::RunsSql
                                | dialect::ArgumentUse::RunsSqlRemotely,
                            ),
                            _,
                        ) => {
                            system_runs.insert((c, argument));
                            RunWays {
                                whole: true,
                                ..RunWays::default()
                            }
                        }
                        // The forms the call fits read the argument apart,
                        // as a name, an option, a connection or SQL text it
                        // runs: masked as the SQL text, which masks the most
                        // of those, and not read as statements.
                        (
                            None,
                            Some(
                                dialect::ArgumentUse::RunsSql
                                | dialect::ArgumentUse::RunsSqlRemotely,
                            ),
                        ) => RunWays {
                            whole: true,
                            ..RunWays::default()
                        },
                        (None, Some(dialect::ArgumentUse::ConnectionString)) => continue,
                        (
                            Some(dialect::ArgumentUse::Command | dialect::ArgumentUse::Credential),
                            _,
                        )
                        | (
                            None,
                            Some(
                                dialect::ArgumentUse::Value
                                | dialect::ArgumentUse::Name
                                | dialect::ArgumentUse::Flag
                                | dialect::ArgumentUse::Command
                                | dialect::ArgumentUse::Credential,
                            )
                            | None,
                        ) => RunWays {
                            operand: true,
                            ..RunWays::default()
                        },
                    };
                    let now = outside.entry((c, argument)).or_default();
                    *now = now.union(how);
                }
            }
            if routines_bound > 1 {
                ambiguous.insert(c);
            }
        }
        if bound.is_empty() && outside.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let mut texts: std::collections::BTreeMap<(usize, usize), Vec<TextPiece>> =
            std::collections::BTreeMap::new();
        let mut text_of = |(c, a): (usize, usize)| -> Vec<TextPiece> {
            texts
                .entry((c, a))
                .or_insert_with(|| {
                    self.calls
                        .get(c)
                        .and_then(|call| call.arguments.get(a))
                        .and_then(|(_, value)| *value)
                        .map(|value| ir::dynamic_sql::text_pieces(value, names.sql, dialect))
                        .unwrap_or_default()
                })
                .clone()
        };
        // How each variable's text is run, grown from the statements that
        // run text until nothing grows.
        let mut ways: std::collections::BTreeMap<FlowVariable, RunWays> =
            std::collections::BTreeMap::new();
        let mut pending: Vec<FlowVariable> = Vec::new();
        fn reach(
            ways: &mut std::collections::BTreeMap<FlowVariable, RunWays>,
            pending: &mut Vec<FlowVariable>,
            variable: FlowVariable,
            how: RunWays,
        ) {
            let now = ways.entry(variable.clone()).or_default();
            let grown = now.union(how);
            if grown != *now {
                *now = grown;
                pending.push(variable);
            }
        }
        for (variable, how, at) in &self.runs {
            let how = if self.parameter_assigned_before(variable, *at) {
                how.written_into()
            } else {
                *how
            };
            reach(&mut ways, &mut pending, variable.clone(), how);
        }
        // A variable an argument run outside the script writes is run as the
        // argument is.
        for (&(c, a), how) in &outside {
            let Some(scope) = self.calls.get(c).map(|call| call.scope) else {
                continue;
            };
            for written in ir::dynamic_sql::executed_variables(&text_of((c, a))) {
                if let Some(variable) = names.variable(scope, &written.name, written.session) {
                    reach(&mut ways, &mut pending, variable, how.carried_to(&written));
                }
            }
        }
        while let Some(variable) = pending.pop() {
            let how = ways.get(&variable).copied().unwrap_or_default();
            for (written, as_written, at) in self.written.get(&variable).into_iter().flatten() {
                // A parameter assigned before its text is written into
                // another variable's gives it what the assignment wrote.
                let carried = how.carried_to(as_written);
                let carried = if self.parameter_assigned_before(written, *at) {
                    carried.written_into()
                } else {
                    carried
                };
                reach(&mut ways, &mut pending, written.clone(), carried);
            }
            for &(c, a) in bound.get(&variable).into_iter().flatten() {
                let Some(scope) = self.calls.get(c).map(|call| call.scope) else {
                    continue;
                };
                for written in ir::dynamic_sql::executed_variables(&text_of((c, a))) {
                    if let Some(variable) = names.variable(scope, &written.name, written.session) {
                        reach(&mut ways, &mut pending, variable, how.carried_to(&written));
                    }
                }
            }
        }
        // Each argument run, with every way a routine called runs it.
        let mut run: std::collections::BTreeMap<(usize, usize), RunWays> = outside;
        for (param, arguments) in &bound {
            let how = ways.get(param).copied().unwrap_or_default();
            if how.is_empty() {
                continue;
            }
            for &argument in arguments {
                let now = run.entry(argument).or_default();
                *now = now.union(how);
            }
        }
        let routine_runs = system_runs
            .iter()
            .filter_map(|&(c, a)| {
                Some(RoutineRun {
                    owner: self.calls.get(c)?.owner,
                    text: text_of((c, a)),
                })
            })
            .collect();
        let mut out = Vec::new();
        for ((c, a), how) in run {
            let Some((at, scope)) = self.calls.get(c).map(|call| (call.at, call.scope)) else {
                continue;
            };
            let how = if ambiguous.contains(&c) {
                how.written_into()
            } else {
                how
            };
            out.extend(
                argument_run_texts(text_of((c, a)), how)
                    .into_iter()
                    .map(|pieces| (at, scope, pieces)),
            );
        }
        (out, routine_runs)
    }
}

/// The text of an argument a routine of the dialect runs as SQL
/// ([`dialect::Dialect::system_routine`]), with the statement that calls it.
#[derive(Debug, Clone)]
pub struct RoutineRun {
    /// The span of the statement that makes the call.
    pub owner: lexer::token::Span,
    /// The pieces of the argument's text.
    pub text: Vec<ir::dynamic_sql::TextPiece>,
}

/// Whether a function call may run SQL text it is passed in `dialect`: a
/// function a user defines can, or, read as a `table` by a `FROM`, it may
/// call a procedure.
fn may_run_sql_text(dialect: &dyn dialect::Dialect, table: bool) -> bool {
    dialect.user_functions_run_sql_text() || (table && dialect.table_calls_may_run_procedures())
}

/// Whether a function call may write rows in `dialect`: a function a user
/// defines can run SQL text it is passed, or write where the dialect's data
/// says such a function may ([`dialect::Dialect::user_functions_write`]);
/// read as a `table` by a `FROM`, it may call a procedure.
fn may_write_rows(dialect: &dyn dialect::Dialect, table: bool) -> bool {
    may_run_sql_text(dialect, table) || dialect.user_functions_write()
}

/// Whether a call naming the parts `name` names a function `dialect`
/// defines, which runs none of its arguments: written bare and known to its
/// catalog, or written in the schema its built-ins are in. The dialect's
/// catalog is built once for the process
/// ([`ir::FunctionCatalog::dialect_defined`]).
fn names_builtin_function(name: &[IdentKey], dialect: &dyn dialect::Dialect) -> bool {
    if name.is_empty() {
        return false;
    }
    let catalog =
        ir::FunctionCatalog::dialect_defined(ir::CatalogDialect::from_dialect_name(dialect.name()));
    names_builtin_function_in(name, dialect, catalog)
}

/// [`names_builtin_function`] against `catalog`, the dialect's.
pub(crate) fn names_builtin_function_in(
    name: &[IdentKey],
    dialect: &dyn dialect::Dialect,
    catalog: &ir::FunctionCatalog,
) -> bool {
    let Some((function, qualifier)) = name.split_last() else {
        return false;
    };
    match qualifier.last() {
        None => catalog.is_builtin(function),
        Some(schema) => dialect
            .builtin_function_schema()
            .is_some_and(|builtin| ir::lower::routine_name(builtin).last() == Some(schema)),
    }
}

/// What a routine of the dialect does with an argument, and what a report
/// masks of it where the forms a call fits read it apart
/// ([`system_routine_uses`]).
type ArgumentReading = (Option<dialect::ArgumentUse>, Option<dialect::ArgumentUse>);

/// What the routine of `dialect`'s own that `call` names does with each of
/// its arguments ([`dialect::Dialect::system_routine`]), each with what a
/// report masks of it where the forms the call fits read it apart
/// ([`dialect::SystemRoutine::masking_uses`]); `None` where the call names
/// none.
fn system_routine_uses(
    call: &ScriptCall<'_>,
    dialect: &dyn dialect::Dialect,
) -> Option<Vec<ArgumentReading>> {
    let parts: Vec<&str> = call.name.iter().map(IdentKey::as_str).collect();
    let routine = dialect.system_routine(&parts)?;
    let written: Vec<dialect::WrittenArgument<'_>> = call
        .arguments
        .iter()
        .map(|(name, value)| dialect::WrittenArgument {
            name: name.as_ref().map(IdentKey::as_str),
            value: value.map_or(dialect::WrittenValue::Other, dialect::WrittenValue::of),
        })
        .collect();
    Some(
        routine
            .argument_uses(&written)
            .into_iter()
            .zip(routine.masking_uses(&written))
            .collect(),
    )
}

/// The texts a routine run `how` runs of an argument whose text is `text`:
/// the text written in as one string where the routine writes it into the
/// text it runs, what is around it being the routine's and not the call's,
/// and the text whole where it runs it whole.
fn argument_run_texts(
    text: Vec<ir::dynamic_sql::TextPiece>,
    how: RunWays,
) -> Vec<Vec<ir::dynamic_sql::TextPiece>> {
    use ir::dynamic_sql::TextPiece;
    let mut out = Vec::new();
    if text.is_empty() {
        return out;
    }
    if how.operand || how.quoted {
        out.push(
            std::iter::once(TextPiece::Break)
                .chain(text.iter().map(written_quoted))
                .chain(std::iter::once(TextPiece::Break))
                .collect(),
        );
    }
    if how.whole {
        out.push(text);
    }
    out
}

/// `piece` written as a quoted literal: a literal's text with its quotes,
/// a variable's value quoted as a literal.
fn written_quoted(piece: &ir::dynamic_sql::TextPiece) -> ir::dynamic_sql::TextPiece {
    use ir::dynamic_sql::{HoleQuoting, TextPiece};
    match piece {
        TextPiece::Literal(literal) => TextPiece::QuotedLiteral(*literal),
        TextPiece::Variable {
            name,
            at,
            quoting: HoleQuoting::Raw,
            session,
        } => TextPiece::Variable {
            name: *name,
            at: *at,
            quoting: HoleQuoting::LitQuoter,
            session: *session,
        },
        TextPiece::Choice { at, choices } => TextPiece::Choice {
            at: *at,
            choices: choices
                .iter()
                .map(|choice| choice.iter().map(written_quoted).collect())
                .collect(),
        },
        TextPiece::QuotedLiteral(_)
        | TextPiece::TemplateText { .. }
        | TextPiece::Verbatim(_)
        | TextPiece::Variable { .. }
        | TextPiece::Value { .. }
        | TextPiece::Rewritten { .. }
        | TextPiece::Break => piece.clone(),
    }
}

/// The parts of the routine name written at `span` ([`ir::lower::routine_name`]).
fn routine_name(span: lexer::token::Span, sql: &str) -> Vec<IdentKey> {
    sql.get(span.start as usize..span.end as usize)
        .map(ir::lower::routine_name)
        .unwrap_or_default()
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
/// database / schema namespace, and holds the string literals the script
/// runs as dynamic SQL.
#[derive(Debug, Clone, Default)]
pub struct ScriptContextFold {
    /// (effect_position, role) — the role set by `USE ROLE`, in effect
    /// from this byte offset until the next change. Ordered ascending.
    role_changes: Vec<(u32, facts::IdentName)>,
    /// (effect_position, database) — the default database set by
    /// `USE DATABASE` / bare `USE <db>` / the db side of `USE <db>.<schema>`.
    db_changes: Vec<(u32, facts::IdentName)>,
    /// (effect_position, schema) — the default schema set by `USE SCHEMA`
    /// / the schema side of `USE <db>.<schema>` / `SET search_path`; `None`
    /// from a reset of the search path.
    schema_changes: Vec<(u32, Option<facts::IdentName>)>,
    /// (effect_position, schemas) — the schemas a `SET search_path` of more
    /// than one schema lists, searched in order while no schema is set;
    /// empty from any other change of the schema, which leaves the
    /// dialect's own path.
    search_path_changes: Vec<(u32, Vec<facts::IdentName>)>,
    /// Where a search path set names the session's user (`$user`), whose
    /// schema the run does not know ([`Self::stated_session_at`]).
    user_path_changes: Vec<(u32, bool)>,
    /// The bodies of routines a `SET search_path` clause of their own runs
    /// under that path, each by the range of the script it covers and the
    /// schemas it lists.
    routine_search_paths: Vec<(std::ops::Range<u32>, Vec<facts::IdentName>)>,
    /// The schemas the dialect looks for a name written without one in,
    /// where the script sets none; empty where the connection decides.
    default_search_path: &'static [&'static str],
    /// The string literals the script runs as dynamic SQL, at any depth,
    /// each the whole text run or a run of literal operands of the
    /// concatenation that builds it: one a statement executes as written,
    /// and one assigned to a variable a statement executes by name.
    dynamic_sql_literals: Vec<ir::dynamic_sql::ExecutedLiteral>,
    /// The spans (start, end) of those literals run as written: by a
    /// statement, or through a variable whose whole text one is when run.
    run_as_written: std::collections::BTreeSet<(u32, u32)>,
    /// Each argument a routine of the dialect runs as SQL.
    routine_runs: Vec<RoutineRun>,
    /// The spans (start, end) of the statements, at any depth, the parser
    /// read only up to a token it does not bind.
    cut_statements: std::collections::BTreeSet<(u32, u32)>,
    /// The variables and routine parameters the script declares, each
    /// with the stretch of the script whose statements read it.
    declared: Vec<DeclaredScope>,
    /// The functions the script's top-level statements define, in order:
    /// where the statement starts, the name as written, what a call returns.
    declared_functions: Vec<(u32, String, ast::AstFunctionReturns)>,
    /// What each variable holds, from where ([`variable_timelines`]).
    variable_texts: std::collections::BTreeMap<FlowVariable, Vec<(u32, Option<String>)>>,
    /// The span of each routine the script creates, by its place.
    routine_spans: Vec<lexer::token::Span>,
    /// Every statement at every depth, in the order
    /// [`flatten_stmts_for_rules`] gives them.
    statements: Vec<FoldStatement>,
    /// The index in `statements` of the statement written at each span.
    statement_at: std::collections::BTreeMap<(u32, u32), usize>,
    /// Where each batch after the first starts.
    batch_starts: Vec<u32>,
    /// Where each statement that calls a routine ends, in order.
    calls_end: Vec<u32>,
}

impl ScriptContextFold {
    /// The texts the script's variables are known to hold at the statement
    /// that starts at `position`, in force while the guard lives: a name
    /// written `IDENTIFIER($v)` or `IDENTIFIER(:v)` in a statement lowered
    /// then is the name its variable holds. A session variable is unknown
    /// after a call: a caller's-rights procedure may set it.
    pub fn enter_statement(&self, position: u32) -> ir::statement_values::StatementValues {
        let local = self.scope_at(position);
        let values = self
            .variable_texts
            .iter()
            .filter_map(|((scope, key), timeline)| {
                let session = *scope == VariableScope::Session;
                if !session && *scope != local {
                    return None;
                }
                let (from, text) = timeline.iter().rev().find(|(from, _)| *from <= position)?;
                let called = session
                    && self
                        .calls_end
                        .iter()
                        .any(|end| (*from..=position).contains(end));
                if called {
                    return None;
                }
                Some(((session, key.clone()), text.clone()?))
            })
            .collect();
        ir::statement_values::StatementValues::enter(values)
    }

    /// The scope a statement that starts at `position` reads its own
    /// variables in: the innermost routine whose body holds it, else its
    /// batch.
    fn scope_at(&self, position: u32) -> VariableScope {
        let routine = self
            .routine_spans
            .iter()
            .enumerate()
            .filter(|(_, span)| span.start < position && position < span.end)
            .max_by_key(|(_, span)| span.start);
        match routine {
            Some((id, _)) => VariableScope::Routine(id),
            None => VariableScope::Batch(
                self.batch_starts
                    .iter()
                    .filter(|start| **start <= position)
                    .count(),
            ),
        }
    }

    /// The statements that hold the statement at `span`, innermost first.
    fn holders(&self, span: lexer::token::Span) -> impl Iterator<Item = &FoldStatement> {
        let first = self
            .statement_at
            .get(&(span.start, span.end))
            .and_then(|&at| self.statements.get(at))
            .and_then(|statement| statement.parent);
        std::iter::successors(first.and_then(|at| self.statements.get(at)), |holder| {
            holder.parent.and_then(|at| self.statements.get(at))
        })
    }

    /// The place, in the order [`flatten_stmts_for_rules`] gives the
    /// script's statements, of the innermost procedure, function or trigger
    /// whose body holds the statement at `span`.
    fn routine_holding(&self, span: lexer::token::Span) -> Option<usize> {
        let mut at = self
            .statement_at
            .get(&(span.start, span.end))
            .and_then(|&at| self.statements.get(at))
            .and_then(|statement| statement.parent);
        while let Some(place) = at {
            let holder = self.statements.get(place)?;
            if matches!(
                holder.body,
                Some(
                    facts::EnclosingKind::Procedure { .. }
                        | facts::EnclosingKind::Function { .. }
                        | facts::EnclosingKind::Trigger { .. }
                )
            ) {
                return Some(place);
            }
            at = holder.parent;
        }
        None
    }

    /// The parameters of the innermost procedure or function whose body
    /// holds the statement at `span`; none in a trigger's.
    fn parameters_at(&self, span: lexer::token::Span) -> &[IdentKey] {
        self.routine_holding(span)
            .and_then(|place| self.statements.get(place))
            .map_or(&[], |routine| routine.parameters.as_slice())
    }

    /// The bodies that hold the statement at `span`, outermost first.
    fn bodies_holding(&self, span: lexer::token::Span) -> Vec<facts::EnclosingKind> {
        let mut out: Vec<facts::EnclosingKind> = self
            .holders(span)
            .filter_map(|holder| holder.body.clone())
            .collect();
        out.reverse();
        out
    }

    /// The functions the script's top-level statements define, in order.
    pub(crate) fn declared_functions(&self) -> &[(u32, String, ast::AstFunctionReturns)] {
        &self.declared_functions
    }

    /// The variables and routine parameters declared around the
    /// statement that starts at `position`.
    fn declared_at(&self, position: u32) -> ir::lower::DeclaredNames {
        ir::lower::DeclaredNames::new(
            self.declared
                .iter()
                .filter(|scope| (scope.from..scope.to).contains(&position))
                .flat_map(|scope| scope.names.iter().cloned())
                .collect(),
        )
    }

    /// Whether the statement at `span` was read only up to a token the
    /// parser does not bind.
    fn is_cut(&self, span: lexer::token::Span) -> bool {
        self.cut_statements.contains(&(span.start, span.end))
    }

    /// The fold with `session` as the namespace in force from the start
    /// of the script: each part it names holds until a `USE` sets that
    /// part, so [`Self::session_context_at`] answers a part no `USE`
    /// before a position has set with `session`'s.
    pub fn starting_under(mut self, session: &ir::SessionContext) -> Self {
        let at_start = |name: &str| (0, facts::IdentName::new(name));
        if let Some(db) = session.db.as_deref() {
            self.db_changes.insert(0, at_start(db));
        }
        if let Some(schema) = session.schema.as_deref() {
            let (at, schema) = at_start(schema);
            self.schema_changes.insert(0, (at, Some(schema)));
        }
        self
    }

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
        self.session_at(position, true)
    }

    /// [`Self::session_context_at`] as the run states it: where no schema
    /// or search path is set, no path, though the dialect has its own, so
    /// a name written without a schema may be one of any schema.
    pub(crate) fn stated_session_at(&self, position: u32) -> ir::SessionContext {
        self.session_at(position, false)
    }

    /// The session at `position`, the dialect's own path taken where the
    /// run sets none and `dialect_path` holds.
    fn session_at(&self, position: u32, dialect_path: bool) -> ir::SessionContext {
        let db = last_change_at(&self.db_changes, position).map(|d| d.raw.clone());
        // A path naming the session's user places a bare name in a schema
        // the run does not know: as the run states it, none.
        let names_user =
            last_change_at(&self.user_path_changes, position).is_some_and(|user| *user);
        if names_user && !dialect_path && self.routine_search_path_at(position).is_none() {
            return ir::SessionContext {
                db,
                schema: None,
                search_path: Vec::new(),
            };
        }
        // A routine's own path, in its body.
        if let Some(listed) = self.routine_search_path_at(position) {
            return match listed {
                [schema] => ir::SessionContext {
                    db,
                    schema: Some(schema.raw.clone()),
                    search_path: Vec::new(),
                },
                [] | [_, _, ..] => ir::SessionContext {
                    db,
                    schema: None,
                    search_path: listed.iter().map(|s| s.raw.clone()).collect(),
                },
            };
        }
        let schema = last_change_at(&self.schema_changes, position)
            .and_then(Option::as_ref)
            .map(|s| s.raw.clone());
        // Where no schema is set, the path a `SET search_path` lists, else
        // the dialect's own.
        let search_path = match (&schema, last_change_at(&self.search_path_changes, position)) {
            (Some(_), _) => Vec::new(),
            (None, Some(listed)) if !listed.is_empty() => {
                listed.iter().map(|s| s.raw.clone()).collect()
            }
            (None, Some(_) | None) if dialect_path => self
                .default_search_path
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            (None, Some(_) | None) => Vec::new(),
        };
        ir::SessionContext {
            db,
            schema,
            search_path,
        }
    }

    /// The path the `SET search_path` clause of the innermost routine
    /// whose body holds `position` lists, where it writes one.
    fn routine_search_path_at(&self, position: u32) -> Option<&[facts::IdentName]> {
        self.routine_search_paths
            .iter()
            .rev()
            .find(|(range, _)| range.contains(&position))
            .map(|(_, listed)| listed.as_slice())
    }

    /// The database and schema a bare name resolves under at `position`.
    fn namespace_at(
        &self,
        position: u32,
    ) -> (Option<&facts::IdentName>, Option<&facts::IdentName>) {
        let schema = match self.routine_search_path_at(position) {
            Some([schema]) => Some(schema),
            Some([] | [_, _, ..]) => None,
            None => last_change_at(&self.schema_changes, position).and_then(Option::as_ref),
        };
        (last_change_at(&self.db_changes, position), schema)
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
            enclosing: self.bodies_holding(span),
            ..facts::ScriptContext::default()
        }
    }
}

/// A statement of a script at any depth ([`ScriptContextFold`]): the
/// statement that holds it, the body it holds statements in, and the keys
/// of the parameters of the procedure or function it creates.
#[derive(Debug, Clone)]
struct FoldStatement {
    parent: Option<usize>,
    body: Option<facts::EnclosingKind>,
    parameters: Vec<IdentKey>,
}

/// The body `stmt` holds statements in, as a statement held there names
/// it; `None` for a statement that holds no body, a `DO` (whose body is a
/// block) and an `INSERT … EXEC` (whose `EXEC` is part of the insert).
fn holding_body(stmt: &ast::AstStmt, sql: &str) -> Option<facts::EnclosingKind> {
    use facts::{ControlFlowKind as Flow, EnclosingKind as Body};
    let name = |span: lexer::token::Span| {
        facts::IdentName::new(ir::utils::slice_span(sql, span).unwrap_or("").trim())
    };
    let flow = |flow_kind: Flow| Some(Body::ControlFlow { flow_kind });
    if let ast::AstStmt::CreateProcedure(p) = stmt {
        Some(Body::Procedure {
            name: name(p.name_span),
        })
    } else if let ast::AstStmt::CreateFunction(f) = stmt {
        Some(Body::Function {
            name: name(f.name_span),
        })
    } else if let ast::AstStmt::CreateMssqlTrigger(t) = stmt {
        Some(Body::Trigger {
            name: name(t.name_span),
        })
    } else if let ast::AstStmt::CreateMysqlTrigger(t) = stmt {
        Some(Body::Trigger {
            name: name(t.name_span),
        })
    } else if let ast::AstStmt::CreateEvent(e) = stmt {
        Some(Body::Event {
            name: name(e.name_span),
        })
    } else if let ast::AstStmt::AlterEvent(e) = stmt {
        Some(Body::Event {
            name: name(e.name_span),
        })
    } else if let ast::AstStmt::CreateTask(t) = stmt {
        Some(Body::Task {
            name: name(t.name_span),
        })
    } else if let ast::AstStmt::PgCreateRule(r) = stmt {
        Some(Body::Rule {
            name: name(r.rule_name),
        })
    } else if let ast::AstStmt::Block(_) = stmt {
        Some(Body::Block)
    } else if let ast::AstStmt::DeclareHandler(_) = stmt {
        Some(Body::Handler)
    } else if let ast::AstStmt::If(_) | ast::AstStmt::MssqlIf(_) = stmt {
        flow(Flow::If)
    } else if let ast::AstStmt::CaseStmt(_) = stmt {
        flow(Flow::Case)
    } else if let ast::AstStmt::While(_) | ast::AstStmt::MssqlWhile(_) = stmt {
        flow(Flow::While)
    } else if let ast::AstStmt::For(_) | ast::AstStmt::ForEach(_) = stmt {
        flow(Flow::For)
    } else if let ast::AstStmt::Loop(_) = stmt {
        flow(Flow::Loop)
    } else if let ast::AstStmt::Repeat(_) = stmt {
        flow(Flow::Repeat)
    } else if let ast::AstStmt::MssqlTryCatch(_) = stmt {
        flow(Flow::TryCatch)
    } else {
        None
    }
}

/// Last `(position, value)` change at or before `position` in an
/// ascending-ordered change list.
/// The schema a `SET search_path` entry at `span` names: a string's value
/// as a name written in quotes, any other entry as written.
fn search_path_schema(sql: &str, span: lexer::token::Span) -> Option<facts::IdentName> {
    let written = ir::utils::slice_span(sql, span)?;
    Some(match ir::span_extract::string_literal_value(written) {
        Some(value) => facts::IdentName::new(format!("\"{}\"", value.replace('"', "\"\""))),
        None => facts::IdentName::new(written),
    })
}

/// The path the last `set_config('search_path', …)` that `stmt` runs where
/// it is written sets ([`set_config_search_path`]): `stmt`'s own, or that of
/// a statement of the body of a DO block, at any depth, outside the body of
/// a routine it defines.
fn set_config_where_written(stmt: &ast::AstStmt, sql: &str) -> Option<Vec<facts::IdentName>> {
    if !matches!(stmt, ast::AstStmt::DoBlock(_)) {
        return set_config_search_path(stmt, sql);
    }
    fn last_in(stmts: &[ast::AstStmt], sql: &str) -> Option<Vec<facts::IdentName>> {
        stmts.iter().rev().find_map(|inner| {
            set_config_search_path(inner, sql).or_else(|| {
                inner
                    .bodies()
                    .iter()
                    .rev()
                    .filter(|body| !is_routine_body(body.role))
                    .find_map(|body| last_in(body.stmts, sql))
            })
        })
    }
    stmt.bodies()
        .iter()
        .rev()
        .find_map(|body| last_in(body.stmts, sql))
}

/// The schemas a `SELECT [pg_catalog.]set_config('search_path', '<path>',
/// …)`, or the same call `PERFORM`ed, sets the session's path to, each
/// entry of the path's text in order: `None` for any other statement, or a
/// path not written as a literal.
fn set_config_search_path(stmt: &ast::AstStmt, sql: &str) -> Option<Vec<facts::IdentName>> {
    if let ast::AstStmt::Perform(perform) = stmt {
        return set_config_search_path(&perform.query, sql);
    }
    let ast::AstStmt::Select(select) = stmt else {
        return None;
    };
    let ast::AstProjectionKind::Columns(items) = &select.projection.kind else {
        return None;
    };
    let [item] = items.as_slice() else {
        return None;
    };
    let ast::ProjectionItemKind::SelectItem(item) = &item.kind else {
        return None;
    };
    let ast::AstExpr::FunctionCall {
        func_name, args, ..
    } = &item.expr
    else {
        return None;
    };
    let name = ir::lower::split_dotted_name(ir::utils::slice_span(sql, func_name.span)?);
    let named = match name.as_slice() {
        [function] => function,
        [schema, function] if IdentKey::new(schema).as_str() == "pg_catalog" => function,
        _ => return None,
    };
    if IdentKey::new_as(named, ir::normalize::NameKind::Routine).as_str() != "set_config" {
        return None;
    }
    let literal = |arg: &ast::AstFunctionArg| {
        let ast::AstFunctionArg::Positional(expr) = arg else {
            return None;
        };
        let ast::AstExpr::Literal {
            literal: ast::AstLiteral::String { span },
            ..
        } = &**expr
        else {
            return None;
        };
        ir::span_extract::string_literal_value(ir::utils::slice_span(sql, *span)?)
    };
    let (parameter, path) = match args.as_slice() {
        [parameter, path, ..] => (literal(parameter)?, literal(path)?),
        _ => return None,
    };
    if !parameter.eq_ignore_ascii_case("search_path") {
        return None;
    }
    Some(
        path.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(facts::IdentName::new)
            .collect(),
    )
}

fn last_change_at<T>(changes: &[(u32, T)], position: u32) -> Option<&T> {
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
///   from real regressions, and so do sqlcmd commands that run what the
///   analysis did not read (`E_STRICT_NOT_READ`).
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
            SkipReason::SqlcmdCommand(runs) => {
                out.push(StrictViolation {
                    code: "E_STRICT_NOT_READ",
                    message: format!(
                        "sqlcmd command at line {} {}: {}",
                        skipped.line_number,
                        runs.describe(),
                        skipped.statement_prefix
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

/// Read `LEXEGA_STRICT` and translate it to a [`StrictMode`]: `Permissive`
/// when it is unset, and the value as set when it names no mode, so a
/// misspelled gate is reported rather than read as off.
pub fn strict_mode_from_env() -> Result<StrictMode, String> {
    match std::env::var("LEXEGA_STRICT") {
        Ok(v) => parse_strict_mode(&v).map_err(|_| v),
        Err(std::env::VarError::NotPresent) => Ok(StrictMode::Permissive),
        Err(std::env::VarError::NotUnicode(v)) => Err(v.to_string_lossy().into_owned()),
    }
}

#[cfg(test)]
mod scan_index_tests {
    use super::*;

    // A query's facts are derived from one scan index of its plan.
    #[test]
    fn a_querys_facts_read_one_scan_index_of_its_plan() {
        let before = ir::expression_fact::scan_indexes_built();
        Engine::recognition()
            .analyze_risk("SELECT a, b FROM t WHERE a > 1")
            .expect("the script is analysed");
        assert_eq!(ir::expression_fact::scan_indexes_built() - before, 1);
    }

    // The reader of a script's last statement is handed that statement as
    // the analysis lowered it, once, the statements before it and those its
    // bodies hold never; the analysis builds no scan index more for it.
    #[test]
    fn the_last_statement_is_handed_over_as_the_analysis_lowered_it() {
        let sql = "SELECT a FROM t1; BEGIN SELECT c FROM t3; END; SELECT b FROM t2 WHERE b > 1";
        let analyse = |read_last: Option<&mut dyn FnMut(LastStatement<'_>)>| {
            let PreparedScript { artifacts, script } = prepare_and_parse_for_analysis(
                sql,
                &None,
                None,
                &facts::reasoning::RecognitionOnly,
            )
            .expect("the script parses");
            let engine = Engine::recognition();
            let config = analyzer::AnalysisConfig::default();
            let before = ir::expression_fact::scan_indexes_built();
            let report = match read_last {
                Some(read) => engine.analyze_script_reading_last(
                    &artifacts, &script, &config, None, None, None, None, read,
                ),
                None => engine.analyze_script(&artifacts, &script, &config, None, None, None, None),
            }
            .expect("the script is analysed");
            let mut report = serde_json::to_value(report).expect("a report serializes");
            report["timestamp"] = serde_json::Value::Null;
            (report, ir::expression_fact::scan_indexes_built() - before)
        };
        let mut read: Vec<(Vec<String>, bool)> = Vec::new();
        let mut reader = |last: LastStatement<'_>| {
            read.push((
                last.derived
                    .tables_read
                    .iter()
                    .map(|table| table.name.clone())
                    .collect(),
                last.plan.has_where(),
            ));
        };
        let reading = analyse(Some(&mut reader));
        assert_eq!(read, vec![(vec!["t2".to_string()], true)]);
        assert_eq!(reading, analyse(None));
    }
}

#[cfg(test)]
mod finding_order_tests {
    use super::*;

    // Findings that differ in nothing but their statement are put in the
    // order of the script, whatever order they are handed over in.
    #[test]
    fn findings_that_differ_only_in_place_are_ordered_by_place() {
        let statements = 40;
        let sql: String = (0..statements)
            .map(|n| format!("CREATE STAGE stage_{n:02} UNKNOWN_FUTURE_OPTION = 'value';\n"))
            .collect();
        let report = Engine::recognition()
            .analyze_risk(&sql)
            .expect("the script is analysed");
        let mut findings: Vec<analyzer::RuleMatch> = report
            .findings
            .into_iter()
            .filter(|finding| finding.rule_id() == Some("SNW-UNKNOWN"))
            .collect();
        assert_eq!(findings.len(), statements);
        findings.reverse();
        findings.sort_by(finding_order);
        let lines: Vec<Option<usize>> = findings
            .iter()
            .map(|analyzer::RuleMatch::Analysis(finding)| finding.statement_line_number)
            .collect();
        let written: Vec<Option<usize>> = (1..=statements).map(Some).collect();
        assert_eq!(lines, written);
    }

    // Findings of statements written on one line are put in the order of
    // the line, whatever order they are handed over in.
    #[test]
    fn findings_on_one_line_are_ordered_by_column() {
        let statements = 40;
        let sql: String = (0..statements)
            .map(|n| format!("CREATE STAGE stage_{n:02} UNKNOWN_FUTURE_OPTION = 'value'; "))
            .collect();
        let report = Engine::recognition()
            .analyze_risk(&sql)
            .expect("the script is analysed");
        let mut findings: Vec<analyzer::RuleMatch> = report
            .findings
            .into_iter()
            .filter(|finding| finding.rule_id() == Some("SNW-UNKNOWN"))
            .collect();
        assert_eq!(findings.len(), statements);
        let columns = |findings: &[analyzer::RuleMatch]| -> Vec<Option<usize>> {
            findings
                .iter()
                .flat_map(|analyzer::RuleMatch::Analysis(finding)| &finding.evidence)
                .map(|evidence| match evidence {
                    analyzer::RiskEvidence::RuleMatch { column_number, .. } => *column_number,
                    analyzer::RiskEvidence::TableReference { .. }
                    | analyzer::RiskEvidence::PredicateInfo { .. } => None,
                })
                .collect()
        };
        let written = columns(&findings);
        assert!(
            written.windows(2).all(|pair| pair[0] < pair[1]),
            "{written:?}"
        );
        findings.reverse();
        findings.sort_by(finding_order);
        assert_eq!(columns(&findings), written);
    }
}

#[cfg(test)]
mod built_text_tests {
    use super::*;

    /// A reading of a script that runs nothing, as T-SQL.
    fn reading() -> DynamicBodies {
        let dialect = dialect::mssql();
        let tokens = lexer::tokenize_with_dialect("", dialect.as_ref()).tokens;
        let script = parser::try_parse_script_with_dialect("", &tokens, dialect.as_ref())
            .expect("the empty script parses");
        let fold = script_context_fold(&script, "", dialect.as_ref());
        DynamicBodies::read("", &fold, &dialect, true, None)
    }

    fn text(k: usize) -> String {
        format!("DELETE FROM dbo.t{k} WHERE id = __lxg_hole_0__")
    }

    #[test]
    fn each_built_text_is_parsed_once_at_every_level() {
        let top = reading();
        let nested = DynamicBodies::read_at(
            "",
            &ScriptContextFold::default(),
            2,
            top.run.clone(),
            true,
            None,
        );
        let first = top.built(&text(1)).expect("parsed");
        assert!(
            first.single_statement().is_some(),
            "a DELETE is one statement"
        );
        // A held parse is lent to every reader, at any level of the run.
        for reader in [&top, &nested] {
            let again = reader.built(&text(1)).expect("parsed");
            assert!(
                std::rc::Rc::ptr_eq(&first, &again),
                "the text is parsed once"
            );
        }
        let other = nested.built(&text(2)).expect("parsed");
        assert!(!std::rc::Rc::ptr_eq(&first, &other));
        assert!(top.built("  ").is_none(), "blank text is not read");
        let failed = top.built("FROB THE __lxg_hole_0__").expect("read");
        assert!(
            failed.single_statement().is_none(),
            "text that does not parse"
        );
    }

    #[test]
    fn a_built_texts_parse_lives_while_a_reader_holds_it() {
        let run = reading();
        let held = run.built(&text(1)).expect("parsed");
        let again = run.built(&text(1)).expect("parsed");
        assert!(std::rc::Rc::ptr_eq(&held, &again), "a held parse is lent");
        let parse = std::rc::Rc::downgrade(&held);
        drop((held, again));
        assert!(parse.upgrade().is_none(), "no reader holds it: it is freed");
        let read_again = run.built(&text(1)).expect("parsed");
        assert!(read_again.single_statement().is_some());
        assert_eq!(
            run.run.built.held.get(),
            text(1).len(),
            "the text is held once"
        );
    }

    #[test]
    fn the_built_texts_held_grow_with_the_distinct_texts() {
        let held = |n: usize| {
            let run = reading();
            for _ in 0..3 {
                for k in 0..n {
                    run.built(&text(k)).expect("parsed");
                }
            }
            run.run.built.held.get()
        };
        let bytes = |n: usize| (0..n).map(|k| text(k).len()).sum::<usize>();
        for n in [25, 100, 400] {
            assert_eq!(
                held(n),
                bytes(n),
                "{n} texts asked three times are held once"
            );
        }
    }

    #[test]
    fn analysing_a_built_text_is_charged_and_refused_past_the_depth() {
        let top = reading();
        let config = analyzer::AnalysisConfig {
            dialect: Some(dialect::mssql()),
            ..Default::default()
        };
        let built = top.built("DELETE FROM dbo.t").expect("parsed");
        let before = top.run.budget.get().bodies;
        assert!(top
            .analyze_built(&built, &facts::reasoning::RecognitionOnly, &config)
            .is_some());
        assert_eq!(top.run.budget.get().bodies, before - 1, "one body charged");
        let deepest = DynamicBodies::read_at(
            "",
            &ScriptContextFold::default(),
            BodyBudget::MAX_DEPTH,
            top.run.clone(),
            true,
            None,
        );
        let deep = deepest
            .built("DELETE FROM dbo.u")
            .expect("parsed past the depth");
        assert!(deep.single_statement().is_some());
        assert!(deepest
            .analyze_built(&deep, &facts::reasoning::RecognitionOnly, &config)
            .is_none());
        assert_eq!(
            top.run.budget.get().bodies,
            before - 1,
            "nothing charged past the depth"
        );
    }
}

#[cfg(test)]
mod run_body_tests {
    use super::*;

    /// The reading of the Snowflake script `src`, kept for analysis.
    fn reading_of(src: &str) -> DynamicBodies {
        let dialect = dialect::snowflake();
        let tokens = lexer::tokenize_with_dialect(src, dialect.as_ref()).tokens;
        let script = parser::try_parse_script_with_dialect(src, &tokens, dialect.as_ref())
            .expect("the script parses");
        let fold = script_context_fold(&script, src, dialect.as_ref());
        DynamicBodies::read(src, &fold, &dialect, true, None)
    }

    #[test]
    fn a_literal_run_is_parsed_at_the_reading_and_again_at_its_analysis() {
        let src = "EXECUTE IMMEDIATE 'DELETE FROM t1';\nEXECUTE IMMEDIATE 'DELETE FROM t2';\n";
        let before = body_parses();
        let bodies = reading_of(src);
        assert_eq!(
            body_parses() - before,
            2,
            "each literal parsed as it is read"
        );
        let config = analyzer::AnalysisConfig {
            dialect: Some(dialect::snowflake()),
            ..Default::default()
        };
        let literals: Vec<(u32, u32)> = bodies.read.keys().copied().collect();
        let texts: Vec<String> = literals
            .into_iter()
            .map(|(start, end)| {
                let (_, text, _) = bodies
                    .analyze_literal(
                        lexer::token::Span { start, end },
                        &facts::reasoning::RecognitionOnly,
                        &config,
                    )
                    .expect("analysed");
                text.to_string()
            })
            .collect();
        assert_eq!(texts, ["DELETE FROM t1", "DELETE FROM t2"]);
        assert_eq!(
            body_parses() - before,
            4,
            "no parse is held from the reading to the analysis"
        );
    }

    #[test]
    fn the_reading_lexes_each_literal_run_once() {
        let lexed = |n: usize| {
            let src: String = (0..n)
                .map(|k| format!("EXECUTE IMMEDIATE 'DELETE FROM t{k} WHERE id = 1';\n"))
                .collect();
            let before = body_lexings();
            let bodies = reading_of(&src);
            assert_eq!(bodies.read.len(), n, "every literal is read");
            body_lexings() - before
        };
        assert_eq!([lexed(4), lexed(16)], [4, 16]);
    }
}
