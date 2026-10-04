// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The analysis engine bound to a reasoning provider.

use crate::dialect::Dialect;
use crate::facts::reasoning::{Reasoning, RecognitionOnly};
use crate::{
    analyze_risk_core, analyzer, apply_dialect_normalization, ast, build_script_context_fold,
    builtin_load_failure_to_parse_error, error, evaluate_ddl_rules_for_script,
    evaluate_policy_attachment_rules_for_script, evaluate_privilege_rules_for_script,
    evaluate_query_rules_for_script, facts, ir, parse_sql, parse_sql_with_dialect,
    parse_with_optional_dialect, prepare_and_parse_for_analysis,
    prepare_sql_for_analysis_with_context, rules, template, PreparedScript,
};

/// Runs analysis with the semantic depth its reasoning provider supplies.
///
/// [`Engine::recognition`] analyses with recognition facts alone; a
/// provider that implements [`Reasoning`] adds the facts its analyses
/// derive, and every rule that predicates on them.
pub struct Engine<'r> {
    reasoning: &'r dyn Reasoning,
}

impl<'r> Engine<'r> {
    /// An engine consulting `reasoning` for every semantic analysis.
    pub fn new(reasoning: &'r dyn Reasoning) -> Self {
        Self { reasoning }
    }

    /// An engine that performs no reasoning.
    pub fn recognition() -> Engine<'static> {
        Engine {
            reasoning: &RecognitionOnly,
        }
    }

    /// The provider this engine consults.
    pub fn reasoning(&self) -> &'r dyn Reasoning {
        self.reasoning
    }

    /// Substitution pre-passes, template render, dialect-aware parse and
    /// ambient dialect setup for one source, in that order.
    pub fn prepare_and_parse(
        &self,
        src: &str,
        dialect: &Option<crate::dialect::DialectRef>,
        file_path: Option<&std::path::Path>,
    ) -> Result<PreparedScript, analyzer::RiskError> {
        prepare_and_parse_for_analysis(src, dialect, file_path, self.reasoning)
    }

    /// Render `src` when it is a template; plain SQL passes through. If
    /// `file_path` is given, the template's project is discovered from
    /// that file's directory.
    pub fn prepare_sql(
        &self,
        src: &str,
        file_path: Option<&std::path::Path>,
    ) -> Result<template::RenderArtifacts, analyzer::RiskError> {
        prepare_sql_for_analysis_with_context(src, file_path, self.reasoning)
    }

    /// Adopt `dialect` for the current thread. Must run before lowering:
    /// identifier normalization reads the ambient dialect.
    pub fn apply_dialect(&self, dialect: &Option<crate::dialect::DialectRef>) {
        apply_dialect_normalization(dialect, self.reasoning);
    }

    /// Analyze a parsed script. `render.sql` must be the exact text
    /// `script` was parsed from — redaction spans, the line index and
    /// the script-context fold all index it.
    #[allow(clippy::too_many_arguments)] // mirrors the analysis inputs one-to-one
    pub fn analyze_script(
        &self,
        render: &template::RenderArtifacts,
        script: &ast::AstScript,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        catalog_path: Option<&str>,
        source_file: Option<&str>,
        model_catalog: Option<&ir::model_catalog::ModelCatalog>,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        analyze_risk_core(
            render,
            script,
            policy_config,
            catalog_index,
            catalog_path,
            source_file,
            model_catalog,
            self.reasoning,
        )
    }

    pub fn analyze_risk(&self, src: &str) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        let PreparedScript { artifacts, script } =
            prepare_and_parse_for_analysis(src, &None, None, self.reasoning)?;
        analyze_risk_core(
            &artifacts,
            &script,
            &analyzer::AnalysisConfig::default(),
            None,
            None, // no catalog path
            None, // no source file for direct API
            None, // no model catalog
            self.reasoning,
        )
    }

    /// Analyze SQL file for risk with dbt context discovery from file's directory
    ///
    /// This variant discovers dbt_project.yml and dbt_packages from the file's directory,
    /// enabling proper expansion of dbt macros (like dbt_utils.date_spine).
    pub fn analyze_risk_from_file(
        &self,
        file_path: &std::path::Path,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        let src = std::fs::read_to_string(file_path).map_err(analyzer::RiskError::IoError)?;
        let PreparedScript { artifacts, script } =
            prepare_and_parse_for_analysis(&src, &None, Some(file_path), self.reasoning)?;
        analyze_risk_core(
            &artifacts,
            &script,
            &analyzer::AnalysisConfig::default(),
            None,
            None,               // no catalog path
            file_path.to_str(), // pass source file path
            None,               // no model catalog
            self.reasoning,
        )
    }

    /// Analyze SQL query with custom policy configuration.
    pub fn analyze_risk_with_policy_config(
        &self,
        src: &str,
        policy_config: &analyzer::AnalysisConfig,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        let PreparedScript { artifacts, script } =
            prepare_and_parse_for_analysis(src, &policy_config.dialect, None, self.reasoning)?;
        analyze_risk_core(
            &artifacts,
            &script,
            policy_config,
            None,
            None,
            None,
            None, // no model catalog
            self.reasoning,
        )
    }

    /// Analyze SQL with custom policy configuration against a loaded catalog
    /// snapshot. `catalog_path` is the path the snapshot was loaded from,
    /// when there is one, so the report can describe the catalog it used.
    pub fn analyze_risk_with_policy_config_and_catalog(
        &self,
        src: &str,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        catalog_path: Option<&str>,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        let PreparedScript { artifacts, script } =
            prepare_and_parse_for_analysis(src, &policy_config.dialect, None, self.reasoning)?;
        analyze_risk_core(
            &artifacts,
            &script,
            policy_config,
            catalog_index,
            catalog_path,
            None, // no source file for this API
            None, // no model catalog
            self.reasoning,
        )
    }

    /// Analyze pre-rendered SQL with its [`template::RenderArtifacts`].
    ///
    /// Use this when the source is already rendered — it skips
    /// re-rendering and analyzes `render.sql` with the artifacts'
    /// provenance. Plain SQL callers wrap the text in
    /// [`template::RenderArtifacts::raw`].
    ///
    /// The catalog should be loaded once at startup by the CLI/tool layer.
    /// This function does ZERO I/O - all file/cloud access is the caller's responsibility.
    pub fn analyze_risk_with_source_map(
        &self,
        render: &template::RenderArtifacts,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        source_file: Option<&str>,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        // Deployment-variable and SnowSQL `&var` substitution on already-rendered
        // SQL (e.g. the CLI renders Jinja then defers substitution here);
        // line-preserving so the source map stays valid. Unresolved-marker
        // placeholders fold into the artifacts' counts so confidence reflects
        // them (a no-op when the caller already substituted).
        let deploy = template::deployvars::preprocess(
            &render.sql,
            &policy_config.dialect,
            &template::SubstitutionConfig::default(),
            None,
        );
        let prepared = template::snowsql::preprocess(&deploy.sql, &policy_config.dialect, None);
        let untouched = deploy.placeholders.is_empty()
            && prepared.placeholders.is_empty()
            && matches!(deploy.sql, std::borrow::Cow::Borrowed(_))
            && matches!(prepared.sql, std::borrow::Cow::Borrowed(_));
        let adjusted;
        let render: &template::RenderArtifacts = if untouched {
            render
        } else {
            let deploy_stats =
                analyzer::compute_placeholder_stats(&deploy.sql, &deploy.placeholders);
            let snow_stats =
                analyzer::compute_placeholder_stats(&prepared.sql, &prepared.placeholders);
            let mut folded = render.clone();
            // A rewrite moves byte offsets: the caller's placeholder spans are
            // stale in the substituted text, so drop them (their counts are
            // already in the stats); each stage's own records attach below iff
            // their offsets index the final text.
            if prepared.sql != folded.sql {
                folded.placeholder_spans.clear();
            }
            folded.sql = prepared.sql.into_owned();
            // SnowSQL records index its output — the final text — by construction.
            folded.attach_placeholder_spans(&prepared.placeholders);
            // Deploy records index deploy.sql; valid only if the SnowSQL stage
            // was an identity pass.
            folded.extend_placeholder_spans_if_current(&deploy.sql, &deploy.placeholders);
            folded.placeholders.absorb(&snow_stats);
            folded.placeholders.absorb(&deploy_stats);
            adjusted = folded;
            &adjusted
        };
        let script = parse_with_optional_dialect(
            &render.sql,
            &policy_config.dialect,
            &render.placeholder_spans,
        )?;
        apply_dialect_normalization(&policy_config.dialect, self.reasoning);

        analyze_risk_core(
            render,
            &script,
            policy_config,
            catalog_index,
            None,
            source_file,
            None, // no model catalog
            self.reasoning,
        )
    }

    /// Customer-facing entry point for the v1 fact-based pipeline.
    /// Parses `sql`, lowers every `GRANT` / `REVOKE` statement to a typed
    /// `PrivilegePlan`, projects to public `PrivilegeFacts`, and evaluates
    /// the built-in privilege-rule corpus. Returns one `Signal` per rule
    /// match.
    ///
    /// Scope: privilege statements only — non-Grant/Revoke statements are
    /// skipped silently.
    pub fn analyze_privilege_facts(
        &self,
        sql: &str,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        let script = parse_sql(sql)?;
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_privilege_rules_for_script(
            &script,
            sql,
            &fold,
            None,
            corpus,
            self.reasoning,
            None,
            None,
        ))
    }

    /// Catalog-aware variant of [`Self::analyze_privilege_facts`].
    ///
    /// Mirrors the no-catalog entry point but threads `catalog` through
    /// the facts projection so rules predicating on
    /// `privilege.role_grant_impact` (effective-access expansion analysis
    /// driven by the grant graph) can fire. Rules that do not depend on
    /// catalog-derived facts behave identically across the two entry
    /// points.
    pub fn analyze_privilege_facts_with_catalog(
        &self,
        sql: &str,
        catalog: &crate::catalog::CatalogIndex,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        let script = parse_sql(sql)?;
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_privilege_rules_for_script(
            &script,
            sql,
            &fold,
            Some(catalog),
            corpus,
            self.reasoning,
            None,
            None,
        ))
    }

    /// Customer-facing entry point for the v1 fact-based pipeline over
    /// stage / storage-DDL statements. Parses `sql`, lowers every supported
    /// stage statement to its typed [`crate::ir::StagePlan`], projects to
    /// public [`facts::StatementFacts`] (`kind = create_stage`, populated
    /// `ddl.stage`), and evaluates the loaded built-in rule corpus against
    /// each statement's facts.
    ///
    /// Returns one `Signal` per rule match across all statements in the
    /// input. Statements outside the supported family are skipped silently
    /// — the customer pipeline is permissive by design so a single
    /// un-handled fragment doesn't suppress signals on the rest of the
    /// script.
    ///
    /// Current scope: `CREATE STAGE`, `ALTER STAGE`, `COPY INTO <location>`,
    /// `CREATE [STORAGE | SERVICE] CREDENTIAL`, and `ALTER [STORAGE |
    /// SERVICE] CREDENTIAL`. The two stage-DDL families dispatch through
    /// `derive_facts_from_stage_plan`; the storage-credential family
    /// dispatches through `derive_facts_from_storage_credential_plan`.
    /// Both feed the same `evaluate_rules` corpus.
    pub fn analyze_ddl_facts(&self, sql: &str) -> Result<Vec<rules::Signal>, error::ParseError> {
        self.analyze_ddl_facts_inner(sql, None)
    }

    /// Dialect-aware variant of [`Self::analyze_ddl_facts`]. Required for the
    /// MSSQL-* DDL rules (BULK INSERT, CREATE LOGIN / USER, CREATE / ALTER /
    /// DROP EXTERNAL MODEL): the default Snowflake-dialect parser does not
    /// recognise the T-SQL-specific grammar these statements use, so the
    /// dispatch table below would never see a `MssqlBulkInsert` /
    /// `MssqlCreateLogin` / etc. variant without dialect-aware parsing.
    pub fn analyze_ddl_facts_with_dialect(
        &self,
        sql: &str,
        dialect: &dyn Dialect,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        self.analyze_ddl_facts_inner(sql, Some(dialect))
    }

    fn analyze_ddl_facts_inner(
        &self,
        sql: &str,
        dialect: Option<&dyn Dialect>,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        let script = match dialect {
            Some(d) => parse_sql_with_dialect(sql, d)?,
            None => parse_sql(sql)?,
        };
        let dialect_name = dialect.map(|d| d.name()).unwrap_or("snowflake");
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        let reasoning = self.reasoning;
        let script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
            script: &script,
            source: sql,
            dialect_name,
            fold: &fold,
            catalog: None,
            model_catalog: None,
        });
        Ok(evaluate_ddl_rules_for_script(
            &script,
            sql,
            &fold,
            corpus,
            reasoning,
            script_reasoning.as_ref(),
            None,
            None,
        ))
    }

    /// Customer-facing entry point for the v1 fact-based pipeline over
    /// query-bearing statements. Parses `sql`, lowers every query-bearing
    /// statement (`SELECT` / `INSERT` / `UPDATE` / `DELETE` / `MERGE` /
    /// `MULTI INSERT` / set-ops / composite `CREATE … AS` DDL) to its
    /// typed `RelPlan`, projects to public `QueryFacts`, and evaluates the
    /// loaded built-in rule corpus against each statement's facts.
    ///
    /// Returns one `Signal` per rule match across all statements in the
    /// input. Statement order is preserved; within a statement, signal
    /// order follows the rule corpus's source order (per
    /// `src/rules/loader.rs`).
    ///
    /// Statements that fail to lower or that are non-query (pure DDL,
    /// session statements) are skipped silently; the customer pipeline is
    /// permissive by design so a single un-handled fragment doesn't
    /// suppress signals on the rest of the script.
    ///
    /// The loaded rule corpus is the unified built-in YAML
    /// (`rules::all_builtin_rules`); rules predicate on `kind: <variant>`
    /// to scope themselves to the statement family they target.
    pub fn analyze_query_facts(&self, sql: &str) -> Result<Vec<rules::Signal>, error::ParseError> {
        self.analyze_query_facts_inner(sql, None, None)
    }

    /// Catalog-aware variant of [`Self::analyze_query_facts`]. Threads
    /// `catalog` into IR lowering so the IR-derived `IndexedCatalogContext`
    /// carries row counts, table tags, and per-column metadata; the facts
    /// projection consults that sidecar when populating `TableEvent`,
    /// `ColumnRef`, `JoinColumnPair`, `WindowEvent.partition_high_cardinality`,
    /// and `ProjectionEvent.taint_labels`. Catalog-gated rules (`*-CENH`,
    /// `Q-AGG-EXPLODE-CENH`, `Q-WIN-UNBOUNDED-CENH`, `Q-NULL-NEQ`, `Q-NULL-COUNT-CENH`,
    /// `Q-AGG-HICARD`, `Q-WIN-HICARD-CENH`, `Q-FLOW-TAINT`, `Q-VIEW-REF-CENH`)
    /// fire only when this entry point is used (or any other path that
    /// supplies a catalog).
    pub fn analyze_query_facts_with_catalog(
        &self,
        sql: &str,
        catalog: &crate::catalog::CatalogIndex,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        self.analyze_query_facts_inner(sql, Some(catalog), None)
    }

    /// Dialect-aware variant of [`Self::analyze_query_facts`]. The MSSQL-HINT-*
    /// rule family requires `Dialect::MsSql` parsing so the lexer
    /// recognises `WITH (NOLOCK)` as a T-SQL table hint rather than a CTE
    /// keyword. Without this, the parser produces an opaque fallback and
    /// no `query.table_hints` are projected. Mirrors
    /// [`parse_sql_with_dialect`] semantics on the parse side.
    pub fn analyze_query_facts_with_dialect(
        &self,
        sql: &str,
        dialect: &dyn Dialect,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        self.analyze_query_facts_inner(sql, None, Some(dialect))
    }

    fn analyze_query_facts_inner(
        &self,
        sql: &str,
        catalog: Option<&crate::catalog::CatalogIndex>,
        dialect: Option<&dyn Dialect>,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        let script = match dialect {
            Some(d) => parse_sql_with_dialect(sql, d)?,
            None => parse_sql(sql)?,
        };
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        let reasoning = self.reasoning;
        let mut script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
            script: &script,
            source: sql,
            dialect_name: dialect.map(|d| d.name()).unwrap_or("snowflake"),
            fold: &fold,
            catalog,
            model_catalog: None,
        });
        Ok(evaluate_query_rules_for_script(
            &script,
            sql,
            &fold,
            catalog,
            None,
            corpus,
            reasoning,
            script_reasoning.as_mut(),
            None,
            None,
        ))
    }

    /// Customer-facing entry point for the v1 fact-based pipeline over
    /// principal-policy *attachment* statements.
    ///
    /// Parses `sql`, lowers every typed `ALTER USER` / `ALTER ACCOUNT`
    /// statement (the AUTHPOL-attachment slice — see
    /// [`crate::ast::AstAlterUser`] / [`crate::ast::AstAlterAccount`]) into
    /// its [`crate::ir::PolicyAttachmentPlan`], projects to public
    /// [`facts::StatementFacts`] (`kind = alter_user | alter_account`,
    /// populated `policy_attachment`), and evaluates the loaded built-in
    /// rule corpus against each statement's facts.
    ///
    /// Returns one `Signal` per rule match across all statements in the
    /// input. Statements outside the AUTHPOL-attachment family are skipped
    /// silently — the customer pipeline is permissive by design so a single
    /// un-handled fragment doesn't suppress signals on the rest of the
    /// script.
    ///
    /// Current scope: the Snowflake AUTHPOL attachment forms
    /// `ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY
    /// [= <policy>]` and `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION
    /// POLICY [= <policy>]`. Both feed `evaluate_rules` against the unified
    /// builtin corpus.
    pub fn analyze_policy_attachment_facts(
        &self,
        sql: &str,
    ) -> Result<Vec<rules::Signal>, error::ParseError> {
        let script = parse_sql(sql)?;
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_policy_attachment_rules_for_script(
            &script, sql, &fold, corpus, None, None,
        ))
    }
}
