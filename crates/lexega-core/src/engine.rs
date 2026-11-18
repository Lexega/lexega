// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The analysis engine bound to a reasoning provider.

use crate::dialect::Dialect;
use crate::facts::reasoning::{Reasoning, RecognitionOnly};
use crate::{
    adopt_dialect, alter_account_facts, alter_user_facts, analyze_carrying, analyze_for_comparison,
    analyze_reading_last, analyze_risk_core, analyzer, ast, build_script_context_fold,
    builtin_load_failure_to_parse_error, ddl_family, ddl_statement_facts, error,
    evaluate_statements, facts, flat_stmts_for_rules, ir, parse_sql, parse_sql_with_dialect,
    parse_with_optional_dialect, prepare_and_parse_for_analysis,
    prepare_sql_for_analysis_with_context, privilege_plan_facts, query_facts, reported_unwalked,
    rules, script_relations, template, CarriedRelations, DdlFamily, DdlReading, DialectScope,
    FamilyReader, LastStatement, PreparedScript, QueryReading, ScriptAnalysis,
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

    /// Substitution pre-passes, template render and dialect-aware parse
    /// for one source, in that order. Adopts no dialect: the analysis of
    /// the result does.
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

    /// Adopt `dialect` (Snowflake when `None`) for the current thread until
    /// the returned scope is dropped, then give the thread back what it had
    /// before. Keep the scope alive across everything that lowers a
    /// statement or folds a name outside [`Self::analyze_script`]: with no
    /// scope alive, a debug build panics at the first name folded and a
    /// release build folds it as Snowflake does, whatever the thread
    /// analysed earlier; a provider's hold dropped as its scope ends is the
    /// one exception (see [`crate::facts::reasoning::DialectHold`]). Scopes
    /// are dropped innermost first, on the thread that opened them: see
    /// [`DialectScope`].
    pub fn apply_dialect(&self, dialect: &Option<crate::dialect::DialectRef>) -> DialectScope {
        adopt_dialect(dialect.as_deref(), self.reasoning)
    }

    /// Analyze a parsed script under `policy_config`'s dialect, which it
    /// adopts for its own length. `render.sql` must be the exact text
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

    /// [`Self::analyze_script`], `read_last` called with the script's last
    /// statement as the analysis lowers it to read it as a query
    /// ([`LastStatement`]); not called where the analysis lowers no such
    /// statement (one that does not lower, or a corpus of no rule).
    #[allow(clippy::too_many_arguments)] // mirrors `analyze_script`, and the reader
    pub fn analyze_script_reading_last(
        &self,
        render: &template::RenderArtifacts,
        script: &ast::AstScript,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        catalog_path: Option<&str>,
        source_file: Option<&str>,
        model_catalog: Option<&ir::model_catalog::ModelCatalog>,
        read_last: &mut dyn FnMut(LastStatement<'_>),
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        analyze_reading_last(
            render,
            script,
            policy_config,
            catalog_index,
            catalog_path,
            source_file,
            model_catalog,
            self.reasoning,
            read_last,
        )
    }

    /// [`Self::analyze_script`] as one of a set of scripts run in order:
    /// `carried` holds the relations the scripts run before it leave
    /// ([`CarriedRelations`]), which its statements find before they change
    /// them, and afterwards those it leaves for the script run after it,
    /// the very ones its own analysis read. Unchanged where the analysis
    /// fails.
    #[allow(clippy::too_many_arguments)] // mirrors `analyze_script`, and the carried relations
    pub fn analyze_script_carrying(
        &self,
        render: &template::RenderArtifacts,
        script: &ast::AstScript,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        catalog_path: Option<&str>,
        source_file: Option<&str>,
        model_catalog: Option<&ir::model_catalog::ModelCatalog>,
        carried: &mut CarriedRelations,
    ) -> Result<analyzer::AnalysisReport, analyzer::RiskError> {
        analyze_carrying(
            render,
            script,
            policy_config,
            catalog_index,
            catalog_path,
            source_file,
            model_catalog,
            carried,
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
        let (render, script) = substituted_and_parsed(render, policy_config)?;
        analyze_risk_core(
            &render,
            &script,
            policy_config,
            catalog_index,
            None,
            source_file,
            None, // no model catalog
            self.reasoning,
        )
    }

    /// [`Self::analyze_risk_with_source_map`], keeping what comparing the
    /// script with another reads: the text analysed, each statement's facts
    /// and the report's findings occurrence by occurrence
    /// ([`ScriptAnalysis::findings_of`]).
    pub fn analyze_for_comparison(
        &self,
        render: &template::RenderArtifacts,
        policy_config: &analyzer::AnalysisConfig,
        catalog_index: Option<&crate::catalog::CatalogIndex>,
        source_file: Option<&str>,
    ) -> Result<ScriptAnalysis, analyzer::RiskError> {
        let (render, script) = substituted_and_parsed(render, policy_config)?;
        analyze_for_comparison(
            &render,
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
    /// the built-in privilege-rule corpus. Returns one `Finding` per rule
    /// match.
    ///
    /// Scope: privilege statements only — non-Grant/Revoke statements are
    /// skipped silently.
    pub fn analyze_privilege_facts(
        &self,
        sql: &str,
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        let script = parse_sql(sql)?;
        let _dialect = adopt_dialect(None, self.reasoning);
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_statements(
            &flat_stmts_for_rules(&script),
            &fold,
            &reported_unwalked(&script, sql, None),
            corpus,
            None,
            None,
            |_, stmt, _, readings| {
                if let DdlFamily::Privilege(plan) = ddl_family(stmt, sql, &[]) {
                    readings
                        .families
                        .push(privilege_plan_facts(&plan, sql, None, self.reasoning));
                }
            },
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
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        let script = parse_sql(sql)?;
        let _dialect = adopt_dialect(None, self.reasoning);
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_statements(
            &flat_stmts_for_rules(&script),
            &fold,
            &reported_unwalked(&script, sql, None),
            corpus,
            None,
            None,
            |_, stmt, _, readings| {
                if let DdlFamily::Privilege(plan) = ddl_family(stmt, sql, &[]) {
                    readings.families.push(privilege_plan_facts(
                        &plan,
                        sql,
                        Some(catalog),
                        self.reasoning,
                    ));
                }
            },
        ))
    }

    /// Customer-facing entry point for the v1 fact-based pipeline over
    /// stage / storage-DDL statements. Parses `sql`, lowers every supported
    /// stage statement to its typed [`crate::ir::StagePlan`], projects to
    /// public [`facts::StatementFacts`] (`kind = create_stage`, populated
    /// `ddl.stage`), and evaluates the loaded built-in rule corpus against
    /// each statement's facts.
    ///
    /// Returns one `Finding` per rule match across all statements in the
    /// input. Statements outside the supported family are skipped silently
    /// — the customer pipeline is permissive by design so a single
    /// un-handled fragment doesn't suppress findings on the rest of the
    /// script.
    ///
    /// Current scope: `CREATE STAGE`, `ALTER STAGE`, `COPY INTO <location>`,
    /// `CREATE [STORAGE | SERVICE] CREDENTIAL`, and `ALTER [STORAGE |
    /// SERVICE] CREDENTIAL`. The two stage-DDL families dispatch through
    /// `derive_facts_from_stage_plan`; the storage-credential family
    /// dispatches through `derive_facts_from_storage_credential_plan`.
    /// Both feed the same `evaluate_rules` corpus.
    pub fn analyze_ddl_facts(&self, sql: &str) -> Result<Vec<rules::Finding>, error::ParseError> {
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
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        self.analyze_ddl_facts_inner(sql, Some(dialect))
    }

    fn analyze_ddl_facts_inner(
        &self,
        sql: &str,
        dialect: Option<&dyn Dialect>,
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        let script = match dialect {
            Some(d) => parse_sql_with_dialect(sql, d)?,
            None => parse_sql(sql)?,
        };
        let _dialect = adopt_dialect(dialect, self.reasoning);
        let dialect_name = dialect.map(|d| d.name()).unwrap_or("snowflake");
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        let reasoning = self.reasoning;
        let functions = crate::ir::ScriptFunctions::new(
            crate::ir::CatalogDialect::from_dialect_name(dialect_name),
            &fold,
        );
        // The dialect read, and what it states its syntax means.
        let snowflake = crate::dialect::snowflake();
        let read_in = dialect.unwrap_or(snowflake.as_ref());
        let meaning = read_in.syntax_meaning();
        let bodies_dialect = run_bodies_dialect(dialect_name);
        let (relations, bodies) = script_relations(
            &script,
            sql,
            &[],
            &fold,
            &functions,
            read_in,
            None,
            reasoning,
            None,
            None,
            &[],
            crate::RunTexts::Read {
                dialect: &bodies_dialect,
                analysed: false,
            },
        );
        let bodies = bodies.unwrap_or_else(|| crate::DynamicBodies::lending(&bodies_dialect));
        let script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
            script: &script,
            source: sql,
            dialect_name,
            fold: &fold,
            catalog: None,
            model_catalog: None,
            bodies: &bodies,
            functions: &functions,
            earlier: facts::reasoning::EarlierRemovals::none(),
            temporary_drops: relations.relations.temporary_drops(),
        });
        let query = QueryReading {
            sql,
            placeholders: &[],
            fold: &fold,
            functions: &functions,
            meaning,
            catalog: None,
            relations: &relations,
            model_catalog: None,
            reasoning,
            output_columns: false,
            last: None,
            shown_tags: &[],
        };
        let ddl = DdlReading::new(
            &script,
            sql,
            &[],
            &fold,
            &functions,
            reasoning,
            &query,
            script_reasoning.as_ref(),
        );
        Ok(evaluate_statements(
            &flat_stmts_for_rules(&script),
            &fold,
            &reported_unwalked(&script, sql, dialect),
            corpus,
            None,
            None,
            |_, stmt, sink, readings| {
                ddl_statement_facts(
                    stmt,
                    &ddl,
                    script_reasoning.as_ref(),
                    sink,
                    &mut readings.families,
                    Some(FamilyReader::Ddl),
                );
            },
        ))
    }

    /// Customer-facing entry point for the v1 fact-based pipeline over
    /// query-bearing statements. Parses `sql`, lowers every query-bearing
    /// statement (`SELECT` / `INSERT` / `UPDATE` / `DELETE` / `MERGE` /
    /// `MULTI INSERT` / set-ops / composite `CREATE … AS` DDL) to its
    /// typed `RelPlan`, projects to public `QueryFacts`, and evaluates the
    /// loaded built-in rule corpus against each statement's facts.
    ///
    /// Returns one `Finding` per rule match across all statements in the
    /// input. Statement order is preserved; within a statement, finding
    /// order follows the rule corpus's source order (per
    /// `src/rules/loader.rs`).
    ///
    /// Statements that fail to lower or that are non-query (pure DDL,
    /// session statements) are skipped silently; the customer pipeline is
    /// permissive by design so a single un-handled fragment doesn't
    /// suppress findings on the rest of the script.
    ///
    /// The loaded rule corpus is the unified built-in YAML
    /// (`rules::all_builtin_rules`); rules predicate on `kind: <variant>`
    /// to scope themselves to the statement family they target.
    pub fn analyze_query_facts(&self, sql: &str) -> Result<Vec<rules::Finding>, error::ParseError> {
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
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
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
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        self.analyze_query_facts_inner(sql, None, Some(dialect))
    }

    fn analyze_query_facts_inner(
        &self,
        sql: &str,
        catalog: Option<&crate::catalog::CatalogIndex>,
        dialect: Option<&dyn Dialect>,
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        let script = match dialect {
            Some(d) => parse_sql_with_dialect(sql, d)?,
            None => parse_sql(sql)?,
        };
        let _dialect = adopt_dialect(dialect, self.reasoning);
        let dialect_name = dialect.map(|d| d.name()).unwrap_or("snowflake");
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        let reasoning = self.reasoning;
        let functions = crate::ir::ScriptFunctions::new(
            crate::ir::CatalogDialect::from_dialect_name(dialect_name),
            &fold,
        );
        // The dialect read, and what it states its syntax means.
        let snowflake = crate::dialect::snowflake();
        let read_in = dialect.unwrap_or(snowflake.as_ref());
        let meaning = read_in.syntax_meaning();
        let bodies_dialect = run_bodies_dialect(dialect_name);
        let (relations, bodies) = script_relations(
            &script,
            sql,
            &[],
            &fold,
            &functions,
            read_in,
            catalog,
            reasoning,
            None,
            None,
            &[],
            crate::RunTexts::Read {
                dialect: &bodies_dialect,
                analysed: false,
            },
        );
        let bodies = bodies.unwrap_or_else(|| crate::DynamicBodies::lending(&bodies_dialect));
        let mut script_reasoning = reasoning.for_script(facts::reasoning::ScriptInputs {
            script: &script,
            source: sql,
            dialect_name,
            fold: &fold,
            catalog,
            model_catalog: None,
            bodies: &bodies,
            functions: &functions,
            earlier: facts::reasoning::EarlierRemovals::none(),
            temporary_drops: relations.relations.temporary_drops(),
        });
        let query = QueryReading {
            sql,
            placeholders: &[],
            fold: &fold,
            functions: &functions,
            meaning,
            catalog,
            relations: &relations,
            model_catalog: None,
            reasoning,
            output_columns: false,
            last: None,
            shown_tags: &[],
        };
        Ok(evaluate_statements(
            &flat_stmts_for_rules(&script),
            &fold,
            &reported_unwalked(&script, sql, dialect),
            corpus,
            None,
            None,
            |position, stmt, sink, readings| {
                readings.query = query_facts(
                    position,
                    stmt,
                    &query,
                    script_reasoning.as_mut(),
                    sink,
                    None,
                );
            },
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
    /// Returns one `Finding` per rule match across all statements in the
    /// input. Statements outside the AUTHPOL-attachment family are skipped
    /// silently — the customer pipeline is permissive by design so a single
    /// un-handled fragment doesn't suppress findings on the rest of the
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
    ) -> Result<Vec<rules::Finding>, error::ParseError> {
        let script = parse_sql(sql)?;
        let _dialect = adopt_dialect(None, self.reasoning);
        let fold = build_script_context_fold(&script, sql);
        let corpus = rules::all_builtin_rules().map_err(builtin_load_failure_to_parse_error)?;
        Ok(evaluate_statements(
            &flat_stmts_for_rules(&script),
            &fold,
            &reported_unwalked(&script, sql, None),
            corpus,
            None,
            None,
            |_, stmt, _, readings| {
                let family = ddl_family(stmt, sql, &[]);
                if let DdlFamily::AlterUser(u) = family {
                    readings.families.push(alter_user_facts(u, sql));
                } else if let DdlFamily::AlterAccount(a) = family {
                    readings.families.extend(alter_account_facts(a, sql));
                }
            },
        ))
    }
}

/// The dialect an entry point that analyses none of the SQL text a script
/// runs reads that text as: the dialect named `dialect_name`, Snowflake
/// where the name is not one.
fn run_bodies_dialect(dialect_name: &str) -> crate::dialect::DialectRef {
    crate::dialect::dialect_from_name(dialect_name).unwrap_or_else(crate::dialect::snowflake)
}

/// `render` with its deployment variables and SnowSQL `&var`s substituted
/// as `policy_config`'s dialect writes them, and the script parsed from it.
fn substituted_and_parsed<'a>(
    render: &'a template::RenderArtifacts,
    policy_config: &analyzer::AnalysisConfig,
) -> Result<
    (
        std::borrow::Cow<'a, template::RenderArtifacts>,
        ast::AstScript,
    ),
    analyzer::RiskError,
> {
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
    let render = if untouched {
        std::borrow::Cow::Borrowed(render)
    } else {
        let deploy_stats = analyzer::compute_placeholder_stats(&deploy.sql, &deploy.placeholders);
        let snow_stats = analyzer::compute_placeholder_stats(&prepared.sql, &prepared.placeholders);
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
        std::borrow::Cow::Owned(folded)
    };
    let script = parse_with_optional_dialect(
        &render.sql,
        &policy_config.dialect,
        &render.placeholder_spans,
    )?;
    Ok((render, script))
}
