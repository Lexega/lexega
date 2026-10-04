// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Seam between recognition and reasoning.
//!
//! Fact extraction recognises what each statement structurally is. The
//! semantic analyses that refine those facts — nullability, lineage,
//! taint, uniqueness, constraint propagation, dynamic-SQL argument
//! resolution, cross-statement schema state — are reached only through
//! the traits in this module, so the extraction walk never names an
//! analysis directly. [`RecognitionOnly`] answers every query with "no
//! information": a run against it yields recognition facts alone, with
//! every reasoning-derived field left at its default.

use std::collections::BTreeSet;

use crate::ast::{AstCallArg, AstExpr, AstScript, AstStmt, AstUnloadSource, NodeId};
use crate::ir::always_true::NonNullProof;
use crate::ir::catalog_context::{CatalogContext, IndexedCatalogContext};
use crate::ir::column::{BindingTable, ColumnId};
use crate::ir::dynamic_sql::{
    classify_execute_immediate_arg, classify_scalar_expr_argument, DynamicSqlArgIr,
    DynamicSqlCallIr, SpliceClass, SyntacticShapes,
};
use crate::ir::model_catalog::ModelCatalog;
use crate::ir::plan::{CteBinding, RelPlan};
use crate::ir::types::SessionContext;
use crate::ir::FunctionCatalog;
use crate::lexer::token::Span;

use super::catalog::{Nullability, TaintLabel, ValueExposure};
use super::ddl::ExportedColumn;
use super::privilege::{ObjectGrantImpactFacts, RoleGrantImpactFacts};
use super::query::{
    ColumnConstraintEvent, OrTautologyEvent, PredicateCrossScopeEffect, RepeatedSubqueryEvent,
    TemporalJoinTable,
};
use super::statement::StatementFacts;

/// Everything a reasoning handle needs about one relational plan.
pub struct QueryInputs<'a> {
    pub plan: &'a RelPlan,
    pub bindings: &'a BindingTable,
    /// The attached catalog, when the caller resolved one.
    pub catalog: Option<&'a IndexedCatalogContext>,
    pub function_catalog: &'a FunctionCatalog,
    pub source: &'a str,
    /// CTE bindings visible from enclosing scopes; empty at a statement root.
    pub outer_ctes: &'a [&'a CteBinding],
    /// Volatile columns of every enclosing scope; empty at a statement root.
    pub outer_volatile: &'a BTreeSet<ColumnId>,
}

/// Everything a reasoning handle needs about one script.
pub struct ScriptInputs<'a> {
    pub script: &'a AstScript,
    pub source: &'a str,
    pub dialect_name: &'a str,
    pub fold: &'a crate::ScriptContextFold,
    pub catalog: Option<&'a crate::catalog::CatalogIndex>,
    pub model_catalog: Option<&'a ModelCatalog>,
}

/// Where a routine call site sits, for inter-procedural dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSiteKind {
    /// T-SQL `EXEC proc [args]`.
    MssqlExec,
    /// `CALL proc(args)`.
    Call,
}

/// A routine call site whose callee may reach a dynamic-SQL sink.
pub struct CallSite<'a> {
    pub span: Span,
    pub callee_name_span: Option<Span>,
    pub args_span: Option<Span>,
    pub args: &'a [AstCallArg],
    pub node_id: NodeId,
    pub kind: CallSiteKind,
}

/// A column reference inside a filter predicate together with what the
/// predicate does to NULLs in that column. `nullability` is the
/// column's classification at the predicate site, every proof applied.
pub struct PredicateNullWitness {
    pub predicate_span: Span,
    pub column: ColumnId,
    pub column_ref_span: Option<Span>,
    pub nullability: Nullability,
    pub drops_null_row: bool,
    pub null_addressed: bool,
    pub aggregate_derived: bool,
    pub inequality_compared: bool,
    pub null_literal_compared: bool,
    pub inner_join_key_protected: bool,
}

/// Reach of a privilege grant through the catalog's role hierarchy.
#[derive(Default)]
pub struct GrantImpacts {
    pub role: Option<RoleGrantImpactFacts>,
    pub object: Option<ObjectGrantImpactFacts>,
}

/// Findings produced by analysing the SQL inside dynamic-SQL string
/// literals, remapped onto the enclosing script.
pub struct DynamicBodyOutcome {
    pub signals: Vec<crate::analyzer::RuleMatch>,
    pub tables_read: std::collections::HashSet<String>,
    pub tables_written: std::collections::HashSet<String>,
}

impl DynamicBodyOutcome {
    pub fn empty() -> Self {
        Self {
            signals: Vec::new(),
            tables_read: std::collections::HashSet::new(),
            tables_written: std::collections::HashSet::new(),
        }
    }
}

/// Fact fields a [`Reasoning`] provider supplies or refines, as
/// `(enclosing key, field)`. `*` matches any enclosing key. Array
/// positions do not count as keys, so a field of every element of
/// `aggregates` is enclosed by `aggregates`.
///
/// Under [`RecognitionOnly`] each of these holds its default, so a rule
/// that reads one sees less than a provider would show it.
pub const REASONING_FIELDS: &[(&str, &str)] = &[
    // Nullability of a column at its use site.
    ("*", "nullability"),
    ("aggregates", "on_nullable_argument"),
    ("*", "null_effects"),
    ("*", "cross_scope_effects"),
    // Constraint propagation over predicates.
    ("*", "column_constraints"),
    ("*", "or_tautologies"),
    // A predicate that keeps every row only because a column is proven
    // non-null.
    ("*", "has_tautology_where"),
    // Uniqueness and key relationships of join columns.
    ("on_columns", "unique_key_backing_known"),
    ("on_columns", "unique_key_backed"),
    ("on_columns", "fk_relationship"),
    // Cardinality.
    ("scopes", "has_high_cardinality_group_by"),
    ("scopes", "high_cardinality_group_by_columns"),
    ("window_functions", "partition_high_cardinality"),
    // Volatility along lineage.
    ("aggregates", "deterministic"),
    ("window_functions", "deterministic"),
    // Temporal columns of the scans a statement joins.
    ("*", "temporal_gating_expressions"),
    ("*", "temporal_join_tables"),
    // Taint.
    ("projections", "taint_labels"),
    ("projections", "value_exposure"),
    ("stage", "exported_columns"),
    // Dynamic-SQL argument resolution.
    ("dynamic_sql_calls", "argument"),
    ("dynamic_sql_calls", "taint_splices"),
    // Cross-statement schema state.
    ("*", "stale_table_refs"),
    ("*", "stale_column_refs"),
    // Repeated subqueries.
    ("*", "repeated_subqueries"),
    // Access a grant opens up, read from the catalog's grant graph.
    ("privilege", "role_grant_impact"),
    ("privilege", "object_grant_impact"),
];

/// Whether `field`, directly under the key `enclosing`, is one of
/// [`REASONING_FIELDS`].
pub fn is_reasoning_field(enclosing: &str, field: &str) -> bool {
    REASONING_FIELDS
        .iter()
        .any(|(parent, name)| *name == field && (*parent == "*" || *parent == enclosing))
}

/// Factory for the per-plan and per-script reasoning handles.
pub trait Reasoning {
    /// Whether this provider performs semantic analysis. One that does
    /// not leaves every fact in [`REASONING_FIELDS`] at its default, and
    /// the report counts the rules that read them.
    fn provides_analysis(&self) -> bool;

    fn for_query<'a>(&'a self, inputs: QueryInputs<'a>) -> Box<dyn QueryReasoning + 'a>;

    fn for_script<'a>(&'a self, inputs: ScriptInputs<'a>) -> Box<dyn ScriptReasoning + 'a>;

    /// Proof of which of the plan's columns hold no NULLs, for judging
    /// whether its row-selecting predicate keeps every row. `None` when
    /// nothing can be proven.
    fn non_null_proof<'a>(
        &'a self,
        plan: &'a RelPlan,
        bindings: &'a BindingTable,
        catalog: Option<&'a dyn CatalogContext>,
    ) -> Option<Box<dyn NonNullProof + 'a>>;

    /// Analyse the SQL carried inside dynamic-SQL string literals and
    /// report its findings against the enclosing script.
    fn dynamic_sql_literal_bodies(
        &self,
        source: &str,
        script: &AstScript,
        config: &crate::analyzer::AnalysisConfig,
        source_file: Option<&str>,
    ) -> DynamicBodyOutcome;

    /// Reach of a privilege grant through the attached catalog's role
    /// hierarchy.
    fn grant_impacts(&self, plan: &crate::ir::PrivilegePlan, source: &str) -> GrantImpacts;

    /// Adopt the analysis dialect for the current thread before lowering
    /// begins; `None` is the Snowflake default.
    fn configure_dialect(&self, dialect: Option<&dyn crate::dialect::Dialect>);

    /// Render a Jinja / dbt template to the SQL to analyse, with the
    /// provenance the report needs. `file_path` locates the project the
    /// template belongs to. A source that could not be rendered comes
    /// back as its template text, marked not rendered.
    fn render_template(
        &self,
        source: &str,
        file_path: Option<&std::path::Path>,
    ) -> crate::template::RenderArtifacts;
}

/// Reasoning over one relational plan, consulted by the facts walk.
pub trait QueryReasoning {
    /// Whether the whole column can be NULL at the plan's output.
    fn is_column_nullable(&self, col: ColumnId) -> bool;

    /// Base-source columns the column's value is drawn from, through
    /// every CTE / derived-table / set-op pass-through.
    fn lineage_roots(&self, col: ColumnId) -> Option<&BTreeSet<ColumnId>>;

    /// Whether the column is provably unique at its binding site.
    fn is_unique(&self, col: ColumnId) -> bool;

    /// Whether uniqueness was analysed at all, so that "not unique" is
    /// a finding rather than an absence of information.
    fn uniqueness_known(&self) -> bool;

    /// Columns whose value reaches a volatile function along their lineage.
    fn volatile_columns(&self) -> &BTreeSet<ColumnId>;

    /// Taint labels flowing into the output column with this display name.
    fn output_taint_labels(&self, display_name: &str) -> Vec<TaintLabel>;

    /// How much of a tainted value the output column with this display
    /// name exposes.
    fn output_value_exposure(&self, display_name: &str) -> ValueExposure;

    /// Whether an enclosing filter or null-safe wrapper guarantees the
    /// projected column is non-null; `at` restricts the proof to filters
    /// strictly upstream of that predicate site.
    fn is_projected_col_null_guarded(
        &self,
        col: ColumnId,
        ctes_in_scope: &[&CteBinding],
        at: Option<Span>,
    ) -> bool;

    /// Whether a column's defining expression makes its value non-null
    /// by shape alone (literal, cast of a literal, null-safe wrapper, …).
    fn is_column_provably_non_null_by_shape(
        &self,
        col: ColumnId,
        ctes_in_scope: &[&CteBinding],
    ) -> bool;

    /// Whether the column is high-cardinality (name pattern plus any
    /// catalog row-count evidence).
    fn is_high_cardinality_column(&self, col: ColumnId) -> bool;

    /// Per-column constraint atoms aggregated across the plan's
    /// predicates, with lattice anomalies attached.
    fn column_constraint_events(&self) -> Vec<ColumnConstraintEvent>;

    /// `OR` branches that make a predicate always true for a column.
    fn or_tautology_events(&self) -> Vec<OrTautologyEvent>;

    /// Null-handling witnesses for every column referenced at a
    /// `WHERE` / `QUALIFY` filter site.
    fn predicate_null_witnesses(&self) -> Vec<PredicateNullWitness>;

    /// Constraint relationships between a predicate and the upstream
    /// scope it filters, keyed by predicate span.
    fn cross_scope_effects(&self) -> Vec<(Span, PredicateCrossScopeEffect)>;

    /// Scans that declare temporal columns.
    fn temporal_join_tables(&self) -> Vec<TemporalJoinTable>;

    /// Whether a column reference is a temporal column of one of those
    /// scans.
    fn is_temporal_gating_column(&self, col: ColumnId) -> bool;

    /// Structurally identical subqueries that occur more than once.
    fn repeated_subqueries(&self) -> Vec<RepeatedSubqueryEvent>;
}

/// Reasoning over one script: state folded across its statements.
pub trait ScriptReasoning {
    /// Dynamic-SQL argument classifier seeded with the script's
    /// top-level variable assignments.
    fn dynamic_sql(&self) -> &dyn DynamicSqlClassifier;

    /// Classifier seeded with one routine body's own assignments.
    fn dynamic_sql_for_body<'b>(&'b self, body: &'b AstStmt) -> Box<dyn DynamicSqlClassifier + 'b>;

    /// Dynamic-SQL sinks reached inside routines that `body` calls.
    fn inter_procedural_calls(&self, body: &AstStmt) -> Vec<DynamicSqlCallIr>;

    /// Dynamic-SQL sinks a call site reaches inside its callee, one per
    /// argument that flows into the callee's sink.
    fn call_site_calls(&self, site: &CallSite<'_>) -> Vec<DynamicSqlCallIr>;

    /// Attach references to tables and columns that earlier DDL in the
    /// script dropped or renamed. `position` is the statement's index
    /// among the top-level statements.
    fn attach_stale_references(
        &mut self,
        facts: &mut StatementFacts,
        position: usize,
        plan: &RelPlan,
        bindings: &BindingTable,
        catalog: Option<&IndexedCatalogContext>,
    );

    /// Columns an unload's source query exports, classified by the
    /// taint reaching each one.
    fn exported_columns(
        &self,
        source: &AstUnloadSource,
        session: &SessionContext,
    ) -> Vec<ExportedColumn>;
}

/// Classifies the SQL-string argument of a dynamic-SQL call.
pub trait DynamicSqlClassifier {
    /// The argument's shape, resolving variables through whatever
    /// assignments the classifier has seen.
    fn classify_arg(&self, expr: &AstExpr, source: &str) -> DynamicSqlArgIr;

    /// Positions at which runtime values splice into the argument.
    fn classify_arg_splices(&self, expr: &AstExpr, source: &str) -> Vec<SpliceClass>;

    /// Shape and splices recorded for a bare variable, when an
    /// assignment seeded it.
    fn variable_shape(&self, name: &str) -> Option<(DynamicSqlArgIr, Vec<SpliceClass>)>;

    /// The argument's shape when it is a lowered expression (a
    /// dynamic-SQL function call inside a query).
    fn classify_scalar_arg(&self, expr: &crate::ir::scalar::ScalarExpr) -> DynamicSqlArgIr;
}

/// Argument classification from the expression's own shape, with
/// variables left unresolved and no splice recovery.
pub struct SyntacticClassifier;

impl DynamicSqlClassifier for SyntacticClassifier {
    fn classify_arg(&self, expr: &AstExpr, source: &str) -> DynamicSqlArgIr {
        classify_execute_immediate_arg(expr, source)
    }

    fn classify_arg_splices(&self, _expr: &AstExpr, _source: &str) -> Vec<SpliceClass> {
        Vec::new()
    }

    fn variable_shape(&self, _name: &str) -> Option<(DynamicSqlArgIr, Vec<SpliceClass>)> {
        None
    }

    fn classify_scalar_arg(&self, expr: &crate::ir::scalar::ScalarExpr) -> DynamicSqlArgIr {
        classify_scalar_expr_argument(expr, &SyntacticShapes)
    }
}

/// The provider that performs no reasoning.
pub struct RecognitionOnly;

impl Reasoning for RecognitionOnly {
    fn provides_analysis(&self) -> bool {
        false
    }

    fn for_query<'a>(&'a self, _inputs: QueryInputs<'a>) -> Box<dyn QueryReasoning + 'a> {
        Box::new(NoQueryReasoning {
            empty: BTreeSet::new(),
        })
    }

    fn for_script<'a>(&'a self, _inputs: ScriptInputs<'a>) -> Box<dyn ScriptReasoning + 'a> {
        Box::new(NoScriptReasoning)
    }

    fn non_null_proof<'a>(
        &'a self,
        _plan: &'a RelPlan,
        _bindings: &'a BindingTable,
        _catalog: Option<&'a dyn CatalogContext>,
    ) -> Option<Box<dyn NonNullProof + 'a>> {
        None
    }

    fn dynamic_sql_literal_bodies(
        &self,
        _source: &str,
        _script: &AstScript,
        _config: &crate::analyzer::AnalysisConfig,
        _source_file: Option<&str>,
    ) -> DynamicBodyOutcome {
        DynamicBodyOutcome::empty()
    }

    fn grant_impacts(&self, _plan: &crate::ir::PrivilegePlan, _source: &str) -> GrantImpacts {
        GrantImpacts::default()
    }

    fn configure_dialect(&self, _dialect: Option<&dyn crate::dialect::Dialect>) {}

    fn render_template(
        &self,
        source: &str,
        _file_path: Option<&std::path::Path>,
    ) -> crate::template::RenderArtifacts {
        crate::template::RenderArtifacts::not_rendered(
            source.to_string(),
            "template rendering is not available in this build".to_string(),
        )
    }
}

struct NoQueryReasoning {
    empty: BTreeSet<ColumnId>,
}

impl QueryReasoning for NoQueryReasoning {
    fn is_column_nullable(&self, _col: ColumnId) -> bool {
        false
    }

    fn lineage_roots(&self, _col: ColumnId) -> Option<&BTreeSet<ColumnId>> {
        None
    }

    fn is_unique(&self, _col: ColumnId) -> bool {
        false
    }

    fn uniqueness_known(&self) -> bool {
        false
    }

    fn volatile_columns(&self) -> &BTreeSet<ColumnId> {
        &self.empty
    }

    fn output_taint_labels(&self, _display_name: &str) -> Vec<TaintLabel> {
        Vec::new()
    }

    fn output_value_exposure(&self, _display_name: &str) -> ValueExposure {
        ValueExposure::Value
    }

    fn is_projected_col_null_guarded(
        &self,
        _col: ColumnId,
        _ctes_in_scope: &[&CteBinding],
        _at: Option<Span>,
    ) -> bool {
        false
    }

    fn is_column_provably_non_null_by_shape(
        &self,
        _col: ColumnId,
        _ctes_in_scope: &[&CteBinding],
    ) -> bool {
        false
    }

    fn is_high_cardinality_column(&self, _col: ColumnId) -> bool {
        false
    }

    fn column_constraint_events(&self) -> Vec<ColumnConstraintEvent> {
        Vec::new()
    }

    fn or_tautology_events(&self) -> Vec<OrTautologyEvent> {
        Vec::new()
    }

    fn predicate_null_witnesses(&self) -> Vec<PredicateNullWitness> {
        Vec::new()
    }

    fn cross_scope_effects(&self) -> Vec<(Span, PredicateCrossScopeEffect)> {
        Vec::new()
    }

    fn temporal_join_tables(&self) -> Vec<TemporalJoinTable> {
        Vec::new()
    }

    fn is_temporal_gating_column(&self, _col: ColumnId) -> bool {
        false
    }

    fn repeated_subqueries(&self) -> Vec<RepeatedSubqueryEvent> {
        Vec::new()
    }
}

struct NoScriptReasoning;

impl ScriptReasoning for NoScriptReasoning {
    fn dynamic_sql(&self) -> &dyn DynamicSqlClassifier {
        &SyntacticClassifier
    }

    fn dynamic_sql_for_body<'b>(
        &'b self,
        _body: &'b AstStmt,
    ) -> Box<dyn DynamicSqlClassifier + 'b> {
        Box::new(SyntacticClassifier)
    }

    fn inter_procedural_calls(&self, _body: &AstStmt) -> Vec<DynamicSqlCallIr> {
        Vec::new()
    }

    fn call_site_calls(&self, _site: &CallSite<'_>) -> Vec<DynamicSqlCallIr> {
        Vec::new()
    }

    fn attach_stale_references(
        &mut self,
        _facts: &mut StatementFacts,
        _position: usize,
        _plan: &RelPlan,
        _bindings: &BindingTable,
        _catalog: Option<&IndexedCatalogContext>,
    ) {
    }

    fn exported_columns(
        &self,
        _source: &AstUnloadSource,
        _session: &SessionContext,
    ) -> Vec<ExportedColumn> {
        Vec::new()
    }
}
