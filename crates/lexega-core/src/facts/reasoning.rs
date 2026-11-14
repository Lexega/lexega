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

use crate::ast::{AstCallArg, AstExpr, AstProcedureParam, AstScript, AstStmt, NodeId};
use crate::context::node_metadata::IdentKey;
use crate::ir::catalog_context::{IndexedCatalogContext, TagRef};
use crate::ir::column::{BindingTable, ColumnId};
use crate::ir::constraint_types::IrColumnConstraints;
use crate::ir::dynamic_sql::{
    classify_execute_immediate_arg, classify_scalar_expr_argument, DynamicSqlArgIr,
    DynamicSqlCallIr, SpliceClass, SyntacticShapes,
};
use crate::ir::model_catalog::ModelCatalog;
use crate::ir::plan::RelPlan;
use crate::ir::FunctionCatalog;
use crate::lexer::token::Span;

use super::catalog::{Nullability, TaintLabel, ValueExposure};
use super::ddl::ExportedColumn;
use super::privilege::{ObjectGrantImpactFacts, RoleGrantImpactFacts};
use super::query::{
    ColumnConstraintEvent, OrTautologyEvent, PredicateCrossScopeEffect, QueryFacts,
    RepeatedSubqueryEvent, TemporalJoinTable,
};
use super::statement::StatementFacts;

/// Everything a reasoning handle needs about one statement's plan.
pub struct QueryInputs<'a> {
    pub plan: &'a RelPlan,
    pub bindings: &'a BindingTable,
    /// The attached catalog, when the caller resolved one.
    pub catalog: Option<&'a IndexedCatalogContext>,
    pub function_catalog: &'a FunctionCatalog,
    pub source: &'a str,
}

/// Everything a reasoning handle needs about one script.
pub struct ScriptInputs<'a> {
    pub script: &'a AstScript,
    pub source: &'a str,
    pub dialect_name: &'a str,
    pub fold: &'a crate::ScriptContextFold,
    pub catalog: Option<&'a crate::catalog::CatalogIndex>,
    pub model_catalog: Option<&'a ModelCatalog>,
    /// The SQL text the script runs, as the engine read it for the run:
    /// the texts the script builds are parsed through it, each parse shared
    /// by the readers that hold it ([`crate::DynamicBodies::built`]).
    pub bodies: &'a crate::DynamicBodies,
    /// The function catalog in force at each statement of the script, as
    /// the engine lowers it.
    pub functions: &'a crate::ir::ScriptFunctions,
    /// What the scripts run before this one, in order, left dropped or
    /// renamed away ([`EarlierRemovals`]); none for a script read on its
    /// own.
    pub earlier: &'a EarlierRemovals,
    /// The spans of the script's statements that drop a temporary table,
    /// on every path into them, which a table of its name may stand
    /// behind: after one the name names what it named before the
    /// temporary table was made.
    pub temporary_drops: &'a [crate::lexer::Span],
}

/// A table's name as a script's schema changes name it: each part
/// normalized, its database and schema where the statement or the session
/// gave them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableIdentity {
    pub database: Option<IdentKey>,
    pub schema: Option<IdentKey>,
    pub name: IdentKey,
}

impl TableIdentity {
    /// The identity of the parts written, each normalized.
    pub fn from_components(database: Option<&str>, schema: Option<&str>, name: &str) -> Self {
        Self {
            database: database.map(IdentKey::new),
            schema: schema.map(IdentKey::new),
            name: IdentKey::new(name),
        }
    }

    /// Whether `other` may name the same table: the name is the same, and
    /// the schema and the database each are where both give it and may be
    /// where either omits it. `analytics.foo` and `staging.foo` are not.
    pub fn partial_match(&self, other: &Self) -> bool {
        fn compatible(a: &Option<IdentKey>, b: &Option<IdentKey>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => a == b,
                (Some(_), None) | (None, Some(_)) | (None, None) => true,
            }
        }
        self.name == other.name
            && compatible(&self.schema, &other.schema)
            && compatible(&self.database, &other.database)
    }
}

/// Where the tables a statement names are, as its session finds them
/// ([`ScriptReasoning::attach_stale_references`]).
pub trait TablePlaces {
    /// The table `table`, a name as the statement writes it, names: a
    /// name the session leaves to its search path is in the first schema
    /// of the path that holds it, else in the path's first; any other as
    /// written. Each part normalized.
    fn place_of(&self, table: &super::identity::TableRef) -> TableIdentity;
}

/// What the scripts run before a script, in order, left removed, as their
/// statements outside a routine's body did it: each table or view dropped
/// or renamed away and not made again on every path after, and each column
/// dropped from a table and not added again nor the table made again.
/// Nothing a statement did to a temporary table, which its session holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EarlierRemovals {
    pub tables: Vec<RemovedTable>,
    pub columns: Vec<RemovedColumn>,
}

impl EarlierRemovals {
    /// Nothing removed.
    pub fn none() -> &'static Self {
        static NONE: EarlierRemovals = EarlierRemovals {
            tables: Vec::new(),
            columns: Vec::new(),
        };
        &NONE
    }
}

/// A table or view a script run before dropped or renamed away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedTable {
    pub table: TableIdentity,
    pub removal: TableRemoval,
    pub at: EarlierStatement,
}

/// How a table was removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableRemoval {
    Dropped(super::query::DroppedObjectKind),
    /// Renamed to the name written.
    RenamedTo(String),
}

/// A column a script run before dropped from a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedColumn {
    pub table: TableIdentity,
    pub column: IdentKey,
    pub at: EarlierStatement,
}

/// Where in a script run before a statement is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlierStatement {
    /// The 0-indexed position, among that script's top-level statements,
    /// of the statement or of the one holding it.
    pub index: u32,
    /// That script's file, where it is named.
    pub file: Option<String>,
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
    /// The keys of the parameters of the procedure or function whose body
    /// holds the call; none at the top level.
    pub parameters: &'a [IdentKey],
}

/// A definition, in another script of the run, of a routine a call names
/// ([`Reasoning::routines_elsewhere`]): each of its parameters in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutineRun {
    pub parameters: Vec<ParameterRun>,
    /// Whether what it runs is not established
    /// ([`crate::definition_unread`]): it may run any argument it is called
    /// with.
    pub unread: bool,
}

/// A parameter of a routine another script of the run defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterRun {
    /// Its name, as a variable of the routine's body is known; `None` for
    /// one with no name.
    pub name: Option<IdentKey>,
    /// How the routine runs the text of the argument written to it; `None`
    /// where it runs none of it.
    pub run: Option<ArgumentRun>,
}

/// How a routine runs the text of an argument it is called with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentRun {
    /// As the whole text of a statement it runs.
    Whole,
    /// Written into the text it builds and runs.
    WrittenInto,
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
    pub drops_padded_row: bool,
    pub aggregate_derived: bool,
    pub inequality_compared: bool,
    pub null_literal_compared: bool,
    pub inner_join_key_protected: bool,
}

/// A column of an earlier outer join's padded row that a join drops or
/// is not shown to keep, with its nullability where the join reads it.
pub struct DroppedPaddedColumn {
    pub column: ColumnId,
    /// Where the join's condition, or its lateral right operand, first
    /// reads the column; `None` where the join names no reference to it
    /// (a `USING` or `NATURAL` join).
    pub column_ref_span: Option<Span>,
    pub nullability: Nullability,
}

/// Where a column is read: a plan node and where in it.
#[derive(Clone, Copy)]
pub struct ReadSite<'a> {
    pub node: &'a RelPlan,
    pub at: ReadAt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAt {
    /// What the node's inputs left.
    Context,
    /// A DML node's context after one definition group's predicate.
    Selected(usize),
    /// After the node's own definitions.
    Defined,
    /// The node's output.
    Output,
    /// A join's `ON` column, for the rule that asks about join keys.
    JoinKey,
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
    /// Each finding, with the span of the statement that runs the body.
    pub findings: Vec<(crate::lexer::token::Span, crate::analyzer::RuleMatch)>,
    pub tables_read: std::collections::HashSet<String>,
    pub tables_written: std::collections::HashSet<String>,
}

impl DynamicBodyOutcome {
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
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
    ("joins", "dropped_padded_columns"),
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
    // What analysis shows of each column of the relation a statement
    // returns or makes.
    ("output_columns", "nullable"),
    ("output_columns", "sources"),
    ("output_columns", "taint_tags"),
    ("output_columns", "constraints"),
    // Taint.
    ("projections", "taint_labels"),
    ("projections", "value_exposure"),
    ("written_columns", "value_taint_labels"),
    ("written_columns", "value_exposure"),
    ("stage", "exported_columns"),
    // Dynamic-SQL argument resolution.
    ("dynamic_sql_calls", "argument"),
    ("dynamic_sql_calls", "argument_parameter"),
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

/// A provider's hold on the dialect it adopted for a thread. Dropping it
/// puts back whatever the thread had before the adoption.
///
/// The thread keeps the hold with the scope it was adopted for and drops
/// it when that scope ends. A scope still open when its thread ends has
/// its hold dropped as the thread's own state is torn down: a hold whose
/// `Drop` reads a thread-local reads it with `try_with` and does nothing
/// where it is gone.
///
/// When a scope ends, its hold is dropped after the thread's folding and
/// `FORMAT` flag are put back: a name the hold's `Drop` folds is folded
/// as the thread folded when the scope was opened. Where no scope is left
/// open as the hold drops (its scope was the outermost, or a scope around
/// it was dropped first and ended both), a debug build refuses that fold
/// and a release build still folds as the thread folded when the scope was
/// opened: as Snowflake does where that was outside every scope.
///
/// What a provider must not do, since each leaves its own state wrong:
///
/// - Leave open a dialect scope it opened while it adopted the dialect,
///   or keep one in the hold it returns. That scope ends with the scope
///   it was opened in, but the provider's state is then put back in the
///   wrong order and stays at the inner dialect.
/// - End a dialect scope from the hold's `Drop`. The thread's folding
///   goes back to where the ended scope found it; what the provider's
///   state goes back to is the provider's to get right.
/// - Panic in the hold's `Drop`. The scopes still to be ended are ended
///   and the panic goes on; a second hold that panics among them aborts
///   the process, as does one dropped while the thread is unwinding or
///   ending.
pub trait DialectHold {}

/// A provider that keeps no dialect state holds nothing.
impl DialectHold for () {}

/// Factory for the per-plan and per-script reasoning handles.
pub trait Reasoning {
    /// Whether this provider performs semantic analysis. One that does
    /// not leaves every fact in [`REASONING_FIELDS`] at its default, and
    /// the report counts the rules that read them.
    fn provides_analysis(&self) -> bool;

    fn for_query<'a>(&'a self, inputs: QueryInputs<'a>) -> Box<dyn QueryReasoning + 'a>;

    fn for_script<'a>(&'a self, inputs: ScriptInputs<'a>) -> Box<dyn ScriptReasoning + 'a>;

    /// Reach of a privilege grant through the attached catalog's role
    /// hierarchy.
    fn grant_impacts(&self, plan: &crate::ir::PrivilegePlan, source: &str) -> GrantImpacts;

    /// Adopt the analysis dialect for the current thread before lowering
    /// begins; `None` is the Snowflake default. The thread keeps it for as
    /// long as the returned hold lives.
    fn configure_dialect(
        &self,
        dialect: Option<&dyn crate::dialect::Dialect>,
    ) -> Box<dyn DialectHold>;

    /// Render a Jinja / dbt template to the SQL to analyse, with the
    /// provenance the report needs. `file_path` locates the project the
    /// template belongs to. A source that could not be rendered comes
    /// back as its template text, marked not rendered.
    fn render_template(
        &self,
        source: &str,
        file_path: Option<&std::path::Path>,
    ) -> crate::template::RenderArtifacts;

    /// Each definition another script of the run holds of the routine whose
    /// name's parts are `name`, each part folded as the dialect folds an
    /// identifier; none where the provider reads no other script. A report
    /// masks what a call's argument holds as each definition runs it, and
    /// every literal a call statement passes to a routine the run holds no
    /// definition of.
    fn routines_elsewhere(&self, name: &[IdentKey]) -> Vec<RoutineRun>;

    /// What the rows of either of two relations meet in a column, the
    /// rows of the one meeting `first` there and those of the other
    /// `second`: no constraint where reasoning has no answer.
    fn rows_of_either(
        &self,
        first: &IrColumnConstraints,
        second: &IrColumnConstraints,
    ) -> IrColumnConstraints;
}

/// Reasoning over one relational plan, consulted by the facts walk.
pub trait QueryReasoning {
    /// The reasoning of the scope rooted at `root`, a plan nested in this
    /// one's.
    fn nested<'b>(&'b self, root: &'b RelPlan) -> Box<dyn QueryReasoning + 'b>;

    /// Nullability of the column where `site` reads it. `Unknown` where
    /// reasoning has no answer.
    fn nullability(&self, site: ReadSite<'_>, col: ColumnId) -> Nullability;

    /// Base-source columns the column's value is drawn from, through
    /// every CTE / derived-table / set-op pass-through.
    fn lineage_roots(&self, col: ColumnId) -> Option<&BTreeSet<ColumnId>>;

    /// Whether the columns of `on` (those the join's `ON` equates) that
    /// the input of `join` carrying `column` carries hold a key of that
    /// input's rows. `None` where uniqueness is not analysed or neither
    /// input carries the column.
    fn key_backed(&self, join: &RelPlan, column: ColumnId, on: &[ColumnId]) -> Option<bool>;

    /// The columns of an earlier outer join's padded row that `join`
    /// drops or is not shown to keep. Empty where reasoning has no answer.
    fn dropped_padded_columns(&self, join: &RelPlan) -> Vec<DroppedPaddedColumn>;

    /// Columns whose value reaches a volatile function along their lineage.
    fn volatile_columns(&self) -> &BTreeSet<ColumnId>;

    /// Taint labels flowing into the output column `column`.
    fn output_taint_labels(&self, column: ColumnId) -> Vec<TaintLabel>;

    /// How much of a tainted value the output column `column` exposes.
    fn output_value_exposure(&self, column: ColumnId) -> ValueExposure;

    /// The catalog tags whose value reaches the output column `column`,
    /// each once, as the catalog states it, whatever the exposure: what a
    /// relation made from the plan carries in that column. Empty where
    /// reasoning has no answer.
    fn output_catalog_tags(&self, column: ColumnId) -> Vec<TagRef>;

    /// The constraints the rows of `relation`, a plan in this one, meet
    /// in its output column `column`. Empty where reasoning has no answer.
    fn output_constraints(&self, relation: &RelPlan, column: ColumnId) -> IrColumnConstraints;

    /// Whether no two rows of `relation`, a plan in this one, hold the
    /// same value in its output column `column`. `false` where reasoning
    /// has no answer.
    fn output_unique(&self, relation: &RelPlan, column: ColumnId) -> bool;

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

    /// Whether a column reference holds a temporal column of one of those
    /// scans: the column itself, or read through a CTE, a subquery or an
    /// alias, or a column a filter computes from one before its predicate.
    fn is_temporal_gating_column(&self, col: ColumnId) -> bool;

    /// Structurally identical subqueries that occur more than once.
    fn repeated_subqueries(&self) -> Vec<RepeatedSubqueryEvent>;
}

/// Reasoning over one script: state folded across its statements.
pub trait ScriptReasoning {
    /// Dynamic-SQL argument classifier of the script's top level: each
    /// call reads its variables as the script has assigned them where it
    /// runs.
    fn dynamic_sql(&self) -> &dyn DynamicSqlClassifier;

    /// Classifier of one routine body: each call reads its variables as the
    /// body has assigned them where it runs, a parameter the caller's value
    /// until the body assigns it.
    fn dynamic_sql_for_body<'b>(&'b self, body: &'b AstStmt) -> Box<dyn DynamicSqlClassifier + 'b>;

    /// Analyse the SQL `script` (the script this reasoning reads) runs: the
    /// text the engine's reading of its string literals and of the text it
    /// builds gives each run, as the run's variables hold it there. Each
    /// finding is placed at its line and column in the script's text.
    fn dynamic_sql_literal_bodies(
        &self,
        script: &AstScript,
        config: &crate::analyzer::AnalysisConfig,
    ) -> DynamicBodyOutcome;

    /// Dynamic-SQL sinks reached inside routines that `body` calls, each
    /// argument read as [`Self::dynamic_sql_for_body`] reads it.
    fn inter_procedural_calls(
        &self,
        body: &AstStmt,
        parameters: &[AstProcedureParam],
    ) -> Vec<DynamicSqlCallIr>;

    /// Attach references to tables and columns that DDL which may run
    /// before the statement dropped or renamed. `position` is the
    /// statement's index in the order [`crate::flatten_stmts_for_rules`]
    /// gives the script's statements: every statement at every depth.
    /// `places` says where each table the statement names is.
    fn attach_stale_references(
        &mut self,
        facts: &mut StatementFacts,
        position: usize,
        plan: &RelPlan,
        bindings: &BindingTable,
        catalog: Option<&IndexedCatalogContext>,
        places: &dyn TablePlaces,
    );

    /// Columns an unload exports, from `query`, the facts of the query it
    /// reads: each classified by the taint reaching it.
    fn exported_columns(&self, query: &QueryFacts) -> Vec<ExportedColumn>;
}

/// Classifies the SQL-string argument of a dynamic-SQL call.
pub trait DynamicSqlClassifier {
    /// The argument's shape, resolving variables through whatever
    /// assignments the classifier has seen.
    fn classify_arg(&self, expr: &AstExpr, source: &str) -> DynamicSqlArgIr;

    /// Positions at which runtime values splice into the argument.
    fn classify_arg_splices(&self, expr: &AstExpr, source: &str) -> Vec<SpliceClass>;

    /// The argument's shape when it is a lowered expression (a
    /// dynamic-SQL function call inside a query).
    fn classify_scalar_arg(&self, expr: &crate::ir::scalar::ScalarExpr) -> DynamicSqlArgIr;

    /// Dynamic-SQL sinks a call site reaches inside its callee, one per
    /// argument that flows into the callee's sink, each argument read as
    /// the classifier reads variables.
    fn call_site_calls(&self, site: &CallSite<'_>) -> Vec<DynamicSqlCallIr>;

    /// The parameter of `parameters`, those of the routine whose body
    /// runs the argument, that the argument is: written alone, or, read as
    /// the classifier reads variables, a variable holding the caller's
    /// text of it.
    fn argument_parameter(
        &self,
        expr: &AstExpr,
        source: &str,
        parameters: &[IdentKey],
    ) -> Option<String> {
        crate::ir::dynamic_sql::expr_parameter(expr, source, parameters)
    }
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

    fn classify_scalar_arg(&self, expr: &crate::ir::scalar::ScalarExpr) -> DynamicSqlArgIr {
        classify_scalar_expr_argument(expr, &SyntacticShapes)
    }

    fn call_site_calls(&self, _site: &CallSite<'_>) -> Vec<DynamicSqlCallIr> {
        Vec::new()
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

    fn grant_impacts(&self, _plan: &crate::ir::PrivilegePlan, _source: &str) -> GrantImpacts {
        GrantImpacts::default()
    }

    fn configure_dialect(
        &self,
        _dialect: Option<&dyn crate::dialect::Dialect>,
    ) -> Box<dyn DialectHold> {
        Box::new(())
    }

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

    fn routines_elsewhere(&self, _name: &[IdentKey]) -> Vec<RoutineRun> {
        Vec::new()
    }

    fn rows_of_either(
        &self,
        _first: &IrColumnConstraints,
        _second: &IrColumnConstraints,
    ) -> IrColumnConstraints {
        IrColumnConstraints::default()
    }
}

struct NoQueryReasoning {
    empty: BTreeSet<ColumnId>,
}

impl QueryReasoning for NoQueryReasoning {
    fn nested<'b>(&'b self, _root: &'b RelPlan) -> Box<dyn QueryReasoning + 'b> {
        Box::new(NoQueryReasoning {
            empty: BTreeSet::new(),
        })
    }

    fn nullability(&self, _site: ReadSite<'_>, _col: ColumnId) -> Nullability {
        Nullability::Unknown
    }

    fn lineage_roots(&self, _col: ColumnId) -> Option<&BTreeSet<ColumnId>> {
        None
    }

    fn key_backed(&self, _join: &RelPlan, _column: ColumnId, _on: &[ColumnId]) -> Option<bool> {
        None
    }

    fn dropped_padded_columns(&self, _join: &RelPlan) -> Vec<DroppedPaddedColumn> {
        Vec::new()
    }

    fn volatile_columns(&self) -> &BTreeSet<ColumnId> {
        &self.empty
    }

    fn output_taint_labels(&self, _column: ColumnId) -> Vec<TaintLabel> {
        Vec::new()
    }

    fn output_value_exposure(&self, _column: ColumnId) -> ValueExposure {
        ValueExposure::Value
    }

    fn output_catalog_tags(&self, _column: ColumnId) -> Vec<TagRef> {
        Vec::new()
    }

    fn output_constraints(&self, _relation: &RelPlan, _column: ColumnId) -> IrColumnConstraints {
        IrColumnConstraints::default()
    }

    fn output_unique(&self, _relation: &RelPlan, _column: ColumnId) -> bool {
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

    fn inter_procedural_calls(
        &self,
        _body: &AstStmt,
        _parameters: &[AstProcedureParam],
    ) -> Vec<DynamicSqlCallIr> {
        Vec::new()
    }

    fn dynamic_sql_literal_bodies(
        &self,
        _script: &AstScript,
        _config: &crate::analyzer::AnalysisConfig,
    ) -> DynamicBodyOutcome {
        DynamicBodyOutcome::empty()
    }

    fn attach_stale_references(
        &mut self,
        _facts: &mut StatementFacts,
        _position: usize,
        _plan: &RelPlan,
        _bindings: &BindingTable,
        _catalog: Option<&IndexedCatalogContext>,
        _places: &dyn TablePlaces,
    ) {
    }

    fn exported_columns(&self, _query: &QueryFacts) -> Vec<ExportedColumn> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognition_answers_unknown_at_every_site() {
        let node = RelPlan::Opaque {
            stmt_node_id: NodeId::new(0),
            reason: crate::ir::strict::OpaqueReason::NonSelectTopLevel,
            hints: Vec::new(),
            span: Span { start: 0, end: 1 },
        };
        let reasoning = NoQueryReasoning {
            empty: BTreeSet::new(),
        };
        for at in [
            ReadAt::Context,
            ReadAt::Selected(0),
            ReadAt::Defined,
            ReadAt::Output,
            ReadAt::JoinKey,
        ] {
            let site = ReadSite { node: &node, at };
            assert_eq!(
                reasoning.nullability(site, ColumnId::new(0)),
                Nullability::Unknown,
                "{at:?}"
            );
        }
    }
}
